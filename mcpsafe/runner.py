"""
mcpsafe.runner
==============
Central orchestrator — ``ScanRunner`` connects to the target MCP server,
runs all test modules in the specified order, collects ``TestResult`` objects,
and returns a complete ``ScanReport``.

Execution order
---------------
  Step 1  ── T01  Discovery          sequential  (required for all others)
  Step 2  ── T08  Latency baseline   sequential  (establishes baseline before load)
  Step 3  ── T06  Schema             sequential
  Step 4  ── T02 + T03 + T04        concurrent  (asyncio.gather)
  Step 5  ── T07  Auth               sequential
  Step 6  ── T05  Load               sequential  (most disruptive; last before report)
  Step 7  ── T08-005 Comparison      sequential  (needs T05 p95 data)

Usage
-----
    config = ScanConfig(transport=TransportType.STDIO, target="npx -y server")
    runner = ScanRunner(config)
    report = await runner.run()
"""

from __future__ import annotations

import asyncio
import time
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskID,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text

from mcpsafe.models import (
    Category,
    ScanConfig,
    ScanReport,
    ServerInfo,
    Severity,
    TestResult,
)
from mcpsafe.transport import MCPConnection, TransportError, discover_server_info

# Test modules — imported here so the runner owns all dependencies.
from mcpsafe.tests import (
    t01_discovery,
    t02_injection,
    t03_fuzzer,
    t04_tool_poison,
    t05_load,
    t06_schema,
    t07_auth,
    t08_latency,
)

# ---------------------------------------------------------------------------
# Severity → rich colour mapping
# ---------------------------------------------------------------------------

_SEVERITY_COLORS: dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "blue",
    "INFO":     "dim",
    "PASS":     "green",
}

_BLOCK_CHAR = "█"
_SUMMARY_BAR_WIDTH = 30   # max block chars in the summary bar


# ---------------------------------------------------------------------------
# ScanRunner
# ---------------------------------------------------------------------------


class ScanRunner:
    """
    Orchestrates a full MCPSafe scan against a single MCP server.

    Parameters
    ----------
    config:
        Fully-populated ``ScanConfig`` (from CLI or programmatic use).
    """

    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self.console = Console()
        self._results: list[TestResult] = []

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def run(self) -> ScanReport:
        """
        Connect to the MCP server, run all test modules, and return a
        ``ScanReport``.

        If the connection itself fails a ``ScanReport`` containing a single
        CRITICAL ``TestResult`` is returned immediately — no tests are run.

        Returns
        -------
        ScanReport:
            Complete report with all results, server info, and timestamps.
        """
        report = ScanReport()
        t_start = time.perf_counter()

        try:
            async with MCPConnection(self.config) as (session, conn_info):
                # ── STEP 1: Discover server info ──────────────────────────
                try:
                    server_info = await discover_server_info(
                        session, self.config, conn_info
                    )
                except Exception as exc:
                    server_info = ServerInfo(
                        name="unknown", version="unknown",
                        protocol_version="unknown",
                        transport=self.config.transport,
                        target=self.config.target,
                    )
                    self.console.print(
                        f"[yellow]Warning: server discovery incomplete: {exc}[/yellow]"
                    )

                report.server_info = server_info

                # ── STEP 2: Print header ──────────────────────────────────
                self._print_header(server_info, conn_info.latency_ms)

                # ── STEP 3: Run all modules with a Progress bar ───────────
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TaskProgressColumn(),
                    TimeElapsedColumn(),
                    console=self.console,
                    transient=False,
                ) as progress:

                    # 3.1 ── T01 Discovery (sequential, required first) ────
                    t01_task = progress.add_task(
                        "[cyan]T01 Discovery[/cyan]", total=1
                    )
                    await self._run_module(
                        "T01 Discovery",
                        t01_discovery.run(session, server_info),
                        progress, t01_task,
                    )

                    # 3.2 ── T08 Latency baseline (sequential) ─────────────
                    t08_task = progress.add_task(
                        "[cyan]T08 Latency Baseline[/cyan]", total=1
                    )
                    await self._run_module(
                        "T08 Latency Baseline",
                        t08_latency.run(session, server_info, self.config),
                        progress, t08_task,
                        exclude_test_ids={"T08-005"},   # T08-005 added after T05
                    )

                    # 3.3 ── T06 Schema (sequential) ──────────────────────
                    t06_task = progress.add_task(
                        "[cyan]T06 Schema[/cyan]", total=1
                    )
                    await self._run_module(
                        "T06 Schema",
                        t06_schema.run(session, server_info),
                        progress, t06_task,
                    )

                    # 3.4 ── T02 + T03 + T04 (concurrent) ─────────────────
                    t02_task = progress.add_task(
                        "[magenta]T02 Injection[/magenta]", total=1
                    )
                    t03_task = progress.add_task(
                        "[magenta]T03 Fuzzer[/magenta]", total=1
                    )
                    t04_task = progress.add_task(
                        "[magenta]T04 Tool Poison[/magenta]", total=1
                    )

                    await asyncio.gather(
                        self._run_module(
                            "T02 Injection",
                            t02_injection.run(
                                session, server_info,
                                skip_large_payloads=self.config.no_load,
                                timeout=self.config.timeout_seconds,
                            ),
                            progress, t02_task,
                        ),
                        self._run_module(
                            "T03 Fuzzer",
                            t03_fuzzer.run(session, server_info, self.config),
                            progress, t03_task,
                        ),
                        self._run_module(
                            "T04 Tool Poison",
                            t04_tool_poison.run(session, server_info),
                            progress, t04_task,
                        ),
                    )

                    # 3.5 ── T07 Auth (sequential) ────────────────────────
                    t07_task = progress.add_task(
                        "[cyan]T07 Auth[/cyan]", total=1
                    )
                    await self._run_module(
                        "T07 Auth",
                        t07_auth.run(session, server_info, self.config),
                        progress, t07_task,
                    )

                    # 3.6 ── T05 Load (most disruptive; second to last) ────
                    t05_task = progress.add_task(
                        "[yellow]T05 Load[/yellow]", total=1
                    )
                    t05_results = await self._run_module(
                        "T05 Load",
                        t05_load.run(session, server_info, self.config),
                        progress, t05_task,
                    )

                    # 3.7 ── T08-005 Latency comparison (last) ─────────────
                    t08_005_task = progress.add_task(
                        "[cyan]T08-005 Latency Comparison[/cyan]", total=1
                    )
                    t08_005_result = await t08_latency.compute_latency_comparison(
                        t05_results
                    )
                    self._results.append(t08_005_result)
                    self._print_live_finding(t08_005_result)
                    progress.update(t08_005_task, completed=1)

        except TransportError as exc:
            # Connection-level failure — produce a CRITICAL result and abort.
            self._results.append(
                TestResult(
                    test_id="T00-001",
                    test_name="Connection Failed",
                    category=Category.SECURITY,
                    severity=Severity.CRITICAL,
                    passed=False,
                    description=(
                        f"Failed to connect to {self.config.target!r}: {exc}"
                    ),
                    duration_ms=(time.perf_counter() - t_start) * 1000.0,
                    details=str(exc),
                    remediation=(
                        "Verify the target command or URL, ensure the server "
                        "process starts correctly, and check network/firewall "
                        "settings."
                    ),
                )
            )
            self.console.print(
                Panel(
                    f"[bold red]Connection failed:[/bold red] {exc}",
                    title="[bold red]MCPSafe — Connection Error[/bold red]",
                    border_style="red",
                )
            )

        except Exception as exc:
            # Unexpected runner crash — produce a CRITICAL result.
            self._results.append(
                TestResult(
                    test_id="T00-002",
                    test_name="Runner Crashed",
                    category=Category.SECURITY,
                    severity=Severity.CRITICAL,
                    passed=False,
                    description=f"Unexpected runner error: {type(exc).__name__}: {exc}",
                    duration_ms=(time.perf_counter() - t_start) * 1000.0,
                    details=str(exc),
                )
            )
            self.console.print_exception()

        # ── STEP 4: Build and return the complete report ──────────────────
        report.add_results(self._results)
        report.finish()
        self._print_summary(report)
        return report

    # ------------------------------------------------------------------
    # Module runner wrapper
    # ------------------------------------------------------------------

    async def _run_module(
        self,
        module_name: str,
        coro: object,
        progress: Progress,
        task_id: TaskID,
        exclude_test_ids: Optional[set[str]] = None,
    ) -> list[TestResult]:
        """
        Await a test-module coroutine, collect its results, update progress.

        Parameters
        ----------
        module_name:
            Human-readable name for logging.
        coro:
            The already-created coroutine (e.g. ``t01.run(session, server_info)``).
        progress:
            The active rich ``Progress`` instance.
        task_id:
            The ``TaskID`` for this module's progress bar row.
        exclude_test_ids:
            If given, results with ``test_id`` in this set are NOT appended to
            ``self._results`` (used to defer T08-005 until after T05).

        Returns
        -------
        list[TestResult]:
            All results the module produced (even excluded ones, for the caller).
        """
        exclude_test_ids = exclude_test_ids or set()
        try:
            results: list[TestResult] = await coro  # type: ignore[misc]
            for r in results:
                if r.test_id not in exclude_test_ids:
                    self._results.append(r)
                    self._print_live_finding(r)
            progress.update(task_id, completed=1)
            return results
        except asyncio.CancelledError:
            progress.update(task_id, completed=1)
            raise
        except Exception as exc:
            # Safety net — test modules must never raise, but just in case.
            self.console.print(
                f"[red]  ✗ {module_name} crashed: "
                f"{type(exc).__name__}: {exc}[/red]"
            )
            progress.update(task_id, completed=1)
            return []

    # ------------------------------------------------------------------
    # Console output helpers
    # ------------------------------------------------------------------

    def _print_header(self, server_info: ServerInfo, latency_ms: float) -> None:
        """Print the scan header as a rich Panel."""
        lines = [
            f"[bold]Target:[/bold]     {self.config.target}",
            f"[bold]Transport:[/bold]  {self.config.transport.value.upper()}",
            f"[bold]Server:[/bold]     {server_info.name} v{server_info.version}",
            f"[bold]Protocol:[/bold]   {server_info.protocol_version}",
            f"[bold]Tools:[/bold]      {len(server_info.tools)}",
            f"[bold]Resources:[/bold]  {len(server_info.resources)}",
            f"[bold]Prompts:[/bold]    {len(server_info.prompts)}",
            f"[bold]Latency:[/bold]    {latency_ms:.0f}ms (connection probe)",
        ]
        if self.config.no_load:
            lines.append(
                "[bold]Mode:[/bold]       [yellow]--no-load "
                "(T05-003, large payloads skipped)[/yellow]"
            )

        self.console.print(
            Panel(
                "\n".join(lines),
                title="[bold blue]MCPSafe v0.1.0 — Security & Performance Scanner[/bold blue]",
                border_style="blue",
                padding=(1, 2),
            )
        )
        self.console.print()

    def _print_live_finding(self, result: TestResult) -> None:
        """
        If ``config.verbose`` is True and the result has a notable severity,
        print a rich Panel for the finding in real time.
        """
        if not self.config.verbose:
            return
        if result.severity in (Severity.PASS, Severity.INFO):
            return

        color = _SEVERITY_COLORS.get(result.severity.value, "white")
        body_parts = [result.description]
        if result.details:
            body_parts.append("")
            body_parts.append(result.details[:600])
        if result.remediation:
            body_parts.append("")
            body_parts.append(f"[dim]Remediation: {result.remediation[:300]}[/dim]")

        self.console.print(
            Panel(
                "\n".join(body_parts),
                title=(
                    f"[{color}]{result.severity.value}[/{color}]"
                    f"  {result.test_id}  —  {result.test_name}"
                ),
                border_style=color.replace("bold ", ""),
                padding=(0, 1),
            )
        )

    def _print_summary(self, report: ScanReport) -> None:
        """Print the final severity-summary table to the console."""
        self.console.print()
        self.console.rule("[bold]Scan Complete[/bold]")

        # Find the max count for bar scaling.
        counts = {
            Severity.CRITICAL: report.critical_count,
            Severity.HIGH:     report.high_count,
            Severity.MEDIUM:   report.medium_count,
            Severity.LOW:      report.low_count,
            Severity.INFO: sum(
                1 for r in report.results if r.severity == Severity.INFO
            ),
            Severity.PASS:     report.passed_count,
        }
        max_count = max(counts.values()) if counts else 1

        table = Table(
            show_header=True,
            header_style="bold",
            box=None,
            padding=(0, 2),
        )
        table.add_column("Severity", style="bold", width=10)
        table.add_column("Count", justify="right", width=7)
        table.add_column("Bar", width=_SUMMARY_BAR_WIDTH + 2)

        for sev in (
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
            Severity.PASS,
        ):
            count = counts[sev]
            color = _SEVERITY_COLORS.get(sev.value, "white")
            bar_len = (
                int(_SUMMARY_BAR_WIDTH * count / max_count) if max_count > 0 else 0
            )
            bar = _BLOCK_CHAR * bar_len if bar_len > 0 else ""
            table.add_row(
                Text(sev.value, style=color),
                Text(str(count), style=color),
                Text(bar, style=color),
            )

        self.console.print(table)
        self.console.print()

        # Footer line.
        dur_s = (report.duration_ms / 1000) if report.duration_ms else 0
        overall_color = _SEVERITY_COLORS.get(report.overall_severity.value, "white")
        self.console.print(
            f"  Tests: [bold]{report.total_tests}[/bold]   "
            f"Passed: [green]{report.passed_count}[/green]   "
            f"Failed: [red]{report.failed_count}[/red]   "
            f"Duration: [bold]{dur_s:.1f}s[/bold]   "
            f"Overall: [{overall_color}]{report.overall_severity.value}[/{overall_color}]"
        )
        self.console.print()
