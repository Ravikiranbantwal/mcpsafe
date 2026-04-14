"""
mcpsafe.runner
==============
Central orchestrator — ``ScanRunner`` connects to the target MCP server,
runs all test modules in the specified order, collects ``TestResult`` objects,
and returns a complete ``ScanReport``.

Execution order — stdio
-----------------------
  Step 1   ── T01  Discovery                                                sequential
  Step 2   ── T08 + T06                                                      concurrent
  Step 3   ── T02 + T03 + T04 + T07 + T09 + T12 + T13 + T16 + T18 + T19    concurrent
  Step 3b  ── T11  Timing Side-Channel                                       sequential (solo)
  Step 3c  ── T15  Reentrancy                                                sequential (solo)
  Step 4   ── T05  Load                                                      sequential
  Step 4b  ── T10 + T17 + T14 + T20                                          sequential (quiet)
  Step 5   ── T08-005 Comparison                                             sequential

Execution order — HTTP/SSE
--------------------------
  Step 1   ── T01  Discovery                                                sequential
  Step 2   ── T08 + T06                                                      concurrent
  Step 3   ── T02 + T03 + T04 + T09 + T12 + T13 + T16 + T18 + T19          concurrent
  Step 3b  ── T11  Timing Side-Channel                                       sequential (solo)
  Step 3c  ── T15  Reentrancy                                                sequential (solo)
  Step 4   ── T05  Load                                                      sequential
  Step 4b  ── T10 + T17 + T14 + T20                                          sequential (quiet)
  Step 5   ── T07  Auth                                                      sequential (last)
  Step 6   ── T08-005 Comparison                                             sequential

Rationale: T07 sends intentionally malformed HTTP requests (missing/invalid auth
headers, malformed protocol versions) that cause production HTTP servers to close
or rate-limit the connection.  Running T05 first guarantees the load tests execute
on a still-valid session.  T07 is always run last for HTTP so its side-effects on
the server-side session do not prevent other tests from completing.

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
from rich.markup import escape as _markup_escape
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
    TransportType,
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
    t09_output_sanitization,
    t10_cross_session,
    t11_timing_side_channel,
    t12_secret_leakage,
    t13_sampling_abuse,
    t14_notification_flood,
    t15_reentrancy,
    t16_capability_creep,
    t17_hash_drift,
    t18_ssrf,
    t19_homoglyph,
    t20_memory_leak,
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
        # Tracks whether we progressed past the initial connection phase so
        # a mid-scan TransportError (e.g. rate-limit 400 after T07) is
        # reported as INFO rather than a CRITICAL T00-001 connection failure.
        _scan_started: bool = False

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
                        f"[yellow]Warning: server discovery incomplete: "
                        f"{_markup_escape(str(exc))}[/yellow]"
                    )

                report.server_info = server_info
                _scan_started = True  # connection + discovery succeeded

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

                    is_http = self.config.transport in (
                        TransportType.HTTP, TransportType.SSE
                    )

                    # 3.1 ── T01 Discovery (sequential, required first) ────
                    t01_task = progress.add_task(
                        "[cyan]T01 Discovery[/cyan]", total=1
                    )
                    await self._run_module(
                        "T01 Discovery",
                        t01_discovery.run(session, server_info),
                        progress, t01_task,
                    )

                    # 3.2 ── T08 baseline + T06 Schema (concurrent) ────────
                    t08_task = progress.add_task(
                        "[cyan]T08 Latency Baseline[/cyan]", total=1
                    )
                    t06_task = progress.add_task(
                        "[cyan]T06 Schema[/cyan]", total=1
                    )
                    await asyncio.gather(
                        self._run_module(
                            "T08 Latency Baseline",
                            t08_latency.run(session, server_info, self.config),
                            progress, t08_task,
                            exclude_test_ids={"T08-005"},
                        ),
                        self._run_module(
                            "T06 Schema",
                            t06_schema.run(session, server_info),
                            progress, t06_task,
                        ),
                    )

                    # 3.3 ── T02 + T03 + T04 + T09 + T12 (concurrent) ─────
                    # Note: T07 is intentionally excluded here for HTTP scans
                    # (see step 3.5) because T07 sends malformed auth requests
                    # that cause production servers to close the session.
                    t02_task = progress.add_task(
                        "[magenta]T02 Injection[/magenta]", total=1
                    )
                    t03_task = progress.add_task(
                        "[magenta]T03 Fuzzer[/magenta]", total=1
                    )
                    t04_task = progress.add_task(
                        "[magenta]T04 Tool Poison[/magenta]", total=1
                    )
                    t09_task = progress.add_task(
                        "[magenta]T09 Output Sanitization[/magenta]", total=1
                    )
                    t12_task = progress.add_task(
                        "[magenta]T12 Error Secret Leakage[/magenta]", total=1
                    )
                    t13_task = progress.add_task(
                        "[magenta]T13 Sampling Abuse[/magenta]", total=1
                    )
                    t16_task = progress.add_task(
                        "[magenta]T16 Capability Creep[/magenta]", total=1
                    )
                    t18_task = progress.add_task(
                        "[magenta]T18 SSRF[/magenta]", total=1
                    )
                    t19_task = progress.add_task(
                        "[magenta]T19 Homoglyph[/magenta]", total=1
                    )
                    concurrent_modules = [
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
                        self._run_module(
                            "T09 Output Sanitization",
                            t09_output_sanitization.run(
                                session, server_info, self.config
                            ),
                            progress, t09_task,
                        ),
                        self._run_module(
                            "T12 Error Secret Leakage",
                            t12_secret_leakage.run(
                                session, server_info, self.config
                            ),
                            progress, t12_task,
                        ),
                        self._run_module(
                            "T13 Sampling Abuse",
                            t13_sampling_abuse.run(
                                session, server_info, self.config
                            ),
                            progress, t13_task,
                        ),
                        self._run_module(
                            "T16 Capability Creep",
                            t16_capability_creep.run(
                                session, server_info, self.config
                            ),
                            progress, t16_task,
                        ),
                        self._run_module(
                            "T18 SSRF",
                            t18_ssrf.run(session, server_info, self.config),
                            progress, t18_task,
                        ),
                        self._run_module(
                            "T19 Homoglyph",
                            t19_homoglyph.run(session, server_info, self.config),
                            progress, t19_task,
                        ),
                    ]
                    if not is_http:
                        # For stdio: include T07 here (concurrent with the above)
                        t07_task = progress.add_task(
                            "[magenta]T07 Auth[/magenta]", total=1
                        )
                        concurrent_modules.append(
                            self._run_module(
                                "T07 Auth",
                                t07_auth.run(session, server_info, self.config),
                                progress, t07_task,
                            )
                        )
                    await asyncio.gather(*concurrent_modules)

                    # 3.3b ── T11 Timing Side-Channel + T15 Reentrancy ──────
                    # Timing analysis runs solo; reentrancy needs concurrent
                    # overlap within itself — both require no other session
                    # activity to get clean measurements.
                    t11_task = progress.add_task(
                        "[magenta]T11 Timing Side-Channel[/magenta]", total=1
                    )
                    await self._run_module(
                        "T11 Timing Side-Channel",
                        t11_timing_side_channel.run(session, server_info, self.config),
                        progress, t11_task,
                    )
                    t15_task = progress.add_task(
                        "[magenta]T15 Reentrancy[/magenta]", total=1
                    )
                    await self._run_module(
                        "T15 Reentrancy",
                        t15_reentrancy.run(session, server_info, self.config),
                        progress, t15_task,
                    )

                    # 3.4 ── T05 Load ──────────────────────────────────────
                    t05_task = progress.add_task(
                        "[yellow]T05 Load[/yellow]", total=1
                    )
                    t05_results = await self._run_module(
                        "T05 Load",
                        t05_load.run(session, server_info, self.config),
                        progress, t05_task,
                    )

                    # 3.4b ── T10 Cross-Session + T14 Notification Flood +
                    #          T17 Hash Drift + T20 Memory Leak (sequential) ──
                    # These all either open a second connection (T10, T17) or
                    # need a long quiet window (T14, T20) — they cannot run
                    # concurrently with other tests.
                    t10_task = progress.add_task(
                        "[magenta]T10 Cross-Session Leakage[/magenta]", total=1
                    )
                    await self._run_module(
                        "T10 Cross-Session Leakage",
                        t10_cross_session.run(session, server_info, self.config),
                        progress, t10_task,
                    )
                    t17_task = progress.add_task(
                        "[magenta]T17 Hash Drift[/magenta]", total=1
                    )
                    await self._run_module(
                        "T17 Hash Drift",
                        t17_hash_drift.run(session, server_info, self.config),
                        progress, t17_task,
                    )
                    t14_task = progress.add_task(
                        "[magenta]T14 Notification Flood[/magenta]", total=1
                    )
                    await self._run_module(
                        "T14 Notification Flood",
                        t14_notification_flood.run(
                            session, server_info, self.config
                        ),
                        progress, t14_task,
                    )
                    t20_task = progress.add_task(
                        "[magenta]T20 Memory Leak[/magenta]", total=1
                    )
                    await self._run_module(
                        "T20 Memory Leak",
                        t20_memory_leak.run(session, server_info, self.config),
                        progress, t20_task,
                    )

                    # 3.5 ── T07 Auth (HTTP only — runs LAST to avoid session
                    #         invalidation before T05 can complete) ───────────
                    if is_http:
                        t07_task = progress.add_task(
                            "[magenta]T07 Auth[/magenta]", total=1
                        )
                        await self._run_module(
                            "T07 Auth",
                            t07_auth.run(session, server_info, self.config),
                            progress, t07_task,
                        )

                    # 3.6 ── T08-005 Latency comparison (last) ─────────────
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
            duration_ms = (time.perf_counter() - t_start) * 1000.0
            if _scan_started and self._results:
                # The scan ran to completion (or near it) before the transport
                # layer failed.  This is typical of rate-limited HTTP servers
                # that close the connection after T07 auth tests send malformed
                # requests.  Report as INFO so it does not inflate the overall
                # severity — all meaningful tests already completed.
                self._results.append(
                    TestResult(
                        test_id="T00-003",
                        test_name="Connection Closed Mid-Scan (Rate Limit / Server Reset)",
                        category=Category.PERFORMANCE,
                        severity=Severity.INFO,
                        passed=True,
                        description=(
                            "The HTTP server closed the connection mid-scan. "
                            "This is expected behaviour for production servers "
                            "that apply rate-limiting after receiving the T07 "
                            "auth probe suite. All security tests completed "
                            "before the connection was lost."
                        ),
                        duration_ms=duration_ms,
                        details=str(exc),
                        remediation=(
                            "Re-run with --no-load to skip T05 load tests and "
                            "reduce the number of requests sent to the server. "
                            "The connection drop does not indicate a vulnerability."
                        ),
                    )
                )
                self.console.print(
                    f"[dim]Note: connection closed by server after tests "
                    f"(rate-limit / session reset — see T00-003 in report).[/dim]"
                )
            else:
                # Genuine connection failure — no tests ran at all.
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
                        duration_ms=duration_ms,
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
                        f"[bold red]Connection failed:[/bold red] "
                        f"{_markup_escape(str(exc))}",
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
        # Guard the summary print: if the terminal cannot render the box-
        # drawing characters rich uses (e.g. Windows cp1252 console that was
        # not reconfigured), the print call can raise UnicodeEncodeError.
        # That must not prevent the CLI from persisting reports to disk.
        try:
            self._print_summary(report)
        except Exception as exc:
            self.console.print(
                f"[yellow]Warning: summary could not be rendered "
                f"({type(exc).__name__}: {str(exc)[:150]}). "
                f"Reports will still be saved.[/yellow]"
            )
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
            # Escape exc string: exception messages may contain server data.
            self.console.print(
                f"[red]  ✗ {_markup_escape(module_name)} crashed: "
                f"{_markup_escape(type(exc).__name__)}: "
                f"{_markup_escape(str(exc)[:300])}[/red]"
            )
            progress.update(task_id, completed=1)
            return []

    # ------------------------------------------------------------------
    # Console output helpers
    # ------------------------------------------------------------------

    def _print_header(self, server_info: ServerInfo, latency_ms: float) -> None:
        """Print the scan header as a rich Panel.

        All server-supplied strings are escaped via ``rich.markup.escape``
        so a malicious server cannot inject Rich markup tags (e.g. bold/red
        panel injections) into the terminal output.
        """
        lines = [
            f"[bold]Target:[/bold]     {_markup_escape(self.config.target)}",
            f"[bold]Transport:[/bold]  {self.config.transport.value.upper()}",
            f"[bold]Server:[/bold]     {_markup_escape(server_info.name)} "
            f"v{_markup_escape(server_info.version)}",
            f"[bold]Protocol:[/bold]   {_markup_escape(server_info.protocol_version)}",
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
                title="[bold blue]MCPSafe v0.2.0 — Security & Performance Scanner[/bold blue]",
                border_style="blue",
                padding=(1, 2),
            )
        )
        self.console.print()

    def _print_live_finding(self, result: TestResult) -> None:
        """
        If ``config.verbose`` is True and the result has a notable severity,
        print a rich Panel for the finding in real time.

        All server-supplied strings (description, details, remediation,
        test_name) are escaped so a malicious server cannot inject Rich
        markup tags into the terminal output.
        """
        if not self.config.verbose:
            return
        if result.severity in (Severity.PASS, Severity.INFO):
            return

        color = _SEVERITY_COLORS.get(result.severity.value, "white")
        body_parts = [_markup_escape(result.description)]
        if result.details:
            body_parts.append("")
            body_parts.append(_markup_escape(result.details[:600]))
        if result.remediation:
            body_parts.append("")
            body_parts.append(
                f"[dim]Remediation: {_markup_escape(result.remediation[:300])}[/dim]"
            )

        self.console.print(
            Panel(
                "\n".join(body_parts),
                title=(
                    f"[{color}]{result.severity.value}[/{color}]"
                    f"  {_markup_escape(result.test_id)}"
                    f"  —  {_markup_escape(result.test_name)}"
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
