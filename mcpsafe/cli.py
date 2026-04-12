"""
mcpsafe.cli
===========
Click-based command-line interface for MCPSafe.

Entry points
------------
  mcpsafe scan          Run a full security + performance scan.
  mcpsafe list-modules  Show every test module with its test count.
  mcpsafe version       Print the installed version and exit.

Exit codes
----------
  0  All checks passed (no CRITICAL or HIGH findings).
  1  One or more CRITICAL or HIGH findings — safe to use in CI pipelines.
  2  Invalid arguments or internal error.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# ---------------------------------------------------------------------------
# Project version — single source of truth
# ---------------------------------------------------------------------------

_VERSION = "0.1.0"

# ---------------------------------------------------------------------------
# Module registry
# ---------------------------------------------------------------------------

_KNOWN_MODULES: list[str] = [
    "discovery",
    "injection",
    "fuzzer",
    "poison",
    "load",
    "schema",
    "auth",
    "latency",
]

_MODULE_TABLE_DATA: list[tuple[str, str, str]] = [
    ("discovery", "8",  "Server identity, tools, resources, prompt enumeration"),
    ("injection",  "16", "Prompt injection attacks across all string parameters"),
    ("fuzzer",     "41", "Boundary values and type confusion for all parameter types"),
    ("poison",     "5",  "Tool description mutation and rug-pull detection"),
    ("load",       "4",  "Concurrent stress testing and latency under load"),
    ("schema",     "5",  "JSON Schema validation and required field enforcement"),
    ("auth",       "7",  "Authentication bypass, path traversal, credential exposure"),
    ("latency",    "5",  "Response time benchmarking and cold-start detection"),
]

# Map module name → only_tests filter values used in ScanConfig
_MODULE_TO_TEST_PREFIX: dict[str, str] = {
    "discovery": "T01",
    "injection":  "T02",
    "fuzzer":     "T03",
    "poison":     "T04",
    "load":       "T05",
    "schema":     "T06",
    "auth":       "T07",
    "latency":    "T08",
}

# ---------------------------------------------------------------------------
# Shared console
# ---------------------------------------------------------------------------

_console = Console()


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

def _print_banner() -> None:
    """Print the MCPSafe startup banner using a rich Panel."""
    _console.print(
        Panel(
            "[bold]MCP Server Security & Stress Tester[/bold]\n"
            "[dim]github.com/your-handle/mcpsafe[/dim]",
            title=f"[bold blue]MCPSafe v{_VERSION}[/bold blue]",
            border_style="blue",
            padding=(0, 2),
        )
    )


# ---------------------------------------------------------------------------
# CLI root group
# ---------------------------------------------------------------------------

@click.group()
def cli() -> None:
    """MCPSafe — MCP Server Security & Performance Testing Framework."""


@cli.result_callback()
def process_result(result: object, **kwargs: object) -> None:
    """Reserved for future pipeline chaining."""
    pass


# ---------------------------------------------------------------------------
# mcpsafe scan
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("target")
@click.option(
    "--transport",
    type=click.Choice(["stdio", "http", "sse"], case_sensitive=False),
    default="stdio",
    show_default=True,
    help="Transport protocol to use.",
)
@click.option(
    "--modules",
    default="all",
    show_default=True,
    help=(
        "Comma-separated modules to run: "
        "discovery,injection,fuzzer,poison,load,schema,auth,latency  "
        "(default: all)"
    ),
)
@click.option(
    "--output",
    type=click.Choice(["json", "html", "both"], case_sensitive=False),
    default="both",
    show_default=True,
    help="Report format to generate.",
)
@click.option(
    "--out-dir",
    type=click.Path(),
    default="./mcpsafe-reports",
    show_default=True,
    help="Directory to save generated reports.",
)
@click.option(
    "--timeout",
    default=10,
    show_default=True,
    type=int,
    help="Seconds per MCP call before timeout.",
)
@click.option(
    "--concurrency",
    default=10,
    show_default=True,
    type=int,
    help="Max concurrent calls during load tests.",
)
@click.option(
    "--no-load",
    is_flag=True,
    default=False,
    help="Skip large payload and stress tests (safe for production targets).",
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    default=False,
    help="Print each finding as it is discovered.",
)
def scan(
    target: str,
    transport: str,
    modules: str,
    output: str,
    out_dir: str,
    timeout: int,
    concurrency: int,
    no_load: bool,
    verbose: bool,
) -> None:
    """
    Run a security and performance scan against TARGET.

    TARGET is the MCP server command (stdio) or base URL (http/sse).

    \b
    Examples:
      mcpsafe scan "npx -y @modelcontextprotocol/server-everything"
      mcpsafe scan http://localhost:8080 --transport http
      mcpsafe scan "python server.py" --modules injection,fuzzer --no-load
    """
    # ── Step 1: Banner ────────────────────────────────────────────────────
    _print_banner()

    # ── Step 2: Parse and validate modules ───────────────────────────────
    if modules.strip().lower() == "all":
        selected_modules = list(_KNOWN_MODULES)
    else:
        raw = [m.strip().lower() for m in modules.split(",") if m.strip()]
        unknown = [m for m in raw if m not in _KNOWN_MODULES]
        if unknown:
            _console.print(
                f"[bold red]Error:[/bold red] Unknown module(s): "
                f"{', '.join(repr(u) for u in unknown)}\n"
                f"Valid modules: {', '.join(_KNOWN_MODULES)}",
            )
            sys.exit(1)
        selected_modules = raw

    # Translate module names to T-prefix filters for ScanConfig.
    only_tests = [_MODULE_TO_TEST_PREFIX[m] for m in selected_modules]
    skip_tests: list[str] = []

    # ── Step 3: Build ScanConfig ──────────────────────────────────────────
    # Defer heavy imports until after argument validation so --help is fast.
    from mcpsafe.models import ScanConfig, TransportType

    transport_map: dict[str, TransportType] = {
        "stdio": TransportType.STDIO,
        "http":  TransportType.HTTP,
        "sse":   TransportType.SSE,
    }

    config = ScanConfig(
        transport=transport_map[transport.lower()],
        target=target,
        args=[],
        env={},
        timeout_seconds=float(timeout),
        concurrency=concurrency,
        skip_tests=skip_tests,
        only_tests=only_tests,
        output_dir=out_dir,
        verbose=verbose,
        no_load=no_load,
    )

    # ── Step 4 & 5: Run scanner ────────────────────────────────────────────
    from mcpsafe.runner import ScanRunner

    runner = ScanRunner(config)
    try:
        report = asyncio.run(runner.run())
    except KeyboardInterrupt:
        _console.print("\n[yellow]Scan interrupted by user.[/yellow]")
        sys.exit(2)
    except Exception as exc:
        _console.print(f"[bold red]Fatal error:[/bold red] {exc}")
        sys.exit(2)

    # ── Step 6: Save reports ───────────────────────────────────────────────
    from mcpsafe.reporter.json_reporter import JsonReporter
    out_path = Path(out_dir)
    saved_paths: list[Path] = []

    if output in ("json", "both"):
        try:
            json_reporter = JsonReporter(report)
            json_path = json_reporter.write(out_path)
            saved_paths.append(json_path)
        except Exception as exc:
            _console.print(f"[yellow]Warning: could not write JSON report: {exc}[/yellow]")

    if output in ("html", "both"):
        try:
            from mcpsafe.reporter.html_reporter import HtmlReporter
            html_reporter = HtmlReporter(report)
            html_path = html_reporter.write(out_path)
            saved_paths.append(html_path)
        except Exception as exc:
            _console.print(f"[yellow]Warning: could not write HTML report: {exc}[/yellow]")

    # ── Step 8: Print saved file paths ────────────────────────────────────
    if saved_paths:
        _console.print()
        _console.rule("[dim]Report Files[/dim]")
        for p in saved_paths:
            icon = "📄" if str(p).endswith(".json") else "🌐"
            _console.print(f"  {icon}  [bold]{p}[/bold]")
        _console.print()

    # ── Step 9: Exit code for CI integration ──────────────────────────────
    if report.critical_count > 0 or report.high_count > 0:
        sys.exit(1)


# ---------------------------------------------------------------------------
# mcpsafe list-modules
# ---------------------------------------------------------------------------

@cli.command("list-modules")
def list_modules() -> None:
    """List all available test modules and their test counts."""
    table = Table(
        title="MCPSafe Test Modules",
        show_header=True,
        header_style="bold cyan",
        border_style="dim",
        show_lines=True,
    )
    table.add_column("Module",      style="bold",  min_width=12)
    table.add_column("Tests",       justify="right", min_width=6)
    table.add_column("Description", min_width=50)

    total_tests = 0
    for module_name, count_str, description in _MODULE_TABLE_DATA:
        table.add_row(module_name, count_str, description)
        total_tests += int(count_str)

    # Totals row
    table.add_section()
    table.add_row(
        f"[bold]{len(_MODULE_TABLE_DATA)} modules[/bold]",
        f"[bold]{total_tests}[/bold]",
        "[dim]Total test cases[/dim]",
    )

    _console.print()
    _console.print(table)
    _console.print()


# ---------------------------------------------------------------------------
# mcpsafe version
# ---------------------------------------------------------------------------

@cli.command()
def version() -> None:
    """Print the MCPSafe version and exit."""
    click.echo(f"MCPSafe {_VERSION}")


# ---------------------------------------------------------------------------
# Main guard
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    cli()
