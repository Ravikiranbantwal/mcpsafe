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
import os
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Windows console Unicode fix
# ---------------------------------------------------------------------------
# rich uses box-drawing characters (█, ─, ╭, ╯, …) in its progress bars and
# severity charts.  On Windows the default stdout codec is cp1252 which
# cannot encode these — resulting in ``'charmap' codec can't encode character``
# crashes that abort the scan AFTER tests finish but BEFORE reports are saved.
#
# Reconfigure stdout/stderr to UTF-8 with error-replacement as the very first
# thing we do.  Setting PYTHONIOENCODING too ensures any child processes
# inherit the same setting.
if sys.platform == "win32":
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
    except (AttributeError, Exception):
        # Older Python or non-standard stream — fall through silently;
        # the scanner will still work, just the box-drawing may render poorly.
        pass

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# ---------------------------------------------------------------------------
# Project version — single source of truth
# ---------------------------------------------------------------------------

_VERSION = "0.3.0"

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
            "[dim]github.com/Ravikiranbantwal/mcpsafe[/dim]",
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
    type=click.Choice(["json", "html", "both", "sarif", "all"], case_sensitive=False),
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
    "--env",
    "env_vars",
    multiple=True,
    metavar="KEY=VALUE",
    help=(
        "Environment variable to pass to the server process (stdio only). "
        "Can be repeated: --env GITHUB_TOKEN=xxx --env FOO=bar"
    ),
)
@click.option(
    "--header",
    "http_headers",
    multiple=True,
    metavar="KEY=VALUE",
    help=(
        "HTTP header to include in requests (http/sse transport only). "
        "Can be repeated: --header Authorization='Bearer tok' --header X-Foo=bar"
    ),
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    default=False,
    help="Print each finding as it is discovered.",
)
@click.option(
    "--config",
    "config_file",
    type=click.Path(exists=False),
    default=None,
    help=(
        "Path to mcpsafe.toml config file. "
        "CLI flags override config values. "
        "Example: mcpsafe-config.toml"
    ),
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
    env_vars: tuple[str, ...],
    http_headers: tuple[str, ...],
    verbose: bool,
    config_file: str | None,
) -> None:
    """
    Run a security and performance scan against TARGET.

    TARGET is the MCP server command (stdio) or base URL (http/sse).

    \b
    Examples:
      mcpsafe scan "npx -y @modelcontextprotocol/server-everything"
      mcpsafe scan http://localhost:8080 --transport http
      mcpsafe scan "python server.py" --modules injection,fuzzer --no-load
      mcpsafe scan "npx -y @modelcontextprotocol/server-github" --env GITHUB_TOKEN=ghp_xxx
      mcpsafe scan "npx @modelcontextprotocol/server-postgres" --env DATABASE_URL=postgres://...
    """
    # ── Step 0: Validate numeric flags ───────────────────────────────────
    if timeout <= 0:
        _console.print(
            f"[bold red]Error:[/bold red] --timeout must be a positive integer "
            f"(got {timeout!r}). Use a value like --timeout 10."
        )
        sys.exit(2)
    if concurrency <= 0:
        _console.print(
            f"[bold red]Error:[/bold red] --concurrency must be a positive integer "
            f"(got {concurrency!r}). Use a value like --concurrency 10."
        )
        sys.exit(2)

    # ── Step 1: Banner ────────────────────────────────────────────────────
    _print_banner()

    # ── Step 1a: Load config file if provided ─────────────────────────────
    config_dict: dict = {}
    if config_file:
        config_path = Path(config_file)
        if not config_path.exists():
            _console.print(
                f"[yellow]Warning:[/yellow] Config file {config_file!r} "
                "does not exist; continuing with CLI defaults."
            )
        else:
            try:
                if sys.version_info >= (3, 11):
                    import tomllib
                    with open(config_path, "rb") as f:
                        config_dict = tomllib.load(f)
                else:
                    try:
                        import tomli as tomllib
                        with open(config_path, "rb") as f:
                            config_dict = tomllib.load(f)
                    except ImportError:
                        _console.print(
                            "[yellow]Warning:[/yellow] tomllib/tomli not available; "
                            "config file ignored."
                        )
                        config_dict = {}
            except Exception as exc:
                _console.print(
                    f"[yellow]Warning:[/yellow] Could not parse {config_file!r}: {exc}"
                )
                config_dict = {}

    # Extract config sections
    scan_config = config_dict.get("scan", {})
    env_config = config_dict.get("env", {})

    # ── Step 1a-ii: Credential risk warning for config file ──────────────
    # If the config file contains [env] keys that look like credentials, warn
    # the user about plain-text secret storage and file permission risks.
    if config_file and env_config:
        _CREDENTIAL_KEY_PATTERNS = (
            "token", "secret", "password", "passwd", "key", "auth",
            "credential", "api_key", "apikey", "access_key", "private",
        )
        cred_keys = [
            k for k in env_config
            if any(pat in k.lower() for pat in _CREDENTIAL_KEY_PATTERNS)
        ]
        if cred_keys:
            _console.print(
                f"[yellow]⚠  Security notice:[/yellow] Config file {config_file!r} "
                f"contains sensitive-looking keys: "
                f"{', '.join(repr(k) for k in cred_keys[:5])}.\n"
                f"   [dim]Ensure the file is not world-readable "
                f"(chmod 600 {config_file}) and is listed in .gitignore.[/dim]"
            )
        # Check file permissions on Unix
        import stat as _stat
        try:
            mode = Path(config_file).stat().st_mode
            if mode & (_stat.S_IRGRP | _stat.S_IROTH):
                _console.print(
                    f"[yellow]⚠  Permission warning:[/yellow] Config file "
                    f"{config_file!r} is readable by group or others "
                    f"(mode {oct(mode & 0o777)}). Run: "
                    f"[bold]chmod 600 {config_file}[/bold]"
                )
        except (OSError, AttributeError):
            pass  # Windows or inaccessible — skip permission check

    # ── Step 1b: Parse --env KEY=VALUE pairs ─────────────────────────────
    env_dict: dict[str, str] = dict(env_config)  # Start with config file env vars
    for kv in env_vars:
        if "=" not in kv:
            _console.print(
                f"[bold red]Error:[/bold red] --env value {kv!r} must be in "
                f"KEY=VALUE format."
            )
            sys.exit(1)
        k, v = kv.split("=", 1)
        env_dict[k] = v  # CLI flags override config

    # ── Step 1c: Parse --header KEY=VALUE pairs (HTTP transport only) ────
    headers_dict: dict[str, str] = {}
    for kv in http_headers:
        if "=" not in kv:
            _console.print(
                f"[bold red]Error:[/bold red] --header value {kv!r} must be in "
                f"KEY=VALUE format."
            )
            sys.exit(1)
        k, v = kv.split("=", 1)
        headers_dict[k] = v

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

    # Apply config file defaults (CLI flags take precedence)
    config_transport = scan_config.get("transport", transport)
    config_timeout = scan_config.get("timeout", timeout)
    config_concurrency = scan_config.get("concurrency", concurrency)
    config_out_dir = scan_config.get("out_dir", out_dir)
    config_output = scan_config.get("output", output)
    config_no_load = scan_config.get("no_load", no_load)
    config_verbose = scan_config.get("verbose", verbose)

    config = ScanConfig(
        transport=transport_map[config_transport.lower()],
        target=target,
        args=[],
        env=env_dict,
        headers=headers_dict,
        timeout_seconds=float(config_timeout),
        concurrency=config_concurrency,
        skip_tests=skip_tests,
        only_tests=only_tests,
        output_dir=config_out_dir,
        verbose=config_verbose,
        no_load=config_no_load,
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
    from mcpsafe.reporter.sarif_reporter import SarifReporter

    # Normalize output format
    if config_output.lower() == "all":
        config_output = "json,html,sarif"

    out_path = Path(config_out_dir)
    saved_paths: list[Path] = []

    if "json" in config_output.lower() or "both" in config_output.lower():
        try:
            json_reporter = JsonReporter(report)
            json_path = json_reporter.write(out_path)
            saved_paths.append(json_path)
        except Exception as exc:
            _console.print(f"[yellow]Warning: could not write JSON report: {exc}[/yellow]")

    if "html" in config_output.lower() or "both" in config_output.lower():
        try:
            from mcpsafe.reporter.html_reporter import HtmlReporter
            html_reporter = HtmlReporter(report)
            html_path = html_reporter.write(out_path)
            saved_paths.append(html_path)
        except Exception as exc:
            _console.print(f"[yellow]Warning: could not write HTML report: {exc}[/yellow]")

    if "sarif" in config_output.lower() or "all" in config_output.lower():
        try:
            sarif_reporter = SarifReporter(report)
            sarif_path = sarif_reporter.save(str(out_path))
            saved_paths.append(sarif_path)
        except Exception as exc:
            _console.print(f"[yellow]Warning: could not write SARIF report: {exc}[/yellow]")

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
# mcpsafe compare
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("report1", type=click.Path(exists=True))
@click.argument("report2", type=click.Path(exists=True))
def compare(report1: str, report2: str) -> None:
    """
    Compare two MCPSafe JSON scan reports and display a diff.

    REPORT1 and REPORT2 are paths to `.json` report files.

    Shows NEW findings (in report2 but not report1, or worse severity),
    FIXED findings (in report1 but not report2, or better severity),
    and UNCHANGED findings present in both.

    Exits with code 1 if new findings were introduced, 0 otherwise.

    \b
    Example:
      mcpsafe compare scan1.json scan2.json
    """
    import json
    from rich.table import Table

    # ── Load both reports ─────────────────────────────────────────────
    def _load_report(path: str) -> dict:
        """
        Load a JSON report from ``path``.

        Raises ``SystemExit(2)`` on any failure:
        - File not readable (OSError)
        - Not valid JSON (JSONDecodeError)
        - Parsed value is not a JSON object (TypeError)
        """
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
        except json.JSONDecodeError as exc:
            _console.print(
                f"[bold red]Error:[/bold red] {path!r} is not valid JSON: {exc}"
            )
            sys.exit(2)
        except OSError as exc:
            _console.print(
                f"[bold red]Error:[/bold red] Cannot read {path!r}: {exc}"
            )
            sys.exit(2)
        if not isinstance(data, dict):
            _console.print(
                f"[bold red]Error:[/bold red] {path!r} does not contain a JSON "
                f"object (got {type(data).__name__!r}). "
                f"Only MCPSafe JSON reports are supported."
            )
            sys.exit(2)
        # Verify it looks like an MCPSafe report (has required top-level keys).
        missing = [k for k in ("scan_id", "results") if k not in data]
        if missing:
            _console.print(
                f"[bold red]Error:[/bold red] {path!r} is missing required "
                f"MCPSafe report keys: {missing}. "
                f"Is this a valid MCPSafe JSON report?"
            )
            sys.exit(2)
        return data

    report1_data = _load_report(report1)
    report2_data = _load_report(report2)

    # ── Extract metadata (defensive — values may be non-string) ──────
    def _safe_str(val: object, fallback: str = "unknown", max_len: int = 80) -> str:
        """Convert an arbitrary JSON value to a safe display string."""
        if val is None:
            return fallback
        s = str(val)
        return s[:max_len] if len(s) > max_len else s

    scan_id_1 = _safe_str(report1_data.get("scan_id"), max_len=8)
    scan_id_2 = _safe_str(report2_data.get("scan_id"), max_len=8)
    si_1 = report1_data.get("server_info")
    si_2 = report2_data.get("server_info")
    target_1 = _safe_str(
        (si_1.get("target") if isinstance(si_1, dict) else None), "unknown"
    )
    target_2 = _safe_str(
        (si_2.get("target") if isinstance(si_2, dict) else None), "unknown"
    )
    ts_1 = _safe_str(report1_data.get("started_at"), "unknown")
    ts_2 = _safe_str(report2_data.get("started_at"), "unknown")

    _console.print()
    _console.rule("[bold]Scan Comparison[/bold]")
    _console.print(f"Report 1:  {scan_id_1}  {target_1}  {ts_1}")
    _console.print(f"Report 2:  {scan_id_2}  {target_2}  {ts_2}")
    _console.print()

    # ── Build severity maps ───────────────────────────────────────────
    _VALID_SEVERITIES = {"PASS", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}

    def extract_findings(report_data: dict) -> dict[str, str]:
        """
        Build a dict of ``{test_id: severity}`` for non-PASS results.

        Defensively handles malformed result entries:
        - skips any result that is not a dict
        - skips results with missing or non-string test_id / severity
        - treats unrecognised severity values as INFO
        """
        findings: dict[str, str] = {}
        results_list = report_data.get("results", [])
        if not isinstance(results_list, list):
            return findings
        for result in results_list:
            if not isinstance(result, dict):
                continue
            test_id = result.get("test_id")
            severity = result.get("severity")
            # Skip non-string values
            if not isinstance(test_id, str) or not test_id:
                continue
            if not isinstance(severity, str):
                severity = "INFO"
            # Normalise unknown severity values to INFO
            if severity not in _VALID_SEVERITIES:
                severity = "INFO"
            if severity != "PASS":
                findings[test_id] = severity
        return findings

    findings_1 = extract_findings(report1_data)
    findings_2 = extract_findings(report2_data)

    # ── Severity ordering for comparison ──────────────────────────────
    severity_order = {"PASS": 0, "INFO": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}

    def is_worse(old_sev: str, new_sev: str) -> bool:
        """Check if new_sev is worse than old_sev."""
        return severity_order.get(new_sev, 0) > severity_order.get(old_sev, 0)

    def is_better(old_sev: str, new_sev: str) -> bool:
        """Check if new_sev is better than old_sev."""
        return severity_order.get(new_sev, 0) < severity_order.get(old_sev, 0)

    # ── Categorize findings ───────────────────────────────────────────
    new_findings: list[str] = []
    fixed_findings: list[str] = []
    unchanged_findings: list[str] = []

    # NEW: in report2 but not report1, or severity got worse
    for test_id, sev2 in findings_2.items():
        if test_id not in findings_1:
            new_findings.append(f"{test_id} ({sev2})")
        elif is_worse(findings_1[test_id], sev2):
            new_findings.append(f"{test_id} ({findings_1[test_id]} → {sev2})")

    # FIXED: in report1 but not report2, or severity improved
    for test_id, sev1 in findings_1.items():
        if test_id not in findings_2:
            fixed_findings.append(f"{test_id} ({sev1})")
        elif is_better(sev1, findings_2[test_id]):
            fixed_findings.append(f"{test_id} ({sev1} → {findings_2[test_id]})")

    # UNCHANGED: same test_id and severity in both
    for test_id, sev1 in findings_1.items():
        if test_id in findings_2 and findings_2[test_id] == sev1:
            unchanged_findings.append(f"{test_id} ({sev1})")

    # ── Print results as tables ───────────────────────────────────────
    if new_findings:
        table = Table(
            title="[bold red]NEW Findings[/bold red]",
            show_header=False,
            border_style="red",
        )
        for item in new_findings:
            table.add_row(f"  [red]{item}[/red]")
        _console.print(table)
        _console.print()

    if fixed_findings:
        table = Table(
            title="[bold green]FIXED Findings[/bold green]",
            show_header=False,
            border_style="green",
        )
        for item in fixed_findings:
            table.add_row(f"  [green]{item}[/green]")
        _console.print(table)
        _console.print()

    if unchanged_findings:
        table = Table(
            title="[bold yellow]UNCHANGED Findings[/bold yellow]",
            show_header=False,
            border_style="yellow",
        )
        for item in unchanged_findings:
            table.add_row(f"  [yellow]{item}[/yellow]")
        _console.print(table)
        _console.print()

    # ── Summary ───────────────────────────────────────────────────────
    _console.print(
        f"Summary: [red]{len(new_findings)} new[/red]  "
        f"[green]{len(fixed_findings)} fixed[/green]  "
        f"[yellow]{len(unchanged_findings)} unchanged[/yellow]"
    )
    _console.print()

    # ── Exit code ─────────────────────────────────────────────────────
    if new_findings:
        sys.exit(1)
    else:
        sys.exit(0)


# ---------------------------------------------------------------------------
# mcpsafe init
# ---------------------------------------------------------------------------

_INIT_TOML_TEMPLATE = """\
# mcpsafe.toml — MCPSafe configuration file
# Generated by: mcpsafe init
# Docs: https://github.com/Ravikiranbantwal/mcpsafe
#
# CLI flags always take precedence over values in this file.
# Remove or comment-out any section you don't need.

[scan]
# Transport protocol: "stdio" | "http" | "sse"
transport = "stdio"

# Seconds per MCP call before timeout (must be > 0)
timeout = 10

# Max concurrent requests during load tests (must be > 0)
concurrency = 10

# Directory to save generated reports
out_dir = "./mcpsafe-reports"

# Report format: "json" | "html" | "both" | "sarif" | "all"
output = "both"

# Skip large-payload and stress tests (safe for production targets)
no_load = false

# Print each finding in real time as it is discovered
verbose = false

# Comma-separated modules to run (leave as "all" to run everything)
# modules = "discovery,injection,fuzzer,poison,load,schema,auth,latency"

[env]
# Environment variables injected into the server process (stdio transport).
# Equivalent to passing --env KEY=VALUE on the command line.
# CLI --env flags override these values.
#
# Examples:
#   GITHUB_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxx"
#   DATABASE_URL = "postgres://user:pass@localhost/db"
#   OPENAI_API_KEY = "sk-..."
"""


@cli.command()
@click.option(
    "--output", "-o",
    "output_path",
    type=click.Path(),
    default="mcpsafe.toml",
    show_default=True,
    help="Path where the config file will be written.",
)
@click.option(
    "--force",
    is_flag=True,
    default=False,
    help="Overwrite an existing config file without prompting.",
)
def init(output_path: str, force: bool) -> None:
    """
    Generate a default mcpsafe.toml configuration file.

    Creates a fully-commented template that you can edit to configure
    default scan settings, environment variables, and output options.

    \b
    Examples:
      mcpsafe init
      mcpsafe init --output my-server.toml
      mcpsafe init --force   # overwrite existing file
    """
    out = Path(output_path)

    if out.exists() and not force:
        _console.print(
            f"[yellow]File {str(out)!r} already exists.[/yellow] "
            f"Use [bold]--force[/bold] to overwrite."
        )
        sys.exit(2)

    try:
        out.write_text(_INIT_TOML_TEMPLATE, encoding="utf-8")
    except OSError as exc:
        _console.print(f"[bold red]Error:[/bold red] Could not write {str(out)!r}: {exc}")
        sys.exit(2)

    _console.print(
        f"[green]✓[/green] Created [bold]{str(out)}[/bold]\n\n"
        f"  Edit the file to configure your scan defaults, then run:\n\n"
        f"    [bold]mcpsafe scan TARGET --config {str(out)}[/bold]\n"
    )


# ---------------------------------------------------------------------------
# Main guard
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    cli()
