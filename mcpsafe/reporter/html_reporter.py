"""
mcpsafe.reporter.html_reporter
================================
Renders a ``ScanReport`` to a self-contained, single-file HTML report using
the Jinja2 template at ``templates/report.html.j2``.

The template is located relative to the **package root** (the directory that
contains the ``mcpsafe/`` folder), so this module resolves it via:

    _TEMPLATE_DIR = Path(__file__).parent.parent.parent / "templates"

Filename format
---------------
    mcpsafe-{scan_id[:8]}-{YYYYMMDD-HHMMSS}.html

Usage
-----
    reporter = HtmlReporter(report)
    path = reporter.write(Path("./mcpsafe-reports"))
    html_str = reporter.render()
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape

from mcpsafe.models import Category, ScanReport, Severity

# ---------------------------------------------------------------------------
# Template resolution
# ---------------------------------------------------------------------------

# This file lives at: mcpsafe/reporter/html_reporter.py
# Project root is three levels up:  .../MCPSafe/
_TEMPLATE_DIR: Path = Path(__file__).parent.parent.parent / "templates"


# ---------------------------------------------------------------------------
# Severity → CSS class and hex colour (matches the template palette)
# ---------------------------------------------------------------------------

_SEVERITY_CSS: dict[str, str] = {
    "CRITICAL": "sev-critical",
    "HIGH":     "sev-high",
    "MEDIUM":   "sev-medium",
    "LOW":      "sev-low",
    "INFO":     "sev-info",
    "PASS":     "sev-pass",
}

_SEVERITY_HEX: dict[str, str] = {
    "CRITICAL": "#dc2626",
    "HIGH":     "#ea580c",
    "MEDIUM":   "#d97706",
    "LOW":      "#2563eb",
    "INFO":     "#6b7280",
    "PASS":     "#16a34a",
}


# ---------------------------------------------------------------------------
# Helper: build donut-chart CSS segments
# ---------------------------------------------------------------------------

def _build_donut_segments(report: ScanReport) -> list[dict[str, Any]]:
    """
    Compute the conic-gradient stop data for the severity donut chart.

    Returns a list of dicts (one per severity) in descending severity order,
    each carrying:
      - severity  (str)
      - count     (int)
      - pct       (float, 0-100)
      - color     (hex string)
      - start_deg (float)  — starting degree for conic-gradient
      - end_deg   (float)  — ending degree

    Zero-count severities are omitted to keep the gradient clean.
    """
    total = report.total_tests or 1  # avoid division-by-zero

    raw: list[tuple[str, int]] = [
        ("CRITICAL", report.critical_count),
        ("HIGH",     report.high_count),
        ("MEDIUM",   report.medium_count),
        ("LOW",      report.low_count),
        ("INFO",     sum(1 for r in report.results if r.severity == Severity.INFO)),
        ("PASS",     report.passed_count),
    ]

    segments: list[dict[str, Any]] = []
    cursor = 0.0
    for sev, count in raw:
        if count == 0:
            continue
        pct = count / total * 100
        deg = pct / 100 * 360
        segments.append(
            {
                "severity":  sev,
                "count":     count,
                "pct":       round(pct, 1),
                "color":     _SEVERITY_HEX[sev],
                "start_deg": round(cursor, 2),
                "end_deg":   round(cursor + deg, 2),
            }
        )
        cursor += deg

    return segments


# ---------------------------------------------------------------------------
# Helper: build conic-gradient CSS value string
# ---------------------------------------------------------------------------

def _build_conic_gradient(segments: list[dict[str, Any]]) -> str:
    """
    Build the full ``conic-gradient(...)`` CSS value from precomputed segments.

    Example output::

        conic-gradient(
          #dc2626 0deg 36deg,
          #ea580c 36deg 72deg,
          #16a34a 72deg 360deg
        )
    """
    if not segments:
        return "conic-gradient(#6b7280 0deg 360deg)"

    parts: list[str] = []
    for seg in segments:
        parts.append(f"{seg['color']} {seg['start_deg']}deg {seg['end_deg']}deg")

    return "conic-gradient(\n  " + ",\n  ".join(parts) + "\n)"


# ---------------------------------------------------------------------------
# Helper: truncate long strings for the report table
# ---------------------------------------------------------------------------

def _truncate(text: str | None, max_len: int = 500) -> str:
    """Truncate ``text`` to ``max_len`` chars, appending ``…`` if clipped."""
    if text is None:
        return ""
    if len(text) <= max_len:
        return text
    return text[:max_len] + "…"


# ---------------------------------------------------------------------------
# HtmlReporter
# ---------------------------------------------------------------------------


class HtmlReporter:
    """
    Render a ``ScanReport`` to a self-contained HTML file.

    Parameters
    ----------
    report:
        A completed ``ScanReport`` (``report.finish()`` must have been called).
    """

    def __init__(self, report: ScanReport) -> None:
        self._report = report
        self._env: Environment | None = None

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def write(self, output_dir: Path) -> Path:
        """
        Render the report and write it to ``output_dir``.

        The directory is created if it does not already exist.

        Parameters
        ----------
        output_dir:
            Directory in which to write the HTML file.

        Returns
        -------
        Path:
            Absolute path of the written file.
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        filename = self._filename()
        out_path = output_dir / filename
        out_path.write_text(self.render(), encoding="utf-8")
        return out_path.resolve()

    def render(self) -> str:
        """
        Return the fully-rendered HTML report as a string.

        Returns
        -------
        str:
            Complete, self-contained HTML document.
        """
        template = self._jinja_env().get_template("report.html.j2")
        ctx = self._build_context()
        return template.render(**ctx)

    # ------------------------------------------------------------------
    # Jinja2 environment
    # ------------------------------------------------------------------

    def _jinja_env(self) -> Environment:
        """Return (or lazily create) the Jinja2 ``Environment``."""
        if self._env is None:
            self._env = Environment(
                loader=FileSystemLoader(str(_TEMPLATE_DIR)),
                autoescape=select_autoescape(["html", "j2"]),
                undefined=StrictUndefined,
                trim_blocks=True,
                lstrip_blocks=True,
            )
            # Custom filter: severity → CSS class name
            self._env.filters["sev_css"] = lambda s: _SEVERITY_CSS.get(str(s), "sev-info")
            # Custom filter: truncate long strings
            self._env.filters["truncate_safe"] = _truncate
        return self._env

    # ------------------------------------------------------------------
    # Template context builder
    # ------------------------------------------------------------------

    def _build_context(self) -> dict[str, Any]:
        """
        Build the full Jinja2 template context from the ``ScanReport``.

        Returns
        -------
        dict:
            All variables the template expects.
        """
        report = self._report
        d = report.to_dict()

        # ── Donut chart ─────────────────────────────────────────────────
        segments = _build_donut_segments(report)
        conic_css = _build_conic_gradient(segments)

        # ── Per-severity stat cards ──────────────────────────────────────
        info_count = sum(1 for r in report.results if r.severity == Severity.INFO)
        stat_cards: list[dict[str, Any]] = [
            {"label": "CRITICAL", "count": report.critical_count,  "css": "sev-critical"},
            {"label": "HIGH",     "count": report.high_count,       "css": "sev-high"},
            {"label": "MEDIUM",   "count": report.medium_count,     "css": "sev-medium"},
            {"label": "LOW",      "count": report.low_count,        "css": "sev-low"},
            {"label": "INFO",     "count": info_count,              "css": "sev-info"},
            {"label": "PASS",     "count": report.passed_count,     "css": "sev-pass"},
        ]

        # ── Results sorted: worst severity first, then by test_id ───────
        severity_order = {s.value: i for i, s in enumerate(
            [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
             Severity.LOW, Severity.INFO, Severity.PASS]
        )}
        sorted_results = sorted(
            report.results,
            key=lambda r: (severity_order.get(r.severity.value, 99), r.test_id),
        )

        # ── Category groups for the findings table ───────────────────────
        categories_ordered = [
            Category.SECURITY,
            Category.DISCOVERY,
            Category.SCHEMA,
            Category.PERFORMANCE,
        ]
        category_groups: list[dict[str, Any]] = []
        for cat in categories_ordered:
            cat_results = [r for r in sorted_results if r.category == cat]
            if cat_results:
                category_groups.append(
                    {
                        "name":    cat.value,
                        "count":   len(cat_results),
                        "results": cat_results,
                    }
                )

        # ── Server info convenience fields ───────────────────────────────
        si = report.server_info
        server_dict: dict[str, Any] = {}
        if si:
            server_dict = {
                "name":             si.name,
                "version":          si.version,
                "protocol_version": si.protocol_version,
                "transport":        si.transport.value.upper(),
                "target":           si.target,
                "tool_count":       len(si.tools),
                "resource_count":   len(si.resources),
                "prompt_count":     len(si.prompts),
                "tool_names":       si.tool_names[:30],  # cap for display
                "discovered_at":    si.discovered_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
            }

        # ── Duration formatting ──────────────────────────────────────────
        dur_s = report.duration_ms / 1000.0 if report.duration_ms else 0.0
        duration_str = f"{dur_s:.1f}s" if dur_s >= 1 else f"{report.duration_ms:.0f}ms"

        # ── Scan timestamps ──────────────────────────────────────────────
        started_str = (
            report.started_at.strftime("%Y-%m-%d %H:%M:%S UTC")
            if report.started_at else "—"
        )
        finished_str = (
            report.finished_at.strftime("%Y-%m-%d %H:%M:%S UTC")
            if report.finished_at else "—"
        )

        return {
            # Raw report dict (for any direct field access in template)
            "report":           d,
            # Scan metadata
            "scan_id":          report.scan_id,
            "mcpsafe_version":  report.mcpsafe_version,
            "started_at":       started_str,
            "finished_at":      finished_str,
            "duration_str":     duration_str,
            # Summary counts
            "total_tests":      report.total_tests,
            "passed_count":     report.passed_count,
            "failed_count":     report.failed_count,
            "overall_severity": report.overall_severity.value,
            "overall_css":      _SEVERITY_CSS.get(report.overall_severity.value, "sev-info"),
            # Severity stat cards
            "stat_cards":       stat_cards,
            # Donut chart
            "donut_segments":   segments,
            "conic_css":        conic_css,
            # Server info
            "server":           server_dict,
            # Findings
            "sorted_results":   sorted_results,
            "category_groups":  category_groups,
            # Helpers
            "severity_css":     _SEVERITY_CSS,
            "severity_hex":     _SEVERITY_HEX,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _filename(self) -> str:
        """Build the output filename from the scan ID and current timestamp."""
        scan_id_short = self._report.scan_id[:8]
        ts = (self._report.started_at or datetime.now(timezone.utc)).strftime(
            "%Y%m%d-%H%M%S"
        )
        return f"mcpsafe-{scan_id_short}-{ts}.html"
