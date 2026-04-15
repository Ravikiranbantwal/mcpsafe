"""
mcpsafe.reporter.json_reporter
================================
Serialises a ``ScanReport`` to a structured JSON file (or string).

Output schema
-------------
The top-level JSON object mirrors ``ScanReport.to_dict()``:

    {
      "scan_id":         "...",
      "mcpsafe_version": "0.3.1",
      "started_at":      "2024-...",
      "finished_at":     "2024-...",
      "server_info":     { ... },
      "summary":         { "total_tests": N, "passed": N, ... },
      "results":         [ { "test_id": "T01-001", ... }, ... ]
    }

Filename format
---------------
    mcpsafe-{scan_id[:8]}-{YYYYMMDD-HHMMSS}.json

Usage
-----
    reporter = JsonReporter(report)
    path = reporter.write(Path("/tmp/mcpsafe-output"))
    print(reporter.to_string())
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mcpsafe.models import ScanReport
from mcpsafe.reporter._common import server_slug as _server_slug
from mcpsafe.tests._helpers import sanitise_server_string as _san


# ---------------------------------------------------------------------------
# Sanitise helper — strips control chars from server-supplied strings
# ---------------------------------------------------------------------------

def _sanitise_value(val: Any, depth: int = 0) -> Any:
    """
    Recursively sanitise string values in nested dicts/lists.

    Applied to the serialised report dict so that NUL bytes, ANSI escapes,
    and other control characters from an untrusted server cannot corrupt
    downstream log consumers or SIEM parsers that ingest the JSON.

    Recursion is capped at depth 10 to guard against pathological structures.
    """
    if depth > 10:
        return val
    if isinstance(val, str):
        return _san(val, max_len=20_000)
    if isinstance(val, dict):
        return {k: _sanitise_value(v, depth + 1) for k, v in val.items()}
    if isinstance(val, list):
        return [_sanitise_value(item, depth + 1) for item in val]
    return val



class JsonReporter:
    """
    Serialise a ``ScanReport`` to JSON.

    Parameters
    ----------
    report:
        A completed ``ScanReport`` (i.e. ``report.finish()`` has been called).
    indent:
        JSON indentation level (default 2).
    """

    def __init__(self, report: ScanReport, indent: int = 2) -> None:
        self._report = report
        self._indent = indent

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def write(self, output_dir: Path) -> Path:
        """
        Serialise the report and write it to ``output_dir``.

        The directory is created if it does not already exist.

        Parameters
        ----------
        output_dir:
            Directory in which to write the JSON file.

        Returns
        -------
        Path:
            Absolute path of the written file.
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        filename = self._filename()
        out_path = output_dir / filename
        out_path.write_text(self.to_string(), encoding="utf-8")
        return out_path.resolve()

    def to_string(self) -> str:
        """
        Return the full JSON report as a string (suitable for piping or
        printing to stdout).

        Server-supplied strings (tool names, descriptions, server name, etc.)
        are sanitised before serialisation to strip NUL bytes, ANSI escapes,
        and other control characters that can corrupt log consumers.

        Returns
        -------
        str:
            Indented JSON text.
        """
        raw = self._report.to_dict()
        raw["legal"] = (
            "MCPSafe is intended for use against MCP servers you own or have "
            "explicit written permission to test. Unauthorised scanning of "
            "third-party servers may violate computer fraud laws in your "
            "jurisdiction. Treat findings as confidential until disclosed to "
            "the server operator."
        )
        sanitised = _sanitise_value(raw)
        return json.dumps(sanitised, indent=self._indent, ensure_ascii=False)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _filename(self) -> str:
        """Build the output filename from the server name, scan ID, and timestamp."""
        scan_id_short = self._report.scan_id[:8]
        ts = (self._report.started_at or datetime.now(timezone.utc)).strftime(
            "%Y%m%d-%H%M%S"
        )
        server_slug = _server_slug(self._report)
        return f"mcpsafe-{server_slug}-{scan_id_short}-{ts}.json"
