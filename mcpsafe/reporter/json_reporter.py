"""
mcpsafe.reporter.json_reporter
================================
Serialises a ``ScanReport`` to a structured JSON file (or string).

Output schema
-------------
The top-level JSON object mirrors ``ScanReport.to_dict()``:

    {
      "scan_id":         "...",
      "mcpsafe_version": "0.1.0",
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

from mcpsafe.models import ScanReport


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

        Returns
        -------
        str:
            Indented JSON text.
        """
        return json.dumps(self._report.to_dict(), indent=self._indent, ensure_ascii=False)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _filename(self) -> str:
        """Build the output filename from the scan ID and current timestamp."""
        scan_id_short = self._report.scan_id[:8]
        ts = (self._report.started_at or datetime.now(timezone.utc)).strftime(
            "%Y%m%d-%H%M%S"
        )
        return f"mcpsafe-{scan_id_short}-{ts}.json"
