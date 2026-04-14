"""
mcpsafe.reporter.sarif_reporter
================================
Serialises a ``ScanReport`` to SARIF 2.1.0 (Static Analysis Results Interchange Format).

SARIF is the GitHub security scanning standard used for integrating findings into
GitHub Security tab and other CI/CD pipelines.

Output schema
-------------
SARIF 2.1.0 compliant structure with:
  - Tool metadata (MCPSafe driver info)
  - Rules (one per unique test_id)
  - Results (one per non-PASS finding)

Filename format
---------------
    mcpsafe-{server_slug}-{scan_id[:8]}-{YYYYMMDD-HHMMSS}.sarif

Usage
-----
    reporter = SarifReporter(report)
    path = reporter.save(Path("/tmp/mcpsafe-output"))
    print(reporter.generate())
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mcpsafe.models import ScanReport, Severity, TestResult
from mcpsafe.reporter._common import server_slug as _server_slug
from mcpsafe.tests._helpers import sanitise_server_string as _san



class SarifReporter:
    """
    Serialise a ``ScanReport`` to SARIF 2.1.0 format.

    Parameters
    ----------
    report:
        A completed ``ScanReport`` (i.e. ``report.finish()`` has been called).
    """

    def __init__(self, report: ScanReport) -> None:
        self._report = report

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def generate(self) -> dict[str, Any]:
        """
        Generate the SARIF 2.1.0 structure as a dict.

        Returns
        -------
        dict:
            A SARIF 2.1.0-compliant object ready for JSON serialization.
        """
        rules = self._generate_rules()
        results = self._generate_results()

        return {
            "version": "2.1.0",
            "$schema": (
                "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
                "Schemata/sarif-schema-2.1.0.json"
            ),
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "MCPSafe",
                            "version": "0.2.0",
                            "informationUri": "https://github.com/Ravikiranbantwal/mcpsafe",
                            "rules": rules,
                        }
                    },
                    "results": results,
                }
            ],
        }

    def save(self, out_dir: str) -> Path:
        """
        Serialise the report and write it to ``out_dir``.

        The directory is created if it does not already exist.

        Parameters
        ----------
        out_dir:
            Directory in which to write the SARIF file.

        Returns
        -------
        Path:
            Absolute path of the written file.
        """
        output_dir = Path(out_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        filename = self._filename()
        out_path = output_dir / filename
        out_path.write_text(
            json.dumps(self.generate(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return out_path.resolve()

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
        return f"mcpsafe-{server_slug}-{scan_id_short}-{ts}.sarif"

    def _generate_rules(self) -> list[dict[str, Any]]:
        """
        Generate the 'rules' array (one per unique test_id).

        Rules define the check types and are referenced by results.
        """
        # Collect unique test_ids and their metadata
        rules_dict: dict[str, dict[str, Any]] = {}

        for result in self._report.results:
            if result.test_id not in rules_dict:
                safe_name = _san(result.test_name)
                rules_dict[result.test_id] = {
                    "id": result.test_id,
                    "name": safe_name,
                    "shortDescription": {"text": safe_name},
                    "helpUri": self._help_uri_for_test(result.test_id),
                    "properties": {"severity": result.severity.value},
                }

        return list(rules_dict.values())

    def _generate_results(self) -> list[dict[str, Any]]:
        """
        Generate the 'results' array (one per non-PASS finding).

        Results describe individual security findings.
        """
        results: list[dict[str, Any]] = []

        for result in self._report.results:
            # Skip PASS results
            if result.severity == Severity.PASS:
                continue

            level = self._severity_to_level(result.severity)
            target_uri = self._get_target_uri(result)

            results.append(
                {
                    "ruleId": result.test_id,
                    "level": level,
                    "message": {"text": _san(result.description, max_len=2000)},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": target_uri}
                            }
                        }
                    ],
                }
            )

        return results

    def _severity_to_level(self, severity: Severity) -> str:
        """
        Map MCPSafe severity to SARIF level.

        SARIF levels: "none", "note", "warning", "error".
        """
        mapping = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "note",
            Severity.PASS: "none",
        }
        return mapping.get(severity, "note")

    def _help_uri_for_test(self, test_id: str) -> str:
        """Generate a help URI for a test ID."""
        # Format: https://github.com/Ravikiranbantwal/mcpsafe/blob/main/docs/T01-001.md
        return (
            f"https://github.com/Ravikiranbantwal/mcpsafe/blob/main/docs/{test_id}.md"
        )

    def _get_target_uri(self, result: TestResult) -> str:
        """
        Extract a meaningful URI from the test result for artifact location.

        Falls back to the server target if no specific resource is identified.
        """
        # Could be enhanced to extract resource URIs from result details
        si = self._report.server_info
        if si:
            return _san(si.target, max_len=2000)
        return "mcp://unknown"
