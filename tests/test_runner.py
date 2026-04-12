"""
Integration-light tests for ScanRunner.

These tests do NOT require a real MCP server — they verify that the runner
initialises correctly and degrades gracefully when the target is unreachable.
"""
import pytest

from mcpsafe.models import ScanConfig, ScanReport, TransportType
from mcpsafe.runner import ScanRunner

pytestmark = pytest.mark.asyncio


async def test_scanrunner_initializes():
    config = ScanConfig(target="echo test", transport=TransportType.STDIO)
    runner = ScanRunner(config)
    assert runner.config == config
    assert runner._results == []


async def test_scanrunner_bad_target_returns_report():
    config = ScanConfig(
        target="this_command_does_not_exist_mcpsafe_xyz_999",
        transport=TransportType.STDIO,
        timeout_seconds=3,
    )
    runner = ScanRunner(config)
    report = await runner.run()
    assert isinstance(report, ScanReport)
    assert report.critical_count >= 1


async def test_scanreport_fields_populated_on_failure():
    config = ScanConfig(
        target="invalid_xyz_target_mcpsafe",
        transport=TransportType.STDIO,
        timeout_seconds=2,
    )
    runner = ScanRunner(config)
    report = await runner.run()
    assert report.scan_id is not None
    assert report.started_at is not None
    assert report.server_info is None or report.server_info.target == "invalid_xyz_target_mcpsafe"
    assert isinstance(report.results, list)
    assert len(report.results) >= 1
