"""
Unit tests for mcpsafe.models — dataclasses, enums, and factory methods.

All tests are synchronous; no MCP connection is required.
"""
import pytest

from mcpsafe.models import (
    Category,
    ScanConfig,
    Severity,
    TestResult,
    TransportType,
)


# ── Severity ordering ────────────────────────────────────────────────────────

def test_severity_ordering():
    assert Severity.PASS < Severity.INFO
    assert Severity.INFO < Severity.LOW
    assert Severity.LOW < Severity.MEDIUM
    assert Severity.MEDIUM < Severity.HIGH
    assert Severity.HIGH < Severity.CRITICAL


def test_severity_from_string():
    assert Severity("CRITICAL") == Severity.CRITICAL
    assert Severity("PASS") == Severity.PASS


# ── TestResult factory methods ────────────────────────────────────────────────

def test_testresult_make_pass():
    result = TestResult.make_pass(
        "T01-001", "Test name", Category.DISCOVERY, "description"
    )
    assert result.passed is True
    assert result.severity == Severity.PASS


def test_testresult_make_fail():
    result = TestResult.make_fail(
        "T01-001", "Test name", Category.DISCOVERY,
        Severity.HIGH, "description", details="details here"
    )
    assert result.passed is False
    assert result.severity == Severity.HIGH


def test_testresult_critical_passed_true_raises():
    with pytest.raises((ValueError, AssertionError)):
        TestResult(
            test_id="T01-001",
            test_name="test",
            category=Category.DISCOVERY,
            severity=Severity.CRITICAL,
            passed=True,
            description="desc",
        )


# ── ScanConfig defaults ───────────────────────────────────────────────────────

def test_scanconfig_defaults():
    config = ScanConfig(target="python server.py", transport=TransportType.STDIO)
    assert config.transport == TransportType.STDIO
    assert config.timeout_seconds == 30.0
    assert config.no_load is False
