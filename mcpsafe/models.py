"""
mcpsafe.models
==============
All shared dataclasses for MCPSafe.

No plain dicts are passed between modules — every boundary uses one of these
typed containers so that type-checkers and the reporter always agree on shape.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class Severity(str, Enum):
    """Ordered severity levels for a test finding."""

    PASS = "PASS"
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    # Comparison operators delegate to the module-level _SEVERITY_ORDER dict.
    def __lt__(self, other: "Severity") -> bool:
        return _SEVERITY_ORDER[self.value] < _SEVERITY_ORDER[other.value]

    def __le__(self, other: "Severity") -> bool:
        return _SEVERITY_ORDER[self.value] <= _SEVERITY_ORDER[other.value]

    def __gt__(self, other: "Severity") -> bool:
        return _SEVERITY_ORDER[self.value] > _SEVERITY_ORDER[other.value]

    def __ge__(self, other: "Severity") -> bool:
        return _SEVERITY_ORDER[self.value] >= _SEVERITY_ORDER[other.value]


_SEVERITY_ORDER: dict[str, int] = {
    "PASS": 0,
    "INFO": 1,
    "LOW": 2,
    "MEDIUM": 3,
    "HIGH": 4,
    "CRITICAL": 5,
}


class Category(str, Enum):
    """Broad category every test belongs to."""

    DISCOVERY = "DISCOVERY"
    SECURITY = "SECURITY"
    PERFORMANCE = "PERFORMANCE"
    SCHEMA = "SCHEMA"


class TransportType(str, Enum):
    """Wire-level transport used to reach the MCP server."""

    STDIO = "stdio"
    HTTP = "http"
    SSE = "sse"


# ---------------------------------------------------------------------------
# Server-capability descriptors (populated during discovery)
# ---------------------------------------------------------------------------


@dataclass
class MCPTool:
    """A single tool advertised by the MCP server."""

    name: str
    description: str
    input_schema: dict[str, Any]


@dataclass
class MCPResource:
    """A single resource URI advertised by the MCP server."""

    uri: str
    name: str
    description: str
    mime_type: Optional[str] = None


@dataclass
class MCPPrompt:
    """A single prompt template advertised by the MCP server."""

    name: str
    description: str
    arguments: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class ServerInfo:
    """
    Snapshot of everything learned about the target MCP server during the
    initial capability-discovery phase (T01).
    """

    name: str
    version: str
    protocol_version: str
    transport: TransportType
    target: str  # e.g. "npx -y @modelcontextprotocol/server-everything" or URL
    tools: list[MCPTool] = field(default_factory=list)
    resources: list[MCPResource] = field(default_factory=list)
    prompts: list[MCPPrompt] = field(default_factory=list)
    capabilities: dict[str, Any] = field(default_factory=dict)
    discovered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # Convenience helpers
    @property
    def tool_names(self) -> list[str]:
        """Return just the tool names for quick membership tests."""
        return [t.name for t in self.tools]

    @property
    def resource_uris(self) -> list[str]:
        """Return just the resource URIs for quick membership tests."""
        return [r.uri for r in self.resources]


# ---------------------------------------------------------------------------
# Per-test result
# ---------------------------------------------------------------------------


@dataclass
class TestResult:
    """
    The atomic unit of MCPSafe output — one result per individual check.

    Every test function in mcpsafe/tests/ must return a ``TestResult``
    (or a list of them).  The runner collects them into a ``ScanReport``.
    """

    test_id: str          # e.g. "T01-001"
    test_name: str        # Human-readable short name
    category: Category
    severity: Severity
    passed: bool

    # Human-readable explanation of what was found.
    description: str = ""

    # Extra structured evidence (payloads, stack-traces, sample values, …).
    details: Optional[str] = None

    # Wall-clock duration in **milliseconds** (use time.perf_counter()).
    duration_ms: float = 0.0

    # Freeform remediation advice shown in the HTML report.
    remediation: Optional[str] = None

    # Raw request/response pair for evidence (truncated to 4 KB each by reporter).
    request_payload: Optional[str] = None
    response_payload: Optional[str] = None

    # Timestamp — set automatically when the dataclass is constructed.
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # Unique ID so the reporter can deduplicate if a test emits duplicates.
    result_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def __post_init__(self) -> None:
        # Normalise: a CRITICAL / HIGH result must not be marked passed.
        if self.severity in (Severity.HIGH, Severity.CRITICAL) and self.passed:
            raise ValueError(
                f"TestResult {self.test_id!r}: severity={self.severity.value} "
                "must not be combined with passed=True."
            )

    # ------------------------------------------------------------------
    # Factory helpers — keep test modules concise
    # ------------------------------------------------------------------

    @classmethod
    def make_pass(
        cls,
        test_id: str,
        test_name: str,
        category: Category,
        description: str = "",
        duration_ms: float = 0.0,
        details: Optional[str] = None,
    ) -> "TestResult":
        """Shorthand for a passing result."""
        return cls(
            test_id=test_id,
            test_name=test_name,
            category=category,
            severity=Severity.PASS,
            passed=True,
            description=description,
            duration_ms=duration_ms,
            details=details,
        )

    @classmethod
    def make_fail(
        cls,
        test_id: str,
        test_name: str,
        category: Category,
        severity: Severity,
        description: str = "",
        duration_ms: float = 0.0,
        details: Optional[str] = None,
        remediation: Optional[str] = None,
    ) -> "TestResult":
        """Shorthand for a failing result with severity."""
        if severity in (Severity.HIGH, Severity.CRITICAL):
            passed = False
        else:
            passed = False  # all make_fail results are failed
        return cls(
            test_id=test_id,
            test_name=test_name,
            category=category,
            severity=severity,
            passed=passed,
            description=description,
            duration_ms=duration_ms,
            details=details,
            remediation=remediation,
        )

    @classmethod
    def from_exception(
        cls,
        test_id: str,
        test_name: str,
        category: Category,
        exc: Exception,
        duration_ms: float = 0.0,
    ) -> "TestResult":
        """
        Wrap an unexpected exception as a MEDIUM-severity failure.

        Use this inside test modules' except blocks to prevent exceptions
        from propagating into the runner.
        """
        return cls(
            test_id=test_id,
            test_name=test_name,
            category=category,
            severity=Severity.MEDIUM,
            passed=False,
            description=f"Unexpected exception: {type(exc).__name__}",
            duration_ms=duration_ms,
            details=str(exc),
        )


# ---------------------------------------------------------------------------
# Aggregate scan report
# ---------------------------------------------------------------------------


@dataclass
class ScanReport:
    """
    Top-level container produced at the end of a full MCPSafe run.

    The JSON and HTML reporters both consume this object exclusively —
    they never reach back into individual module state.
    """

    scan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: Optional[datetime] = None
    server_info: Optional[ServerInfo] = None
    results: list[TestResult] = field(default_factory=list)
    mcpsafe_version: str = "0.3.0"

    # ------------------------------------------------------------------
    # Derived statistics (computed on demand, not stored)
    # ------------------------------------------------------------------

    @property
    def total_tests(self) -> int:
        return len(self.results)

    @property
    def passed_count(self) -> int:
        return sum(1 for r in self.results if r.passed)

    @property
    def failed_count(self) -> int:
        return sum(1 for r in self.results if not r.passed)

    @property
    def critical_count(self) -> int:
        return sum(1 for r in self.results if r.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for r in self.results if r.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for r in self.results if r.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for r in self.results if r.severity == Severity.LOW)

    @property
    def duration_ms(self) -> float:
        """Total wall-clock time across all test results."""
        return sum(r.duration_ms for r in self.results)

    @property
    def overall_severity(self) -> Severity:
        """Worst severity across all results; PASS when there are no failures."""
        if not self.results:
            return Severity.PASS
        return max((r.severity for r in self.results), default=Severity.PASS)

    @property
    def results_by_category(self) -> dict[Category, list[TestResult]]:
        """Group results by their category for report rendering."""
        grouped: dict[Category, list[TestResult]] = {c: [] for c in Category}
        for r in self.results:
            grouped[r.category].append(r)
        return grouped

    @property
    def results_by_severity(self) -> dict[Severity, list[TestResult]]:
        """Group results by severity for report rendering."""
        grouped: dict[Severity, list[TestResult]] = {s: [] for s in Severity}
        for r in self.results:
            grouped[r.severity].append(r)
        return grouped

    def add_result(self, result: TestResult) -> None:
        """Append a single ``TestResult``."""
        self.results.append(result)

    def add_results(self, results: list[TestResult]) -> None:
        """Append a batch of ``TestResult`` objects."""
        self.results.extend(results)

    def finish(self) -> None:
        """Record the scan completion timestamp."""
        self.finished_at = datetime.now(timezone.utc)

    def to_dict(self) -> dict:
        """
        Serialise the entire ``ScanReport`` to a JSON-serialisable ``dict``.

        Rules
        -----
        - ``Enum`` values → their ``.value`` string
        - ``datetime`` objects → ISO 8601 strings
        - Nested dataclasses → recursively serialised dicts
        - ``None`` → ``null`` (preserved)
        - ``dict`` keys that are ``Enum`` instances are converted via ``.value``
        """
        from enum import Enum as _Enum

        def _ser(obj: object) -> object:
            if obj is None:
                return None
            if isinstance(obj, _Enum):
                return obj.value
            if isinstance(obj, datetime):
                return obj.isoformat()
            if isinstance(obj, (str, int, float, bool)):
                return obj
            if isinstance(obj, dict):
                return {
                    (k.value if isinstance(k, _Enum) else str(k)): _ser(v)
                    for k, v in obj.items()
                }
            if isinstance(obj, (list, tuple)):
                return [_ser(i) for i in obj]
            # dataclass — recurse over declared fields
            if hasattr(obj, "__dataclass_fields__"):
                return {
                    field_name: _ser(getattr(obj, field_name))
                    for field_name in obj.__dataclass_fields__
                }
            return str(obj)

        return {
            "scan_id":          self.scan_id,
            "mcpsafe_version":  self.mcpsafe_version,
            "started_at":       self.started_at.isoformat(),
            "finished_at":      self.finished_at.isoformat() if self.finished_at else None,
            "server_info":      _ser(self.server_info),
            "summary": {
                "total_tests":       self.total_tests,
                "passed":            self.passed_count,
                "failed":            self.failed_count,
                "critical":          self.critical_count,
                "high":              self.high_count,
                "medium":            self.medium_count,
                "low":               self.low_count,
                "overall_severity":  self.overall_severity.value,
                "duration_ms":       round(self.duration_ms, 2),
            },
            "results": [_ser(r) for r in self.results],
        }


# ---------------------------------------------------------------------------
# Connection / runner configuration (passed in from CLI)
# ---------------------------------------------------------------------------


@dataclass
class ScanConfig:
    """
    All runtime parameters for a scan — parsed from CLI flags and
    passed through to the runner and every test module.
    """

    # Target specification
    transport: TransportType
    target: str                         # command string (stdio) or base URL (http/sse)
    args: list[str] = field(default_factory=list)  # extra args for stdio command
    env: dict[str, str] = field(default_factory=dict)

    # HTTP-specific
    headers: dict[str, str] = field(default_factory=dict)
    auth_token: Optional[str] = None

    # Timeouts & load parameters
    timeout_seconds: float = 30.0
    concurrency: int = 10              # parallel workers for load test (T05)
    request_count: int = 100           # total requests for load test (T05)

    # Test selection
    skip_tests: list[str] = field(default_factory=list)   # e.g. ["T05", "T07"]
    only_tests: list[str] = field(default_factory=list)   # run ONLY these modules

    # Output
    output_dir: Optional[str] = None   # where to write JSON + HTML reports
    verbose: bool = False

    # Load-test gate: skip large / slow payload tests when True
    # (FUZZ-STR-009, FUZZ-ARR-005, PI-013, PI-014, T05-003)
    no_load: bool = False


# ---------------------------------------------------------------------------
# Transport-layer connection metadata (populated by transport.py)
# ---------------------------------------------------------------------------


@dataclass
class ConnectionInfo:
    """
    Metadata about an established MCP connection, returned by the transport
    layer and attached to the ScanReport for provenance.
    """

    transport: TransportType
    target: str
    connected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    latency_ms: float = 0.0            # time to first successful ping
    tls_verified: Optional[bool] = None  # HTTP only; None for stdio
    server_header: Optional[str] = None  # HTTP Server: header if present
