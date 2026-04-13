"""
mcpsafe.tests.t03_fuzzer
========================
SECURITY category — Input fuzzing and type-confusion tests.

For every tool parameter whose JSON Schema type is known, MCPSafe substitutes
boundary / wrong-type values from ``FUZZ_CASES`` and classifies the response:

  ┌─────────────────────────────────────────────────┬──────────┬────────┐
  │ Condition                                       │ Severity │ Passed │
  ├─────────────────────────────────────────────────┼──────────┼────────┤
  │ Connection drop / process crash                 │ HIGH     │ False  │
  │ Response time > 30 s  (hard timeout)            │ HIGH     │ False  │
  │ Response time > 5 s   (slow response)           │ MEDIUM   │ False  │
  │ Stack trace / exception detail in response      │ MEDIUM   │ False  │
  │ Wrong type silently accepted (no error)         │ LOW      │ False  │
  │ Server returns proper error/rejection           │ PASS     │ True   │
  └─────────────────────────────────────────────────┴──────────┴────────┘

Test ID format
--------------
  T03-{tool_index:02d}-{param_slug}-{fuzz_id}

Where tool_index is the 1-based position in server_info.tools, param_slug is the
parameter name slug-ified to 12 chars, and fuzz_id is the FUZZ-TYPE-NNN tag.

Public API
----------
    async def run(
        session: ClientSession,
        server_info: ServerInfo,
        config: ScanConfig,
    ) -> list[TestResult]
"""

from __future__ import annotations

import asyncio
import re
import time
from typing import Any, Optional

from mcp import ClientSession
from mcp.types import TextContent

from mcpsafe.models import (
    Category,
    MCPTool,
    ScanConfig,
    ServerInfo,
    Severity,
    TestResult,
)

# ---------------------------------------------------------------------------
# Pre-computed payload constants
# ---------------------------------------------------------------------------

# 100-level nested array: [[[...100 levels...]]] — tests recursive JSON parsers.
# Built at module load so it can be embedded in the FUZZ_CASES dict literal.
_NESTED_ARR_100: list = []
for _i in range(100):
    _NESTED_ARR_100 = [_NESTED_ARR_100]
del _i  # keep module namespace clean


# ---------------------------------------------------------------------------
# Fuzz case corpus
# ---------------------------------------------------------------------------

# Each entry: (fuzz_id, label, value)
# ``value`` is deliberately Any — the whole point is to send the wrong type.
FUZZ_CASES: dict[str, list[tuple[str, str, Any]]] = {
    "string": [
        ("FUZZ-STR-001", "empty string", ""),
        ("FUZZ-STR-002", "single space", " "),
        ("FUZZ-STR-003", "whitespace only", "\t\n\r"),
        ("FUZZ-STR-004", "null value", None),
        ("FUZZ-STR-005", "integer as string field", 42),
        ("FUZZ-STR-006", "boolean as string field", True),
        ("FUZZ-STR-007", "list as string field", []),
        ("FUZZ-STR-008", "dict as string field", {}),
        ("FUZZ-STR-009", "very long string 10k", "x" * 10_000),
        ("FUZZ-STR-010", "newlines and tabs", "\n" * 100 + "\t" * 100),
        ("FUZZ-STR-011", "null byte in string", "test\x00end"),
        ("FUZZ-STR-012", "all unicode planes", "\u0000\uFFFF\U0001F600"),
    ],
    "integer": [
        ("FUZZ-INT-001", "zero", 0),
        ("FUZZ-INT-002", "negative one", -1),
        ("FUZZ-INT-003", "min int32", -2_147_483_648),
        ("FUZZ-INT-004", "max int32", 2_147_483_647),
        ("FUZZ-INT-005", "max int64", 9_223_372_036_854_775_807),
        ("FUZZ-INT-006", "float as integer", 3.14),
        ("FUZZ-INT-007", "string as integer", "notanint"),
        ("FUZZ-INT-008", "null as integer", None),
        ("FUZZ-INT-009", "boolean as integer", True),
        ("FUZZ-INT-010", "list as integer", [1, 2, 3]),
        # Beyond int64 / IEEE 754 edge cases
        ("FUZZ-INT-011", "beyond int64", 9_223_372_036_854_775_808),
        ("FUZZ-INT-012", "NaN string as integer", "NaN"),           # wrong type
        ("FUZZ-INT-013", "Infinity string as integer", "Infinity"),  # wrong type
    ],
    "number": [
        # Re-use integer cases — JSON Schema "number" covers both int and float.
        ("FUZZ-INT-001", "zero", 0),
        ("FUZZ-INT-002", "negative one", -1),
        ("FUZZ-INT-003", "min int32", -2_147_483_648),
        ("FUZZ-INT-004", "max int32", 2_147_483_647),
        ("FUZZ-INT-006", "float as number", 3.14),
        ("FUZZ-INT-007", "string as number", "notanumber"),
        ("FUZZ-INT-008", "null as number", None),
        ("FUZZ-INT-009", "boolean as number", True),
        # Boundary / IEEE 754 edge cases
        ("FUZZ-NUM-001", "NaN string as number", "NaN"),           # wrong type
        ("FUZZ-NUM-002", "Infinity string as number", "Infinity"),  # wrong type
        ("FUZZ-NUM-003", "-Infinity string as number", "-Infinity"), # wrong type
        ("FUZZ-NUM-004", "very large float 1e308", 1e308),
        ("FUZZ-NUM-005", "very small float 1e-308", 1e-308),
    ],
    "boolean": [
        ("FUZZ-BOOL-001", "null as boolean", None),
        ("FUZZ-BOOL-002", "string true", "true"),
        ("FUZZ-BOOL-003", "string false", "false"),
        ("FUZZ-BOOL-004", "integer zero", 0),
        ("FUZZ-BOOL-005", "integer one", 1),
        ("FUZZ-BOOL-006", "list as boolean", []),
        ("FUZZ-BOOL-007", "dict as boolean", {}),
    ],
    "array": [
        ("FUZZ-ARR-001", "null as array", None),
        ("FUZZ-ARR-002", "dict as array", {}),
        ("FUZZ-ARR-003", "string as array", "notanarray"),
        ("FUZZ-ARR-004", "empty array", []),
        ("FUZZ-ARR-005", "array of nulls 1000", [None] * 1_000),
        ("FUZZ-ARR-006", "deeply nested array 10", [[[[[]]]] ] * 10),
        # Memory/resource exhaustion candidates
        ("FUZZ-ARR-007", "large array 10k nulls", [None] * 10_000),
        ("FUZZ-ARR-008", "large array 1k mixed", [0, "", None, False] * 250),
        # Recursive / deeply nested (100 levels) — tests parser stack depth
        ("FUZZ-ARR-009", "100-level nested array", _NESTED_ARR_100),
    ],
    "object": [
        ("FUZZ-OBJ-001", "null as object", None),
        ("FUZZ-OBJ-002", "list as object", []),
        ("FUZZ-OBJ-003", "string as object", "notanobject"),
        ("FUZZ-OBJ-004", "empty object", {}),
        ("FUZZ-OBJ-005", "prototype pollution", {"__proto__": {"admin": True}}),
        ("FUZZ-OBJ-006", "deeply nested object", {"a": {"b": {"c": {"d": {}}}}}),
    ],
}

# Fuzz IDs whose payloads are large enough to constitute load tests.
_LARGE_FUZZ_IDS: frozenset[str] = frozenset({
    "FUZZ-STR-009", "FUZZ-ARR-005", "FUZZ-ARR-007", "FUZZ-ARR-008",
})

# Hard timeout (seconds) per fuzz call — triggers HIGH if exceeded.
_HARD_TIMEOUT: float = 35.0

# Soft timeout (seconds) — response slower than this is MEDIUM.
_SLOW_THRESHOLD: float = 5.0

# ---------------------------------------------------------------------------
# Stack-trace detection patterns
# ---------------------------------------------------------------------------

STACK_TRACE_PATTERNS: list[str] = [
    r"Traceback \(most recent call last\)",
    r"at [A-Za-z]+\.[A-Za-z]+\(",
    r"Exception in thread",
    r"Error: Cannot read propert",
    r"TypeError:|ValueError:|KeyError:|IndexError:",
    r"NullPointerException",
    r"undefined is not a function",
]

_COMPILED_STACK_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE) for p in STACK_TRACE_PATTERNS
]

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_MAX_ID_LEN = 72


def _make_test_id(tool_index: int, param_name: str, fuzz_id: str) -> str:
    """Build a test ID: ``T03-{tool_index:02d}-{param_slug}-{fuzz_id}``."""
    slug = re.sub(r"[^a-z0-9]+", "_", param_name.lower()).strip("_")[:12]
    return f"T03-{tool_index:02d}-{slug}-{fuzz_id}"


def _extract_text(response: object) -> str:
    """Flatten an MCP tool response to a plain string."""
    if isinstance(response, str):
        return response
    items = response if isinstance(response, list) else [response]
    parts: list[str] = []
    for item in items:
        if isinstance(item, TextContent):
            parts.append(item.text or "")
        elif hasattr(item, "text"):
            parts.append(str(item.text))
        else:
            parts.append(str(item))
    return "\n".join(parts)


def _find_stack_trace(text: str) -> Optional[str]:
    """Return the first matching stack-trace pattern, or ``None``."""
    for compiled, raw in zip(_COMPILED_STACK_PATTERNS, STACK_TRACE_PATTERNS):
        if compiled.search(text):
            return raw
    return None


def _is_connection_error(exc: Exception) -> bool:
    """Return True when the exception indicates a server crash / disconnect."""
    crash_types = (
        "ConnectionError", "BrokenPipeError", "EOFError",
        "ConnectionResetError", "ConnectionAbortedError", "TransportError",
    )
    crash_msgs = ("connection", "broken pipe", "eof", "reset by peer", "transport")
    exc_type = type(exc).__name__
    exc_str = str(exc).lower()
    return (
        any(c in exc_type for c in crash_types)
        or any(m in exc_str for m in crash_msgs)
    )


def _collect_params(tool: MCPTool) -> list[tuple[str, str]]:
    """
    Return a list of ``(param_name, json_schema_type)`` pairs from the tool's
    inputSchema, in definition order.  Params with unknown or missing types are
    skipped.
    """
    schema = tool.input_schema
    if not isinstance(schema, dict):
        return []
    props = schema.get("properties")
    if not isinstance(props, dict):
        return []

    supported_types = set(FUZZ_CASES.keys())
    result: list[tuple[str, str]] = []
    for pname, pschema in props.items():
        if not isinstance(pschema, dict):
            continue
        ptype = pschema.get("type", "")
        if isinstance(ptype, str) and ptype in supported_types:
            result.append((pname, ptype))
    return result


def _response_is_error(response: object) -> bool:
    """Return True if the MCP call_tool response indicates the server rejected the call."""
    # CallToolResult has an isError flag.
    if hasattr(response, "isError"):
        return bool(response.isError)
    # Some servers embed an error in the content list.
    text = _extract_text(response).lower()
    error_signals = ("error", "invalid", "exception", "failed", "bad request",
                     "type error", "validation", "not allowed")
    return any(s in text for s in error_signals)


# ---------------------------------------------------------------------------
# Single fuzz call
# ---------------------------------------------------------------------------


async def _run_single_fuzz(
    session: ClientSession,
    tool: MCPTool,
    tool_index: int,
    param_name: str,
    param_type: str,
    fuzz_id: str,
    fuzz_label: str,
    fuzz_value: Any,
) -> TestResult:
    """
    Send one fuzz value to one parameter of one tool and classify the result.

    Returns
    -------
    TestResult:
        Never raises — all exceptions are caught and converted.
    """
    tid = _make_test_id(tool_index, param_name, fuzz_id)
    tname = f"Fuzz {fuzz_id} → {tool.name}.{param_name}"
    t0 = time.perf_counter()

    # Build minimal call arguments: inject the fuzz value into the target param
    # and leave all other required params absent (to maximise path coverage).
    call_args: dict[str, Any] = {param_name: fuzz_value}

    try:
        response = await asyncio.wait_for(
            session.call_tool(tool.name, arguments=call_args),
            timeout=_HARD_TIMEOUT,
        )
        duration = (time.perf_counter() - t0) * 1000.0
        response_text = _extract_text(response)

        # --- Check: stack trace in response ---
        matched_pattern = _find_stack_trace(response_text)
        if matched_pattern:
            return TestResult(
                test_id=tid,
                test_name=tname,
                category=Category.SECURITY,
                severity=Severity.MEDIUM,
                passed=False,
                description=(
                    f"Tool {tool.name!r} leaked a stack trace / exception detail "
                    f"in its response to {fuzz_id} ({fuzz_label}) on param "
                    f"{param_name!r} (expected {param_type!r})."
                ),
                duration_ms=duration,
                details=(
                    f"Matched pattern: {matched_pattern!r}\n"
                    f"Fuzz value: {fuzz_value!r}\n"
                    f"Response excerpt: {response_text[:500]!r}"
                ),
                remediation=(
                    "Never expose internal stack traces, exception messages, or "
                    "file paths in tool responses. Sanitise all error output before "
                    "returning it to callers."
                ),
                request_payload=f"{tool.name}({param_name}={fuzz_value!r})",
                response_payload=response_text[:2_000],
            )

        # --- Check: slow response (soft threshold) ---
        if duration > _SLOW_THRESHOLD * 1000:
            return TestResult(
                test_id=tid,
                test_name=tname,
                category=Category.SECURITY,
                severity=Severity.MEDIUM,
                passed=False,
                description=(
                    f"Tool {tool.name!r} took {duration:.0f} ms on {fuzz_id} "
                    f"({fuzz_label}) — potential DoS via slow-processing input."
                ),
                duration_ms=duration,
                details=(
                    f"Threshold: {_SLOW_THRESHOLD * 1000:.0f} ms. "
                    f"Fuzz value type: {type(fuzz_value).__name__!r}. "
                    f"Param type expected: {param_type!r}."
                ),
                remediation=(
                    "Add input size and type guards before processing. "
                    "Unbounded processing time on arbitrary inputs is a DoS vector."
                ),
                request_payload=f"{tool.name}({param_name}={str(fuzz_value)[:200]!r})",
            )

        # --- Check: wrong type silently accepted ---
        # A correct-type fuzz value (e.g. empty string for a string param) is fine
        # to accept.  We flag acceptance only when the value is clearly the *wrong*
        # JSON type (e.g. a list where a string is expected).
        expected_python_types: dict[str, tuple[type, ...]] = {
            "string":  (str,),
            "integer": (int,),
            "number":  (int, float),
            "boolean": (bool,),
            "array":   (list,),
            "object":  (dict,),
        }
        expected = expected_python_types.get(param_type, ())
        value_is_wrong_type = (
            fuzz_value is not None
            and expected
            and not isinstance(fuzz_value, expected)
            # bool is a subclass of int in Python — treat it as wrong for int params
            and not (param_type == "integer" and isinstance(fuzz_value, bool))
        )

        if value_is_wrong_type and not _response_is_error(response):
            return TestResult(
                test_id=tid,
                test_name=tname,
                category=Category.SECURITY,
                severity=Severity.LOW,
                passed=False,
                description=(
                    f"Tool {tool.name!r} silently accepted {fuzz_id} "
                    f"({fuzz_label}) — {type(fuzz_value).__name__!r} sent "
                    f"where {param_type!r} expected, no error returned."
                ),
                duration_ms=duration,
                details=(
                    f"Fuzz value: {fuzz_value!r}\n"
                    f"Response excerpt: {response_text[:300]!r}"
                ),
                remediation=(
                    "Validate parameter types at the tool boundary and return a "
                    "structured error when the caller sends the wrong type. "
                    "Silent type coercion can lead to unexpected behaviour."
                ),
                request_payload=f"{tool.name}({param_name}={fuzz_value!r})",
                response_payload=response_text[:2_000],
            )

        # --- All clear: server properly handled the fuzz input ---
        return TestResult.make_pass(
            test_id=tid,
            test_name=tname,
            category=Category.SECURITY,
            description=(
                f"Tool {tool.name!r} handled {fuzz_id} ({fuzz_label}) "
                f"on param {param_name!r} correctly."
            ),
            duration_ms=duration,
            details=f"Response excerpt: {response_text[:200]!r}",
        )

    except asyncio.TimeoutError:
        duration = (time.perf_counter() - t0) * 1000.0
        return TestResult.make_fail(
            test_id=tid,
            test_name=tname,
            category=Category.SECURITY,
            severity=Severity.HIGH,
            description=(
                f"Tool {tool.name!r} hung for > {_HARD_TIMEOUT:.0f}s on {fuzz_id} "
                f"({fuzz_label}) — hard DoS timeout triggered."
            ),
            duration_ms=duration,
            details=(
                f"Hard timeout: {_HARD_TIMEOUT}s. "
                f"Fuzz value: {str(fuzz_value)[:200]!r}. "
                f"Param type: {param_type!r}."
            ),
            remediation=(
                "The tool did not respond within the hard timeout. "
                "Add an execution deadline and enforce input-size limits to prevent "
                "denial-of-service via unbounded computation."
            ),
        )

    except asyncio.CancelledError:
        raise  # never swallow CancelledError

    except Exception as exc:
        duration = (time.perf_counter() - t0) * 1000.0

        if _is_connection_error(exc):
            return TestResult.make_fail(
                test_id=tid,
                test_name=tname,
                category=Category.SECURITY,
                severity=Severity.HIGH,
                description=(
                    f"Tool {tool.name!r} caused a server crash / connection drop "
                    f"on {fuzz_id} ({fuzz_label}) — param {param_name!r}."
                ),
                duration_ms=duration,
                details=f"Server crash on fuzz input\n{type(exc).__name__}: {exc}",
                remediation=(
                    "The server process crashed or dropped the connection. "
                    "This indicates the tool has no guard against malformed inputs "
                    "and can be taken down by a malicious caller."
                ),
            )

        # Structured MCP error response — treat as graceful rejection (PASS).
        return TestResult.make_pass(
            test_id=tid,
            test_name=tname,
            category=Category.SECURITY,
            description=(
                f"Tool {tool.name!r} returned a structured error for {fuzz_id} "
                f"({fuzz_label}) on param {param_name!r} — handled gracefully."
            ),
            duration_ms=duration,
            details=f"{type(exc).__name__}: {str(exc)[:300]}",
        )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


async def run(
    session: ClientSession,
    server_info: ServerInfo,
    config: ScanConfig,
) -> list[TestResult]:
    """
    Execute type-confusion and boundary-value fuzz tests against every tool
    parameter whose type can be inferred from the inputSchema.

    Parameters
    ----------
    session:
        An initialised ``mcp.ClientSession``.
    server_info:
        Populated ``ServerInfo`` from the discovery phase.
    config:
        Active ``ScanConfig``; ``getattr(config, 'no_load', False)`` is checked
        to skip the large-payload fuzz cases (FUZZ-STR-009, FUZZ-ARR-005).

    Returns
    -------
    list[TestResult]:
        One result per (tool, param, fuzz_case) triple exercised.
    """
    results: list[TestResult] = []
    skip_large: bool = getattr(config, "no_load", False)

    testable: list[tuple[int, MCPTool, list[tuple[str, str]]]] = []
    for idx, tool in enumerate(server_info.tools, start=1):
        params = _collect_params(tool)
        if params:
            testable.append((idx, tool, params))

    if not testable:
        results.append(
            TestResult(
                test_id="T03-00-PREFLIGHT",
                test_name="Fuzzer Pre-flight",
                category=Category.SECURITY,
                severity=Severity.INFO,
                passed=True,
                description=(
                    "No tools with typed parameters found. "
                    "Fuzz tests skipped."
                ),
                duration_ms=0.0,
                details=(
                    f"Total tools: {len(server_info.tools)}. "
                    "None had parameters with recognised JSON Schema types."
                ),
            )
        )
        return results

    for tool_index, tool, params in testable:
        for param_name, param_type in params:
            cases = FUZZ_CASES.get(param_type, [])
            for fuzz_id, fuzz_label, fuzz_value in cases:
                if skip_large and fuzz_id in _LARGE_FUZZ_IDS:
                    continue
                result = await _run_single_fuzz(
                    session=session,
                    tool=tool,
                    tool_index=tool_index,
                    param_name=param_name,
                    param_type=param_type,
                    fuzz_id=fuzz_id,
                    fuzz_label=fuzz_label,
                    fuzz_value=fuzz_value,
                )
                results.append(result)

    return results
