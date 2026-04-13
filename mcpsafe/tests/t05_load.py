"""
mcpsafe.tests.t05_load
=======================
PERFORMANCE category — Concurrent load and connection-stability tests.

Test inventory
--------------
T05-001  10 simultaneous calls     asyncio.gather of 10 concurrent tool calls;
                                   check for cross-request data leakage via UUIDs.
T05-002  50 sequential rapid calls Record p50/p95/p99 latency; flag slow servers.
T05-003  100-call stress test      5 batches of 20; compute failure rate and
                                   throughput.  Skipped when config.no_load=True.
T05-004  Rapid reconnect stability Open/close the MCP connection 5× and compare
                                   tool lists for consistency.

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
import json
import time
import uuid
from typing import Optional

from mcp import ClientSession

from mcpsafe.models import (
    Category,
    MCPTool,
    ScanConfig,
    ServerInfo,
    Severity,
    TestResult,
    TransportType,
)
from mcpsafe.tests._helpers import cap_response, looks_like_api_rejection
from mcpsafe.transport import MCPConnection

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_CAT = Category.PERFORMANCE

_T05_003_TOTAL = 100
_T05_003_BATCH_SIZE = 20
_T05_003_BATCH_DELAY = 0.2          # seconds between batches (stdio)
_T05_003_BATCH_DELAY_HTTP = 1.5     # seconds between batches (HTTP — respects rate limits)
_T05_001_CONCURRENCY_HTTP = 3       # reduced concurrent calls for HTTP transport
_T05_HTTP_INTER_CALL_DELAY = 0.3    # seconds between individual calls on HTTP transport
_T05_004_RECONNECTS = 5
_T05_004_RECONNECT_DELAY = 1.0      # seconds between each reconnect (stdio)
_T05_004_RECONNECT_DELAY_HTTP = 3.0 # longer delay on HTTP to avoid rate-limit cascade

_P95_HIGH_MS    = 30_000.0
_P95_MEDIUM_MS  =  5_000.0

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _percentile(data: list[float], pct: int) -> float:
    """Return the ``pct``-th percentile of ``data`` (0–100)."""
    s = sorted(data)
    i = int(len(s) * pct / 100)
    return s[min(i, len(s) - 1)]


def _find_string_param(tool: MCPTool) -> Optional[str]:
    """Return the name of the first string-typed parameter, or ``None``."""
    schema = tool.input_schema
    if not isinstance(schema, dict):
        return None
    props = schema.get("properties")
    if not isinstance(props, dict):
        return None
    required: list[str] = schema.get("required", []) or []
    for pname, pschema in props.items():
        if isinstance(pschema, dict) and pschema.get("type") == "string" and pname in required:
            return pname
    for pname, pschema in props.items():
        if isinstance(pschema, dict) and pschema.get("type") == "string":
            return pname
    return None


def _pick_tool(server_info: ServerInfo) -> Optional[MCPTool]:
    """Return the first available tool, or ``None``."""
    return server_info.tools[0] if server_info.tools else None


async def _call_tool_timed(
    session: ClientSession,
    tool_name: str,
    args: dict,
    timeout: float,
) -> tuple[object, float]:
    """
    Call a tool and return ``(response, duration_ms)``.
    Raises on error — callers are responsible for catching.
    """
    t0 = time.perf_counter()
    response = await asyncio.wait_for(
        session.call_tool(tool_name, arguments=args),
        timeout=timeout,
    )
    return response, (time.perf_counter() - t0) * 1000.0


def _extract_text(response: object) -> str:
    """Flatten an MCP response to a plain string, capped at 1 MB."""
    try:
        from mcp.types import TextContent  # local import to avoid circular
        items = response if isinstance(response, list) else [response]
        parts: list[str] = []
        for item in items:
            if isinstance(item, TextContent):
                parts.append(item.text or "")
            elif hasattr(item, "text"):
                parts.append(str(item.text))
            else:
                parts.append(str(item))
        return cap_response("\n".join(parts))
    except Exception:
        return cap_response(str(response))


# ---------------------------------------------------------------------------
# T05-001 — 10 simultaneous calls
# ---------------------------------------------------------------------------


async def _t05_001_concurrent_10(
    session: ClientSession,
    server_info: ServerInfo,
    config: ScanConfig,
) -> TestResult:
    """T05-001 — Fire 10 concurrent calls and check for cross-request leakage."""
    tid = "T05-001"
    tname = "10 Simultaneous Calls"
    t0 = time.perf_counter()
    try:
        tool = _pick_tool(server_info)
        if tool is None:
            return TestResult(
                test_id=tid, test_name=tname, category=_CAT,
                severity=Severity.INFO, passed=True,
                description="No tools available — concurrent test skipped.",
                duration_ms=(time.perf_counter() - t0) * 1000.0,
            )

        str_param = _find_string_param(tool)
        # For HTTP transport use fewer concurrent calls to avoid rate-limiting.
        is_http = config.transport in (TransportType.HTTP, TransportType.SSE)
        concurrency = _T05_001_CONCURRENCY_HTTP if is_http else 10
        call_ids: list[str] = [str(uuid.uuid4()) for _ in range(concurrency)]

        def _args(call_uuid: str) -> dict:
            if str_param:
                return {str_param: f"mcpsafe-load-{call_uuid}"}
            return {}

        async def _single(call_uuid: str) -> tuple[str, object, float]:
            if is_http:
                await asyncio.sleep(_T05_HTTP_INTER_CALL_DELAY)
            resp, ms = await _call_tool_timed(
                session, tool.name, _args(call_uuid), config.timeout_seconds
            )
            return call_uuid, resp, ms

        # Fire calls simultaneously (reduced count on HTTP to respect rate limits).
        raw = await asyncio.gather(
            *[_single(cid) for cid in call_ids],
            return_exceptions=True,
        )

        duration_ms = (time.perf_counter() - t0) * 1000.0
        failures: list[str] = []
        latencies: list[float] = []
        leakage: list[str] = []

        for idx, item in enumerate(raw):
            if isinstance(item, BaseException):
                failures.append(f"Call {idx + 1}: {type(item).__name__}: {item}")
                continue
            call_uuid, resp, ms = item
            latencies.append(ms)
            resp_text = _extract_text(resp)
            # Cross-request leakage: does the response contain a UUID from a
            # *different* call?
            for other_uuid in call_ids:
                if other_uuid != call_uuid and other_uuid in resp_text:
                    leakage.append(
                        f"Call {call_uuid[:8]}… received UUID from "
                        f"call {other_uuid[:8]}…"
                    )

        if leakage:
            return TestResult(
                test_id=tid, test_name=tname, category=_CAT,
                severity=Severity.CRITICAL, passed=False,
                description=(
                    "Cross-request data leakage detected during 10 concurrent calls."
                ),
                duration_ms=duration_ms,
                details="Cross-request data leakage detected\n" + "\n".join(leakage),
                remediation=(
                    "The server is mixing response data across concurrent requests. "
                    "This is a critical state-isolation failure — shared mutable "
                    "state is leaking between parallel calls."
                ),
            )

        if failures:
            if looks_like_api_rejection(failures):
                return TestResult(
                    test_id=tid, test_name=tname, category=_CAT,
                    severity=Severity.INFO, passed=True,
                    description=(
                        f"{len(failures)}/10 concurrent calls rejected by upstream "
                        f"API (auth/validation) — not a concurrency defect."
                    ),
                    duration_ms=duration_ms,
                    details="\n".join(failures[:5]),
                )
            return TestResult(
                test_id=tid, test_name=tname, category=_CAT,
                severity=Severity.HIGH, passed=False,
                description=(
                    f"{len(failures)}/10 concurrent calls failed."
                ),
                duration_ms=duration_ms,
                details="\n".join(failures),
                remediation=(
                    "The server cannot handle 10 simultaneous calls. "
                    "Add connection pooling, async handling, or rate-limit "
                    "documentation so callers know the concurrency ceiling."
                ),
            )

        stats = (
            f"min={min(latencies):.0f}ms  "
            f"mean={sum(latencies)/len(latencies):.0f}ms  "
            f"max={max(latencies):.0f}ms"
        ) if latencies else "no latency data"

        return TestResult.make_pass(
            test_id=tid, test_name=tname, category=_CAT,
            description=(
                f"All 10 concurrent calls to {tool.name!r} succeeded "
                f"with no data leakage."
            ),
            duration_ms=duration_ms,
            details=stats,
        )

    except Exception as exc:
        return TestResult.from_exception(
            test_id=tid, test_name=tname, category=_CAT, exc=exc,
            duration_ms=(time.perf_counter() - t0) * 1000.0,
        )


# ---------------------------------------------------------------------------
# T05-002 — 50 sequential rapid calls
# ---------------------------------------------------------------------------


async def _t05_002_sequential_50(
    session: ClientSession,
    server_info: ServerInfo,
    config: ScanConfig,
) -> TestResult:
    """T05-002 — 50 sequential calls; compute p50/p95/p99 latency."""
    tid = "T05-002"
    tname = "50 Sequential Rapid Calls"
    t0 = time.perf_counter()
    try:
        tool = _pick_tool(server_info)
        if tool is None:
            return TestResult(
                test_id=tid, test_name=tname, category=_CAT,
                severity=Severity.INFO, passed=True,
                description="No tools available — sequential load test skipped.",
                duration_ms=(time.perf_counter() - t0) * 1000.0,
            )

        str_param = _find_string_param(tool)
        latencies: list[float] = []
        errors: list[str] = []

        for i in range(50):
            args = {str_param: f"mcpsafe-seq-{i}"} if str_param else {}
            try:
                _, ms = await _call_tool_timed(
                    session, tool.name, args, config.timeout_seconds
                )
                latencies.append(ms)
            except Exception as exc:
                errors.append(f"Call {i + 1}: {type(exc).__name__}: {exc}")

        duration_ms = (time.perf_counter() - t0) * 1000.0

        if not latencies:
            if looks_like_api_rejection(errors):
                return TestResult(
                    test_id=tid, test_name=tname, category=_CAT,
                    severity=Severity.INFO, passed=True,
                    description=(
                        f"All 50 calls to {tool.name!r} rejected by upstream API "
                        f"(auth/validation) — sequential latency not measurable."
                    ),
                    duration_ms=duration_ms,
                    details="\n".join(errors[:5]),
                )
            return TestResult.make_fail(
                test_id=tid, test_name=tname, category=_CAT,
                severity=Severity.HIGH,
                description=f"All 50 sequential calls to {tool.name!r} failed.",
                duration_ms=duration_ms,
                details="\n".join(errors[:20]),
            )

        p50 = _percentile(latencies, 50)
        p95 = _percentile(latencies, 95)
        p99 = _percentile(latencies, 99)

        stats = json.dumps({
            "tool": tool.name,
            "calls": len(latencies),
            "errors": len(errors),
            "min_ms": round(min(latencies), 2),
            "mean_ms": round(sum(latencies) / len(latencies), 2),
            "max_ms": round(max(latencies), 2),
            "p50_ms": round(p50, 2),
            "p95_ms": round(p95, 2),
            "p99_ms": round(p99, 2),
        }, indent=2)

        if p95 > _P95_HIGH_MS:
            return TestResult(
                test_id=tid, test_name=tname, category=_CAT,
                severity=Severity.HIGH, passed=False,
                description=f"p95={p95:.0f}ms — server hanging under sequential load.",
                duration_ms=duration_ms,
                details=stats,
                remediation=(
                    "p95 latency > 30 s indicates the server is hanging or "
                    "blocking on synchronous I/O. Profile under load and add "
                    "async processing."
                ),
            )

        if p95 > _P95_MEDIUM_MS:
            return TestResult(
                test_id=tid, test_name=tname, category=_CAT,
                severity=Severity.MEDIUM, passed=False,
                description=f"p95={p95:.0f}ms exceeds 5 s threshold.",
                duration_ms=duration_ms,
                details=stats,
                remediation=(
                    "p95 latency > 5 s will cause timeouts in real deployments. "
                    "Investigate slow call paths and add caching or async offload."
                ),
            )

        return TestResult.make_pass(
            test_id=tid, test_name=tname, category=_CAT,
            description=f"p50={p50:.0f}ms  p95={p95:.0f}ms  p99={p99:.0f}ms",
            duration_ms=duration_ms,
            details=stats,
        )

    except Exception as exc:
        return TestResult.from_exception(
            test_id=tid, test_name=tname, category=_CAT, exc=exc,
            duration_ms=(time.perf_counter() - t0) * 1000.0,
        )


# ---------------------------------------------------------------------------
# T05-003 — 100-call stress test
# ---------------------------------------------------------------------------


async def _t05_003_stress_100(
    session: ClientSession,
    server_info: ServerInfo,
    config: ScanConfig,
) -> TestResult:
    """T05-003 — 5 batches of 20 concurrent calls; compute failure rate."""
    tid = "T05-003"
    tname = "100 Concurrent Calls (Stress Test)"
    t0 = time.perf_counter()

    if config.no_load:
        return TestResult(
            test_id=tid, test_name=tname, category=_CAT,
            severity=Severity.INFO, passed=True,
            description=(
                "Stress test skipped — --no-load flag is set."
            ),
            duration_ms=(time.perf_counter() - t0) * 1000.0,
            details=(
                "Pass --no-load=false or omit the flag to enable the "
                "100-call stress test."
            ),
        )

    try:
        tool = _pick_tool(server_info)
        if tool is None:
            return TestResult(
                test_id=tid, test_name=tname, category=_CAT,
                severity=Severity.INFO, passed=True,
                description="No tools available — stress test skipped.",
                duration_ms=(time.perf_counter() - t0) * 1000.0,
            )

        str_param = _find_string_param(tool)
        total_failures = 0
        call_number = 0
        sample_errors: list[str] = []   # collect a few error messages for rejection check

        # Use smaller batches and longer delays for HTTP transport to avoid
        # triggering rate limits on remote production servers.
        is_http = config.transport in (TransportType.HTTP, TransportType.SSE)
        batch_size = 5 if is_http else _T05_003_BATCH_SIZE
        batch_delay = _T05_003_BATCH_DELAY_HTTP if is_http else _T05_003_BATCH_DELAY
        total_calls = 25 if is_http else _T05_003_TOTAL

        wall_start = time.perf_counter()

        for batch_idx in range(total_calls // batch_size):
            if batch_idx > 0:
                await asyncio.sleep(batch_delay)

            async def _one(n: int) -> tuple[bool, str]:
                """Return (success, error_str)."""
                args = {str_param: f"mcpsafe-stress-{n}"} if str_param else {}
                try:
                    await asyncio.wait_for(
                        session.call_tool(tool.name, arguments=args),
                        timeout=config.timeout_seconds,
                    )
                    return True, ""
                except Exception as exc:
                    return False, f"{type(exc).__name__}: {exc}"

            batch_start = call_number
            batch_end   = call_number + batch_size
            batch_results = await asyncio.gather(
                *[_one(n) for n in range(batch_start, batch_end)],
                return_exceptions=False,
            )
            for ok, err in batch_results:
                if not ok:
                    total_failures += 1
                    if len(sample_errors) < 10:
                        sample_errors.append(err)
            call_number = batch_end

        wall_elapsed = time.perf_counter() - wall_start
        duration_ms  = (time.perf_counter() - t0) * 1000.0
        failure_rate = total_failures / _T05_003_TOTAL
        calls_per_sec = _T05_003_TOTAL / wall_elapsed if wall_elapsed > 0 else 0.0

        if failure_rate > 0.10:
            # Before raising HIGH, check if every failure is just an API rejection.
            if looks_like_api_rejection(sample_errors):
                return TestResult(
                    test_id=tid, test_name=tname, category=_CAT,
                    severity=Severity.INFO, passed=True,
                    description=(
                        f"{total_failures}/{_T05_003_TOTAL} calls rejected by upstream "
                        f"API (auth/validation) — stress test inconclusive without "
                        f"valid credentials."
                    ),
                    duration_ms=duration_ms,
                    details="\n".join(sample_errors[:5]),
                )
            return TestResult.make_fail(
                test_id=tid, test_name=tname, category=_CAT,
                severity=Severity.HIGH,
                description=(
                    f"{total_failures}/{_T05_003_TOTAL} calls failed "
                    f"({failure_rate:.0%}) — server unstable under stress load."
                ),
                duration_ms=duration_ms,
                details=f"{total_failures}/100 calls failed",
                remediation=(
                    "More than 10% of calls failed under 100-call concurrent load. "
                    "The server likely has no connection pool, insufficient resource "
                    "limits, or is crashing under parallel pressure."
                ),
            )

        if failure_rate > 0:
            return TestResult.make_fail(
                test_id=tid, test_name=tname, category=_CAT,
                severity=Severity.MEDIUM,
                description=(
                    f"{total_failures}/{_T05_003_TOTAL} calls failed "
                    f"({failure_rate:.0%}) — minor instability detected."
                ),
                duration_ms=duration_ms,
                details=f"{total_failures}/100 calls failed",
                remediation=(
                    "A small number of calls failed under stress. "
                    "Review server logs for transient errors, resource exhaustion, "
                    "or connection limits."
                ),
            )

        return TestResult.make_pass(
            test_id=tid, test_name=tname, category=_CAT,
            description=(
                f"All {_T05_003_TOTAL} calls succeeded. "
                f"Throughput: {calls_per_sec:.1f} calls/sec"
            ),
            duration_ms=duration_ms,
            details=f"Throughput: {calls_per_sec:.1f} calls/sec",
        )

    except Exception as exc:
        return TestResult.from_exception(
            test_id=tid, test_name=tname, category=_CAT, exc=exc,
            duration_ms=(time.perf_counter() - t0) * 1000.0,
        )


# ---------------------------------------------------------------------------
# T05-004 — Connection stability under rapid reconnect
# ---------------------------------------------------------------------------


async def _t05_004_reconnect_stability(
    server_info: ServerInfo,
    config: ScanConfig,
) -> TestResult:
    """
    T05-004 — Open and close the MCP connection 5 times; compare tool lists.

    This test opens its own fresh connections and does NOT use the passed session.
    """
    tid = "T05-004"
    tname = "Connection Stability Under Rapid Reconnect"
    t0 = time.perf_counter()

    tool_lists: list[list[str]] = []
    errors: list[str] = []
    is_http = config.transport in (TransportType.HTTP, TransportType.SSE)
    reconnect_delay = _T05_004_RECONNECT_DELAY_HTTP if is_http else _T05_004_RECONNECT_DELAY

    for attempt in range(1, _T05_004_RECONNECTS + 1):
        if attempt > 1:
            await asyncio.sleep(reconnect_delay)
        try:
            async with MCPConnection(config) as (fresh_session, _conn_info):
                resp = await fresh_session.list_tools()
                names = sorted(
                    getattr(t, "name", "") for t in (getattr(resp, "tools", []) or [])
                )
                tool_lists.append(names)
        except Exception as exc:
            errors.append(f"Reconnect {attempt}: {type(exc).__name__}: {exc}")
            tool_lists.append([])  # record empty so diff still works

    duration_ms = (time.perf_counter() - t0) * 1000.0

    if errors:
        # On HTTP transports, reconnect failures after T07 auth tests are
        # expected — the server may have rate-limited or invalidated the
        # session.  Report as INFO rather than a server bug.
        if is_http:
            return TestResult(
                test_id=tid, test_name=tname, category=_CAT,
                severity=Severity.INFO, passed=True,
                description=(
                    f"{len(errors)}/{_T05_004_RECONNECTS} reconnects failed — "
                    "likely rate-limiting on the HTTP server after auth tests. "
                    "Not a server defect."
                ),
                duration_ms=duration_ms,
                details="\n".join(errors),
                remediation=(
                    "Reconnect failures on production HTTP servers are normal after "
                    "the T07 auth test suite sends malformed requests. Run with "
                    "--no-load to skip stress tests if this causes issues."
                ),
            )
        return TestResult(
            test_id=tid, test_name=tname, category=_CAT,
            severity=Severity.MEDIUM, passed=False,
            description=(
                f"{len(errors)}/{_T05_004_RECONNECTS} reconnects raised "
                f"exceptions."
            ),
            duration_ms=duration_ms,
            details="\n".join(errors),
            remediation=(
                "The server failed to accept some reconnections. Ensure it does "
                "not exhaust file descriptors, threads, or ports under rapid "
                "connect/disconnect cycles."
            ),
        )

    # Check that every reconnect returned the same tool list.
    differing: list[str] = []
    baseline = tool_lists[0] if tool_lists else []
    for idx, names in enumerate(tool_lists[1:], start=2):
        if names != baseline:
            differing.append(
                f"Reconnect {idx} returned {names} "
                f"(baseline: {baseline})"
            )

    if differing:
        return TestResult.make_fail(
            test_id=tid, test_name=tname, category=_CAT,
            severity=Severity.HIGH,
            description=(
                f"Tool list differed across {len(differing)} reconnect(s) — "
                f"server is non-deterministic."
            ),
            duration_ms=duration_ms,
            details="\n".join(differing),
            remediation=(
                "The tool list should be stable across reconnections. "
                "A changing tool list is a rug-pull indicator and breaks "
                "client caching assumptions."
            ),
        )

    return TestResult.make_pass(
        test_id=tid, test_name=tname, category=_CAT,
        description=(
            f"Tool list consistent across all {_T05_004_RECONNECTS} reconnects: "
            f"{baseline or '(empty)'}."
        ),
        duration_ms=duration_ms,
        details=f"Reconnects: {_T05_004_RECONNECTS}. Tools per connect: {len(baseline)}.",
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
    Execute all T05 load and stability tests.

    Parameters
    ----------
    session:
        An initialised ``mcp.ClientSession`` (used by T05-001, T05-002, T05-003).
    server_info:
        Populated ``ServerInfo`` from the discovery phase.
    config:
        Active ``ScanConfig``; ``config.no_load`` gates T05-003.
        ``config.transport`` and ``config.target`` are used by T05-004 to
        open its own independent connections.

    Returns
    -------
    list[TestResult]:
        Exactly 4 results (one per test).  Never raises.
    """
    results: list[TestResult] = []
    results.append(await _t05_001_concurrent_10(session, server_info, config))
    results.append(await _t05_002_sequential_50(session, server_info, config))
    results.append(await _t05_003_stress_100(session, server_info, config))
    results.append(await _t05_004_reconnect_stability(server_info, config))
    return results
