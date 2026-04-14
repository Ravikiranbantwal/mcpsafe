"""
mcpsafe.tests.t15_reentrancy
==============================
SECURITY category — **Tool reentrancy / race condition** detection.

Many MCP tools appear thread-safe in isolation but corrupt state when
two concurrent invocations overlap.  Classic reentrancy bugs:

  * Shared request-scoped globals (e.g. ``current_user``) bleed between
    overlapping requests.
  * Non-atomic read-modify-write on an in-memory counter.
  * File-handle reuse (tool A opens file, tool B starts before A closes).
  * Cached results keyed only by tool name, not arguments+session.

What this test does
-------------------
For each suitable tool we fire ``N`` concurrent invocations with unique,
distinguishable arguments and record which argument each call returned.
A response that references an argument value the caller did NOT send is
proof of state bleed.

Suitable tools are those that:
  * Accept at least one string parameter.
  * Echo or process their input in a detectable way (we scan for our
    unique markers in the response).

Test inventory
--------------
T15-TOOL-{slug}    Per-tool reentrancy probe.
T15-001            Summary.

Public API
----------
    async def run(session, server_info, config) -> list[TestResult]
"""

from __future__ import annotations

import asyncio
import re
import secrets
import time
from typing import Optional

import anyio
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
from mcpsafe.tests._helpers import RateLimiter, cap_response, looks_like_api_rejection

_CONCURRENT_CALLS = 6
_CALL_TIMEOUT_SEC = 15.0
_MAX_TOOLS_PROBED = 6
_MAX_TEST_ID_LEN = 64


def _slug(name: str, budget: int = 28) -> str:
    s = re.sub(r"[^a-z0-9]+", "_", (name or "unknown").lower()).strip("_")
    return (s or "unknown")[:budget] or "unknown"


def _first_string_param(tool: MCPTool) -> Optional[str]:
    schema = tool.input_schema
    if not isinstance(schema, dict):
        return None
    props = schema.get("properties") or {}
    required = schema.get("required", []) or []
    for pname in required:
        pschema = props.get(pname) or {}
        if isinstance(pschema, dict) and pschema.get("type") == "string":
            return pname
    for pname, pschema in props.items():
        if isinstance(pschema, dict) and pschema.get("type") == "string":
            return pname
    return None


def _extract_text(response: object) -> str:
    if isinstance(response, str):
        return cap_response(response)
    if not isinstance(response, list) and hasattr(response, "content"):
        content = getattr(response, "content", None)
        if isinstance(content, list):
            response = content
    parts: list[str] = []
    items = response if isinstance(response, list) else [response]
    for item in items:
        if isinstance(item, TextContent):
            parts.append(item.text or "")
        elif hasattr(item, "text"):
            val = getattr(item, "text", None)
            parts.append(str(val) if val is not None else "")
        else:
            parts.append(str(item))
    return cap_response("\n".join(parts))


async def _one_call(
    session: ClientSession,
    tool_name: str,
    pname: str,
    marker: str,
) -> tuple[str, Optional[str]]:
    """Return ``(marker_sent, response_text_or_None)``."""
    try:
        with anyio.fail_after(_CALL_TIMEOUT_SEC):
            resp = await session.call_tool(
                tool_name, arguments={pname: marker}
            )
        return marker, _extract_text(resp)
    except Exception:
        return marker, None


async def _probe_tool(
    session: ClientSession,
    tool: MCPTool,
    limiter: RateLimiter,
) -> TestResult:
    tid = f"T15-TOOL-{_slug(tool.name)}"
    if len(tid) > _MAX_TEST_ID_LEN:
        tid = tid[:_MAX_TEST_ID_LEN]
    tname = f"Reentrancy → {tool.name}"
    t0 = time.perf_counter()

    pname = _first_string_param(tool)
    if not pname:
        return TestResult(
            test_id=tid, test_name=tname,
            category=Category.SECURITY, severity=Severity.INFO,
            passed=True,
            description=f"Tool {tool.name!r} has no string parameter; reentrancy probe skipped.",
            duration_ms=(time.perf_counter() - t0) * 1000.0,
        )

    # Generate unique markers for each concurrent call.
    markers = [
        f"MCPSAFE-T15-{secrets.token_hex(6)}-{i:02d}"
        for i in range(_CONCURRENT_CALLS)
    ]

    # Fire all N calls concurrently (no limiter between them — we WANT overlap).
    # The limiter is applied once upfront to avoid hitting rate limits.
    await limiter.acquire()
    tasks = [_one_call(session, tool.name, pname, m) for m in markers]
    outcomes = await asyncio.gather(*tasks, return_exceptions=True)

    duration = (time.perf_counter() - t0) * 1000.0

    # Build a set of all markers for fast lookup.
    all_markers = set(markers)
    bleeds: list[str] = []
    responses_seen = 0

    for outcome in outcomes:
        if isinstance(outcome, BaseException):
            continue
        sent_marker, resp_text = outcome
        if resp_text is None:
            continue
        responses_seen += 1
        # Look for ANY other marker in this response — that's state bleed.
        other_markers = [m for m in all_markers if m != sent_marker and m in resp_text]
        if other_markers:
            bleeds.append(
                f"sent={sent_marker}, response contained: {other_markers}"
            )

    if responses_seen == 0:
        return TestResult(
            test_id=tid, test_name=tname,
            category=Category.SECURITY, severity=Severity.INFO,
            passed=True,
            description=(
                f"Tool {tool.name!r} rejected or failed all {_CONCURRENT_CALLS} "
                f"concurrent probes; reentrancy could not be evaluated."
            ),
            duration_ms=duration,
        )

    if bleeds:
        return TestResult(
            test_id=tid, test_name=tname,
            category=Category.SECURITY, severity=Severity.HIGH,
            passed=False,
            description=(
                f"Tool {tool.name!r} leaked arguments across {len(bleeds)} of "
                f"{responses_seen} concurrent invocation(s). State is shared "
                f"between overlapping calls — a classic reentrancy bug."
            ),
            duration_ms=duration,
            details="\n".join(bleeds[:5]),
            remediation=(
                "Ensure every request-scoped value (user context, request ID, "
                "arguments) is passed through call-stack parameters rather than "
                "stored in module-level globals. Use contextvars if you need "
                "per-task storage. Audit file handles, DB connections, and "
                "caches for shared state."
            ),
        )

    return TestResult.make_pass(
        test_id=tid, test_name=tname,
        category=Category.SECURITY,
        description=(
            f"{_CONCURRENT_CALLS} concurrent calls to {tool.name!r} returned "
            f"independent results — no state bleed detected."
        ),
        duration_ms=duration,
    )


async def run(
    session: ClientSession,
    server_info: ServerInfo,
    config: ScanConfig,
) -> list[TestResult]:
    """Execute T15 — Tool Chain Reentrancy."""
    t_start = time.perf_counter()
    results: list[TestResult] = []
    limiter = RateLimiter(config)

    candidates = [t for t in (server_info.tools or []) if _first_string_param(t)]
    candidates = candidates[:_MAX_TOOLS_PROBED]

    if not candidates:
        results.append(
            TestResult(
                test_id="T15-001",
                test_name="Reentrancy — Summary",
                category=Category.SECURITY,
                severity=Severity.INFO, passed=True,
                description="No suitable tools for reentrancy probing.",
                duration_ms=(time.perf_counter() - t_start) * 1000.0,
            )
        )
        return results

    for tool in candidates:
        results.append(await _probe_tool(session, tool, limiter))

    bad = sum(1 for r in results if r.severity == Severity.HIGH and not r.passed)
    if bad == 0:
        results.append(
            TestResult.make_pass(
                test_id="T15-001",
                test_name="Reentrancy — Summary",
                category=Category.SECURITY,
                description=(
                    f"Probed {len(candidates)} tool(s) with {_CONCURRENT_CALLS} "
                    f"concurrent invocations each; no state-bleed detected."
                ),
                duration_ms=(time.perf_counter() - t_start) * 1000.0,
            )
        )
    else:
        results.append(
            TestResult.make_fail(
                test_id="T15-001",
                test_name="Reentrancy — Summary",
                category=Category.SECURITY,
                severity=Severity.HIGH,
                description=(
                    f"{bad} of {len(candidates)} tool(s) exhibit state bleed "
                    f"between concurrent invocations."
                ),
                duration_ms=(time.perf_counter() - t_start) * 1000.0,
                remediation="See per-tool T15-TOOL-* findings.",
            )
        )
    return results
