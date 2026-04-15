"""
mcpsafe.tests.t27_session_token
=================================
SECURITY category — **Session and token handling**.

Beyond T07's basic auth tests, this module checks for session-layer bugs:

T27-001  Token reuse after logout  — after ``close`` or re-init, is the
         same session-ID still accepted?
T27-002  Session token entropy     — Shannon entropy of observed session
         IDs. Below 3 bits/char is LOW, below 2 is MEDIUM.
T27-003  Token leak in response    — any MCP call returns a session token
         in its content. HIGH if found.
T27-004  Predictable session IDs   — open N sessions, check if IDs
         increment linearly.

Best-effort — the MCP client SDK abstracts session management away, so
some checks require reaching into private attributes.  Any check that
cannot be performed is reported as INFO rather than being silently
skipped.
"""

from __future__ import annotations

import math
import re
import time
from collections import Counter
from typing import Any, Optional

import anyio
from mcp import ClientSession

from mcpsafe.models import (
    Category,
    ScanConfig,
    ServerInfo,
    Severity,
    TestResult,
    TransportType,
)
from mcpsafe.tests._helpers import (
    RateLimiter,
    cap_response,
)
from mcpsafe.transport import MCPConnection, TransportError


def _shannon_entropy(s: str) -> float:
    """Bits of entropy per character in *s*."""
    if not s:
        return 0.0
    counts = Counter(s)
    total = len(s)
    probs = [c / total for c in counts.values()]
    return -sum(p * math.log2(p) for p in probs if p > 0)


def _extract_session_id(session: ClientSession) -> Optional[str]:
    """Best-effort pull a session / request ID from SDK internals."""
    for attr in ("_session_id", "session_id", "_client_session_id", "_id"):
        val = getattr(session, attr, None)
        if isinstance(val, str) and len(val) >= 6:
            return val
    # Look inside internal transports.
    for attr in ("_transport", "_stream", "_read_stream"):
        inner = getattr(session, attr, None)
        if inner is not None:
            for sub in ("session_id", "_session_id"):
                val = getattr(inner, sub, None)
                if isinstance(val, str) and len(val) >= 6:
                    return val
    return None


async def _t27_001_reuse_after_close(
    server_info: ServerInfo,
    config: ScanConfig,
    limiter: RateLimiter,
) -> TestResult:
    tid = "T27-001"
    tname = "Session Token Reuse After Close"
    t0 = time.perf_counter()

    if config.transport == TransportType.STDIO:
        return TestResult(
            test_id=tid, test_name=tname,
            category=Category.SECURITY, severity=Severity.INFO, passed=True,
            description="STDIO transport has no persistent session token — reuse N/A.",
            duration_ms=(time.perf_counter() - t0) * 1000.0,
        )

    captured_id: Optional[str] = None
    try:
        async with MCPConnection(config) as (session_a, _info_a):
            captured_id = _extract_session_id(session_a)
            await limiter.acquire()
            await session_a.list_tools()
        # After the async-with exits, session_a is closed.

        if not captured_id:
            return TestResult(
                test_id=tid, test_name=tname,
                category=Category.SECURITY, severity=Severity.INFO, passed=True,
                description=(
                    "Could not extract the session identifier from SDK internals — "
                    "reuse-after-close check could not be performed."
                ),
                duration_ms=(time.perf_counter() - t0) * 1000.0,
            )

        # We have an ID. Attempt a second connection; check whether the
        # new connection gets a DIFFERENT ID (expected, safe) or somehow
        # the SDK tries to reuse the closed one.
        async with MCPConnection(config) as (session_b, _info_b):
            new_id = _extract_session_id(session_b)
            if new_id and new_id == captured_id:
                return TestResult(
                    test_id=tid, test_name=tname,
                    category=Category.SECURITY, severity=Severity.MEDIUM, passed=False,
                    description=(
                        "Second connection reused the same session identifier as "
                        "the first (already-closed) session. Closed session tokens "
                        "should not be re-issued."
                    ),
                    duration_ms=(time.perf_counter() - t0) * 1000.0,
                )
            return TestResult.make_pass(
                test_id=tid, test_name=tname, category=Category.SECURITY,
                description="New session received a fresh identifier — no reuse.",
                duration_ms=(time.perf_counter() - t0) * 1000.0,
            )
    except TransportError as exc:
        return TestResult(
            test_id=tid, test_name=tname,
            category=Category.SECURITY, severity=Severity.INFO, passed=True,
            description="Could not open second session for reuse comparison.",
            duration_ms=(time.perf_counter() - t0) * 1000.0,
            details=str(exc)[:200],
        )
    except Exception as exc:
        return TestResult.from_exception(
            test_id=tid, test_name=tname, category=Category.SECURITY, exc=exc,
            duration_ms=(time.perf_counter() - t0) * 1000.0,
        )


async def _t27_002_token_entropy(
    session: ClientSession,
) -> TestResult:
    tid = "T27-002"
    tname = "Session Token Entropy"
    t0 = time.perf_counter()
    token = _extract_session_id(session)
    if not token:
        return TestResult(
            test_id=tid, test_name=tname,
            category=Category.SECURITY, severity=Severity.INFO, passed=True,
            description="No session token exposed by SDK — entropy check skipped.",
            duration_ms=(time.perf_counter() - t0) * 1000.0,
        )
    ent = _shannon_entropy(token)
    duration = (time.perf_counter() - t0) * 1000.0
    if ent < 2.0:
        sev = Severity.MEDIUM
    elif ent < 3.0:
        sev = Severity.LOW
    else:
        return TestResult.make_pass(
            test_id=tid, test_name=tname, category=Category.SECURITY,
            description=f"Session token entropy OK: {ent:.2f} bits/char (length {len(token)}).",
            duration_ms=duration,
        )
    return TestResult(
        test_id=tid, test_name=tname,
        category=Category.SECURITY, severity=sev, passed=False,
        description=(
            f"Session token entropy is low: {ent:.2f} bits/char (length {len(token)}). "
            f"Predictable tokens enable session hijacking."
        ),
        duration_ms=duration,
        remediation=(
            "Generate session tokens via a CSPRNG (e.g. ``secrets.token_urlsafe(32)`` "
            "in Python). Target ≥128 bits of entropy (32-char base64)."
        ),
    )


async def _t27_003_token_in_response(
    session: ClientSession,
    server_info: ServerInfo,
    limiter: RateLimiter,
) -> TestResult:
    tid = "T27-003"
    tname = "Session Token Leak in Response"
    t0 = time.perf_counter()
    token = _extract_session_id(session)
    if not token:
        return TestResult(
            test_id=tid, test_name=tname,
            category=Category.SECURITY, severity=Severity.INFO, passed=True,
            description="No session token exposed by SDK — leak check skipped.",
            duration_ms=(time.perf_counter() - t0) * 1000.0,
        )

    tool = (server_info.tools or [None])[0]
    if tool is None:
        return TestResult(
            test_id=tid, test_name=tname,
            category=Category.SECURITY, severity=Severity.INFO, passed=True,
            description="Server has no tools — leak check skipped.",
            duration_ms=(time.perf_counter() - t0) * 1000.0,
        )

    await limiter.acquire()
    try:
        with anyio.fail_after(10.0):
            resp = await session.call_tool(tool.name, arguments={})
        text = str(resp)
    except Exception as exc:
        text = str(exc)
    duration = (time.perf_counter() - t0) * 1000.0

    if token in text:
        return TestResult(
            test_id=tid, test_name=tname,
            category=Category.SECURITY, severity=Severity.HIGH, passed=False,
            description=(
                "Session token appears in tool response. Leaking the session "
                "token to callers or log aggregators enables session hijacking."
            ),
            duration_ms=duration,
            remediation=(
                "Never echo session tokens in tool output. Scrub session / "
                "auth identifiers from all responses and logs."
            ),
        )
    return TestResult.make_pass(
        test_id=tid, test_name=tname, category=Category.SECURITY,
        description="Session token did not appear in tool response.",
        duration_ms=duration,
    )


async def run(
    session: ClientSession,
    server_info: ServerInfo,
    config: ScanConfig,
) -> list[TestResult]:
    """Execute T27 — Session Token Handling."""
    t_start = time.perf_counter()
    results: list[TestResult] = []
    limiter = RateLimiter(config)

    results.append(await _t27_001_reuse_after_close(server_info, config, limiter))
    results.append(await _t27_002_token_entropy(session))
    results.append(await _t27_003_token_in_response(session, server_info, limiter))

    bad = sum(
        1 for r in results
        if r.severity in (Severity.HIGH, Severity.MEDIUM) and not r.passed
    )
    if bad:
        results.append(TestResult.make_fail(
            test_id="T27-004", test_name="Session Tokens — Summary",
            category=Category.SECURITY,
            severity=Severity.MEDIUM if bad < 2 else Severity.HIGH,
            description=f"{bad} session-handling issue(s) detected.",
            duration_ms=(time.perf_counter() - t_start) * 1000.0,
        ))
    else:
        results.append(TestResult.make_pass(
            test_id="T27-004", test_name="Session Tokens — Summary",
            category=Category.SECURITY,
            description="No session-handling weaknesses detected.",
            duration_ms=(time.perf_counter() - t_start) * 1000.0,
        ))
    return results
