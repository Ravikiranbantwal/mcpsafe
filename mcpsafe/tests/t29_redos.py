"""
mcpsafe.tests.t29_redos
=========================
SECURITY category — **Regular Expression Denial of Service (ReDoS)**.

If a tool server runs a user-supplied string through a naive regex
with catastrophic backtracking (e.g. ``(a+)+$``, ``(.+)+$``), a modest
100-character input can hang the server for seconds to minutes.

This module sends inputs known to trigger worst-case exponential
backtracking in vulnerable engines (Python ``re``, Node.js V8,
Ruby, Java), then measures response time against a benign baseline.

Attack inputs
-------------
RD-001  Anchor pathological  ``aaaaaa…aaaa!`` (32 × 'a' + '!')
RD-002  Branch alternation   ``(a|aa)*X``-triggering input
RD-003  Nested quantifier    ``((ab)+)+c``-triggering input
RD-004  JS exponential email ``a@a.aaaaaa…aaaa!``
RD-005  Long repeat + mismatch  32-char alt pattern

Detection
---------
Benign-input baseline vs attack-input timing.  If attack input takes
≥5× longer AND ≥3 seconds absolute, flag HIGH (real ReDoS hang).
"""

from __future__ import annotations

import re
import time
from typing import Optional

import anyio
from mcp import ClientSession

from mcpsafe.models import (
    Category,
    MCPTool,
    ScanConfig,
    ServerInfo,
    Severity,
    TestResult,
)
from mcpsafe.tests._helpers import (
    RateLimiter,
    cap_response,
    looks_like_api_rejection,
)

_CALL_TIMEOUT_SEC = 8.0           # bounded; ReDoS is detected by ratio, not hit
_MAX_TEST_ID_LEN = 64
_MAX_TOOLS_PROBED = 4             # reduced from 6 to cap total module time
_REDOS_RATIO_THRESHOLD = 5.0
_REDOS_MIN_ABS_MS = 2000.0

_ATTACKS: tuple[tuple[str, str, str], ...] = (
    ("RD-001", "Anchor pathological",   "a" * 32 + "!"),
    ("RD-002", "Branch alternation",    "a" * 28 + "X"),
    ("RD-003", "Nested quantifier",     "ababababababababababab" + "d"),
    ("RD-004", "Exponential email",     "a@a." + "a" * 25 + "!"),
    ("RD-005", "Long repeat mismatch",  ("ab" * 15) + "c"),
)

_LONG_RUNNING_KW = frozenset({
    "long_running", "long-running", "trigger_long", "trigger-long",
    "sleep", "wait", "delay",
})


def _is_long_running(n: str) -> bool:
    return any(kw in (n or "").lower() for kw in _LONG_RUNNING_KW)


def _slug(name: str, budget: int = 20) -> str:
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


async def _timed(
    session: ClientSession,
    tool_name: str,
    args: dict,
) -> tuple[float, Optional[str]]:
    t0 = time.perf_counter()
    try:
        with anyio.fail_after(_CALL_TIMEOUT_SEC):
            await session.call_tool(tool_name, arguments=args)
        return (time.perf_counter() - t0) * 1000.0, None
    except Exception as exc:
        return (time.perf_counter() - t0) * 1000.0, str(exc)


async def _probe(
    session: ClientSession,
    tool: MCPTool,
    pname: str,
    limiter: RateLimiter,
) -> list[TestResult]:
    results: list[TestResult] = []

    await limiter.acquire()
    baseline_ms, baseline_err = await _timed(session, tool.name, {pname: "hello"})

    for rid, label, payload in _ATTACKS:
        tid = f"T29-TOOL-{_slug(tool.name)}-{rid}"
        if len(tid) > _MAX_TEST_ID_LEN:
            tid = tid[:_MAX_TEST_ID_LEN]
        tname = f"ReDoS {rid} → {tool.name}"

        await limiter.acquire()
        attack_ms, attack_err = await _timed(session, tool.name, {pname: payload})
        ratio = (attack_ms / baseline_ms) if baseline_ms > 1 else 0.0
        delta = attack_ms - baseline_ms

        if (attack_err and "timeout" in attack_err.lower()) or attack_ms >= (_CALL_TIMEOUT_SEC * 1000 - 200):
            results.append(TestResult(
                test_id=tid, test_name=tname,
                category=Category.SECURITY, severity=Severity.HIGH, passed=False,
                description=(
                    f"Tool {tool.name!r} hit the {int(_CALL_TIMEOUT_SEC)}s client "
                    f"timeout when given the {label} pattern — confirmed ReDoS."
                ),
                duration_ms=attack_ms,
                details=f"Payload length: {len(payload)} chars",
                remediation=(
                    "Replace backtracking regex engine with RE2 (linear-time). "
                    "If RE2 is not an option, manually audit the regex for "
                    "nested quantifiers, ambiguous alternations, and catastrophic "
                    "backtracking patterns."
                ),
            ))
            continue

        if (ratio >= _REDOS_RATIO_THRESHOLD
                and delta >= _REDOS_MIN_ABS_MS
                and attack_err is None):
            results.append(TestResult(
                test_id=tid, test_name=tname,
                category=Category.SECURITY, severity=Severity.MEDIUM, passed=False,
                description=(
                    f"Tool {tool.name!r} shows regex backtracking signature on "
                    f"{label}: {attack_ms:.0f}ms vs {baseline_ms:.0f}ms baseline "
                    f"(ratio {ratio:.1f}×, delta {delta:.0f}ms)."
                ),
                duration_ms=attack_ms,
                details=f"Payload ({len(payload)}c): {payload[:80]!r}",
            ))
            continue

        results.append(TestResult.make_pass(
            test_id=tid, test_name=tname, category=Category.SECURITY,
            description=(
                f"No ReDoS signature: baseline {baseline_ms:.0f}ms, "
                f"attack {attack_ms:.0f}ms, ratio {ratio:.1f}×."
            ),
            duration_ms=attack_ms,
        ))

    return results


async def run(
    session: ClientSession,
    server_info: ServerInfo,
    config: ScanConfig,
) -> list[TestResult]:
    """Execute T29 — Regex DoS."""
    t_start = time.perf_counter()
    results: list[TestResult] = []
    limiter = RateLimiter(config)

    candidates = [
        t for t in (server_info.tools or [])
        if not _is_long_running(t.name) and _first_string_param(t)
    ][:_MAX_TOOLS_PROBED]

    for tool in candidates:
        pname = _first_string_param(tool) or ""
        results.extend(await _probe(session, tool, pname, limiter))

    bad = sum(
        1 for r in results
        if r.severity in (Severity.HIGH, Severity.MEDIUM) and not r.passed
    )
    if bad:
        results.append(TestResult.make_fail(
            test_id="T29-001", test_name="ReDoS — Summary",
            category=Category.SECURITY, severity=Severity.MEDIUM,
            description=f"{bad} ReDoS signature(s) across probed tools.",
            duration_ms=(time.perf_counter() - t_start) * 1000.0,
        ))
    else:
        results.append(TestResult.make_pass(
            test_id="T29-001", test_name="ReDoS — Summary",
            category=Category.SECURITY,
            description=f"No ReDoS signatures across {len(candidates)} probed tool(s).",
            duration_ms=(time.perf_counter() - t_start) * 1000.0,
        ))
    return results
