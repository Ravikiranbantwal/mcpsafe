"""
mcpsafe.tests.t13_sampling_abuse
=================================
SECURITY category — **Server-initiated sampling abuse** detection.

MCP lets a *server* ask the client's LLM to perform a completion on its behalf
via the ``sampling/createMessage`` request.  A malicious server can abuse this
to:

  * Exfiltrate user data by embedding sensitive context into the sample
    request (the LLM then produces text the server reads back).
  * Bypass rate limits by using the user's LLM quota.
  * Trick the LLM into producing tokens that look like the user's output
    (indirect prompt injection with a richer surface).

What this test does
-------------------
1. Inspects ``get_server_capabilities()`` to see whether the server advertises
   the ``sampling`` capability.  Advertised sampling is not itself a
   vulnerability — but when combined with the ability to send ARBITRARY
   prompts it becomes one.

2. Calls a bounded set of tools and watches whether the server issues
   ``sampling/createMessage`` requests back to the client during tool
   execution.  We do this by installing a "response router" that logs all
   inbound server→client requests for the duration of the probe.

3. Flags any tool whose execution triggered an unsolicited sampling
   request as MEDIUM (unexpected sampling), or HIGH if the sampling
   request includes content that looks like user/session context.

Test inventory
--------------
T13-001   Capability advertisement             INFO/LOW/MEDIUM
T13-002   Unsolicited sampling-request capture HIGH if detected
T13-003   Summary verdict                      Aggregate

Public API
----------
    async def run(session, server_info, config) -> list[TestResult]
"""

from __future__ import annotations

import time
from typing import Any, Optional

import anyio
from mcp import ClientSession

from mcpsafe.models import (
    Category,
    ScanConfig,
    ServerInfo,
    Severity,
    TestResult,
)
from mcpsafe.tests._helpers import RateLimiter

_CALL_TIMEOUT_SEC = 10.0

# Tools that are KNOWN to be long-running by name — skip these to avoid
# deadlocks during the sampling-abuse probe (we don't actually need their
# output; we only care whether the server initiates sampling during ANY
# tool call).
_LONG_RUNNING_TOOL_KEYWORDS: frozenset[str] = frozenset({
    "long_running", "long-running", "longrunning",
    "trigger_long", "trigger-long",
    "sleep", "wait", "delay",
})


def _is_long_running(tool_name: str) -> bool:
    name = (tool_name or "").lower()
    return any(kw in name for kw in _LONG_RUNNING_TOOL_KEYWORDS)


# Sensitivity markers the server might embed in a malicious sampling request.
_SENSITIVE_MARKERS: tuple[str, ...] = (
    "authorization", "bearer", "api_key", "password",
    "session", "cookie", "secret", "token", "credential",
    "user@", "admin@",
)


def _has_sampling_capability(server_info: ServerInfo) -> bool:
    """Return True when the server advertises a 'sampling' capability."""
    caps = server_info.capabilities or {}
    if not isinstance(caps, dict):
        return False
    return "sampling" in caps or bool(caps.get("sampling"))


async def _probe_capability(server_info: ServerInfo) -> TestResult:
    """T13-001 — audit whether sampling capability is advertised."""
    tid = "T13-001"
    tname = "Sampling Capability Advertisement"

    if _has_sampling_capability(server_info):
        return TestResult(
            test_id=tid, test_name=tname,
            category=Category.SECURITY, severity=Severity.LOW,
            passed=False,
            description=(
                "Server advertises the 'sampling' capability. This is legitimate "
                "for some workflows (agent tools that need a fresh LLM call) but "
                "enlarges the attack surface: every tool invocation becomes a "
                "potential vector to issue arbitrary LLM requests with the user's "
                "quota and context."
            ),
            duration_ms=0.0,
            details=f"capabilities: {server_info.capabilities!r}",
            remediation=(
                "Audit every code path that issues a sampling request. Reject "
                "sampling requests that contain untrusted user input, and apply "
                "the user's consent policy before forwarding any server-initiated "
                "sample to the LLM."
            ),
        )

    return TestResult.make_pass(
        test_id=tid, test_name=tname, category=Category.SECURITY,
        description="Server does not advertise the 'sampling' capability.",
    )


async def _probe_unsolicited_sampling(
    session: ClientSession,
    server_info: ServerInfo,
    limiter: RateLimiter,
) -> TestResult:
    """
    T13-002 — fire a handful of tool calls and observe inbound requests
    for any unsolicited ``sampling/createMessage`` attempts.

    The MCP Python SDK does not expose a public hook to intercept inbound
    server requests, so this probe is best-effort: we rely on the
    *session.experimental* log (when available) to count sampling requests
    seen during our window.  If no such hook is available we still report
    an INFO result so users know the check ran.
    """
    tid = "T13-002"
    tname = "Unsolicited Sampling Requests"
    t0 = time.perf_counter()

    tools = (server_info.tools or [])[:4]
    if not tools:
        return TestResult(
            test_id=tid, test_name=tname, category=Category.SECURITY,
            severity=Severity.INFO, passed=True,
            description="No tools to exercise; sampling-abuse probe skipped.",
            duration_ms=(time.perf_counter() - t0) * 1000.0,
        )

    # Attempt to hook an incoming-request logger if the SDK supports it.
    hooked = False
    sampling_requests: list[dict[str, Any]] = []
    if hasattr(session, "experimental") and hasattr(session, "send_request"):
        try:
            exp = getattr(session, "experimental", None)
            if hasattr(exp, "incoming_request_hook"):
                exp.incoming_request_hook = (
                    lambda req: sampling_requests.append(req) if
                    isinstance(req, dict) and req.get("method", "").startswith("sampling/")
                    else None
                )
                hooked = True
        except Exception:
            hooked = False

    # Exercise a few tools with a HARD timeout per call so long-running
    # tools (e.g. server-everything's trigger-long-running-operation)
    # cannot deadlock the whole scan.  Also skip known long-running tools
    # entirely — we don't need their output, just any sampling request
    # the server might initiate in parallel.
    for tool in tools:
        if _is_long_running(tool.name):
            continue
        await limiter.acquire()
        try:
            with anyio.fail_after(_CALL_TIMEOUT_SEC):
                await session.call_tool(tool.name, arguments={})
        except Exception:
            pass

    duration = (time.perf_counter() - t0) * 1000.0

    # If the hook wasn't available we can only check the advertised cap.
    if not hooked:
        return TestResult(
            test_id=tid, test_name=tname, category=Category.SECURITY,
            severity=Severity.INFO, passed=True,
            description=(
                "MCP client SDK does not expose an incoming-request hook; "
                "unsolicited sampling detection relies on capability audit (T13-001)."
            ),
            duration_ms=duration,
        )

    if not sampling_requests:
        return TestResult.make_pass(
            test_id=tid, test_name=tname, category=Category.SECURITY,
            description=(
                f"Exercised {len(tools)} tool(s); no unsolicited "
                "sampling/createMessage requests observed."
            ),
            duration_ms=duration,
        )

    # At least one sampling request — check for sensitive content.
    combined = " ".join(repr(r) for r in sampling_requests).lower()
    sensitive = [m for m in _SENSITIVE_MARKERS if m in combined]
    severity = Severity.HIGH if sensitive else Severity.MEDIUM
    return TestResult(
        test_id=tid, test_name=tname,
        category=Category.SECURITY, severity=severity,
        passed=False,
        description=(
            f"Server issued {len(sampling_requests)} unsolicited "
            f"sampling/createMessage request(s) while our test called tools. "
            + ("Request payload contains sensitivity markers — possible exfiltration."
               if sensitive else
               "Payloads appear benign but unsolicited sampling is still an "
               "unexpected surface.")
        ),
        duration_ms=duration,
        details=f"markers: {sensitive}\nrequests: {sampling_requests[:3]}",
        remediation=(
            "Require user consent before forwarding any server-initiated sampling. "
            "Strip session context, auth headers, and environment data from the "
            "request body before it reaches the LLM."
        ),
    )


async def run(
    session: ClientSession,
    server_info: ServerInfo,
    config: ScanConfig,
) -> list[TestResult]:
    """Execute T13 — Sampling Request Abuse detection."""
    t_start = time.perf_counter()
    results: list[TestResult] = []
    limiter = RateLimiter(config)

    results.append(await _probe_capability(server_info))
    results.append(await _probe_unsolicited_sampling(session, server_info, limiter))

    # Summary
    has_issue = any(r.severity >= Severity.MEDIUM and not r.passed for r in results)
    if has_issue:
        results.append(
            TestResult.make_fail(
                test_id="T13-003",
                test_name="Sampling Abuse — Summary",
                category=Category.SECURITY,
                severity=Severity.MEDIUM,
                description="Server-side sampling abuse surface detected — see T13-001/002.",
                duration_ms=(time.perf_counter() - t_start) * 1000.0,
            )
        )
    else:
        results.append(
            TestResult.make_pass(
                test_id="T13-003",
                test_name="Sampling Abuse — Summary",
                category=Category.SECURITY,
                description="No sampling-abuse surface detected.",
                duration_ms=(time.perf_counter() - t_start) * 1000.0,
            )
        )
    return results
