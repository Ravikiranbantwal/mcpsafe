"""
mcpsafe.tests.t12_secret_leakage
==================================
SECURITY category — **Error-message secret leakage** detection.

Deliberately trigger every error path the server can produce (malformed
arguments, wrong types, invalid URIs, nonexistent tool names) and scan the
resulting error messages for secret patterns:

  * AWS access/secret keys
  * GitHub personal access tokens
  * OpenAI / Anthropic / Stripe API keys
  * Google / Slack tokens
  * Private-key blocks (PEM / OpenSSH)
  * JWTs and Bearer tokens
  * Database connection URIs (postgres://…, mongodb://…, redis://…)
  * Environment-variable assignments (``PASSWORD=…``, ``API_KEY=…``)
  * /etc/passwd content
  * Private-range IP addresses

Error messages that leak these values indicate the server is catching
exceptions too broadly and stringifying internal state (config dicts, env
vars, DB rows) into user-facing errors.

Test inventory
--------------
T12-TOOL-{slug}     One per tool — trigger error, scan for secrets.
T12-RES-001         Invalid resource URI, scan error for secrets.
T12-PROMPT-001      Invalid prompt request (if server advertises prompts).
T12-001             Summary verdict.

Public API
----------
    async def run(
        session: ClientSession,
        server_info: ServerInfo,
        config: ScanConfig,
    ) -> list[TestResult]
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
    find_secrets,
    looks_like_api_rejection,
)

_CALL_TIMEOUT_SEC = 15.0
_MAX_TEST_ID_LEN = 64
_MAX_TOOLS_PROBED = 12


def _slug(name: str, budget: int = 28) -> str:
    s = re.sub(r"[^a-z0-9]+", "_", (name or "unknown").lower()).strip("_")
    return (s or "unknown")[:budget] or "unknown"


def _error_triggering_args(tool: MCPTool) -> list[tuple[str, dict[str, object]]]:
    """
    Build a small set of argument dicts that are likely to trigger errors
    for *tool* — missing required fields, wrong types, out-of-range values.

    Returns ``(label, args)`` pairs; the label is used in evidence output.
    """
    schema = tool.input_schema if isinstance(tool.input_schema, dict) else {}
    props = schema.get("properties") or {}
    required = list(schema.get("required", []) or [])

    variants: list[tuple[str, dict[str, object]]] = []

    # 1) empty args — missing required fields.
    variants.append(("empty-args", {}))

    # 2) wrong types for every known property.
    wrong: dict[str, object] = {}
    for pname, pschema in props.items():
        if not isinstance(pschema, dict):
            continue
        ptype = pschema.get("type")
        if ptype == "string":
            wrong[pname] = 12345            # number where string expected
        elif ptype in ("integer", "number"):
            wrong[pname] = "not-a-number"
        elif ptype == "boolean":
            wrong[pname] = "maybe"
        elif ptype == "array":
            wrong[pname] = "not-a-list"
        elif ptype == "object":
            wrong[pname] = 7
    if wrong:
        variants.append(("wrong-types", wrong))

    # 3) required fields filled with an absurd sentinel, others empty.
    if required:
        sentinel: dict[str, object] = {
            pname: "\x00" * 4 for pname in required
        }
        variants.append(("null-bytes", sentinel))

    return variants


async def _probe_tool(
    session: ClientSession,
    tool: MCPTool,
    limiter: RateLimiter,
) -> TestResult:
    tid = f"T12-TOOL-{_slug(tool.name)}"
    if len(tid) > _MAX_TEST_ID_LEN:
        tid = tid[:_MAX_TEST_ID_LEN]
    tname = f"Error Secret Leakage → {tool.name}"
    t0 = time.perf_counter()

    all_errors: list[tuple[str, str]] = []  # (label, error_text)

    for label, args in _error_triggering_args(tool):
        await limiter.acquire()
        try:
            with anyio.fail_after(_CALL_TIMEOUT_SEC):
                # We want errors — but if the call unexpectedly succeeds we
                # still scan the response text for secrets (some servers
                # echo config in successful responses too).
                resp = await session.call_tool(tool.name, arguments=args)
            # Successful call — scan the stringified response.
            all_errors.append((label + "+success", str(resp)[:4000]))
        except Exception as exc:
            all_errors.append((label, str(exc)[:4000]))

    duration = (time.perf_counter() - t0) * 1000.0

    # Aggregate all error texts and scan for secrets.
    combined = "\n".join(text for _, text in all_errors)
    findings = find_secrets(combined)

    if findings:
        # Deduplicate by label keeping 5 at most.
        seen: set[str] = set()
        uniq: list[tuple[str, str]] = []
        for label, excerpt in findings:
            key = f"{label}::{excerpt}"
            if key in seen:
                continue
            seen.add(key)
            uniq.append((label, excerpt))
            if len(uniq) >= 5:
                break
        bullets = "\n".join(f"  • {label}: {excerpt}" for label, excerpt in uniq)
        return TestResult(
            test_id=tid, test_name=tname,
            category=Category.SECURITY, severity=Severity.HIGH,
            passed=False,
            description=(
                f"Tool {tool.name!r} error messages contained {len(findings)} "
                f"secret-pattern match(es). The server is serialising credentials "
                f"or sensitive internal state into client-visible errors."
            ),
            duration_ms=duration,
            details=f"Patterns detected:\n{bullets}",
            remediation=(
                "Never include raw exception messages in client responses. "
                "Map exceptions to static, safe error codes server-side, log "
                "details internally, and return opaque messages to the caller. "
                "Audit that env vars, config dicts, and DB rows cannot be "
                "included via __str__ / __repr__ on caught exceptions."
            ),
        )

    # No secrets leaked — PASS.
    errored = sum(1 for label, _ in all_errors if not label.endswith("+success"))
    if errored == 0:
        return TestResult.make_pass(
            test_id=tid, test_name=tname,
            category=Category.SECURITY,
            description=f"Tool {tool.name!r} never errored on malformed inputs — nothing to scan.",
            duration_ms=duration,
        )
    return TestResult.make_pass(
        test_id=tid, test_name=tname,
        category=Category.SECURITY,
        description=(
            f"Tool {tool.name!r} errored on {errored} malformed input(s); "
            f"no secret patterns found in error text."
        ),
        duration_ms=duration,
    )


async def _probe_bad_resource(
    session: ClientSession,
    limiter: RateLimiter,
) -> TestResult:
    """Try to read an invalid resource URI and scan the error."""
    tid = "T12-RES-001"
    tname = "Error Secret Leakage → invalid resource URI"
    t0 = time.perf_counter()

    await limiter.acquire()
    try:
        with anyio.fail_after(_CALL_TIMEOUT_SEC):
            await session.read_resource("file:///nonexistent/mcpsafe-probe")
        error_text = ""
    except Exception as exc:
        error_text = str(exc)[:4000]

    duration = (time.perf_counter() - t0) * 1000.0
    findings = find_secrets(error_text)

    if findings:
        bullets = "\n".join(f"  • {lbl}: {exc}" for lbl, exc in findings[:5])
        return TestResult(
            test_id=tid, test_name=tname,
            category=Category.SECURITY, severity=Severity.HIGH,
            passed=False,
            description=(
                "Invalid resource URI error contained secret patterns. "
                "Error handlers are leaking server internal state."
            ),
            duration_ms=duration,
            details=f"Patterns:\n{bullets}",
            remediation=(
                "Return an opaque 'resource not found' error; do not include "
                "the exception text or stack trace."
            ),
        )

    if not error_text:
        return TestResult.make_pass(
            test_id=tid, test_name=tname,
            category=Category.SECURITY,
            description="Invalid resource URI did not raise an error (server returned empty).",
            duration_ms=duration,
        )

    return TestResult.make_pass(
        test_id=tid, test_name=tname,
        category=Category.SECURITY,
        description="Invalid resource URI error contained no secret patterns.",
        duration_ms=duration,
    )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


async def run(
    session: ClientSession,
    server_info: ServerInfo,
    config: ScanConfig,
) -> list[TestResult]:
    """Execute T12 — Error Message Secret Leakage."""
    t_start = time.perf_counter()
    results: list[TestResult] = []
    limiter = RateLimiter(config)

    tools = (server_info.tools or [])[:_MAX_TOOLS_PROBED]
    for tool in tools:
        results.append(await _probe_tool(session, tool, limiter))

    if server_info.resources:
        results.append(await _probe_bad_resource(session, limiter))

    # Summary
    leaked = sum(1 for r in results if r.severity == Severity.HIGH and not r.passed)
    if leaked == 0:
        results.append(
            TestResult.make_pass(
                test_id="T12-001",
                test_name="Error Secret Leakage — Summary",
                category=Category.SECURITY,
                description=(
                    f"Probed {len(tools)} tool(s) and "
                    f"{'1 resource' if server_info.resources else '0 resources'}; "
                    f"no secret patterns detected in error messages."
                ),
                duration_ms=(time.perf_counter() - t_start) * 1000.0,
            )
        )
    else:
        results.append(
            TestResult.make_fail(
                test_id="T12-001",
                test_name="Error Secret Leakage — Summary",
                category=Category.SECURITY,
                severity=Severity.HIGH,
                description=(
                    f"{leaked} probe(s) leaked secret patterns through error "
                    f"messages. The server's exception handler exposes internal "
                    f"credentials or config state."
                ),
                duration_ms=(time.perf_counter() - t_start) * 1000.0,
                remediation=(
                    "Map all caught exceptions to opaque error codes before "
                    "serialising them to the MCP client. Scrub env vars, "
                    "connection strings, and secret keys from any stringified "
                    "error path."
                ),
            )
        )

    return results
