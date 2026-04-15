"""
mcpsafe.tests.t22_command_injection
=====================================
SECURITY category — **Shell command injection** via tool arguments.

Many MCP servers pass tool arguments to a shell or subprocess — git,
filesystem, fetch, sqlite server often shell out.  If the tool does not
properly quote its arguments, shell metacharacters in the argument value
become executable commands.

Attack payloads inject a CANARY string via common shell-injection
primitives and then look for that canary in the response.  The canary
is a 16-char random token that has zero probability of appearing by
chance, so any echo of it proves command execution.

Payload primitives
------------------
CI-001  Semicolon chain             ``safe; echo CANARY``
CI-002  Pipe                        ``safe | echo CANARY``
CI-003  Background ampersand        ``safe & echo CANARY``
CI-004  Logical AND                 ``safe && echo CANARY``
CI-005  Logical OR                  ``safe || echo CANARY``
CI-006  Command substitution $()    ``$(echo CANARY)``
CI-007  Backtick command sub        ``\`echo CANARY\```
CI-008  Newline injection           ``safe\\necho CANARY``
CI-009  Null byte + chain           ``safe\\x00; echo CANARY``
CI-010  Windows cmd chain           ``safe & echo CANARY``

Detection
---------
After stripping the payload (including the canary that was injected)
from the response, look for the canary text remaining — which proves
the shell evaluated the substitution rather than echoed it.

Test inventory
--------------
T22-TOOL-{slug}-CI-###
T22-001   Summary
"""

from __future__ import annotations

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
from mcpsafe.tests._helpers import (
    RateLimiter,
    cap_response,
    looks_like_api_rejection,
)

_CALL_TIMEOUT_SEC = 6.0
_MAX_TEST_ID_LEN = 64
_MAX_TOOLS_PROBED = 4


def _primitives() -> list[tuple[str, str, str]]:
    """
    Return (payload_id, label, payload-template) list. Caller substitutes CANARY.

    Note: CI-008 (newline injection) and CI-009 (NUL + chain) were removed
    because servers commonly echo these payloads back JSON-escaped
    (``\\n`` → ``\\\\n``, ``\\x00`` → ``\\\\x00``), which defeats literal
    payload-stripping and produces noisy canary detections. The remaining
    eight primitives survive echo detection reliably.
    """
    return [
        ("CI-001", "Semicolon chain",         "safe; echo {CANARY}"),
        ("CI-002", "Pipe",                    "safe | echo {CANARY}"),
        ("CI-003", "Background ampersand",    "safe & echo {CANARY}"),
        ("CI-004", "Logical AND",             "safe && echo {CANARY}"),
        ("CI-005", "Logical OR",              "safe || echo {CANARY}"),
        ("CI-006", "Command substitution $()","$(echo {CANARY})"),
        ("CI-007", "Backtick cmdsub",         "`echo {CANARY}`"),
        ("CI-010", "Windows cmd chain",       "safe & echo {CANARY}"),
    ]


def _slug(name: str, budget: int = 20) -> str:
    s = re.sub(r"[^a-z0-9]+", "_", (name or "unknown").lower()).strip("_")
    return (s or "unknown")[:budget] or "unknown"


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


_LONG_RUNNING_KW = frozenset({
    "long_running", "long-running", "trigger_long", "trigger-long",
    "sleep", "wait", "delay",
})


def _is_long_running(tool_name: str) -> bool:
    n = (tool_name or "").lower()
    return any(kw in n for kw in _LONG_RUNNING_KW)


async def _probe(
    session: ClientSession,
    tool: MCPTool,
    pname: str,
    pid: str,
    label: str,
    payload_tmpl: str,
    limiter: RateLimiter,
) -> TestResult:
    tid = f"T22-TOOL-{_slug(tool.name)}-{pid}"
    if len(tid) > _MAX_TEST_ID_LEN:
        tid = tid[:_MAX_TEST_ID_LEN]
    tname = f"Command Injection {pid} → {tool.name}"
    t0 = time.perf_counter()

    # Fresh canary per call so echoes don't cross-contaminate.
    canary = f"MCPSAFE{secrets.token_hex(6).upper()}"
    payload = payload_tmpl.replace("{CANARY}", canary)

    await limiter.acquire()
    try:
        with anyio.fail_after(_CALL_TIMEOUT_SEC):
            resp = await session.call_tool(tool.name, arguments={pname: payload})
        text = _extract_text(resp)
        duration = (time.perf_counter() - t0) * 1000.0

        # Strip the literal payload (including canary) — any REMAINING copy
        # of the canary proves the shell executed the echo.
        cleaned = text.replace(payload, "[PAYLOAD]")
        cleaned = cleaned.replace(payload.strip(), "[PAYLOAD]")
        # Also strip a quoted echo if the server wrapped the arg.
        cleaned = cleaned.replace(f'"{payload}"', "[PAYLOAD]")
        cleaned = cleaned.replace(f"'{payload}'", "[PAYLOAD]")
        # Strip variants where the server re-encoded shell metacharacters
        # before echoing — e.g. Stripe JSON-encodes ``&`` as ``\u0026`` so
        # the literal payload bytes differ from what survived the transport.
        encoded_payload = (
            payload
            .replace("&", "\\u0026")
            .replace("<", "\\u003c")
            .replace(">", "\\u003e")
        )
        if encoded_payload != payload:
            cleaned = cleaned.replace(encoded_payload, "[PAYLOAD]")

        # Second-order FP guard: if the canary is immediately preceded by
        # the literal string ``echo `` (within a few chars, possibly with
        # hyphens / quotes in place of stripped metacharacters), then what
        # we are seeing is still a modified echo of our payload, not shell
        # execution. A genuine RCE emits the canary as the OUTPUT of
        # ``echo``, which is bare text — the word "echo" never appears.
        looks_like_echo_of_payload = False
        if canary in cleaned:
            idx = cleaned.find(canary)
            window_start = max(0, idx - 30)
            window = cleaned[window_start: idx]
            # Match ``echo`` possibly followed by whitespace, hyphens,
            # quotes, or other filler introduced by name-sanitisers.
            if re.search(r"echo[\s\-'\"`_]*$", window, re.IGNORECASE):
                looks_like_echo_of_payload = True

        if canary in cleaned and not looks_like_echo_of_payload:
            idx = cleaned.find(canary)
            excerpt = cleaned[max(0, idx - 40): idx + len(canary) + 40]
            return TestResult(
                test_id=tid, test_name=tname,
                category=Category.SECURITY, severity=Severity.CRITICAL,
                passed=False,
                description=(
                    f"Tool {tool.name!r} executed shell command substitution: "
                    f"our injected canary string {canary!r} survived in the "
                    f"response AFTER the literal payload was stripped, proving "
                    f"the shell evaluated our echo rather than passing the arg "
                    f"as a string."
                ),
                duration_ms=duration,
                details=(
                    f"Primitive: {label}\n"
                    f"Payload: {payload!r}\n"
                    f"Canary: {canary}\n"
                    f"Response excerpt (post-strip): {excerpt!r}"
                ),
                remediation=(
                    "Never pass user-controlled strings through a shell. Use "
                    "``subprocess.run([...], shell=False)`` with the command "
                    "arguments as a list. If a shell is unavoidable, quote "
                    "with ``shlex.quote()`` and apply strict allow-list "
                    "validation on the input."
                ),
            )
        return TestResult.make_pass(
            test_id=tid, test_name=tname, category=Category.SECURITY,
            description=f"Tool {tool.name!r} safely handled {label}.",
            duration_ms=duration,
        )
    except Exception as exc:
        duration = (time.perf_counter() - t0) * 1000.0
        err = str(exc)
        if looks_like_api_rejection([err]):
            return TestResult(
                test_id=tid, test_name=tname,
                category=Category.SECURITY, severity=Severity.INFO, passed=True,
                description=f"Tool {tool.name!r} rejected {label} at the API layer.",
                duration_ms=duration, details=err[:200],
            )
        return TestResult.make_pass(
            test_id=tid, test_name=tname, category=Category.SECURITY,
            description=f"Tool {tool.name!r} errored on {label} without shell execution.",
            duration_ms=duration, details=err[:200],
        )


async def run(
    session: ClientSession,
    server_info: ServerInfo,
    config: ScanConfig,
) -> list[TestResult]:
    """Execute T22 — Shell Command Injection."""
    t_start = time.perf_counter()
    results: list[TestResult] = []
    limiter = RateLimiter(config)

    candidates = [
        t for t in (server_info.tools or [])
        if not _is_long_running(t.name) and _first_string_param(t)
    ][:_MAX_TOOLS_PROBED]

    for tool in candidates:
        pname = _first_string_param(tool) or ""
        for pid, label, payload_tmpl in _primitives():
            results.append(
                await _probe(session, tool, pname, pid, label, payload_tmpl, limiter)
            )

    crit = sum(1 for r in results if r.severity == Severity.CRITICAL and not r.passed)
    total = len(results)
    if crit:
        results.append(
            TestResult.make_fail(
                test_id="T22-001", test_name="Command Injection — Summary",
                category=Category.SECURITY, severity=Severity.CRITICAL,
                description=f"{crit} confirmed shell command injection(s) across {total} probes.",
                duration_ms=(time.perf_counter() - t_start) * 1000.0,
                remediation="See individual T22-TOOL-* findings.",
            )
        )
    else:
        results.append(
            TestResult.make_pass(
                test_id="T22-001", test_name="Command Injection — Summary",
                category=Category.SECURITY,
                description=f"{total} probe(s) sent, no shell execution confirmed.",
                duration_ms=(time.perf_counter() - t_start) * 1000.0,
            )
        )
    return results
