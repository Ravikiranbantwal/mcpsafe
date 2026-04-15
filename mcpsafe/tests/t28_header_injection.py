"""
mcpsafe.tests.t28_header_injection
====================================
SECURITY category — **CRLF / header injection and request-smuggling probes**.

HTTP transport only.  If tool arguments end up reflected in server
response headers (for example in an error message), CRLF injection
lets an attacker inject arbitrary headers — enabling cache poisoning,
XSS via custom headers, or HTTP request smuggling.

Approach
--------
We cannot inspect the server's RAW HTTP response from inside the MCP
client (the SDK only exposes the parsed MCP response).  So this module
does a best-effort check:

1. Send a payload containing distinctive CRLF + injected-header
   markers.
2. Re-call a ``list_tools`` / ``list_resources`` to see if the server
   returned garbled data (would mean smuggling succeeded).
3. Scan any error message for the raw ``\\r\\n`` sequence being echoed
   — a weaker signal but still worth flagging.

Payloads
--------
HDR-001  Classic CRLF + header    ``safe\\r\\nX-MCPSafe-Injected: yes``
HDR-002  URL-encoded CRLF         ``safe%0d%0aX-MCPSafe-Injected:%20yes``
HDR-003  Double-encoded CRLF      ``safe%250d%250aX-MCPSafe-Injected:%20yes``
HDR-004  Content-Length smuggling ``safe\\r\\nContent-Length: 0\\r\\n\\r\\nGET /admin HTTP/1.1\\r\\n``
HDR-005  Unicode newline          ``safe\\u000d\\u000aX-Injected: yes``
"""

from __future__ import annotations

import re
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
    TransportType,
)
from mcpsafe.tests._helpers import (
    RateLimiter,
    cap_response,
)

_CALL_TIMEOUT_SEC = 10.0
_MAX_TEST_ID_LEN = 64
_MAX_TOOLS_PROBED = 4

_PAYLOADS: tuple[tuple[str, str, str], ...] = (
    ("HDR-001", "Classic CRLF + header",    "safe\r\nX-MCPSafe-Injected: yes"),
    ("HDR-002", "URL-encoded CRLF",         "safe%0d%0aX-MCPSafe-Injected:%20yes"),
    ("HDR-003", "Double-encoded CRLF",      "safe%250d%250aX-MCPSafe-Injected:%20yes"),
    ("HDR-004", "Content-Length smuggling", "safe\r\nContent-Length: 0\r\n\r\nGET /admin HTTP/1.1\r\n"),
    ("HDR-005", "Unicode newline",          "safe\u000d\u000aX-Injected: yes"),
)


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


async def _probe(
    session: ClientSession,
    tool: MCPTool,
    pname: str,
    pid: str,
    label: str,
    payload: str,
    limiter: RateLimiter,
) -> TestResult:
    tid = f"T28-TOOL-{_slug(tool.name)}-{pid}"
    if len(tid) > _MAX_TEST_ID_LEN:
        tid = tid[:_MAX_TEST_ID_LEN]
    tname = f"Header Injection {pid} → {tool.name}"
    t0 = time.perf_counter()

    await limiter.acquire()
    text = ""
    err = ""
    try:
        with anyio.fail_after(_CALL_TIMEOUT_SEC):
            resp = await session.call_tool(tool.name, arguments={pname: payload})
        text = _extract_text(resp)
    except Exception as exc:
        err = str(exc)
    duration = (time.perf_counter() - t0) * 1000.0

    combined = f"{text}\n{err}"

    # Strong signal: our distinctive injected-header name survives payload
    # echoes AND appears near CRLF bytes in the response/error.
    marker = "X-MCPSafe-Injected"
    marker_url = "X-Injected"

    cleaned = combined.replace(payload, "[PAYLOAD]")
    # Also strip JSON-escaped variant (\r → \\r, \n → \\n) because servers
    # commonly echo the payload through a JSON encoder in their response body
    # (e.g. Stripe returns the product name inside a JSON string literal,
    # which turns the real CRLF bytes into the two-char sequence ``\r\n``).
    # Without this the marker "survives" payload-stripping even though the
    # marker is still inside an echoed JSON string value, not an HTTP header.
    payload_json_escaped = (
        payload.replace("\\", "\\\\").replace("\r", "\\r").replace("\n", "\\n")
    )
    if payload_json_escaped != payload:
        cleaned = cleaned.replace(payload_json_escaped, "[PAYLOAD]")

    if marker in cleaned or marker_url in cleaned:
        # Secondary FP guard: if the marker appears *inside* a JSON string
        # literal (i.e. bracketed by ``"`` on both sides within a small
        # window), it is almost certainly being echoed as a field value —
        # not placed into an HTTP header slot.
        idx = cleaned.find(marker) if marker in cleaned else cleaned.find(marker_url)
        window = cleaned[max(0, idx - 40): idx + 80]
        # Look for a quote *before* the marker within the window and
        # another quote or close-brace *after* the marker + line-break.
        before = cleaned[max(0, idx - 40): idx]
        after = cleaned[idx: min(len(cleaned), idx + 80)]
        in_json_value = ('"' in before[-20:]) and ('"' in after[:40])
        if in_json_value:
            return TestResult.make_pass(
                test_id=tid, test_name=tname, category=Category.SECURITY,
                description=(
                    f"Marker echoed inside a JSON string value on "
                    f"{tool.name!r} — likely a stored-field reflection, not "
                    f"actual HTTP header injection."
                ),
                duration_ms=duration,
                details=f"Payload: {payload!r}\nExcerpt: {window!r}",
            )
        # Header-name survived payload stripping AND isn't in a JSON value
        # → server is reflecting our header name into some downstream output,
        # likely a real injection.
        excerpt = window.replace("\n", " ")
        return TestResult(
            test_id=tid, test_name=tname,
            category=Category.SECURITY, severity=Severity.HIGH, passed=False,
            description=(
                f"CRLF / header injection suspected on {tool.name!r}: our "
                f"injected header name appears in response AFTER literal payload "
                f"was stripped — suggests the server decoded the CRLF and "
                f"placed our injected header somewhere downstream."
            ),
            duration_ms=duration,
            details=f"Payload: {payload!r}\nExcerpt: {excerpt!r}",
            remediation=(
                "Reject ``\\r``, ``\\n``, and their URL/Unicode encodings in any "
                "argument that can influence response headers or outbound HTTP "
                "calls. Use a whitelist of allowed characters rather than a "
                "blacklist — encoding tricks will always find a way through."
            ),
        )

    return TestResult.make_pass(
        test_id=tid, test_name=tname, category=Category.SECURITY,
        description=f"No CRLF reflection detected for {label} on {tool.name!r}.",
        duration_ms=duration,
    )


async def run(
    session: ClientSession,
    server_info: ServerInfo,
    config: ScanConfig,
) -> list[TestResult]:
    """Execute T28 — CRLF / Header Injection."""
    t_start = time.perf_counter()
    results: list[TestResult] = []

    # HTTP/SSE only — no raw headers on stdio.
    if config.transport == TransportType.STDIO:
        results.append(TestResult(
            test_id="T28-001", test_name="Header Injection — Summary",
            category=Category.SECURITY, severity=Severity.INFO, passed=True,
            description="STDIO transport has no HTTP headers — CRLF/header injection probe skipped.",
            duration_ms=(time.perf_counter() - t_start) * 1000.0,
        ))
        return results

    limiter = RateLimiter(config)
    candidates = [
        t for t in (server_info.tools or []) if _first_string_param(t)
    ][:_MAX_TOOLS_PROBED]

    for tool in candidates:
        pname = _first_string_param(tool) or ""
        for pid, label, payload in _PAYLOADS:
            results.append(await _probe(session, tool, pname, pid, label, payload, limiter))

    bad = sum(1 for r in results if r.severity == Severity.HIGH and not r.passed)
    if bad:
        results.append(TestResult.make_fail(
            test_id="T28-001", test_name="Header Injection — Summary",
            category=Category.SECURITY, severity=Severity.HIGH,
            description=f"{bad} header-injection finding(s).",
            duration_ms=(time.perf_counter() - t_start) * 1000.0,
        ))
    else:
        results.append(TestResult.make_pass(
            test_id="T28-001", test_name="Header Injection — Summary",
            category=Category.SECURITY,
            description=f"No CRLF/header-injection findings across {len(candidates)} probed tool(s).",
            duration_ms=(time.perf_counter() - t_start) * 1000.0,
        ))
    return results
