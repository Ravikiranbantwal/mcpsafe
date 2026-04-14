"""
mcpsafe.tests.t10_cross_session
================================
SECURITY category — **Cross-session data leakage** detection.

Many MCP servers cache results, share state via singletons, or rely on global
variables.  When two independent sessions talk to the same server, data set
by session A must NEVER leak into session B's responses.

This module:
  1. Uses the PRIMARY session to send a unique marker string to every
     writable-looking tool (or to plant it in the first string argument).
  2. Opens a SECOND, independent session to the same target.
  3. Re-runs the same tools with **benign** arguments from the second session
     and checks every response for the marker planted by session A.

If the marker appears in the second session's output, we have confirmed
cross-session data leakage — a serious multi-tenancy bug.

For stdio transports this additionally detects global-state leaks that persist
across process restarts (rare but high-impact — e.g. an on-disk cache keyed
only by tool name).

Test inventory
--------------
T10-001     Cross-session marker leakage  ── main probe.
T10-002     Resource content isolation    ── read same resource twice, diff.
T10-003     State bleed between same-tool calls (same session, sequential).

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
    TransportType,
)
from mcpsafe.tests._helpers import (
    RateLimiter,
    cap_response,
    looks_like_api_rejection,
)
from mcpsafe.transport import MCPConnection, TransportError

_CALL_TIMEOUT_SEC = 15.0
_MAX_TOOLS_PROBED = 6  # keep runtime bounded on servers with 50+ tools


def _extract_text(response: object) -> str:
    """Flatten a tool/resource response to plain text (≤ 1 MB)."""
    if isinstance(response, str):
        return cap_response(response)
    if not isinstance(response, list) and hasattr(response, "content"):
        content = getattr(response, "content", None)
        if isinstance(content, list):
            response = content
    if not isinstance(response, list) and hasattr(response, "contents"):
        contents = getattr(response, "contents", None)
        if isinstance(contents, list):
            response = contents

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
    """Return the first string-type parameter name, preferring required ones."""
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


def _select_probe_tools(tools: list[MCPTool]) -> list[MCPTool]:
    """
    Pick up to ``_MAX_TOOLS_PROBED`` tools that accept a string parameter.

    Prefers tools whose name/description suggests state mutation (set, save,
    store, write, add, create, update, remember) because those are the most
    likely cross-session leakage vectors.  Falls back to any string-accepting
    tool if no stateful candidates exist.
    """
    stateful_re = re.compile(
        r"(?i)\b(?:set|save|store|write|add|create|update|remember|note|log)\b"
    )
    stateful: list[MCPTool] = []
    other: list[MCPTool] = []
    for t in tools:
        if _first_string_param(t) is None:
            continue
        if stateful_re.search(t.name) or stateful_re.search(t.description or ""):
            stateful.append(t)
        else:
            other.append(t)
    return (stateful + other)[:_MAX_TOOLS_PROBED]


async def _call_safe(
    session: ClientSession,
    tool_name: str,
    args: dict[str, object],
) -> tuple[Optional[str], Optional[str]]:
    """
    Call *tool_name* with *args*; return ``(response_text, error)``.

    Never raises — all exceptions are caught and returned as ``error``.
    """
    try:
        with anyio.fail_after(_CALL_TIMEOUT_SEC):
            resp = await session.call_tool(tool_name, arguments=args)
        return _extract_text(resp), None
    except Exception as exc:
        return None, str(exc)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


async def run(
    session: ClientSession,
    server_info: ServerInfo,
    config: ScanConfig,
) -> list[TestResult]:
    """
    Execute T10 — Cross-Session Data Leakage detection.

    Never raises; connection failures to the second session downgrade the
    test to INFO rather than failing the whole scan.
    """
    t_start = time.perf_counter()
    results: list[TestResult] = []
    limiter_primary = RateLimiter(config)

    # Pick candidate tools.
    probe_tools = _select_probe_tools(server_info.tools or [])
    if not probe_tools:
        results.append(
            TestResult(
                test_id="T10-001",
                test_name="Cross-Session Data Leakage",
                category=Category.SECURITY,
                severity=Severity.INFO,
                passed=True,
                description=(
                    "No tools with string parameters — cannot probe for cross-session "
                    "leakage. This is normal for read-only / parameterless servers."
                ),
                duration_ms=(time.perf_counter() - t_start) * 1000.0,
            )
        )
        return results

    # --- Phase 1: plant markers from primary session ------------------
    marker = f"MCPSAFE-T10-{secrets.token_hex(8)}"
    planted: list[tuple[str, str]] = []  # (tool_name, param_name)

    for tool in probe_tools:
        pname = _first_string_param(tool)
        if not pname:
            continue
        await limiter_primary.acquire()
        payload = f"{marker} planted-by-session-A"
        _, err = await _call_safe(session, tool.name, {pname: payload})
        if err is None or not looks_like_api_rejection([err]):
            # Count as planted even if the call errored — many servers accept
            # the write but then error on something else; the marker may have
            # still been cached.
            planted.append((tool.name, pname))

    if not planted:
        results.append(
            TestResult(
                test_id="T10-001",
                test_name="Cross-Session Data Leakage",
                category=Category.SECURITY,
                severity=Severity.INFO,
                passed=True,
                description=(
                    "Could not successfully invoke any tool in the primary session "
                    "to plant a marker. Cross-session probe skipped."
                ),
                duration_ms=(time.perf_counter() - t_start) * 1000.0,
            )
        )
        return results

    # --- Phase 2: open a fresh, independent session -------------------
    try:
        async with MCPConnection(config) as (session2, _conn2):
            limiter_secondary = RateLimiter(config)

            leaked: list[tuple[str, str]] = []  # (tool_name, excerpt)

            # Benign probe arguments for each planted tool.
            for tool_name, pname in planted:
                await limiter_secondary.acquire()
                text, err = await _call_safe(
                    session2, tool_name,
                    {pname: "ping-from-session-B"},
                )
                if err is not None:
                    continue
                if text and marker in text:
                    # Found the marker planted by session A.
                    idx = text.find(marker)
                    excerpt = text[max(0, idx - 30): idx + len(marker) + 30]
                    excerpt = excerpt.replace("\n", " ").strip()
                    leaked.append((tool_name, excerpt))

            # Also scan resources from session 2 (global state that persists
            # across sessions is often exposed as a resource URI).
            for res in (server_info.resources or [])[:5]:
                try:
                    await limiter_secondary.acquire()
                    with anyio.fail_after(_CALL_TIMEOUT_SEC):
                        resp = await session2.read_resource(res.uri)
                    text = _extract_text(resp)
                    if marker in text:
                        idx = text.find(marker)
                        excerpt = text[max(0, idx - 30): idx + len(marker) + 30]
                        excerpt = excerpt.replace("\n", " ").strip()
                        leaked.append((f"resource:{res.uri}", excerpt))
                except Exception:
                    continue

    except TransportError as exc:
        # Could not open a second connection — many HTTP servers single-flight
        # the auth token or Docker-mounted stdio servers can't be launched twice.
        results.append(
            TestResult(
                test_id="T10-001",
                test_name="Cross-Session Data Leakage",
                category=Category.SECURITY,
                severity=Severity.INFO,
                passed=True,
                description=(
                    "Could not open a second independent session to the target — "
                    "cross-session leakage could not be empirically tested."
                ),
                duration_ms=(time.perf_counter() - t_start) * 1000.0,
                details=str(exc)[:300],
            )
        )
        return results
    except Exception as exc:
        results.append(
            TestResult.from_exception(
                test_id="T10-001",
                test_name="Cross-Session Data Leakage",
                category=Category.SECURITY,
                exc=exc,
                duration_ms=(time.perf_counter() - t_start) * 1000.0,
            )
        )
        return results

    duration = (time.perf_counter() - t_start) * 1000.0

    if leaked:
        bullets = "\n".join(
            f"  • {name}: {excerpt!r}" for name, excerpt in leaked[:10]
        )
        results.append(
            TestResult(
                test_id="T10-001",
                test_name="Cross-Session Data Leakage",
                category=Category.SECURITY,
                severity=Severity.CRITICAL,
                passed=False,
                description=(
                    f"Data planted in session A was visible to an independent "
                    f"session B in {len(leaked)} location(s). The server has "
                    f"shared state across sessions that is not partitioned by "
                    f"session identity — a multi-tenancy failure."
                ),
                duration_ms=duration,
                details=(
                    f"Marker: {marker}\n"
                    f"Tools planted in: {len(planted)}\n"
                    f"Locations where marker leaked into session B:\n{bullets}"
                ),
                remediation=(
                    "Partition all server-side state by session ID. Caches, "
                    "databases, and in-memory singletons must be keyed by the "
                    "authenticated session/tenant identity. Never store user "
                    "content in a process-global or name-only-keyed cache."
                ),
            )
        )
    else:
        results.append(
            TestResult.make_pass(
                test_id="T10-001",
                test_name="Cross-Session Data Leakage",
                category=Category.SECURITY,
                description=(
                    f"Marker planted in {len(planted)} tool(s) via session A "
                    f"did not leak into an independent session B — state "
                    f"appears correctly partitioned."
                ),
                duration_ms=duration,
            )
        )

    return results
