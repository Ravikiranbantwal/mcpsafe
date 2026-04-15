"""
mcpsafe.tests.t16_capability_creep
====================================
SECURITY category — **Silent capability expansion** detection.

Detects servers that silently grow their capability surface over time —
distinct from T04 (which detects tool *description* mutation).  Examples:

  * New tools appear between two ``list_tools()`` calls seconds apart.
  * Tool input-schema gains new properties after the initial handshake.
  * Resource list grows; resource MIME types shift to executable types.
  * Server announces new capabilities after client looks idle.

Strategy
--------
1. Snapshot tools, resources, prompts, and ``server_capabilities`` at T=0.
2. Sleep ``WAIT_SECONDS``.
3. Snapshot again.
4. Diff the two snapshots and flag:
    - NEW tools added                             → MEDIUM
    - NEW resources added                         → MEDIUM
    - Tool input-schemas gaining required fields  → LOW
    - New capabilities advertised                 → MEDIUM

Test inventory
--------------
T16-001    Tool set drift
T16-002    Resource set drift
T16-003    Schema drift (added required fields)
T16-004    Capability drift
T16-005    Summary

Public API
----------
    async def run(session, server_info, config) -> list[TestResult]
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Optional

from mcp import ClientSession

from mcpsafe.models import (
    Category,
    MCPPrompt,
    MCPResource,
    MCPTool,
    ScanConfig,
    ServerInfo,
    Severity,
    TestResult,
)
from mcpsafe.tests._helpers import RateLimiter

_WAIT_SECONDS = 3.0


async def _snapshot(session: ClientSession) -> dict[str, Any]:
    """Capture current tools/resources/prompts/capabilities."""
    snap: dict[str, Any] = {
        "tools": {},
        "resources": set(),
        "prompts": set(),
        "capabilities": {},
    }
    try:
        tr = await session.list_tools()
        for t in getattr(tr, "tools", []) or []:
            name = getattr(t, "name", None) or str(t)
            schema = getattr(t, "inputSchema", None) or {}
            snap["tools"][name] = schema
    except Exception:
        pass
    try:
        rr = await session.list_resources()
        for r in getattr(rr, "resources", []) or []:
            uri = getattr(r, "uri", None) or str(r)
            snap["resources"].add(str(uri))
    except Exception:
        pass
    try:
        pr = await session.list_prompts()
        for p in getattr(pr, "prompts", []) or []:
            name = getattr(p, "name", None) or str(p)
            snap["prompts"].add(name)
    except Exception:
        pass
    try:
        caps = await session.get_server_capabilities()
        if caps is not None:
            # May be a pydantic object — normalise to dict.
            if hasattr(caps, "model_dump"):
                snap["capabilities"] = caps.model_dump()
            elif hasattr(caps, "dict"):
                snap["capabilities"] = caps.dict()
            elif isinstance(caps, dict):
                snap["capabilities"] = dict(caps)
    except Exception:
        pass
    return snap


def _required_fields(schema: Any) -> set[str]:
    if isinstance(schema, dict):
        req = schema.get("required", []) or []
        if isinstance(req, list):
            return set(str(x) for x in req)
    return set()


async def run(
    session: ClientSession,
    server_info: ServerInfo,
    config: ScanConfig,
) -> list[TestResult]:
    """Execute T16 — Capability Creep Detection."""
    t_start = time.perf_counter()
    results: list[TestResult] = []
    limiter = RateLimiter(config)

    await limiter.acquire()
    snap_a = await _snapshot(session)
    await asyncio.sleep(_WAIT_SECONDS)
    await limiter.acquire()
    snap_b = await _snapshot(session)

    # ── T16-001 tool set drift ──────────────────────────────────────────
    added_tools = set(snap_b["tools"]) - set(snap_a["tools"])
    removed_tools = set(snap_a["tools"]) - set(snap_b["tools"])
    if added_tools or removed_tools:
        severity = Severity.MEDIUM if added_tools else Severity.LOW
        results.append(
            TestResult(
                test_id="T16-001",
                test_name="Tool Set Drift",
                category=Category.SECURITY,
                severity=severity,
                passed=False,
                description=(
                    f"Tool inventory changed within {_WAIT_SECONDS:.0f}s: "
                    f"{len(added_tools)} added, {len(removed_tools)} removed. "
                    f"A server that silently grows its tool surface is an "
                    f"integrity risk — initial audit may miss later-added tools."
                ),
                duration_ms=(time.perf_counter() - t_start) * 1000.0,
                details=f"added: {sorted(added_tools)}\nremoved: {sorted(removed_tools)}",
                remediation=(
                    "Tool discovery should be deterministic. Pin the tool "
                    "inventory at session-start; treat any later change as a "
                    "reason to re-run the full security audit."
                ),
            )
        )
    else:
        results.append(
            TestResult.make_pass(
                test_id="T16-001", test_name="Tool Set Drift",
                category=Category.SECURITY,
                description="Tool inventory stable across snapshots.",
                duration_ms=(time.perf_counter() - t_start) * 1000.0,
            )
        )

    # ── T16-002 resource set drift ─────────────────────────────────────
    added_res = snap_b["resources"] - snap_a["resources"]
    removed_res = snap_a["resources"] - snap_b["resources"]

    # Noise filter: auto-generated resource streams (e.g. server-everything's
    # periodic ``test://static/resource/{N}`` feed, or any server that creates
    # resources from our own T02 injection payloads via a
    # ``create-resource-from-input`` tool).  If ALL newly-added resources share
    # a common prefix up to the final path component, we treat the change as
    # a server-side auto-generator rather than capability creep.
    def _is_auto_generator_noise(uris: set[str]) -> bool:
        if len(uris) < 5:
            return False
        # Strip trailing numeric / hash-like suffix from each URI, look for a
        # shared prefix.
        def _strip_tail(u: str) -> str:
            # Remove the last path segment (after final '/').
            slash = u.rfind("/")
            return u[:slash] if slash > 0 else u
        prefixes = {_strip_tail(u) for u in uris}
        # If all N URIs collapse to ≤ 2 distinct prefixes, it's a bulk-create
        # pattern (server is numbering resources under a single namespace).
        return len(prefixes) <= 2

    added_is_noise = _is_auto_generator_noise(added_res)

    if added_res or removed_res:
        if added_is_noise and not removed_res:
            # Demote to LOW with a different description so the operator
            # still sees the event but isn't alarmed.
            results.append(
                TestResult(
                    test_id="T16-002",
                    test_name="Resource Set Drift",
                    category=Category.SECURITY,
                    severity=Severity.LOW,
                    passed=False,
                    description=(
                        f"Server added {len(added_res)} resource(s) within "
                        f"{_WAIT_SECONDS:.0f}s, but all share a common namespace "
                        f"prefix — likely an auto-generated resource stream or "
                        f"a create-from-input side-effect of earlier tests, not "
                        f"capability creep."
                    ),
                    duration_ms=(time.perf_counter() - t_start) * 1000.0,
                    details=(
                        f"added (sample): "
                        f"{sorted(added_res)[:3]} … ({len(added_res)} total)"
                    ),
                    remediation=(
                        "If this resource stream is intentional (e.g. "
                        "documenting user uploads), document it in the server "
                        "manifest so downstream clients don't treat it as drift."
                    ),
                )
            )
        else:
            results.append(
                TestResult(
                    test_id="T16-002",
                    test_name="Resource Set Drift",
                    category=Category.SECURITY,
                    severity=Severity.MEDIUM,
                    passed=False,
                    description=(
                        f"Resource inventory changed within {_WAIT_SECONDS:.0f}s: "
                        f"{len(added_res)} added, {len(removed_res)} removed."
                    ),
                    duration_ms=(time.perf_counter() - t_start) * 1000.0,
                    details=f"added: {sorted(added_res)}\nremoved: {sorted(removed_res)}",
                    remediation=(
                        "Subscribe to resource-list-changed notifications explicitly; "
                        "do not expose new resources mid-session without client consent."
                    ),
                )
            )
    else:
        results.append(
            TestResult.make_pass(
                test_id="T16-002", test_name="Resource Set Drift",
                category=Category.SECURITY,
                description="Resource inventory stable.",
            )
        )

    # ── T16-003 required-field drift ───────────────────────────────────
    drifted_tools: list[str] = []
    for tname in set(snap_a["tools"]) & set(snap_b["tools"]):
        req_a = _required_fields(snap_a["tools"][tname])
        req_b = _required_fields(snap_b["tools"][tname])
        if req_a != req_b:
            drifted_tools.append(f"{tname}: {sorted(req_a)} → {sorted(req_b)}")
    if drifted_tools:
        results.append(
            TestResult(
                test_id="T16-003",
                test_name="Tool Schema Required-Field Drift",
                category=Category.SCHEMA,
                severity=Severity.LOW,
                passed=False,
                description=(
                    f"{len(drifted_tools)} tool(s) changed their required fields "
                    f"within {_WAIT_SECONDS:.0f}s. May indicate a server switching "
                    f"validation modes or A/B-testing clients."
                ),
                duration_ms=(time.perf_counter() - t_start) * 1000.0,
                details="\n".join(drifted_tools[:5]),
            )
        )
    else:
        results.append(
            TestResult.make_pass(
                test_id="T16-003", test_name="Tool Schema Required-Field Drift",
                category=Category.SCHEMA,
                description="No required-field drift detected.",
            )
        )

    # ── T16-004 capability drift ──────────────────────────────────────
    if snap_a["capabilities"] != snap_b["capabilities"]:
        results.append(
            TestResult(
                test_id="T16-004",
                test_name="Server Capability Drift",
                category=Category.SECURITY,
                severity=Severity.MEDIUM,
                passed=False,
                description=(
                    "Advertised server capabilities changed between snapshots."
                ),
                duration_ms=(time.perf_counter() - t_start) * 1000.0,
                details=f"before: {snap_a['capabilities']}\nafter: {snap_b['capabilities']}",
            )
        )
    else:
        results.append(
            TestResult.make_pass(
                test_id="T16-004", test_name="Server Capability Drift",
                category=Category.SECURITY,
                description="Server capabilities stable.",
            )
        )

    # ── Summary ────────────────────────────────────────────────────────
    bad = sum(1 for r in results if r.severity >= Severity.MEDIUM and not r.passed)
    if bad > 0:
        results.append(
            TestResult.make_fail(
                test_id="T16-005",
                test_name="Capability Creep — Summary",
                category=Category.SECURITY,
                severity=Severity.MEDIUM,
                description=f"{bad} capability drift(s) detected. See T16-001/002/003/004.",
                duration_ms=(time.perf_counter() - t_start) * 1000.0,
            )
        )
    else:
        results.append(
            TestResult.make_pass(
                test_id="T16-005",
                test_name="Capability Creep — Summary",
                category=Category.SECURITY,
                description=f"All capability surfaces stable over {_WAIT_SECONDS:.0f}s window.",
                duration_ms=(time.perf_counter() - t_start) * 1000.0,
            )
        )
    return results
