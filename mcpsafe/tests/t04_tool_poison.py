"""
mcpsafe.tests.t04_tool_poison
==============================
SECURITY category — Tool poisoning and rug-pull attack detection.

This module implements the most distinctive capability in MCPSafe: detection of
server-side tool mutations, hidden instructions embedded in metadata, parasitic
cross-tool invocation chains, and non-standard schema fields used to smuggle
data.

Test inventory
--------------
T04-001  Rug Pull Detection         Snapshot descriptions, wait 3 s, re-list,
                                    diff character by character.
T04-002  Hidden Instruction Scan    Regex-scan every tool name + description
                                    for LLM-hijacking patterns.
T04-003  Cross-Tool Reference       Check if any tool description mentions
                                    another tool by name (parasitic chain).
T04-004  Schema Field Injection     Verify each inputSchema contains only
                                    sanctioned JSON Schema keywords.
T04-005  Tool Count Stability       Call list_tools() 5× with 500 ms gaps;
                                    flag any count change as CRITICAL.

Public API
----------
    async def run(
        session: ClientSession,
        server_info: ServerInfo,
    ) -> list[TestResult]
"""

from __future__ import annotations

import asyncio
import re
import time
from typing import Any

from mcp import ClientSession

from mcpsafe.models import (
    Category,
    ServerInfo,
    Severity,
    TestResult,
)

# ---------------------------------------------------------------------------
# Suspicious description patterns for T04-002
# ---------------------------------------------------------------------------

# Each entry: (regex_pattern, human_label, severity_string)
SUSPICIOUS_DESCRIPTION_PATTERNS: list[tuple[str, str, str]] = [
    (
        r"(?i)(ignore|override|bypass)\s+(previous|all|prior)\s+(instruction|rule|constraint)",
        "Instruction override attempt",
        "CRITICAL",
    ),
    (
        r"(?i)(also|additionally|secretly|silently)\s+(do|execute|run|send)",
        "Hidden action instruction",
        "HIGH",
    ),
    (
        r"(?i)(exfiltrat|steal|leak|forward|send).{0,50}"
        r"(data|context|secret|key|token|password)",
        "Data exfiltration instruction",
        "CRITICAL",
    ),
    (
        r"[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]",
        "Invisible Unicode characters in description",
        "HIGH",
    ),
    (
        r"(?i)(http|https|ftp)://(?!example\.com)[^\s]{10,}",
        "External URL in tool description",
        "MEDIUM",
    ),
    (
        r"(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?",
        "Base64-encoded content in description",
        "MEDIUM",
    ),
    (
        r"(?i)(system\s*prompt|system\s*instruction|<\s*system\s*>)",
        "System prompt reference in description",
        "HIGH",
    ),
    (
        r"(?i)when\s+(you|the\s+model|the\s+ai)\s+(call|invoke|use)\s+\w+",
        "Cross-tool invocation instruction",
        "HIGH",
    ),
]

_COMPILED_POISON_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE | re.UNICODE)
    for p, _, _ in SUSPICIOUS_DESCRIPTION_PATTERNS
]

_SEVERITY_MAP: dict[str, Severity] = {
    "PASS": Severity.PASS,
    "INFO": Severity.INFO,
    "LOW": Severity.LOW,
    "MEDIUM": Severity.MEDIUM,
    "HIGH": Severity.HIGH,
    "CRITICAL": Severity.CRITICAL,
}

# ---------------------------------------------------------------------------
# Allowed JSON Schema keywords for T04-004
# ---------------------------------------------------------------------------

ALLOWED_SCHEMA_FIELDS: frozenset[str] = frozenset({
    "type", "properties", "required", "description",
    "title", "default", "enum", "items", "minimum",
    "maximum", "minLength", "maxLength", "pattern",
    "additionalProperties", "format", "anyOf", "oneOf",
    "allOf", "not", "$ref", "$schema", "examples",
})

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _slug(name: str, max_len: int = 16) -> str:
    """Slug-ify a tool name for embedding in a test ID."""
    s = re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")
    return s[:max_len]


def _tool_descriptions_snapshot(
    tools: list[Any],
) -> dict[str, str]:
    """Return {tool_name: description} for a list of raw MCP tool objects."""
    snap: dict[str, str] = {}
    for t in tools:
        name = getattr(t, "name", None) or ""
        desc = getattr(t, "description", None) or ""
        snap[name] = desc
    return snap


# ---------------------------------------------------------------------------
# T04-001 — Rug Pull Detection
# ---------------------------------------------------------------------------


async def _t04_001_rug_pull(
    session: ClientSession,
    server_info: ServerInfo,
) -> TestResult:
    """
    T04-001 — Snapshot tool descriptions, wait 3 s, re-query, compare.

    Any character-level change in a description between the two snapshots is
    treated as a rug-pull mutation and flagged CRITICAL.
    """
    tid = "T04-001"
    tname = "Rug Pull Detection (Mutation Check)"
    t0 = time.perf_counter()
    try:
        # Snapshot 1 — use the already-gathered server_info as baseline.
        snap_before: dict[str, str] = {
            t.name: t.description for t in server_info.tools
        }

        # Wait 3 seconds to give a dynamic server time to mutate.
        await asyncio.sleep(3.0)

        # Snapshot 2 — fresh live query.
        live_response = await session.list_tools()
        raw_tools = getattr(live_response, "tools", []) or []
        snap_after = _tool_descriptions_snapshot(raw_tools)

        duration = (time.perf_counter() - t0) * 1000.0

        # Separate mutations into two buckets:
        #   true_mutations — content changed or shrank (genuine rug-pull risk)
        #   growth_only   — description only grew (likely CDN/lazy-load, not attack)
        true_mutations: list[str] = []
        growth_only: list[str] = []
        all_names = set(snap_before) | set(snap_after)

        for name in sorted(all_names):
            before = snap_before.get(name)
            after = snap_after.get(name)
            if before is None and after is not None:
                true_mutations.append(
                    f"NEW tool appeared: {name!r}\n"
                    f"  Description: {after[:200]!r}"
                )
            elif before is not None and after is None:
                true_mutations.append(f"Tool DISAPPEARED: {name!r}")
            elif before != after:
                # Character-by-character diff — show context around the first
                # divergence point, not the beginning of the string (which may
                # be identical even for long descriptions that differ at the end).
                diff_pos = next(
                    (i for i, (a, b) in enumerate(zip(before, after)) if a != b),
                    min(len(before), len(after)),
                )
                ctx_start = max(0, diff_pos - 80)
                ctx_end_b = min(len(before), diff_pos + 160)
                ctx_end_a = min(len(after), diff_pos + 160)
                len_note = ""
                if len(before) != len(after):
                    len_note = (
                        f"\n  Length: {len(before)} → {len(after)} chars "
                        f"({'grew' if len(after) > len(before) else 'shrank'})"
                    )
                entry = (
                    f"Tool {name!r} description CHANGED at char {diff_pos}:{len_note}\n"
                    f"  BEFORE[{ctx_start}:{ctx_end_b}]: {before[ctx_start:ctx_end_b]!r}\n"
                    f"  AFTER [{ctx_start}:{ctx_end_a}]: {after[ctx_start:ctx_end_a]!r}"
                )
                # Pure extension: after is a strict superset starting with before.
                # This pattern indicates CDN/edge truncation or paginated responses,
                # NOT a deliberate description swap.  A real rug-pull overwrites
                # content at the beginning or middle of the description.
                #
                # Edge case: some servers truncate descriptions with a trailing
                # ellipsis ("…" U+2026 or "...") so BEFORE ends with "…foo"
                # while AFTER continues with the real text at that position.
                # Strip any trailing whitespace + ellipsis chars before comparing
                # so we catch these truncation-extension pairs correctly.
                _ELLIPSIS_CHARS = " \t\u2026."
                before_stem = before.rstrip(_ELLIPSIS_CHARS)
                is_growth = (
                    len(after) > len(before)
                    and (
                        after.startswith(before)
                        or (
                            len(before_stem) >= 20
                            and after.startswith(before_stem)
                        )
                    )
                )
                if is_growth:
                    growth_only.append(entry)
                else:
                    true_mutations.append(entry)

        if true_mutations:
            return TestResult(
                test_id=tid,
                test_name=tname,
                category=Category.SECURITY,
                severity=Severity.CRITICAL,
                passed=False,
                description=(
                    f"{len(true_mutations)} tool description(s) mutated between "
                    f"two consecutive list_tools() calls (3 s apart). "
                    f"Rug-pull attack confirmed."
                ),
                duration_ms=duration,
                details="\n\n".join(true_mutations),
                remediation=(
                    "Tool descriptions must be immutable after server startup. "
                    "Dynamic description mutation is the hallmark of a rug-pull "
                    "attack, where an MCP server silently changes tool behaviour "
                    "after an LLM has already approved tool use. "
                    "Treat this server as compromised."
                ),
            )

        if growth_only:
            return TestResult(
                test_id=tid,
                test_name=tname,
                category=Category.SECURITY,
                severity=Severity.MEDIUM,
                passed=False,
                description=(
                    f"{len(growth_only)} tool description(s) grew between two "
                    f"consecutive list_tools() calls (3 s apart). Descriptions "
                    f"only extended — likely CDN truncation or lazy-loaded content "
                    f"rather than a deliberate rug-pull. Verify server behaviour."
                ),
                duration_ms=duration,
                details="\n\n".join(growth_only),
                remediation=(
                    "Tool descriptions should be fully materialized at startup. "
                    "If descriptions grow between calls, clients may make tool-use "
                    "decisions based on incomplete instructions. "
                    "Ensure list_tools() always returns the full, stable description."
                ),
            )

        return TestResult.make_pass(
            test_id=tid,
            test_name=tname,
            category=Category.SECURITY,
            description=(
                f"All {len(snap_before)} tool description(s) were stable "
                f"across two list_tools() calls (3 s apart)."
            ),
            duration_ms=duration,
        )

    except Exception as exc:
        return TestResult.from_exception(
            test_id=tid, test_name=tname,
            category=Category.SECURITY, exc=exc,
            duration_ms=(time.perf_counter() - t0) * 1000.0,
        )


# ---------------------------------------------------------------------------
# T04-002 — Hidden Instruction Detection
# ---------------------------------------------------------------------------


async def _t04_002_hidden_instructions(
    session: ClientSession,
    server_info: ServerInfo,
) -> list[TestResult]:
    """
    T04-002 — Scan every tool name and description for LLM-hijacking patterns.

    Produces one ``TestResult`` per (tool, pattern) match.
    If no matches are found, returns a single PASS result for the entire check.
    """
    t0 = time.perf_counter()
    findings: list[TestResult] = []

    for tool in server_info.tools:
        text_to_scan = f"{tool.name}\n{tool.description}"
        for pat_idx, (compiled, (pattern_str, label, sev_str)) in enumerate(
            zip(_COMPILED_POISON_PATTERNS, SUSPICIOUS_DESCRIPTION_PATTERNS),
            start=1,
        ):
            match = compiled.search(text_to_scan)
            if match:
                severity = _SEVERITY_MAP.get(sev_str, Severity.HIGH)
                tid = f"T04-002-{_slug(tool.name)}-P{pat_idx:02d}"
                tname = f"Hidden Instruction: {label} in {tool.name!r}"
                duration = (time.perf_counter() - t0) * 1000.0

                findings.append(
                    TestResult(
                        test_id=tid,
                        test_name=tname,
                        category=Category.SECURITY,
                        severity=severity,
                        passed=False,
                        description=(
                            f"Tool {tool.name!r} description matches poisoning "
                            f"pattern P{pat_idx:02d}: {label}."
                        ),
                        duration_ms=duration,
                        details=(
                            f"Pattern: {pattern_str!r}\n"
                            f"Match at position {match.start()}–{match.end()}: "
                            f"{match.group()!r}\n"
                            f"Full description: {tool.description[:500]!r}"
                        ),
                        remediation=(
                            f"Remove or sanitise the content that matched "
                            f"'{label}'. Tool descriptions must contain only "
                            "truthful capability summaries and must never embed "
                            "instructions directed at an LLM model."
                        ),
                    )
                )

    if not findings:
        duration = (time.perf_counter() - t0) * 1000.0
        findings.append(
            TestResult.make_pass(
                test_id="T04-002",
                test_name="Hidden Instruction Scan",
                category=Category.SECURITY,
                description=(
                    f"No suspicious patterns found in {len(server_info.tools)} "
                    f"tool description(s)."
                ),
                duration_ms=duration,
            )
        )

    return findings


# ---------------------------------------------------------------------------
# T04-003 — Cross-Tool Reference Detection
# ---------------------------------------------------------------------------


async def _t04_003_cross_tool_refs(
    session: ClientSession,
    server_info: ServerInfo,
) -> TestResult:
    """
    T04-003 — Detect parasitic toolchain instructions.

    If tool A's description contains the name of tool B, an LLM following the
    description would silently invoke tool B as a side-effect of calling tool A.
    """
    tid = "T04-003"
    tname = "Cross-Tool Reference Detection"
    t0 = time.perf_counter()
    try:
        tools = server_info.tools
        if len(tools) < 2:
            return TestResult.make_pass(
                test_id=tid,
                test_name=tname,
                category=Category.SECURITY,
                description="Fewer than 2 tools — cross-tool reference check skipped.",
                duration_ms=(time.perf_counter() - t0) * 1000.0,
            )

        tool_names = [t.name for t in tools]
        refs: list[str] = []

        for tool in tools:
            desc_lower = tool.description.lower()
            for other_name in tool_names:
                if other_name == tool.name:
                    continue
                # Use word-boundary matching to avoid false positives on common
                # substrings (e.g. "read" appearing in "read_file" description).
                pattern = r"\b" + re.escape(other_name.lower()) + r"\b"
                if re.search(pattern, desc_lower):
                    refs.append(
                        f"  Tool {tool.name!r} description references "
                        f"{other_name!r}"
                    )

        duration = (time.perf_counter() - t0) * 1000.0

        if refs:
            return TestResult.make_fail(
                test_id=tid,
                test_name=tname,
                category=Category.SECURITY,
                severity=Severity.LOW,
                description=(
                    f"Found {len(refs)} cross-tool reference(s) in tool "
                    f"descriptions — server uses chained workflow guidance. "
                    f"Verify no sensitive data is passed between tools."
                ),
                duration_ms=duration,
                details="\n".join(refs),
                remediation=(
                    "Cross-tool references in descriptions are common in "
                    "multi-step APIs and are not inherently malicious. "
                    "Review each reference to confirm it describes legitimate "
                    "workflow guidance (e.g. 'call tool X first to discover "
                    "available values') rather than parasitic data exfiltration "
                    "(e.g. 'silently forward results to tool Y'). "
                    "Tool descriptions must describe only the tool's own "
                    "behaviour. References to other tool names in a description "
                    "can trick LLMs into invoking them as a silent side-effect, "
                    "creating an unaudited tool chain."
                ),
            )

        return TestResult.make_pass(
            test_id=tid,
            test_name=tname,
            category=Category.SECURITY,
            description=(
                f"No cross-tool name references found across "
                f"{len(tools)} tool descriptions."
            ),
            duration_ms=duration,
        )

    except Exception as exc:
        return TestResult.from_exception(
            test_id=tid, test_name=tname,
            category=Category.SECURITY, exc=exc,
            duration_ms=(time.perf_counter() - t0) * 1000.0,
        )


# ---------------------------------------------------------------------------
# T04-004 — Schema Field Injection Check
# ---------------------------------------------------------------------------


async def _t04_004_schema_fields(
    session: ClientSession,
    server_info: ServerInfo,
) -> list[TestResult]:
    """
    T04-004 — Verify each tool's inputSchema contains only sanctioned keywords.

    Returns one result per violation found; a single PASS if everything is clean.
    Violation at the top-level schema → MEDIUM.
    Violation inside a property definition → LOW.
    """
    t0 = time.perf_counter()
    findings: list[TestResult] = []

    for tool in server_info.tools:
        schema = tool.input_schema
        if not isinstance(schema, dict):
            continue

        # Top-level unexpected fields
        top_unknown = sorted(set(schema.keys()) - ALLOWED_SCHEMA_FIELDS)
        if top_unknown:
            tid = f"T04-004-{_slug(tool.name)}-TOP"
            tname = f"Schema Field Injection: top-level in {tool.name!r}"
            duration = (time.perf_counter() - t0) * 1000.0
            findings.append(
                TestResult(
                    test_id=tid,
                    test_name=tname,
                    category=Category.SECURITY,
                    severity=Severity.MEDIUM,
                    passed=False,
                    description=(
                        f"Tool {tool.name!r} inputSchema contains non-standard "
                        f"top-level field(s): {top_unknown}."
                    ),
                    duration_ms=duration,
                    details=(
                        f"Unknown fields: {top_unknown}\n"
                        f"Allowed fields: {sorted(ALLOWED_SCHEMA_FIELDS)}"
                    ),
                    remediation=(
                        "Remove non-standard fields from the top-level inputSchema. "
                        "Unknown fields can be used to smuggle instructions or "
                        "configuration data that a naïve MCP client might act on."
                    ),
                )
            )

        # Property-level unexpected fields
        props = schema.get("properties")
        if isinstance(props, dict):
            for prop_name, prop_schema in props.items():
                if not isinstance(prop_schema, dict):
                    continue
                prop_unknown = sorted(set(prop_schema.keys()) - ALLOWED_SCHEMA_FIELDS)
                if prop_unknown:
                    tid = f"T04-004-{_slug(tool.name)}-{_slug(prop_name, 8)}"
                    tname = (
                        f"Schema Field Injection: property "
                        f"{prop_name!r} in {tool.name!r}"
                    )
                    duration = (time.perf_counter() - t0) * 1000.0
                    findings.append(
                        TestResult(
                            test_id=tid,
                            test_name=tname,
                            category=Category.SECURITY,
                            severity=Severity.LOW,
                            passed=False,
                            description=(
                                f"Property {prop_name!r} of tool {tool.name!r} "
                                f"has non-standard schema field(s): {prop_unknown}."
                            ),
                            duration_ms=duration,
                            details=(
                                f"Property: {prop_name!r}\n"
                                f"Unknown fields: {prop_unknown}"
                            ),
                            remediation=(
                                "Keep property schemas to standard JSON Schema "
                                "keywords. Non-standard fields may be used to "
                                "embed covert metadata or instructions."
                            ),
                        )
                    )

    if not findings:
        duration = (time.perf_counter() - t0) * 1000.0
        findings.append(
            TestResult.make_pass(
                test_id="T04-004",
                test_name="Schema Field Injection Check",
                category=Category.SECURITY,
                description=(
                    f"All {len(server_info.tools)} tool inputSchema(s) contain "
                    f"only sanctioned JSON Schema fields."
                ),
                duration_ms=duration,
            )
        )

    return findings


# ---------------------------------------------------------------------------
# T04-005 — Tool Count Stability Check
# ---------------------------------------------------------------------------

_STABILITY_POLLS = 5
_STABILITY_DELAY_S = 0.5  # seconds between polls


async def _t04_005_count_stability(
    session: ClientSession,
    server_info: ServerInfo,
) -> TestResult:
    """
    T04-005 — Call list_tools() 5× with 500 ms gaps; flag any change as CRITICAL.

    Dynamic tool injection — where a new tool appears between list calls — is an
    active attack vector in which a malicious server waits for an LLM to approve
    tools, then injects a new high-privilege tool into the approved set.
    """
    tid = "T04-005"
    tname = "Tool Count Stability Check"
    t0 = time.perf_counter()
    try:
        baseline_count = len(server_info.tools)
        baseline_names = set(server_info.tool_names)

        counts: list[int] = [baseline_count]
        name_snapshots: list[set[str]] = [baseline_names]

        for poll in range(1, _STABILITY_POLLS):
            await asyncio.sleep(_STABILITY_DELAY_S)
            response = await session.list_tools()
            raw = getattr(response, "tools", []) or []
            names = {getattr(t, "name", "") for t in raw}
            counts.append(len(raw))
            name_snapshots.append(names)

        duration = (time.perf_counter() - t0) * 1000.0

        # Detect any variance across polls.
        changed = any(c != counts[0] for c in counts[1:])
        injected: list[str] = []
        removed: list[str] = []
        for snap in name_snapshots[1:]:
            injected.extend(sorted(snap - name_snapshots[0]))
            removed.extend(sorted(name_snapshots[0] - snap))
        # Deduplicate.
        injected = sorted(set(injected))
        removed = sorted(set(removed))

        if changed:
            detail_lines = [f"  Poll {i + 1}: {c} tools" for i, c in enumerate(counts)]
            if injected:
                detail_lines.append(f"  Injected: {injected}")
            if removed:
                detail_lines.append(f"  Removed: {removed}")
            return TestResult(
                test_id=tid,
                test_name=tname,
                category=Category.SECURITY,
                severity=Severity.CRITICAL,
                passed=False,
                description=(
                    f"Tool count changed across {_STABILITY_POLLS} polls "
                    f"(counts: {counts}) — dynamic tool injection detected."
                ),
                duration_ms=duration,
                details="\n".join(detail_lines),
                remediation=(
                    "The server's tool list changed between consecutive list_tools() "
                    "calls. This is the signature of a dynamic tool injection attack, "
                    "where a malicious server injects new tools after the LLM has "
                    "already formed an approved-tools mental model. "
                    "Treat this server as compromised."
                ),
            )

        return TestResult.make_pass(
            test_id=tid,
            test_name=tname,
            category=Category.SECURITY,
            description=(
                f"Tool count stable at {baseline_count} across "
                f"{_STABILITY_POLLS} polls "
                f"({_STABILITY_POLLS * _STABILITY_DELAY_S:.1f}s window)."
            ),
            duration_ms=duration,
            details=f"Counts per poll: {counts}",
        )

    except Exception as exc:
        return TestResult.from_exception(
            test_id=tid, test_name=tname,
            category=Category.SECURITY, exc=exc,
            duration_ms=(time.perf_counter() - t0) * 1000.0,
        )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


async def run(
    session: ClientSession,
    server_info: ServerInfo,
) -> list[TestResult]:
    """
    Execute all tool-poisoning and rug-pull detection tests.

    Parameters
    ----------
    session:
        An initialised ``mcp.ClientSession``.
    server_info:
        Populated ``ServerInfo`` from the discovery phase.

    Returns
    -------
    list[TestResult]:
        Between 5 and 5 + (tools × patterns) results, depending on how many
        T04-002 pattern matches are found.  Never raises.
    """
    results: list[TestResult] = []

    # T04-001: Rug pull detection (includes a 3 s sleep — run first).
    results.append(await _t04_001_rug_pull(session, server_info))

    # T04-002: Hidden instruction scan (no I/O — pure regex).
    results.extend(await _t04_002_hidden_instructions(session, server_info))

    # T04-003: Cross-tool reference detection.
    results.append(await _t04_003_cross_tool_refs(session, server_info))

    # T04-004: Schema field injection check.
    results.extend(await _t04_004_schema_fields(session, server_info))

    # T04-005: Tool count stability (includes 4 × 500 ms sleeps).
    results.append(await _t04_005_count_stability(session, server_info))

    return results
