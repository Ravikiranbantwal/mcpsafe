"""
mcpsafe.tests.t01_discovery
============================
DISCOVERY category — 8 tests that interrogate a live MCP server's capability
advertisement without modifying any server state.

Test inventory
--------------
T01-001  Server identity        Connect and capture server name / version.
T01-002  Tool enumeration       List all tools, record counts and names.
T01-003  Resource enumeration   List all resources, record counts and URIs.
T01-004  Prompt enumeration     List all prompts, record counts and names.
T01-005  Tool description gate  Every tool must have a non-empty description.
T01-006  Tool schema validity   Every tool's inputSchema must be a valid JSON Schema object.
T01-007  Duplicate tool names   Tool names must be globally unique.
T01-008  Description length     Descriptions > 2 000 chars may carry injected instructions.

Public API
----------
    async def run(session: ClientSession, server_info: ServerInfo) -> list[TestResult]
"""

from __future__ import annotations

import time
from typing import Any, Optional

from mcp import ClientSession

from mcpsafe.models import (
    Category,
    ServerInfo,
    Severity,
    TestResult,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_CAT = Category.DISCOVERY
_MAX_DESC_LEN = 2_000   # characters — T01-008 threshold
_REQUIRED_SCHEMA_KEYS = {"type"}  # minimum keys a valid JSON Schema object has


# ---------------------------------------------------------------------------
# Individual test functions
# ---------------------------------------------------------------------------


async def _t01_001_server_identity(
    session: ClientSession,
    server_info: ServerInfo,
) -> TestResult:
    """T01-001 — Capture server name and version from initialisation response."""
    tid = "T01-001"
    name = "Server Identity"
    t0 = time.perf_counter()
    try:
        sname = server_info.name
        sver = server_info.version
        proto = server_info.protocol_version

        missing: list[str] = []
        if not sname or sname == "unknown":
            missing.append("name")
        if not sver or sver == "unknown":
            missing.append("version")

        duration = (time.perf_counter() - t0) * 1000.0

        if missing:
            return TestResult(
                test_id=tid,
                test_name=name,
                category=_CAT,
                severity=Severity.INFO,
                passed=False,
                description=(
                    f"Server did not advertise: {', '.join(missing)}. "
                    f"Got name={sname!r} version={sver!r} protocol={proto!r}."
                ),
                duration_ms=duration,
                remediation=(
                    "Ensure the MCP server returns a populated 'serverInfo' object "
                    "in its initialize response (name and version fields)."
                ),
            )

        return TestResult.make_pass(
            test_id=tid,
            test_name=name,
            category=_CAT,
            description=(
                f"Server identified as {sname!r} v{sver!r} "
                f"(protocol {proto!r})."
            ),
            duration_ms=duration,
        )

    except Exception as exc:
        return TestResult.from_exception(
            test_id=tid,
            test_name=name,
            category=_CAT,
            exc=exc,
            duration_ms=(time.perf_counter() - t0) * 1000.0,
        )


async def _t01_002_tool_enumeration(
    session: ClientSession,
    server_info: ServerInfo,
) -> TestResult:
    """T01-002 — List all tools; record count, names, and descriptions."""
    tid = "T01-002"
    name = "Tool Enumeration"
    t0 = time.perf_counter()
    try:
        tools = server_info.tools
        count = len(tools)
        duration = (time.perf_counter() - t0) * 1000.0

        names = [t.name for t in tools]
        detail_lines = [f"{t.name}: {t.description[:80]!r}" for t in tools]

        return TestResult.make_pass(
            test_id=tid,
            test_name=name,
            category=_CAT,
            description=f"Discovered {count} tool(s): {', '.join(names) or '(none)'}.",
            duration_ms=duration,
            details="\n".join(detail_lines) if detail_lines else None,
        )

    except Exception as exc:
        return TestResult.from_exception(
            test_id=tid,
            test_name=name,
            category=_CAT,
            exc=exc,
            duration_ms=(time.perf_counter() - t0) * 1000.0,
        )


async def _t01_003_resource_enumeration(
    session: ClientSession,
    server_info: ServerInfo,
) -> TestResult:
    """T01-003 — List all resources; record count, URIs, and MIME types."""
    tid = "T01-003"
    name = "Resource Enumeration"
    t0 = time.perf_counter()
    try:
        resources = server_info.resources
        count = len(resources)
        duration = (time.perf_counter() - t0) * 1000.0

        uris = [str(r.uri) for r in resources]
        detail_lines = [
            f"{str(r.uri)} ({r.mime_type or 'unknown type'}): {r.description[:60]!r}"
            for r in resources
        ]

        return TestResult.make_pass(
            test_id=tid,
            test_name=name,
            category=_CAT,
            description=(
                f"Discovered {count} resource(s)"
                + (f": {', '.join(uris[:5])}{'…' if count > 5 else ''}" if uris else ".")
            ),
            duration_ms=duration,
            details="\n".join(detail_lines) if detail_lines else None,
        )

    except Exception as exc:
        return TestResult.from_exception(
            test_id=tid,
            test_name=name,
            category=_CAT,
            exc=exc,
            duration_ms=(time.perf_counter() - t0) * 1000.0,
        )


async def _t01_004_prompt_enumeration(
    session: ClientSession,
    server_info: ServerInfo,
) -> TestResult:
    """T01-004 — List all prompts; record count and names."""
    tid = "T01-004"
    name = "Prompt Enumeration"
    t0 = time.perf_counter()
    try:
        prompts = server_info.prompts
        count = len(prompts)
        duration = (time.perf_counter() - t0) * 1000.0

        pnames = [p.name for p in prompts]
        detail_lines = [
            f"{p.name}: {p.description[:80]!r} ({len(p.arguments)} arg(s))"
            for p in prompts
        ]

        return TestResult.make_pass(
            test_id=tid,
            test_name=name,
            category=_CAT,
            description=f"Discovered {count} prompt(s): {', '.join(pnames) or '(none)'}.",
            duration_ms=duration,
            details="\n".join(detail_lines) if detail_lines else None,
        )

    except Exception as exc:
        return TestResult.from_exception(
            test_id=tid,
            test_name=name,
            category=_CAT,
            exc=exc,
            duration_ms=(time.perf_counter() - t0) * 1000.0,
        )


async def _t01_005_tool_descriptions(
    session: ClientSession,
    server_info: ServerInfo,
) -> TestResult:
    """T01-005 — Every tool must have a non-empty description."""
    tid = "T01-005"
    name = "Tool Description Completeness"
    t0 = time.perf_counter()
    try:
        tools = server_info.tools
        empty: list[str] = [t.name for t in tools if not t.description.strip()]
        duration = (time.perf_counter() - t0) * 1000.0

        if not tools:
            return TestResult.make_pass(
                test_id=tid,
                test_name=name,
                category=_CAT,
                description="No tools registered — nothing to check.",
                duration_ms=duration,
            )

        if empty:
            return TestResult(
                test_id=tid,
                test_name=name,
                category=_CAT,
                severity=Severity.INFO,
                passed=False,
                description=(
                    f"{len(empty)} tool(s) have empty descriptions: "
                    f"{', '.join(empty)}."
                ),
                duration_ms=duration,
                details="\n".join(empty),
                remediation=(
                    "Add meaningful descriptions to all tools so that LLM agents "
                    "can correctly decide when and how to call them."
                ),
            )

        return TestResult.make_pass(
            test_id=tid,
            test_name=name,
            category=_CAT,
            description=f"All {len(tools)} tool(s) have non-empty descriptions.",
            duration_ms=duration,
        )

    except Exception as exc:
        return TestResult.from_exception(
            test_id=tid,
            test_name=name,
            category=_CAT,
            exc=exc,
            duration_ms=(time.perf_counter() - t0) * 1000.0,
        )


def _validate_json_schema(schema: Any) -> Optional[str]:
    """
    Lightweight JSON Schema object validator.

    Returns ``None`` when valid, or an error string when invalid.
    A valid tool inputSchema must be a JSON object (dict) with at least a
    ``"type"`` key whose value is ``"object"`` (MCP convention).
    """
    if not isinstance(schema, dict):
        return f"inputSchema is {type(schema).__name__!r}, expected a dict/object"
    if "type" not in schema:
        return "inputSchema missing required 'type' key"
    if schema.get("type") != "object":
        return f"inputSchema['type'] is {schema['type']!r}, expected 'object'"
    props = schema.get("properties")
    if props is not None and not isinstance(props, dict):
        return f"inputSchema['properties'] is {type(props).__name__!r}, expected a dict"
    return None  # valid


async def _t01_006_tool_schema_validity(
    session: ClientSession,
    server_info: ServerInfo,
) -> TestResult:
    """T01-006 — Every tool's inputSchema must be a valid JSON Schema object."""
    tid = "T01-006"
    name = "Tool Schema Validity"
    t0 = time.perf_counter()
    try:
        tools = server_info.tools
        invalid: list[tuple[str, str]] = []

        for tool in tools:
            error = _validate_json_schema(tool.input_schema)
            if error:
                invalid.append((tool.name, error))

        duration = (time.perf_counter() - t0) * 1000.0

        if not tools:
            return TestResult.make_pass(
                test_id=tid,
                test_name=name,
                category=_CAT,
                description="No tools registered — nothing to check.",
                duration_ms=duration,
            )

        if invalid:
            detail_lines = [f"  {tname}: {err}" for tname, err in invalid]
            return TestResult.make_fail(
                test_id=tid,
                test_name=name,
                category=_CAT,
                severity=Severity.MEDIUM,
                description=(
                    f"{len(invalid)} tool(s) have invalid inputSchema: "
                    f"{', '.join(n for n, _ in invalid)}."
                ),
                duration_ms=duration,
                details="\n".join(detail_lines),
                remediation=(
                    "Ensure every tool's 'inputSchema' is a well-formed JSON Schema "
                    "object with at least {'type': 'object', 'properties': {...}}. "
                    "Malformed schemas can cause type-confusion attacks."
                ),
            )

        return TestResult.make_pass(
            test_id=tid,
            test_name=name,
            category=_CAT,
            description=f"All {len(tools)} tool(s) have valid JSON Schema inputSchema.",
            duration_ms=duration,
        )

    except Exception as exc:
        return TestResult.from_exception(
            test_id=tid,
            test_name=name,
            category=_CAT,
            exc=exc,
            duration_ms=(time.perf_counter() - t0) * 1000.0,
        )


async def _t01_007_duplicate_tool_names(
    session: ClientSession,
    server_info: ServerInfo,
) -> TestResult:
    """T01-007 — Tool names must be globally unique within the server."""
    tid = "T01-007"
    name = "Duplicate Tool Names"
    t0 = time.perf_counter()
    try:
        tools = server_info.tools
        seen: dict[str, int] = {}
        for t in tools:
            seen[t.name] = seen.get(t.name, 0) + 1

        duplicates = {n: c for n, c in seen.items() if c > 1}
        duration = (time.perf_counter() - t0) * 1000.0

        if duplicates:
            detail_lines = [f"  {n!r}: appears {c} times" for n, c in duplicates.items()]
            return TestResult.make_fail(
                test_id=tid,
                test_name=name,
                category=_CAT,
                severity=Severity.HIGH,
                description=(
                    f"Found {len(duplicates)} duplicate tool name(s): "
                    f"{', '.join(duplicates)}."
                ),
                duration_ms=duration,
                details="\n".join(detail_lines),
                remediation=(
                    "Tool names must be unique. Duplicate names allow a malicious "
                    "server update ('rug pull') to silently shadow a trusted tool "
                    "with a differently-behaved one without the LLM noticing."
                ),
            )

        return TestResult.make_pass(
            test_id=tid,
            test_name=name,
            category=_CAT,
            description=f"All {len(tools)} tool name(s) are unique.",
            duration_ms=duration,
        )

    except Exception as exc:
        return TestResult.from_exception(
            test_id=tid,
            test_name=name,
            category=_CAT,
            exc=exc,
            duration_ms=(time.perf_counter() - t0) * 1000.0,
        )


async def _t01_008_description_length(
    session: ClientSession,
    server_info: ServerInfo,
) -> TestResult:
    """T01-008 — Tool descriptions longer than 2 000 chars are a poisoning vector."""
    tid = "T01-008"
    name = "Tool Description Length"
    t0 = time.perf_counter()
    try:
        tools = server_info.tools
        long_desc: list[tuple[str, int]] = [
            (t.name, len(t.description))
            for t in tools
            if len(t.description) > _MAX_DESC_LEN
        ]
        duration = (time.perf_counter() - t0) * 1000.0

        if not tools:
            return TestResult.make_pass(
                test_id=tid,
                test_name=name,
                category=_CAT,
                description="No tools registered — nothing to check.",
                duration_ms=duration,
            )

        if long_desc:
            detail_lines = [
                f"  {tname!r}: {length:,} chars (limit {_MAX_DESC_LEN:,})"
                for tname, length in long_desc
            ]
            return TestResult.make_fail(
                test_id=tid,
                test_name=name,
                category=_CAT,
                severity=Severity.MEDIUM,
                description=(
                    f"{len(long_desc)} tool(s) have descriptions exceeding "
                    f"{_MAX_DESC_LEN:,} characters — potential tool-poisoning vector."
                ),
                duration_ms=duration,
                details="\n".join(detail_lines),
                remediation=(
                    "Unusually long tool descriptions can embed hidden instructions "
                    "that hijack LLM behaviour (prompt-injection via tool metadata). "
                    "Keep descriptions concise and audit any description > 2 000 chars."
                ),
            )

        return TestResult.make_pass(
            test_id=tid,
            test_name=name,
            category=_CAT,
            description=(
                f"All {len(tools)} tool description(s) are within "
                f"the {_MAX_DESC_LEN:,}-character limit."
            ),
            duration_ms=duration,
        )

    except Exception as exc:
        return TestResult.from_exception(
            test_id=tid,
            test_name=name,
            category=_CAT,
            exc=exc,
            duration_ms=(time.perf_counter() - t0) * 1000.0,
        )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

_TESTS = [
    _t01_001_server_identity,
    _t01_002_tool_enumeration,
    _t01_003_resource_enumeration,
    _t01_004_prompt_enumeration,
    _t01_005_tool_descriptions,
    _t01_006_tool_schema_validity,
    _t01_007_duplicate_tool_names,
    _t01_008_description_length,
]


async def run(session: ClientSession, server_info: ServerInfo) -> list[TestResult]:
    """
    Execute all T01 discovery tests against the connected MCP server.

    Parameters
    ----------
    session:
        An initialised ``mcp.ClientSession`` (from ``MCPConnection``).
    server_info:
        Populated ``ServerInfo`` from the transport discovery phase.

    Returns
    -------
    list[TestResult]:
        Exactly 8 results — one per test.  No exception can propagate out;
        each test is individually wrapped in try/except.
    """
    results: list[TestResult] = []
    for test_fn in _TESTS:
        result = await test_fn(session, server_info)
        results.append(result)
    return results
