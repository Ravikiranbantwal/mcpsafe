"""
mcpsafe.tests.t06_schema
=========================
SCHEMA category — JSON Schema correctness and server-side enforcement tests.

Test inventory
--------------
T06-001  Schema structural validity     Verify every tool's inputSchema is a
                                        well-formed JSON Schema object.
T06-002  Required field enforcement     Call each tool with an empty argument
                                        dict; verify the server rejects it when
                                        required fields are defined.
T06-003  additionalProperties strictness
                                        Flag tools missing
                                        "additionalProperties": false.
T06-004  Return-type consistency        Call each callable tool twice with
                                        identical inputs; compare response keys.
T06-005  Overly permissive schema       Flag properties missing "type" and
                                        schemas with no structure at all.

Public API
----------
    async def run(
        session: ClientSession,
        server_info: ServerInfo,
    ) -> list[TestResult]
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Optional

from mcp import ClientSession

from mcpsafe.models import (
    Category,
    ServerInfo,
    Severity,
    TestResult,
)

_CAT = Category.SCHEMA
_CALL_TIMEOUT = 30.0   # seconds per tool call

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _extract_text(response: object) -> str:
    """Flatten an MCP response to a plain string."""
    try:
        from mcp.types import TextContent
        items = response if isinstance(response, list) else [response]
        parts: list[str] = []
        for item in items:
            if isinstance(item, TextContent):
                parts.append(item.text or "")
            elif hasattr(item, "text"):
                parts.append(str(item.text))
            else:
                parts.append(str(item))
        return "\n".join(parts)
    except Exception:
        return str(response)


def _response_is_error(response: object) -> bool:
    """Return True if the MCP response indicates an error."""
    if hasattr(response, "isError"):
        return bool(response.isError)
    text = _extract_text(response).lower()
    return any(s in text for s in ("error", "invalid", "required", "missing",
                                   "exception", "failed", "validation"))


def _try_parse_json_keys(text: str) -> Optional[set[str]]:
    """
    Try to parse the text as JSON and return the top-level keys.
    Returns ``None`` if the text is not valid JSON or not a dict.
    """
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return set(obj.keys())
    except (json.JSONDecodeError, ValueError):
        pass
    return None


async def _safe_call(
    session: ClientSession,
    tool_name: str,
    args: dict,
) -> tuple[Optional[object], Optional[Exception]]:
    """
    Call a tool and return ``(response, None)`` on success or
    ``(None, exception)`` on failure.  Never raises.
    """
    try:
        resp = await asyncio.wait_for(
            session.call_tool(tool_name, arguments=args),
            timeout=_CALL_TIMEOUT,
        )
        return resp, None
    except Exception as exc:
        return None, exc


# ---------------------------------------------------------------------------
# T06-001 — Schema structural validity
# ---------------------------------------------------------------------------


async def _t06_001_schema_validity(
    session: ClientSession,
    server_info: ServerInfo,
) -> TestResult:
    """T06-001 — Verify every tool's inputSchema is a valid JSON Schema object."""
    tid = "T06-001"
    tname = "Schema Structural Validity"
    t0 = time.perf_counter()
    try:
        failures: list[str] = []

        for tool in server_info.tools:
            schema = tool.input_schema
            errs: list[str] = []

            if not isinstance(schema, dict):
                errs.append(f"inputSchema is {type(schema).__name__}, expected dict")
            else:
                if schema.get("type") != "object":
                    errs.append(
                        f"top-level type={schema.get('type')!r}, expected 'object'"
                    )
                required = schema.get("required")
                props = schema.get("properties")
                if required is not None:
                    if not isinstance(props, dict):
                        errs.append(
                            "'required' present but 'properties' is missing or not a dict"
                        )
                    elif isinstance(required, list):
                        missing_props = [
                            r for r in required
                            if r not in props
                        ]
                        if missing_props:
                            errs.append(
                                f"required fields not in properties: {missing_props}"
                            )

            if errs:
                failures.append(f"  {tool.name!r}: " + "; ".join(errs))

        duration = (time.perf_counter() - t0) * 1000.0

        if not server_info.tools:
            return TestResult.make_pass(
                test_id=tid, test_name=tname, category=_CAT,
                description="No tools registered — schema validity check skipped.",
                duration_ms=duration,
            )

        if failures:
            return TestResult.make_fail(
                test_id=tid, test_name=tname, category=_CAT,
                severity=Severity.MEDIUM,
                description=(
                    f"{len(failures)}/{len(server_info.tools)} tool(s) have "
                    f"structurally invalid inputSchema."
                ),
                duration_ms=duration,
                details="\n".join(failures),
                remediation=(
                    "Each tool's inputSchema must be a JSON Schema object with "
                    "'type': 'object', and every field listed in 'required' must "
                    "appear in 'properties'."
                ),
            )

        return TestResult.make_pass(
            test_id=tid, test_name=tname, category=_CAT,
            description=(
                f"All {len(server_info.tools)} tool inputSchema(s) are "
                f"structurally valid."
            ),
            duration_ms=duration,
        )

    except Exception as exc:
        return TestResult.from_exception(
            test_id=tid, test_name=tname, category=_CAT, exc=exc,
            duration_ms=(time.perf_counter() - t0) * 1000.0,
        )


# ---------------------------------------------------------------------------
# T06-002 — Required field enforcement
# ---------------------------------------------------------------------------


async def _t06_002_required_enforcement(
    session: ClientSession,
    server_info: ServerInfo,
) -> list[TestResult]:
    """
    T06-002 — Call each tool with {} and verify the server rejects it when
    required fields are declared.  One result per tool tested.
    """
    results: list[TestResult] = []

    tools_with_required = [
        t for t in server_info.tools
        if isinstance(t.input_schema, dict)
        and isinstance(t.input_schema.get("required"), list)
        and len(t.input_schema["required"]) > 0
    ]

    if not tools_with_required:
        results.append(
            TestResult(
                test_id="T06-002", test_name="Required Field Enforcement",
                category=_CAT, severity=Severity.INFO, passed=True,
                description=(
                    "No tools with 'required' fields found — "
                    "enforcement test skipped."
                ),
                duration_ms=0.0,
            )
        )
        return results

    for tool in tools_with_required:
        tid = f"T06-002-{tool.name[:32]}"
        tname = f"Required Enforcement: {tool.name}"
        t0 = time.perf_counter()
        try:
            resp, exc = await _safe_call(session, tool.name, {})
            duration = (time.perf_counter() - t0) * 1000.0

            if exc is not None:
                # Exception = server rejected the call — correct behaviour.
                results.append(
                    TestResult.make_pass(
                        test_id=tid, test_name=tname, category=_CAT,
                        description=(
                            f"Tool {tool.name!r} correctly raised an error when "
                            f"called with missing required fields."
                        ),
                        duration_ms=duration,
                        details=f"{type(exc).__name__}: {str(exc)[:200]}",
                    )
                )
                continue

            # No exception — check if the response itself signals an error.
            if _response_is_error(resp):
                results.append(
                    TestResult.make_pass(
                        test_id=tid, test_name=tname, category=_CAT,
                        description=(
                            f"Tool {tool.name!r} returned an error response for "
                            f"missing required fields."
                        ),
                        duration_ms=duration,
                    )
                )
                continue

            # Server accepted an empty call despite required fields — flag it.
            required = tool.input_schema.get("required", [])
            results.append(
                TestResult.make_fail(
                    test_id=tid, test_name=tname, category=_CAT,
                    severity=Severity.MEDIUM,
                    description=(
                        f"Tool {tool.name!r} accepted a call with all required "
                        f"fields missing."
                    ),
                    duration_ms=duration,
                    details=(
                        f"Tool '{tool.name}' accepted call with all required "
                        f"fields missing\nRequired: {required}"
                    ),
                    remediation=(
                        "Validate required parameters at the tool entry point and "
                        "return a descriptive error when any are absent. Silently "
                        "proceeding with missing fields leads to undefined behaviour."
                    ),
                )
            )

        except Exception as exc:
            results.append(
                TestResult.from_exception(
                    test_id=tid, test_name=tname, category=_CAT, exc=exc,
                    duration_ms=(time.perf_counter() - t0) * 1000.0,
                )
            )

    return results


# ---------------------------------------------------------------------------
# T06-003 — additionalProperties strictness
# ---------------------------------------------------------------------------


async def _t06_003_additional_properties(
    session: ClientSession,
    server_info: ServerInfo,
) -> TestResult:
    """T06-003 — Check each tool for 'additionalProperties': false."""
    tid = "T06-003"
    tname = "additionalProperties Strictness"
    t0 = time.perf_counter()
    try:
        missing: list[str] = []
        for tool in server_info.tools:
            schema = tool.input_schema
            if not isinstance(schema, dict):
                continue
            if schema.get("additionalProperties") is not False:
                missing.append(tool.name)

        duration = (time.perf_counter() - t0) * 1000.0

        if not server_info.tools:
            return TestResult.make_pass(
                test_id=tid, test_name=tname, category=_CAT,
                description="No tools registered.",
                duration_ms=duration,
            )

        if missing:
            return TestResult(
                test_id=tid, test_name=tname, category=_CAT,
                severity=Severity.INFO, passed=True,
                description=(
                    f"{len(missing)}/{len(server_info.tools)} tool(s) missing "
                    f"'additionalProperties': false."
                ),
                duration_ms=duration,
                details=(
                    "Tools missing additionalProperties:false: "
                    + ", ".join(missing)
                ),
                remediation=(
                    "Adding 'additionalProperties': false to every inputSchema "
                    "prevents callers from silently passing undeclared fields "
                    "that could confuse server-side processing."
                ),
            )

        return TestResult.make_pass(
            test_id=tid, test_name=tname, category=_CAT,
            description=(
                f"All {len(server_info.tools)} tool(s) have "
                f"'additionalProperties': false."
            ),
            duration_ms=duration,
        )

    except Exception as exc:
        return TestResult.from_exception(
            test_id=tid, test_name=tname, category=_CAT, exc=exc,
            duration_ms=(time.perf_counter() - t0) * 1000.0,
        )


# ---------------------------------------------------------------------------
# T06-004 — Return-type consistency
# ---------------------------------------------------------------------------


async def _t06_004_return_consistency(
    session: ClientSession,
    server_info: ServerInfo,
) -> list[TestResult]:
    """
    T06-004 — Call each tool twice with identical inputs and compare response keys.
    One result per tool tested.
    """
    results: list[TestResult] = []

    # Only test tools we can call without required args, or with empty args.
    callable_tools = [
        t for t in server_info.tools
        if not (
            isinstance(t.input_schema, dict)
            and isinstance(t.input_schema.get("required"), list)
            and len(t.input_schema["required"]) > 0
        )
    ]

    if not callable_tools:
        results.append(
            TestResult(
                test_id="T06-004", test_name="Return Type Consistency",
                category=_CAT, severity=Severity.INFO, passed=True,
                description=(
                    "All tools have required fields — return-type consistency "
                    "test skipped."
                ),
                duration_ms=0.0,
            )
        )
        return results

    for tool in callable_tools:
        tid = f"T06-004-{tool.name[:32]}"
        tname = f"Return Consistency: {tool.name}"
        t0 = time.perf_counter()
        try:
            resp1, exc1 = await _safe_call(session, tool.name, {})
            resp2, exc2 = await _safe_call(session, tool.name, {})
            duration = (time.perf_counter() - t0) * 1000.0

            if exc1 is not None or exc2 is not None:
                # Tool errors on empty call — skip without flagging.
                continue

            text1 = _extract_text(resp1)
            text2 = _extract_text(resp2)

            keys1 = _try_parse_json_keys(text1)
            keys2 = _try_parse_json_keys(text2)

            if keys1 is None or keys2 is None:
                # Non-JSON responses — skip without flagging.
                continue

            if keys1 != keys2:
                results.append(
                    TestResult.make_fail(
                        test_id=tid, test_name=tname, category=_CAT,
                        severity=Severity.MEDIUM,
                        description=(
                            f"Tool {tool.name!r} returned different top-level "
                            f"JSON keys across two identical calls."
                        ),
                        duration_ms=duration,
                        details=(
                            f"Call 1 keys: {sorted(keys1)}\n"
                            f"Call 2 keys: {sorted(keys2)}\n"
                            f"Added: {sorted(keys2 - keys1)}\n"
                            f"Removed: {sorted(keys1 - keys2)}"
                        ),
                        remediation=(
                            "Tool responses must have a stable schema. "
                            "Non-deterministic response shapes break clients "
                            "that rely on a fixed structure."
                        ),
                    )
                )
            else:
                results.append(
                    TestResult.make_pass(
                        test_id=tid, test_name=tname, category=_CAT,
                        description=(
                            f"Tool {tool.name!r} returned consistent response "
                            f"keys across two identical calls."
                        ),
                        duration_ms=duration,
                        details=f"Keys: {sorted(keys1)}",
                    )
                )

        except Exception as exc:
            results.append(
                TestResult.from_exception(
                    test_id=tid, test_name=tname, category=_CAT, exc=exc,
                    duration_ms=(time.perf_counter() - t0) * 1000.0,
                )
            )

    if not results:
        results.append(
            TestResult(
                test_id="T06-004", test_name="Return Type Consistency",
                category=_CAT, severity=Severity.INFO, passed=True,
                description=(
                    "No tools returned comparable JSON responses — "
                    "consistency check not applicable."
                ),
                duration_ms=0.0,
            )
        )

    return results


# ---------------------------------------------------------------------------
# T06-005 — Overly permissive schema detection
# ---------------------------------------------------------------------------


async def _t06_005_permissive_schemas(
    session: ClientSession,
    server_info: ServerInfo,
) -> list[TestResult]:
    """
    T06-005 — Flag properties missing 'type' and schemas with no structure.
    One result per tool with findings; one PASS if all schemas are acceptably strict.
    """
    results: list[TestResult] = []
    t0 = time.perf_counter()

    # All permitted multi-type values that mean "accept anything".
    _ALL_TYPES = frozenset({"string", "number", "boolean", "null", "array", "object"})

    for tool in server_info.tools:
        schema = tool.input_schema
        if not isinstance(schema, dict):
            continue

        tool_findings: list[tuple[Severity, str]] = []

        props = schema.get("properties")
        required = schema.get("required")

        # Check 1: top-level schema with no properties AND no required.
        if not isinstance(props, dict) and not isinstance(required, list):
            tool_findings.append((
                Severity.MEDIUM,
                "Top-level schema has neither 'properties' nor 'required' — "
                "accepts any input without validation.",
            ))

        # Check 2: individual property issues.
        if isinstance(props, dict):
            for pname, pschema in props.items():
                if not isinstance(pschema, dict):
                    continue

                ptype = pschema.get("type")

                # Missing type entirely.
                if ptype is None:
                    tool_findings.append((
                        Severity.LOW,
                        f"Property {pname!r} missing 'type' field.",
                    ))
                    continue

                # type is a list containing all JSON types.
                if isinstance(ptype, list) and _ALL_TYPES.issubset(set(ptype)):
                    tool_findings.append((
                        Severity.LOW,
                        f"Property {pname!r} allows all types: {ptype}.",
                    ))

        if not tool_findings:
            continue

        # Determine worst severity among findings for this tool.
        worst = max(sev for sev, _ in tool_findings)
        tid   = f"T06-005-{tool.name[:32]}"
        tname = f"Permissive Schema: {tool.name}"
        duration = (time.perf_counter() - t0) * 1000.0

        results.append(
            TestResult(
                test_id=tid, test_name=tname, category=_CAT,
                severity=worst, passed=False,
                description=(
                    f"Tool {tool.name!r} has {len(tool_findings)} overly "
                    f"permissive schema finding(s)."
                ),
                duration_ms=duration,
                details="\n".join(f"  [{s.value}] {msg}" for s, msg in tool_findings),
                remediation=(
                    "Declare explicit 'type' for every property and use "
                    "'required' to enforce mandatory inputs. Overly permissive "
                    "schemas allow type-confusion and injection attacks."
                ),
            )
        )

    if not results:
        duration = (time.perf_counter() - t0) * 1000.0
        results.append(
            TestResult.make_pass(
                test_id="T06-005", test_name="Overly Permissive Schema Detection",
                category=_CAT,
                description=(
                    f"All {len(server_info.tools)} tool schema(s) are "
                    f"acceptably strict."
                ),
                duration_ms=duration,
            )
        )

    return results


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


async def run(
    session: ClientSession,
    server_info: ServerInfo,
) -> list[TestResult]:
    """
    Execute all T06 JSON Schema validation tests.

    Parameters
    ----------
    session:
        An initialised ``mcp.ClientSession``.
    server_info:
        Populated ``ServerInfo`` from the discovery phase.

    Returns
    -------
    list[TestResult]:
        Between 5 and 5 + N results depending on how many per-tool tests run.
        Never raises.
    """
    results: list[TestResult] = []

    results.append(await _t06_001_schema_validity(session, server_info))
    results.extend(await _t06_002_required_enforcement(session, server_info))
    results.append(await _t06_003_additional_properties(session, server_info))
    results.extend(await _t06_004_return_consistency(session, server_info))
    results.extend(await _t06_005_permissive_schemas(session, server_info))

    return results
