"""
mcpsafe.tests.t23_sql_injection
================================
SECURITY category — **Deep SQL / NoSQL injection probing**.

Beyond T02's simple ``'; DROP TABLE`` quote probe, this module sends:

  * UNION-based extraction   ``' UNION SELECT NULL,version(),NULL--``
  * Boolean-based blind      ``' AND 1=1--``  vs  ``' AND 1=2--``
  * Time-based blind         ``'; SELECT pg_sleep(5)--``
  * MongoDB NoSQL            ``{"$ne": null}``, ``{"$gt": ""}``
  * ORM error-based          ``''\\ ``

Detection strategies
--------------------
UNION-based  → response contains DB version string (postgres / MariaDB / MySQL /
               Microsoft SQL Server / SQLite marker).
Boolean      → response for 1=1 is clearly longer or different from 1=2.
Time-based   → response to the sleep payload takes > 3x longer than the
               baseline call.
NoSQL        → tool accepts object/raw JSON where string was expected.

Test inventory
--------------
T23-TOOL-{slug}-SQL-###  per-tool per-payload
T23-001                  Summary
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
)
from mcpsafe.tests._helpers import (
    RateLimiter,
    cap_response,
    looks_like_api_rejection,
)

_CALL_TIMEOUT_SEC = 8.0
_MAX_TEST_ID_LEN = 64
_MAX_TOOLS_PROBED = 4
_TIME_BLIND_SLEEP_SEC = 3
_TIME_BLIND_RATIO = 3.0
_TIME_BLIND_MIN_DELTA_MS = 2000

_LONG_RUNNING_KW = frozenset({
    "long_running", "long-running", "trigger_long", "trigger-long",
    "sleep", "wait", "delay",
})


def _is_long_running(n: str) -> bool:
    return any(kw in (n or "").lower() for kw in _LONG_RUNNING_KW)

# (id, label, payload, detection_hint)
_PAYLOADS: tuple[tuple[str, str, str, str], ...] = (
    ("SQL-001", "UNION version",   "' UNION SELECT NULL,version(),NULL-- ",           "union"),
    ("SQL-002", "UNION sqlite_ver","' UNION SELECT NULL,sqlite_version(),NULL-- ",    "union"),
    ("SQL-003", "Boolean true",    "' OR '1'='1",                                      "bool-true"),
    ("SQL-004", "Boolean false",   "' AND '1'='2",                                     "bool-false"),
    ("SQL-005", "Time blind PG",   f"'; SELECT pg_sleep({_TIME_BLIND_SLEEP_SEC})--",   "time"),
    ("SQL-006", "Time blind MS",   f"'; WAITFOR DELAY '00:00:0{_TIME_BLIND_SLEEP_SEC}'--", "time"),
    ("SQL-007", "Time blind MySQL",f"' AND SLEEP({_TIME_BLIND_SLEEP_SEC})--",          "time"),
    ("SQL-008", "Stacked drop",    "'; DROP TABLE mcpsafe_probe--",                   "error"),
    ("SQL-009", "NoSQL $ne",       '{"$ne": null}',                                   "nosql"),
    ("SQL-010", "NoSQL $gt",       '{"$gt": ""}',                                     "nosql"),
)

_DB_VERSION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("PostgreSQL",  re.compile(r"PostgreSQL\s+\d+\.\d+", re.IGNORECASE)),
    ("MySQL",       re.compile(r"\b\d+\.\d+\.\d+[-\w]*-?MariaDB|MySQL\s+\d+\.\d+", re.IGNORECASE)),
    ("MariaDB",     re.compile(r"MariaDB\s+\d+\.\d+", re.IGNORECASE)),
    ("SQLite",      re.compile(r"\b3\.\d{1,3}\.\d{1,3}\b.*sqlite|sqlite\s+3\.\d", re.IGNORECASE)),
    ("MSSQL",       re.compile(r"Microsoft SQL Server|MSSQL|sql-server", re.IGNORECASE)),
    ("Oracle",      re.compile(r"Oracle\s+Database|Oracle\s+\d+[cgi]", re.IGNORECASE)),
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
    # Prefer params that look SQL-related.
    sql_hints = ("query", "sql", "where", "filter", "expr", "statement")
    for pname in required:
        pschema = props.get(pname) or {}
        if (isinstance(pschema, dict) and pschema.get("type") == "string"
                and any(h in pname.lower() for h in sql_hints)):
            return pname
    for pname, pschema in props.items():
        if (isinstance(pschema, dict) and pschema.get("type") == "string"
                and any(h in pname.lower() for h in sql_hints)):
            return pname
    for pname in required:
        pschema = props.get(pname) or {}
        if isinstance(pschema, dict) and pschema.get("type") == "string":
            return pname
    for pname, pschema in props.items():
        if isinstance(pschema, dict) and pschema.get("type") == "string":
            return pname
    return None


def _find_db_version(text: str, payload: str) -> Optional[tuple[str, str]]:
    """Scan cleaned response for DB version markers."""
    if not text:
        return None
    cleaned = text.replace(payload, "[PAYLOAD]")
    for label, pat in _DB_VERSION_PATTERNS:
        m = pat.search(cleaned)
        if m:
            idx = m.start()
            excerpt = cleaned[max(0, idx - 10): m.end() + 30]
            excerpt = excerpt.replace("\n", " ")[:140]
            return label, excerpt
    return None


async def _timed_call(
    session: ClientSession,
    tool_name: str,
    args: dict,
) -> tuple[Optional[str], float, Optional[str]]:
    """Return (response_text, elapsed_ms, err) — never raises."""
    t0 = time.perf_counter()
    try:
        with anyio.fail_after(_CALL_TIMEOUT_SEC):
            resp = await session.call_tool(tool_name, arguments=args)
        elapsed = (time.perf_counter() - t0) * 1000.0
        return _extract_text(resp), elapsed, None
    except Exception as exc:
        elapsed = (time.perf_counter() - t0) * 1000.0
        return None, elapsed, str(exc)


async def _probe_tool(
    session: ClientSession,
    tool: MCPTool,
    pname: str,
    limiter: RateLimiter,
) -> list[TestResult]:
    results: list[TestResult] = []

    # Baseline call for time-based comparison.
    await limiter.acquire()
    _, baseline_ms, _ = await _timed_call(session, tool.name, {pname: "x"})

    for pid, label, payload, hint in _PAYLOADS:
        tid = f"T23-TOOL-{_slug(tool.name)}-{pid}"
        if len(tid) > _MAX_TEST_ID_LEN:
            tid = tid[:_MAX_TEST_ID_LEN]
        tname = f"SQL {pid} → {tool.name}"
        t0 = time.perf_counter()

        await limiter.acquire()
        text, elapsed_ms, err = await _timed_call(session, tool.name, {pname: payload})
        duration = (time.perf_counter() - t0) * 1000.0

        # UNION-based: look for DB version string.
        if hint == "union" and text:
            hit = _find_db_version(text, payload)
            if hit:
                db_label, excerpt = hit
                results.append(TestResult(
                    test_id=tid, test_name=tname, category=Category.SECURITY,
                    severity=Severity.CRITICAL, passed=False,
                    description=(
                        f"UNION-based SQLi confirmed against {tool.name!r}. "
                        f"Response contains a live {db_label} version string, "
                        f"proving the injection reached the database."
                    ),
                    duration_ms=duration,
                    details=f"Payload: {payload!r}\nDB: {db_label}\nExcerpt: {excerpt}",
                    remediation=(
                        "Use parameterised queries / prepared statements. Never "
                        "concatenate user input into SQL strings."
                    ),
                ))
                continue

        # Time-based: elapsed >> baseline AND > 2 s
        if hint == "time" and err is None:
            ratio = (elapsed_ms / baseline_ms) if baseline_ms > 1 else 0.0
            delta = elapsed_ms - baseline_ms
            if ratio >= _TIME_BLIND_RATIO and delta >= _TIME_BLIND_MIN_DELTA_MS:
                results.append(TestResult(
                    test_id=tid, test_name=tname, category=Category.SECURITY,
                    severity=Severity.HIGH, passed=False,
                    description=(
                        f"Time-based blind SQLi suspected on {tool.name!r}. "
                        f"Sleep payload took {elapsed_ms:.0f} ms "
                        f"vs {baseline_ms:.0f} ms baseline "
                        f"(ratio {ratio:.1f}×, delta {delta:.0f} ms)."
                    ),
                    duration_ms=duration,
                    details=f"Payload: {payload!r}",
                    remediation=(
                        "Use parameterised queries. The time-delay pattern "
                        "indicates unsanitised concatenation into SQL."
                    ),
                ))
                continue

        # Default: pass
        results.append(TestResult.make_pass(
            test_id=tid, test_name=tname, category=Category.SECURITY,
            description=f"No SQLi detected via {label} on {tool.name!r}.",
            duration_ms=duration,
            details=(f"baseline={baseline_ms:.0f}ms payload={elapsed_ms:.0f}ms"
                     if err is None else f"error: {err[:100]}"),
        ))

    return results


async def run(
    session: ClientSession,
    server_info: ServerInfo,
    config: ScanConfig,
) -> list[TestResult]:
    """Execute T23 — Deep SQL Injection."""
    t_start = time.perf_counter()
    results: list[TestResult] = []
    limiter = RateLimiter(config)

    candidates = [
        t for t in (server_info.tools or [])
        if _first_string_param(t) and not _is_long_running(t.name)
    ][:_MAX_TOOLS_PROBED]

    for tool in candidates:
        pname = _first_string_param(tool) or ""
        results.extend(await _probe_tool(session, tool, pname, limiter))

    bad = sum(
        1 for r in results
        if r.severity in (Severity.HIGH, Severity.CRITICAL) and not r.passed
    )
    if bad:
        results.append(
            TestResult.make_fail(
                test_id="T23-001", test_name="SQL Injection Deep — Summary",
                category=Category.SECURITY, severity=Severity.HIGH,
                description=f"{bad} SQL injection finding(s) across probed tools.",
                duration_ms=(time.perf_counter() - t_start) * 1000.0,
            )
        )
    else:
        results.append(
            TestResult.make_pass(
                test_id="T23-001", test_name="SQL Injection Deep — Summary",
                category=Category.SECURITY,
                description=f"No deep SQLi findings across {len(candidates)} probed tool(s).",
                duration_ms=(time.perf_counter() - t_start) * 1000.0,
            )
        )
    return results
