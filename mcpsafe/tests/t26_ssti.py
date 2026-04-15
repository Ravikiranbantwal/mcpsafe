"""
mcpsafe.tests.t26_ssti
========================
SECURITY category — **Server-Side Template Injection**.

If a tool argument is rendered through a template engine on the server
(Jinja2, Handlebars, ERB, Velocity, Freemarker, etc.) without escaping,
the attacker can execute code in the template sandbox — often leading
to RCE.

This module sends template-syntax primitives and looks for **evaluated
output** rather than the payload echo.

Primitives
----------
SSTI-001  Jinja2 / Twig arithmetic    ``{{7*7}}``        → expect ``49``
SSTI-002  Jinja2 string concat        ``{{"foo"+"bar"}}`` → expect ``foobar``
SSTI-003  Handlebars arithmetic       ``{{#with 7}}{{this}}{{/with}}``
SSTI-004  ERB ruby inline             ``<%= 7*7 %>``      → expect ``49``
SSTI-005  Freemarker                  ``${7*7}``          → expect ``49``
SSTI-006  Velocity                    ``#set($x=7*7)$x``  → expect ``49``
SSTI-007  JSP expression              ``${7*7}``          → expect ``49``
SSTI-008  Smarty                      ``{$var=7*7}{$var}`` → expect ``49``
SSTI-009  Razor (C#)                  ``@(7*7)``          → expect ``49``
SSTI-010  Mako                        ``<%= 7*7 %>``      → expect ``49``

Detection
---------
Every primitive produces a distinctive NUMBER (49 or ``foobar``) that
is UNLIKELY to appear in the response by chance. If the number is in
the cleaned response, evaluation occurred → CRITICAL.
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

_CALL_TIMEOUT_SEC = 6.0
_MAX_TEST_ID_LEN = 64
_MAX_TOOLS_PROBED = 4

_LONG_RUNNING_KW = frozenset({
    "long_running", "long-running", "trigger_long", "trigger-long",
    "sleep", "wait", "delay",
})


def _is_long_running(n: str) -> bool:
    return any(kw in (n or "").lower() for kw in _LONG_RUNNING_KW)

# (id, label, payload, expected_eval_result)
_PAYLOADS: tuple[tuple[str, str, str, str], ...] = (
    ("SSTI-001", "Jinja/Twig {{7*7}}",      "mcpsafe-{{7*7}}-probe",                "49"),
    ("SSTI-002", "Jinja concat",            'mcpsafe-{{"foo"+"bar"}}-probe',        "foobar"),
    ("SSTI-003", "Handlebars #with",        "mcpsafe-{{#with 7}}{{this}}{{/with}}-probe", "7"),
    ("SSTI-004", "ERB <%= 7*7 %>",          "mcpsafe-<%= 7*7 %>-probe",             "49"),
    ("SSTI-005", "Freemarker ${7*7}",       "mcpsafe-${7*7}-probe",                 "49"),
    ("SSTI-006", "Velocity #set",           "mcpsafe-#set($x=7*7)$x-probe",         "49"),
    ("SSTI-007", "JSP ${7*7}",              "mcpsafe-${7*7}-probe-jsp",             "49"),
    ("SSTI-008", "Smarty {$x=7*7}",         "mcpsafe-{$x=7*7}{$x}-probe",           "49"),
    ("SSTI-009", "Razor @(7*7)",            "mcpsafe-@(7*7)-probe",                 "49"),
    ("SSTI-010", "Mako <%= 7*7 %>",         "mcpsafe-<%= 7*7 %>-probe-mako",        "49"),
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
    expected: str,
    limiter: RateLimiter,
) -> TestResult:
    tid = f"T26-TOOL-{_slug(tool.name)}-{pid}"
    if len(tid) > _MAX_TEST_ID_LEN:
        tid = tid[:_MAX_TEST_ID_LEN]
    tname = f"SSTI {pid} → {tool.name}"
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
    cleaned = combined.replace(payload, "[PAYLOAD]")
    # Also strip payload with expected result baked in (accidental match guard)
    # e.g. original payload includes "7*7" so "49" appearing elsewhere is the tell.

    # Accidental-match guard: ``49`` is a common number. Require that we see
    # ``mcpsafe-49-probe`` (or equivalent) — i.e. the expected string
    # appears BETWEEN our literal marker prefix and suffix.
    # Pattern: look for "mcpsafe-<expected>-" anywhere in cleaned.
    marker_re = re.compile(
        re.escape("mcpsafe-") + re.escape(expected) + r"[-\w]", re.IGNORECASE
    )
    m = marker_re.search(combined)  # search raw text; cleaned might have stripped bridge
    if m:
        idx = m.start()
        excerpt = combined[max(0, idx - 20): m.end() + 20]
        return TestResult(
            test_id=tid, test_name=tname,
            category=Category.SECURITY, severity=Severity.CRITICAL,
            passed=False,
            description=(
                f"Server-Side Template Injection confirmed on {tool.name!r}. "
                f"Payload {label} was evaluated: expected output {expected!r} "
                f"found in response between our marker brackets."
            ),
            duration_ms=duration,
            details=f"Payload: {payload!r}\nExcerpt: {excerpt!r}",
            remediation=(
                "Never pass untrusted input through a template engine. Render "
                "user data with .text() / {{| escape }} / an equivalent HTML-"
                "escaping helper. If template evaluation is required, restrict "
                "to a strict sandbox that forbids attribute access on globals."
            ),
        )

    if err and looks_like_api_rejection([err]):
        return TestResult(
            test_id=tid, test_name=tname,
            category=Category.SECURITY, severity=Severity.INFO, passed=True,
            description=f"Tool {tool.name!r} rejected {label} at the API layer.",
            duration_ms=duration, details=err[:200],
        )

    return TestResult.make_pass(
        test_id=tid, test_name=tname, category=Category.SECURITY,
        description=f"No template evaluation detected for {label} on {tool.name!r}.",
        duration_ms=duration,
    )


async def run(
    session: ClientSession,
    server_info: ServerInfo,
    config: ScanConfig,
) -> list[TestResult]:
    """Execute T26 — Server-Side Template Injection."""
    t_start = time.perf_counter()
    results: list[TestResult] = []
    limiter = RateLimiter(config)

    candidates = [
        t for t in (server_info.tools or [])
        if _first_string_param(t) and not _is_long_running(t.name)
    ][:_MAX_TOOLS_PROBED]

    for tool in candidates:
        pname = _first_string_param(tool) or ""
        for pid, label, payload, expected in _PAYLOADS:
            results.append(await _probe(
                session, tool, pname, pid, label, payload, expected, limiter
            ))

    crit = sum(1 for r in results if r.severity == Severity.CRITICAL and not r.passed)
    if crit:
        results.append(TestResult.make_fail(
            test_id="T26-001", test_name="SSTI — Summary",
            category=Category.SECURITY, severity=Severity.CRITICAL,
            description=f"{crit} confirmed SSTI finding(s) across probed tools.",
            duration_ms=(time.perf_counter() - t_start) * 1000.0,
        ))
    else:
        results.append(TestResult.make_pass(
            test_id="T26-001", test_name="SSTI — Summary",
            category=Category.SECURITY,
            description=f"No SSTI detected across {len(candidates)} probed tool(s).",
            duration_ms=(time.perf_counter() - t_start) * 1000.0,
        ))
    return results
