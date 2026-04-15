"""
mcpsafe.tests.t24_deserialization
===================================
SECURITY category — **Insecure deserialization probing**.

If a tool accepts a string that the server decodes as Python pickle,
YAML, XML, or Java serialised objects, a malicious payload can achieve
remote code execution.

This module sends representative deserialisation payloads in any
string parameter and checks for:

  * Error messages revealing the deserialiser (``_pickle.UnpicklingError``,
    ``yaml.constructor``, ``ObjectInputStream``) — LOW informational.
  * A canary that proves code execution — CRITICAL.

We do NOT weaponise payloads with real system calls; we use ``echo``
command substitution that is harmless but detectable.

Payloads
--------
DS-001  Python pickle (base64)    b64-encoded ``posix.system("echo CANARY")``
DS-002  YAML unsafe               ``!!python/object/apply:builtins.print ["CANARY"]``
DS-003  YAML Python sys.exit      ``!!python/object/apply:os.popen ["echo CANARY"]``
DS-004  XML XXE local file        SYSTEM "file:///etc/passwd"
DS-005  XML XXE parameter entity  %xxe parameter-entity probe
DS-006  Java Object header        ``aced0005`` Java serialised magic bytes (b64)
DS-007  Ruby Marshal header       ``\\x04\\x08`` Ruby marshal magic (b64)
DS-008  JSON.parse reviver        ``{\"__proto__\": {\"admin\": true}}``
"""

from __future__ import annotations

import base64
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

_CANARY = "MCPSAFE_DESER_CANARY_Z9XK4P"

# Static payloads (id, label, payload_string)
# Note: the pickle payload is a *template* — real pickles in the wild that
# contain echo of our canary would trigger. This is safe because we ship
# the base64 of a harmless ``print`` reduce — it still proves the
# deserialiser ran if the canary echoes.
_PICKLE_B64 = base64.b64encode(
    b"\x80\x04\x95#\x00\x00\x00\x00\x00\x00\x00\x8c\x08builtins\x94\x8c\x05print\x94\x93\x94\x8c\x1a"
    + _CANARY.encode() + b"\x94\x85\x94R\x94."
).decode()

# Each payload is (id, label, payload_string, canary_in_payload).
# ``canary_in_payload=True`` means the canary string is baked into the
# payload itself (e.g. ``{"__proto__": {"canary": "MCPSAFE..."}}``), so an
# echo of the payload in the response would spuriously match the
# canary-stripping detection. For those payloads we ONLY rely on deserialiser
# error-marker detection (LOW severity) and skip the CRITICAL canary path.
_PAYLOADS: tuple[tuple[str, str, str, bool], ...] = (
    ("DS-001", "Python pickle (b64)",       _PICKLE_B64, False),
    ("DS-002", "YAML !!python apply print", f"!!python/object/apply:builtins.print [{_CANARY!r}]", True),
    ("DS-003", "YAML !!python os.popen",    f"!!python/object/apply:os.popen ['echo {_CANARY}']", True),
    ("DS-004", "XML XXE file://",
     '<?xml version="1.0"?><!DOCTYPE d [<!ENTITY x SYSTEM "file:///etc/passwd">]><d>&x;</d>', False),
    ("DS-005", "XML XXE parameter entity",
     '<?xml version="1.0"?><!DOCTYPE d [<!ENTITY % x "test"> %x;]><d/>', False),
    ("DS-006", "Java serialised magic (b64)",
     base64.b64encode(b"\xac\xed\x00\x05sr\x00\x04Test" + _CANARY.encode()).decode(), False),
    ("DS-007", "Ruby Marshal magic (b64)",
     base64.b64encode(b"\x04\x08o:\x04Test" + _CANARY.encode()).decode(), False),
    ("DS-008", "JSON __proto__ pollution",
     f'{{"__proto__": {{"canary": "{_CANARY}"}}}}', True),
)

# Markers that suggest a specific deserialiser is being invoked.
_DESERIALIZER_MARKERS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("Python pickle",     re.compile(r"_pickle\.\w+Error|pickle\.UnpicklingError|can't find \S+ attribute", re.IGNORECASE)),
    ("PyYAML unsafe",     re.compile(r"yaml\.constructor\.Constructor\w*|yaml\.YAMLError|!!python/object", re.IGNORECASE)),
    ("XML parser",        re.compile(r"xml\.sax|ExpatError|lxml\.etree|DTD|undefined entity", re.IGNORECASE)),
    ("Java OIS",          re.compile(r"ObjectInputStream|StreamCorruptedException|readObject", re.IGNORECASE)),
    ("Ruby Marshal",      re.compile(r"Marshal\.load|TypeError.*marshal", re.IGNORECASE)),
    ("JSON parser error", re.compile(r"JSON\.parse|SyntaxError.*JSON|invalid JSON", re.IGNORECASE)),
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
    canary_in_payload: bool,
    limiter: RateLimiter,
) -> TestResult:
    tid = f"T24-TOOL-{_slug(tool.name)}-{pid}"
    if len(tid) > _MAX_TEST_ID_LEN:
        tid = tid[:_MAX_TEST_ID_LEN]
    tname = f"Deserialisation {pid} → {tool.name}"
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

    # Canary echo outside payload → RCE via deserialiser.
    # For payloads where the canary lives INSIDE the payload (YAML apply,
    # os.popen, __proto__ pollution), literal payload-stripping cannot
    # distinguish a benign echo from real evaluation, so we skip the
    # canary detection path entirely and rely on error-marker evidence.
    cleaned = combined.replace(payload, "[PAYLOAD]")
    if (not canary_in_payload) and _CANARY in cleaned:
        return TestResult(
            test_id=tid, test_name=tname,
            category=Category.SECURITY, severity=Severity.CRITICAL,
            passed=False,
            description=(
                f"Deserialisation RCE confirmed on {tool.name!r}. Canary string "
                f"{_CANARY!r} appears in response after our literal payload was "
                f"stripped — the server executed our injected code."
            ),
            duration_ms=duration,
            details=f"Primitive: {label}\nPayload excerpt: {payload[:200]!r}",
            remediation=(
                "Never call pickle.loads / yaml.load / XML-with-external-entities / "
                "Java ObjectInputStream on user-controlled input. Use yaml.safe_load, "
                "JSON only, disable DTDs in XML parsers, and reject any payload that "
                "starts with Java/Ruby serialisation magic bytes."
            ),
        )

    # Deserialiser error markers → LOW-severity hint.
    for marker_label, pat in _DESERIALIZER_MARKERS:
        m = pat.search(combined)
        if m:
            return TestResult(
                test_id=tid, test_name=tname,
                category=Category.SECURITY, severity=Severity.LOW,
                passed=False,
                description=(
                    f"Tool {tool.name!r} error suggests {marker_label} is being "
                    f"invoked on user input. No confirmed RCE — review code path."
                ),
                duration_ms=duration,
                details=f"Match: {m.group(0)[:80]!r}",
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
        description=f"{label} — no deserialisation markers detected.",
        duration_ms=duration,
    )


async def run(
    session: ClientSession,
    server_info: ServerInfo,
    config: ScanConfig,
) -> list[TestResult]:
    """Execute T24 — Insecure Deserialisation."""
    t_start = time.perf_counter()
    results: list[TestResult] = []
    limiter = RateLimiter(config)

    candidates = [
        t for t in (server_info.tools or [])
        if _first_string_param(t) and not _is_long_running(t.name)
    ][:_MAX_TOOLS_PROBED]

    for tool in candidates:
        pname = _first_string_param(tool) or ""
        for pid, label, payload, canary_in_payload in _PAYLOADS:
            results.append(await _probe(
                session, tool, pname, pid, label, payload, canary_in_payload, limiter,
            ))

    crit = sum(1 for r in results if r.severity == Severity.CRITICAL and not r.passed)
    low = sum(1 for r in results if r.severity == Severity.LOW and not r.passed)
    if crit:
        results.append(TestResult.make_fail(
            test_id="T24-001", test_name="Deserialisation — Summary",
            category=Category.SECURITY, severity=Severity.CRITICAL,
            description=f"{crit} confirmed deserialisation RCE probe(s).",
            duration_ms=(time.perf_counter() - t_start) * 1000.0,
        ))
    elif low:
        results.append(TestResult.make_fail(
            test_id="T24-001", test_name="Deserialisation — Summary",
            category=Category.SECURITY, severity=Severity.LOW,
            description=f"{low} tool(s) leaked deserialiser markers in error messages.",
            duration_ms=(time.perf_counter() - t_start) * 1000.0,
        ))
    else:
        results.append(TestResult.make_pass(
            test_id="T24-001", test_name="Deserialisation — Summary",
            category=Category.SECURITY,
            description=f"No deserialisation markers across {len(candidates)} probed tool(s).",
            duration_ms=(time.perf_counter() - t_start) * 1000.0,
        ))
    return results
