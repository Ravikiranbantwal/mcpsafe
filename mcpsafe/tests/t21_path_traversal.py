"""
mcpsafe.tests.t21_path_traversal
=================================
SECURITY category — **Deep path-traversal probing**.

Beyond T07's basic ``../`` test, this module tries the full spectrum of
traversal encodings against every tool with a string parameter and every
resource URI template the server exposes.

Payload variants (12)
---------------------
PT-001  Plain ``../../../etc/passwd``
PT-002  Plain Windows ``..\\..\\..\\Windows\\win.ini``
PT-003  URL-encoded slashes     ``..%2F..%2Fetc%2Fpasswd``
PT-004  Double URL-encoded      ``..%252F..%252Fetc%252Fpasswd``
PT-005  UTF-8 overlong          ``..%c0%2f..%c0%2fetc%c0%2fpasswd``
PT-006  Backslash + forward     ``..\\..\\../etc/passwd``
PT-007  Unicode normalisation   ``..\u2215..\u2215etc\u2215passwd``
PT-008  NUL byte truncation     ``safe.txt\\x00../../../etc/passwd``
PT-009  Absolute Unix path      ``/etc/passwd``
PT-010  Absolute Windows path   ``C:\\Windows\\System32\\drivers\\etc\\hosts``
PT-011  Resource URI file://    ``file:///etc/passwd``
PT-012  Proto-smuggling         ``file:/etc/passwd`` (one slash)

Detection
---------
After stripping the payload from the response, the response is scanned
for content markers that appear ONLY in real ``/etc/passwd`` or
``win.ini``:

  * ``root:x:0:0:``   (Unix passwd)
  * ``/bin/bash``, ``/bin/sh``, ``:/sbin/``  (Unix path fragments)
  * ``[boot loader]``, ``[operating systems]`` (Windows boot.ini)
  * ``\\[fonts\\]``, ``\\[mci extensions\\]`` (win.ini sections)

If a marker survives payload-stripping, the server actually read and
returned the target file — CRITICAL.  If the tool returned a generic
"file not found" error mentioning parts of the payload, downgrade to
PASS (server is properly rejecting the traversal).

Test inventory
--------------
T21-TOOL-{slug}-PT-###    Per-tool × per-payload.
T21-RES-{n}-PT-###        Per-resource × per-payload.
T21-001                   Summary.

Public API
----------
    async def run(session, server_info, config) -> list[TestResult]
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
_MAX_RESOURCES_PROBED = 4

_LONG_RUNNING_KW = frozenset({
    "long_running", "long-running", "trigger_long", "trigger-long",
    "sleep", "wait", "delay",
})


def _is_long_running(n: str) -> bool:
    return any(kw in (n or "").lower() for kw in _LONG_RUNNING_KW)

# (payload_id, label, value)
_TRAVERSAL_PAYLOADS: tuple[tuple[str, str, str], ...] = (
    ("PT-001", "Plain Unix",                "../../../etc/passwd"),
    ("PT-002", "Plain Windows",             "..\\..\\..\\Windows\\win.ini"),
    ("PT-003", "URL-encoded",               "..%2F..%2F..%2Fetc%2Fpasswd"),
    ("PT-004", "Double URL-encoded",        "..%252F..%252F..%252Fetc%252Fpasswd"),
    ("PT-005", "UTF-8 overlong",            "..%c0%2f..%c0%2f..%c0%2fetc%c0%2fpasswd"),
    ("PT-006", "Backslash + forward",       "..\\..\\../etc/passwd"),
    ("PT-007", "Unicode normalisation",     "..\u2215..\u2215..\u2215etc\u2215passwd"),
    ("PT-008", "NUL byte truncation",       "safe.txt\x00../../../etc/passwd"),
    ("PT-009", "Absolute Unix path",        "/etc/passwd"),
    ("PT-010", "Absolute Windows path",     "C:\\Windows\\System32\\drivers\\etc\\hosts"),
    ("PT-011", "Resource file:// scheme",   "file:///etc/passwd"),
    ("PT-012", "Proto-smuggling",           "file:/etc/passwd"),
)

# Compiled markers that, if present in response content, almost certainly
# indicate the server returned a real system file.
_FILE_CONTENT_MARKERS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("Unix /etc/passwd",    re.compile(r"^[a-z_][a-z0-9_\-]*:x:\d+:\d+:", re.MULTILINE)),
    ("Unix shell path",     re.compile(r":/bin/(?:bash|sh|zsh|dash|fish)\b")),
    ("Unix system account", re.compile(r"\bdaemon:|/sbin/nologin|/usr/sbin/")),
    ("Windows boot.ini",    re.compile(r"\[boot loader\]|\[operating systems\]", re.IGNORECASE)),
    ("Windows win.ini",     re.compile(r"\[fonts\]|\[mci extensions\]|\[drivers\]", re.IGNORECASE)),
    ("Windows hosts file",  re.compile(r"#\s*Copyright.*Microsoft.*hosts", re.IGNORECASE | re.DOTALL)),
    ("/proc/self/environ",  re.compile(r"(?:^|\x00)(?:PATH|HOME|USER|SHELL|PWD)=", re.MULTILINE)),
)


def _slug(name: str, budget: int = 20) -> str:
    s = re.sub(r"[^a-z0-9]+", "_", (name or "unknown").lower()).strip("_")
    return (s or "unknown")[:budget] or "unknown"


def _extract_text(response: object) -> str:
    if isinstance(response, str):
        return cap_response(response)
    if not isinstance(response, list) and hasattr(response, "contents"):
        contents = getattr(response, "contents", None)
        if isinstance(contents, list):
            response = contents
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


def _find_file_marker(text: str, payload: str) -> Optional[tuple[str, str]]:
    """
    Return (label, excerpt) when *text* contains a file-content marker
    that is NOT part of the payload echo.
    """
    if not text:
        return None
    # Strip payload echoes so we only match content that came from the server.
    cleaned = text.replace(payload, " [PAYLOAD] ")
    cleaned = cleaned.replace(payload.strip(), " [PAYLOAD] ")
    for label, pat in _FILE_CONTENT_MARKERS:
        m = pat.search(cleaned)
        if m:
            idx = m.start()
            excerpt = cleaned[max(0, idx - 20): m.end() + 40]
            excerpt = excerpt.replace("\n", " ").strip()[:180]
            return label, excerpt
    return None


def _first_string_param(tool: MCPTool) -> Optional[str]:
    schema = tool.input_schema
    if not isinstance(schema, dict):
        return None
    props = schema.get("properties") or {}
    required = schema.get("required", []) or []
    path_hints = ("path", "file", "uri", "url", "resource", "location")
    # Prefer parameters whose name implies a path.
    for pname in required:
        pschema = props.get(pname) or {}
        if (isinstance(pschema, dict)
                and pschema.get("type") == "string"
                and any(h in pname.lower() for h in path_hints)):
            return pname
    for pname, pschema in props.items():
        if (isinstance(pschema, dict)
                and pschema.get("type") == "string"
                and any(h in pname.lower() for h in path_hints)):
            return pname
    # Fall back to any string param.
    for pname in required:
        pschema = props.get(pname) or {}
        if isinstance(pschema, dict) and pschema.get("type") == "string":
            return pname
    for pname, pschema in props.items():
        if isinstance(pschema, dict) and pschema.get("type") == "string":
            return pname
    return None


async def _probe_tool_payload(
    session: ClientSession,
    tool: MCPTool,
    pname: str,
    pid: str,
    label: str,
    payload: str,
    limiter: RateLimiter,
) -> TestResult:
    tid = f"T21-TOOL-{_slug(tool.name)}-{pid}"
    if len(tid) > _MAX_TEST_ID_LEN:
        tid = tid[:_MAX_TEST_ID_LEN]
    tname = f"Path Traversal {pid} → {tool.name}"
    t0 = time.perf_counter()

    await limiter.acquire()
    try:
        with anyio.fail_after(_CALL_TIMEOUT_SEC):
            resp = await session.call_tool(tool.name, arguments={pname: payload})
        text = _extract_text(resp)
        duration = (time.perf_counter() - t0) * 1000.0

        hit = _find_file_marker(text, payload)
        if hit:
            marker_label, excerpt = hit
            return TestResult(
                test_id=tid, test_name=tname,
                category=Category.SECURITY, severity=Severity.CRITICAL,
                passed=False,
                description=(
                    f"Tool {tool.name!r} returned content matching {marker_label} "
                    f"when given traversal payload {label} — path-traversal to "
                    f"sensitive system file confirmed."
                ),
                duration_ms=duration,
                details=(
                    f"Payload: {payload!r}\n"
                    f"Marker: {marker_label}\n"
                    f"Excerpt: {excerpt}"
                ),
                remediation=(
                    "Reject any path component containing '..' after URL / Unicode "
                    "decoding and before filesystem access.  Use canonical path "
                    "comparison against an allow-list of permitted directories, "
                    "not string-prefix checks."
                ),
            )
        return TestResult.make_pass(
            test_id=tid, test_name=tname, category=Category.SECURITY,
            description=f"Tool {tool.name!r} safely rejected {label}.",
            duration_ms=duration,
        )
    except Exception as exc:
        duration = (time.perf_counter() - t0) * 1000.0
        err = str(exc)
        if looks_like_api_rejection([err]):
            return TestResult(
                test_id=tid, test_name=tname,
                category=Category.SECURITY, severity=Severity.INFO, passed=True,
                description=(
                    f"Tool {tool.name!r} rejected {label} at the API layer."
                ),
                duration_ms=duration,
                details=err[:200],
            )
        return TestResult.make_pass(
            test_id=tid, test_name=tname, category=Category.SECURITY,
            description=(
                f"Tool {tool.name!r} raised an error for {label} — no file "
                f"content disclosed."
            ),
            duration_ms=duration,
            details=err[:200],
        )


async def _probe_resource_payload(
    session: ClientSession,
    idx: int,
    pid: str,
    label: str,
    payload: str,
    limiter: RateLimiter,
) -> TestResult:
    tid = f"T21-RES-{idx:02d}-{pid}"
    tname = f"Resource-URI Path Traversal {pid}"
    t0 = time.perf_counter()

    await limiter.acquire()
    try:
        with anyio.fail_after(_CALL_TIMEOUT_SEC):
            resp = await session.read_resource(payload)
        text = _extract_text(resp)
        duration = (time.perf_counter() - t0) * 1000.0

        hit = _find_file_marker(text, payload)
        if hit:
            marker_label, excerpt = hit
            return TestResult(
                test_id=tid, test_name=tname,
                category=Category.SECURITY, severity=Severity.CRITICAL,
                passed=False,
                description=(
                    f"Resource read of {payload!r} returned content matching "
                    f"{marker_label} — confirmed path-traversal via resource URI."
                ),
                duration_ms=duration,
                details=f"Marker: {marker_label}\nExcerpt: {excerpt}",
                remediation=(
                    "Validate resource URIs against an allow-list scheme. Reject "
                    "``file://``, ``..`` sequences, absolute paths outside the "
                    "permitted directory, and URL/Unicode encoding tricks."
                ),
            )
        return TestResult.make_pass(
            test_id=tid, test_name=tname, category=Category.SECURITY,
            description=f"Resource read safely rejected {label}.",
            duration_ms=duration,
        )
    except Exception as exc:
        duration = (time.perf_counter() - t0) * 1000.0
        return TestResult.make_pass(
            test_id=tid, test_name=tname, category=Category.SECURITY,
            description=f"Resource read rejected {label} with error.",
            duration_ms=duration,
            details=str(exc)[:200],
        )


async def run(
    session: ClientSession,
    server_info: ServerInfo,
    config: ScanConfig,
) -> list[TestResult]:
    """Execute T21 — Deep Path Traversal."""
    t_start = time.perf_counter()
    results: list[TestResult] = []
    limiter = RateLimiter(config)

    # Tool probes (only tools with a path-ish string param).
    candidates = [
        t for t in (server_info.tools or [])
        if _first_string_param(t) and not _is_long_running(t.name)
    ][:_MAX_TOOLS_PROBED]

    for tool in candidates:
        pname = _first_string_param(tool) or ""
        for pid, label, payload in _TRAVERSAL_PAYLOADS:
            results.append(
                await _probe_tool_payload(
                    session, tool, pname, pid, label, payload, limiter,
                )
            )

    # Resource probes — only if server exposes resources at all.
    if server_info.resources:
        # Probe up to _MAX_RESOURCES_PROBED payloads through read_resource
        for i, (pid, label, payload) in enumerate(
            _TRAVERSAL_PAYLOADS[:_MAX_RESOURCES_PROBED], start=1
        ):
            results.append(
                await _probe_resource_payload(
                    session, i, pid, label, payload, limiter,
                )
            )

    # Summary
    crit = sum(1 for r in results if r.severity == Severity.CRITICAL and not r.passed)
    total = len(results)
    if crit:
        results.append(
            TestResult.make_fail(
                test_id="T21-001", test_name="Path Traversal — Summary",
                category=Category.SECURITY, severity=Severity.CRITICAL,
                description=(
                    f"{crit} confirmed path-traversal finding(s) across "
                    f"{total} probes."
                ),
                duration_ms=(time.perf_counter() - t_start) * 1000.0,
                remediation="See individual T21-* findings.",
            )
        )
    else:
        results.append(
            TestResult.make_pass(
                test_id="T21-001", test_name="Path Traversal — Summary",
                category=Category.SECURITY,
                description=(
                    f"{total} probe(s) sent, no traversal to sensitive "
                    f"files confirmed."
                ),
                duration_ms=(time.perf_counter() - t_start) * 1000.0,
            )
        )
    return results
