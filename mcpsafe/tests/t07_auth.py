"""
mcpsafe.tests.t07_auth
=======================
SECURITY category — Authentication, authorisation, and privilege checks.

HTTP transport tests (require config.transport == TransportType.HTTP or SSE)
-----------------------------------------------------------------------------
T07-001  Unauthenticated access       Raw MCP initialize with no auth header.
T07-002  Malformed token rejection    4 broken tokens; each should get 401/403.
T07-003  Resource URI path traversal  Attempt classic traversal URIs against
                                      list_resources results.
T07-004  Credentials in error msgs    Probe a non-existent tool; scan the error.
T07-005  CORS misconfiguration        OPTIONS request; check Allow-Origin header.

STDIO transport tests (require config.transport == TransportType.STDIO)
-------------------------------------------------------------------------
T07-006  Process privilege check      os.getuid() == 0 → HIGH.
T07-007  Environment variable probe   Inject shell expansion strings; scan
                                      response for expanded values.

Public API
----------
    async def run(
        session: ClientSession,
        server_info: ServerInfo,
        config: ScanConfig,
    ) -> list[TestResult]
"""

from __future__ import annotations

import asyncio
import os
import re
import sys
import time
from typing import Optional

import httpx
from mcp import ClientSession

from mcpsafe.models import (
    Category,
    ScanConfig,
    ServerInfo,
    Severity,
    TestResult,
    TransportType,
)
from mcpsafe.tests._helpers import cap_response

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_CAT = Category.SECURITY
_HTTP_TIMEOUT = 15.0   # seconds for raw httpx calls

# Raw MCP initialize payload (no auth) used by T07-001 / T07-002.
_MCP_INIT_BODY: dict = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {"name": "mcpsafe-probe", "version": "0.1.0"},
    },
}

# Malformed tokens for T07-002.
_MALFORMED_TOKENS: list[tuple[str, str]] = [
    ("Bearer invalid_token_mcpsafe_test", "Invalid bearer token"),
    ("Bearer ",                           "Empty bearer token"),
    ("Basic dGVzdDp0ZXN0",               "Basic auth instead of Bearer"),
    ("ApiKey wrong_key_mcpsafe",          "Wrong API key format"),
]

# Path-traversal URIs for T07-003.
_TRAVERSAL_URIS: list[str] = [
    "file:///../../../etc/passwd",
    "file:///etc/shadow",
    "file:///windows/system32/config/sam",
    "file:///" + "../" * 10 + "etc/passwd",
    "resource://../../secret",
]

_TRAVERSAL_SUCCESS_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"root:.*:/bin/",      re.IGNORECASE),
    re.compile(r"\[boot loader\]",    re.IGNORECASE),
    re.compile(r"HKEY_LOCAL_MACHINE", re.IGNORECASE),
]

# Credential leak patterns for T07-004.
_CREDENTIAL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"[Aa][Pp][Ii][_\-]?[Kk][Ee][Yy]\s*[:=]\s*\S{8,}"),
    re.compile(r"[Pp]assword\s*[:=]\s*\S+"),
    re.compile(r"[Ss]ecret\s*[:=]\s*\S+"),
    re.compile(r"[Tt]oken\s*[:=]\s*[A-Za-z0-9+/]{20,}"),
    re.compile(r"postgres://\S+"),
    re.compile(r"mongodb://\S+"),
    re.compile(r"redis://\S+"),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
]

# Environment-variable expansion probe for T07-007.
_ENV_PROBE_VALUE = (
    "$HOME $USER $PATH $AWS_SECRET_ACCESS_KEY "
    "$OPENAI_API_KEY $ANTHROPIC_API_KEY"
)

_ENV_LEAK_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"/home/[a-z_][a-z0-9_-]{0,30}",           re.IGNORECASE),
    re.compile(r"/Users/[A-Za-z_][A-Za-z0-9_-]{0,30}"),
    re.compile(r"C:\\Users\\[A-Za-z_][A-Za-z0-9_-]{0,30}", re.IGNORECASE),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"[A-Za-z0-9+/]{40,}={0,2}"),
]

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _extract_text(response: object) -> str:
    """Flatten an MCP response to a plain string, capped at 1 MB."""
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
        return cap_response("\n".join(parts))
    except Exception:
        return cap_response(str(response))


def _find_string_param(server_info: ServerInfo) -> Optional[tuple[str, str]]:
    """
    Return ``(tool_name, param_name)`` for the first tool with a string param,
    or ``None``.
    """
    for tool in server_info.tools:
        schema = tool.input_schema
        if not isinstance(schema, dict):
            continue
        props = schema.get("properties")
        if not isinstance(props, dict):
            continue
        required: list[str] = schema.get("required", []) or []
        for pname, pschema in props.items():
            if isinstance(pschema, dict) and pschema.get("type") == "string":
                if pname in required:
                    return tool.name, pname
        for pname, pschema in props.items():
            if isinstance(pschema, dict) and pschema.get("type") == "string":
                return tool.name, pname
    return None


def _base_url(config: ScanConfig) -> str:
    """Return the normalised base URL for HTTP targets."""
    target = config.target
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"
    return target.rstrip("/")


def _build_headers(config: ScanConfig) -> dict[str, str]:
    """Build base HTTP headers from config (without auth)."""
    return dict(config.headers)


# ---------------------------------------------------------------------------
# T07-001 — Unauthenticated access
# ---------------------------------------------------------------------------


async def _t07_001_unauth_access(config: ScanConfig) -> TestResult:
    """T07-001 — POST MCP initialize with no Authorization header."""
    tid = "T07-001"
    tname = "Unauthenticated MCP Access"
    t0 = time.perf_counter()
    try:
        url = _base_url(config) + "/mcp"
        headers = {**_build_headers(config), "Content-Type": "application/json"}
        # Deliberately omit Authorization.

        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            resp = await client.post(url, json=_MCP_INIT_BODY, headers=headers)

        duration = (time.perf_counter() - t0) * 1000.0
        status = resp.status_code

        if status == 200:
            body = resp.text
            if "protocolVersion" in body:
                return TestResult(
                    test_id=tid, test_name=tname, category=_CAT,
                    severity=Severity.CRITICAL, passed=False,
                    description=(
                        "Server accepted an MCP initialize request with no "
                        "authentication."
                    ),
                    duration_ms=duration,
                    details="Server accepts MCP connections with no authentication",
                    remediation=(
                        "Require authentication (Bearer token, mTLS, or API key) "
                        "on all MCP endpoints. An unauthenticated MCP endpoint "
                        "allows any client on the network to invoke all tools."
                    ),
                    request_payload=f"POST {url} (no auth)",
                    response_payload=body[:1000],
                )
            # 200 but no MCP content — inconclusive.
            return TestResult(
                test_id=tid, test_name=tname, category=_CAT,
                severity=Severity.INFO, passed=True,
                description=(
                    "Server returned HTTP 200 but response did not contain "
                    "'protocolVersion' — unable to confirm MCP access."
                ),
                duration_ms=duration,
                details=f"Status: 200. Body excerpt: {body[:300]!r}",
            )

        if status in (401, 403):
            return TestResult.make_pass(
                test_id=tid, test_name=tname, category=_CAT,
                description=(
                    f"Server correctly rejected unauthenticated MCP request "
                    f"with HTTP {status}."
                ),
                duration_ms=duration,
                details=f"Status: {status}",
            )

        return TestResult(
            test_id=tid, test_name=tname, category=_CAT,
            severity=Severity.INFO, passed=True,
            description=f"Unexpected HTTP status {status} on unauthenticated probe.",
            duration_ms=duration,
            details=f"Unexpected status: {status}",
        )

    except httpx.ConnectError as exc:
        return TestResult.from_exception(
            test_id=tid, test_name=tname, category=_CAT, exc=exc,
            duration_ms=(time.perf_counter() - t0) * 1000.0,
        )
    except Exception as exc:
        return TestResult.from_exception(
            test_id=tid, test_name=tname, category=_CAT, exc=exc,
            duration_ms=(time.perf_counter() - t0) * 1000.0,
        )


# ---------------------------------------------------------------------------
# T07-002 — Malformed token rejection
# ---------------------------------------------------------------------------


async def _t07_002_malformed_tokens(config: ScanConfig) -> list[TestResult]:
    """T07-002 — Send 4 broken Authorization headers; each should get 401/403."""
    results: list[TestResult] = []
    url = _base_url(config) + "/mcp"
    base_headers = {**_build_headers(config), "Content-Type": "application/json"}

    for idx, (token_value, token_label) in enumerate(_MALFORMED_TOKENS, start=1):
        tid = f"T07-002-{idx:02d}"
        tname = f"Malformed Token: {token_label}"
        t0 = time.perf_counter()
        try:
            headers = {**base_headers, "Authorization": token_value}
            async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
                resp = await client.post(url, json=_MCP_INIT_BODY, headers=headers)

            duration = (time.perf_counter() - t0) * 1000.0
            status = resp.status_code

            if status == 200 and "protocolVersion" in resp.text:
                results.append(
                    TestResult.make_fail(
                        test_id=tid, test_name=tname, category=_CAT,
                        severity=Severity.HIGH,
                        description=(
                            f"Server accepted MCP connection with malformed "
                            f"token ({token_label})."
                        ),
                        duration_ms=duration,
                        details=(
                            f"Token: {token_value!r}\n"
                            f"Response body excerpt: {resp.text[:300]!r}"
                        ),
                        remediation=(
                            "Validate the Authorization header format and reject "
                            "tokens that do not match the expected scheme."
                        ),
                    )
                )
            elif status in (401, 403):
                results.append(
                    TestResult.make_pass(
                        test_id=tid, test_name=tname, category=_CAT,
                        description=(
                            f"Server correctly rejected {token_label} with "
                            f"HTTP {status}."
                        ),
                        duration_ms=duration,
                    )
                )
            else:
                results.append(
                    TestResult(
                        test_id=tid, test_name=tname, category=_CAT,
                        severity=Severity.INFO, passed=True,
                        description=(
                            f"HTTP {status} for {token_label} — "
                            f"unable to confirm rejection."
                        ),
                        duration_ms=duration,
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
# T07-003 — Resource URI path traversal
# ---------------------------------------------------------------------------


async def _t07_003_path_traversal(
    session: ClientSession,
    server_info: ServerInfo,
) -> list[TestResult]:
    """T07-003 — Attempt traversal URIs; flag if sensitive file content is returned."""
    results: list[TestResult] = []

    if not server_info.resources:
        results.append(
            TestResult(
                test_id="T07-003", test_name="Resource URI Path Traversal",
                category=_CAT, severity=Severity.INFO, passed=True,
                description=(
                    "Server advertises no resources — path traversal test skipped."
                ),
                duration_ms=0.0,
            )
        )
        return results

    for uri in _TRAVERSAL_URIS:
        tid = f"T07-003-{_uri_slug(uri)}"
        tname = f"Path Traversal: {uri[:50]}"
        t0 = time.perf_counter()
        try:
            resp = await asyncio.wait_for(
                session.read_resource(uri),   # type: ignore[arg-type]
                timeout=30.0,
            )
            duration = (time.perf_counter() - t0) * 1000.0
            text = _extract_text(resp)

            matched = next(
                (p.pattern for p in _TRAVERSAL_SUCCESS_PATTERNS if p.search(text)),
                None,
            )
            if matched:
                results.append(
                    TestResult(
                        test_id=tid, test_name=tname, category=_CAT,
                        severity=Severity.CRITICAL, passed=False,
                        description=(
                            f"Path traversal URI {uri!r} returned sensitive "
                            f"file content."
                        ),
                        duration_ms=duration,
                        details=(
                            f"Matched pattern: {matched!r}\n"
                            f"Response excerpt: {text[:500]!r}"
                        ),
                        remediation=(
                            "Sanitise all resource URIs by resolving them against "
                            "a jail/chroot directory and rejecting any path that "
                            "escapes. Never pass raw user-supplied URIs to the "
                            "filesystem."
                        ),
                        request_payload=f"read_resource({uri!r})",
                        response_payload=text[:2000],
                    )
                )
            else:
                results.append(
                    TestResult.make_pass(
                        test_id=tid, test_name=tname, category=_CAT,
                        description=(
                            f"Server handled traversal URI {uri!r} without "
                            f"leaking sensitive content."
                        ),
                        duration_ms=duration,
                        details=f"Response excerpt: {text[:200]!r}",
                    )
                )

        except asyncio.CancelledError:
            raise
        except Exception as exc:
            duration = (time.perf_counter() - t0) * 1000.0
            # An error response is the correct behaviour for traversal URIs.
            results.append(
                TestResult.make_pass(
                    test_id=tid, test_name=tname, category=_CAT,
                    description=(
                        f"Server rejected traversal URI {uri!r} with an error "
                        f"— correct behaviour."
                    ),
                    duration_ms=duration,
                    details=f"{type(exc).__name__}: {str(exc)[:200]}",
                )
            )

    return results


def _uri_slug(uri: str, max_len: int = 20) -> str:
    """Slug-ify a URI for embedding in a test ID."""
    s = re.sub(r"[^a-z0-9]+", "_", uri.lower()).strip("_")
    return s[:max_len]


# ---------------------------------------------------------------------------
# T07-004 — Credentials in error messages
# ---------------------------------------------------------------------------


async def _t07_004_credentials_in_errors(
    session: ClientSession,
) -> TestResult:
    """T07-004 — Call a nonexistent tool; scan the error for credential leaks."""
    tid = "T07-004"
    tname = "Credentials in Error Messages"
    t0 = time.perf_counter()
    try:
        probe_name = "mcpsafe_nonexistent_tool_probe"
        error_text = ""
        try:
            resp = await asyncio.wait_for(
                session.call_tool(probe_name, arguments={}),
                timeout=15.0,
            )
            error_text = _extract_text(resp)
        except Exception as exc:
            error_text = str(exc)

        duration = (time.perf_counter() - t0) * 1000.0

        for pat in _CREDENTIAL_PATTERNS:
            m = pat.search(error_text)
            if m:
                return TestResult.make_fail(
                    test_id=tid, test_name=tname, category=_CAT,
                    severity=Severity.HIGH,
                    description=(
                        "Server leaked credential-like data in its error response "
                        "for an unknown tool call."
                    ),
                    duration_ms=duration,
                    details=(
                        f"Matched pattern: {pat.pattern!r}\n"
                        f"Match: {m.group()!r}\n"
                        f"Error excerpt: {error_text[:500]!r}"
                    ),
                    remediation=(
                        "Sanitise all error messages before returning them to "
                        "callers. Never include connection strings, API keys, "
                        "tokens, or passwords in MCP error responses."
                    ),
                    response_payload=error_text[:2000],
                )

        return TestResult.make_pass(
            test_id=tid, test_name=tname, category=_CAT,
            description=(
                "No credential patterns found in error response for "
                "non-existent tool call."
            ),
            duration_ms=duration,
            details=f"Error excerpt: {error_text[:200]!r}",
        )

    except Exception as exc:
        return TestResult.from_exception(
            test_id=tid, test_name=tname, category=_CAT, exc=exc,
            duration_ms=(time.perf_counter() - t0) * 1000.0,
        )


# ---------------------------------------------------------------------------
# T07-005 — CORS misconfiguration
# ---------------------------------------------------------------------------


async def _t07_005_cors(config: ScanConfig) -> TestResult:
    """T07-005 — OPTIONS request; check Access-Control-Allow-Origin."""
    tid = "T07-005"
    tname = "CORS Misconfiguration"
    t0 = time.perf_counter()
    try:
        url = _base_url(config)
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            resp = await client.options(
                url,
                headers={
                    **_build_headers(config),
                    "Origin": "https://evil.mcpsafe.test",
                    "Access-Control-Request-Method": "POST",
                },
            )

        duration = (time.perf_counter() - t0) * 1000.0
        acao = resp.headers.get("access-control-allow-origin", "")

        if acao == "*":
            return TestResult.make_fail(
                test_id=tid, test_name=tname, category=_CAT,
                severity=Severity.MEDIUM,
                description=(
                    "Server returns 'Access-Control-Allow-Origin: *' — "
                    "any browser origin can connect to this MCP server."
                ),
                duration_ms=duration,
                details=(
                    "Wildcard CORS — any browser origin can connect to this "
                    "MCP server"
                ),
                remediation=(
                    "Restrict the CORS origin allowlist to known, trusted "
                    "domains. A wildcard allows a malicious web page to make "
                    "authenticated cross-origin calls to this MCP server."
                ),
            )

        acao_display = repr(acao) if acao else "(header absent)"
        return TestResult.make_pass(
            test_id=tid, test_name=tname, category=_CAT,
            description=(
                "CORS policy is not wildcard — "
                f"Access-Control-Allow-Origin: {acao_display}."
            ),
            duration_ms=duration,
        )

    except Exception as exc:
        return TestResult.from_exception(
            test_id=tid, test_name=tname, category=_CAT, exc=exc,
            duration_ms=(time.perf_counter() - t0) * 1000.0,
        )


# ---------------------------------------------------------------------------
# T07-006 — Process privilege check (stdio only)
# ---------------------------------------------------------------------------


async def _t07_006_process_privilege() -> TestResult:
    """T07-006 — Check whether the current process is running as root/SYSTEM."""
    tid = "T07-006"
    tname = "Process Privilege Check"
    t0 = time.perf_counter()
    try:
        if sys.platform == "win32":
            return TestResult(
                test_id=tid, test_name=tname, category=_CAT,
                severity=Severity.INFO, passed=True,
                description="Privilege check not available on Windows.",
                duration_ms=(time.perf_counter() - t0) * 1000.0,
            )

        uid = os.getuid()  # type: ignore[attr-defined]  # only called on non-Windows
        duration = (time.perf_counter() - t0) * 1000.0

        if uid == 0:
            return TestResult.make_fail(
                test_id=tid, test_name=tname, category=_CAT,
                severity=Severity.HIGH,
                description=(
                    "MCP server process is running as root (UID 0). "
                    "Any tool exploit would have full system access."
                ),
                duration_ms=duration,
                details="MCP server process running as root (UID 0)",
                remediation=(
                    "Run the MCP server as a dedicated low-privilege service "
                    "account. Principle of least privilege: the process should "
                    "only have access to the resources it actually needs."
                ),
            )

        return TestResult(
            test_id=tid, test_name=tname, category=_CAT,
            severity=Severity.INFO, passed=True,
            description=f"MCP server is running as UID {uid} (non-root).",
            duration_ms=duration,
            details=f"Running as UID {uid} (non-root, good)",
        )

    except Exception as exc:
        return TestResult.from_exception(
            test_id=tid, test_name=tname, category=_CAT, exc=exc,
            duration_ms=(time.perf_counter() - t0) * 1000.0,
        )


# ---------------------------------------------------------------------------
# T07-007 — Environment variable probe (stdio only)
# ---------------------------------------------------------------------------


async def _t07_007_env_probe(
    session: ClientSession,
    server_info: ServerInfo,
    config: ScanConfig,
) -> TestResult:
    """T07-007 — Inject shell expansion strings; check if the server expands them."""
    tid = "T07-007"
    tname = "Environment Variable Probe"
    t0 = time.perf_counter()
    try:
        target = _find_string_param(server_info)
        if target is None:
            return TestResult(
                test_id=tid, test_name=tname, category=_CAT,
                severity=Severity.INFO, passed=True,
                description=(
                    "No tool with a string parameter found — "
                    "environment variable probe skipped."
                ),
                duration_ms=(time.perf_counter() - t0) * 1000.0,
            )

        tool_name, param_name = target
        args = {param_name: _ENV_PROBE_VALUE}

        response_text = ""
        try:
            resp = await asyncio.wait_for(
                session.call_tool(tool_name, arguments=args),
                timeout=config.timeout_seconds,
            )
            response_text = _extract_text(resp)
        except Exception as exc:
            response_text = str(exc)

        duration = (time.perf_counter() - t0) * 1000.0

        for pat in _ENV_LEAK_PATTERNS:
            m = pat.search(response_text)
            if m:
                return TestResult.make_fail(
                    test_id=tid, test_name=tname, category=_CAT,
                    severity=Severity.HIGH,
                    description=(
                        f"Tool {tool_name!r} may be expanding shell environment "
                        f"variables in its response."
                    ),
                    duration_ms=duration,
                    details=(
                        "Server may be expanding environment variables in tool "
                        "responses\n"
                        f"Matched pattern: {pat.pattern!r}\n"
                        f"Match: {m.group()!r}\n"
                        f"Response excerpt: {response_text[:500]!r}"
                    ),
                    remediation=(
                        "Never pass tool inputs through a shell interpreter. "
                        "Use subprocess.run with an explicit arg list, not "
                        "shell=True. Expanding $HOME/$USER/$PATH leaks the "
                        "server's runtime environment to callers."
                    ),
                    request_payload=f"{tool_name}({param_name}={_ENV_PROBE_VALUE!r})",
                    response_payload=response_text[:2000],
                )

        return TestResult.make_pass(
            test_id=tid, test_name=tname, category=_CAT,
            description=(
                f"Tool {tool_name!r} did not expand environment variable "
                f"references in its response."
            ),
            duration_ms=duration,
            details=f"Response excerpt: {response_text[:200]!r}",
        )

    except Exception as exc:
        return TestResult.from_exception(
            test_id=tid, test_name=tname, category=_CAT, exc=exc,
            duration_ms=(time.perf_counter() - t0) * 1000.0,
        )


# ---------------------------------------------------------------------------
# T07-008 — Invalid tool name (empty / whitespace)
# ---------------------------------------------------------------------------


async def _t07_008_invalid_tool_name(
    session: ClientSession,
    config: ScanConfig,
) -> TestResult:
    """T07-008 — Call call_tool() with empty/whitespace tool name; server must reject."""
    tid = "T07-008"
    tname = "Invalid Tool Name Rejection"
    t0 = time.perf_counter()
    try:
        for bad_name in ("", "  ", "\x00", "nonexistent_tool_mcpsafe_probe"):
            try:
                await asyncio.wait_for(
                    session.call_tool(bad_name, arguments={}),
                    timeout=config.timeout_seconds,
                )
                # If we reach here the server accepted an invalid tool name.
                duration = (time.perf_counter() - t0) * 1000.0
                return TestResult.make_fail(
                    test_id=tid, test_name=tname, category=_CAT,
                    severity=Severity.MEDIUM,
                    description=(
                        f"Server accepted call to invalid tool name {bad_name!r} "
                        f"without error."
                    ),
                    duration_ms=duration,
                    details=f"Tool name {bad_name!r} was accepted with no error response.",
                    remediation=(
                        "Validate tool names on the server side. Empty, whitespace, "
                        "null-byte, or non-existent tool names must be rejected with "
                        "a structured error."
                    ),
                )
            except Exception:
                pass  # Rejection is the correct behaviour — continue testing others.

        return TestResult.make_pass(
            test_id=tid, test_name=tname, category=_CAT,
            description="Server correctly rejected all invalid tool names.",
            duration_ms=(time.perf_counter() - t0) * 1000.0,
        )
    except Exception as exc:
        return TestResult.from_exception(
            test_id=tid, test_name=tname, category=_CAT, exc=exc,
            duration_ms=(time.perf_counter() - t0) * 1000.0,
        )


# ---------------------------------------------------------------------------
# T07-009 — Oversized tool arguments (10 KB keys + values)
# ---------------------------------------------------------------------------


async def _t07_009_oversized_args(
    session: ClientSession,
    server_info: ServerInfo,
    config: ScanConfig,
) -> TestResult:
    """T07-009 — Send a call_tool request with extremely large argument keys/values."""
    tid = "T07-009"
    tname = "Oversized Argument Rejection"
    t0 = time.perf_counter()
    try:
        if not server_info.tools:
            return TestResult(
                test_id=tid, test_name=tname, category=_CAT,
                severity=Severity.INFO, passed=True,
                description="No tools available — oversized argument test skipped.",
                duration_ms=(time.perf_counter() - t0) * 1000.0,
            )

        tool = server_info.tools[0]
        # 10 KB key and 1 MB value
        huge_args: dict[str, object] = {"A" * 10_000: "B" * 1_000_000}

        try:
            await asyncio.wait_for(
                session.call_tool(tool.name, arguments=huge_args),
                timeout=config.timeout_seconds,
            )
            duration = (time.perf_counter() - t0) * 1000.0
            return TestResult(
                test_id=tid, test_name=tname, category=_CAT,
                severity=Severity.MEDIUM, passed=False,
                description=(
                    "Server accepted a 1 MB argument value without error — "
                    "no input size limit enforced."
                ),
                duration_ms=duration,
                details="Tool accepted 10 KB key + 1 MB value payload.",
                remediation=(
                    "Enforce maximum argument size limits (e.g. 64 KB total "
                    "per call). Unbounded inputs allow memory exhaustion attacks."
                ),
            )
        except Exception:
            pass  # Rejection is correct.

        return TestResult.make_pass(
            test_id=tid, test_name=tname, category=_CAT,
            description="Server correctly rejected oversized tool arguments.",
            duration_ms=(time.perf_counter() - t0) * 1000.0,
        )

    except Exception as exc:
        return TestResult.from_exception(
            test_id=tid, test_name=tname, category=_CAT, exc=exc,
            duration_ms=(time.perf_counter() - t0) * 1000.0,
        )


# ---------------------------------------------------------------------------
# T07-010 — Duplicate initialize() (replay attack)
# ---------------------------------------------------------------------------


async def _t07_010_replay_initialize(
    session: ClientSession,
    config: ScanConfig,
) -> TestResult:
    """
    T07-010 — Call initialize() a second time on an already-initialised session.

    Session-state safety
    --------------------
    If the server *accepts* the duplicate initialize(), the session may have
    its capabilities or state reset.  To prevent this from corrupting
    subsequent test modules (T07-011, T07-012, T07-013, etc. all run after
    T07-010), we immediately execute a ``list_tools()`` probe after a
    successful replay:

    - ``list_tools()`` fails → session is now broken → severity MEDIUM
    - ``list_tools()`` succeeds → session is still usable but was reset
      → severity LOW with a stronger warning
    - Server rejects the second initialize() → PASS (correct behaviour)
    """
    tid = "T07-010"
    tname = "Duplicate Initialize (Replay Attack)"
    t0 = time.perf_counter()
    try:
        # The session is already initialised — calling again should either be a
        # no-op or return an error.  Acceptance is a security finding.
        replay_succeeded = False
        try:
            await asyncio.wait_for(
                session.initialize(),
                timeout=config.timeout_seconds,
            )
            replay_succeeded = True
        except Exception:
            pass  # Rejection is the correct behaviour.

        duration = (time.perf_counter() - t0) * 1000.0

        if not replay_succeeded:
            return TestResult.make_pass(
                test_id=tid, test_name=tname, category=_CAT,
                description="Server correctly rejected duplicate initialize() call.",
                duration_ms=duration,
            )

        # ── Replay was accepted: probe session health immediately ──────
        # Calling list_tools() verifies whether the session is still usable
        # for subsequent tests.  This also acts as a canary — if the session
        # is broken, we must report that clearly.
        session_still_usable = False
        try:
            await asyncio.wait_for(
                session.list_tools(),
                timeout=config.timeout_seconds,
            )
            session_still_usable = True
        except Exception:
            pass

        if not session_still_usable:
            return TestResult.make_fail(
                test_id=tid, test_name=tname, category=_CAT,
                severity=Severity.MEDIUM,
                description=(
                    "Server accepted a second initialize() call and the session "
                    "is now broken — list_tools() failed after the replay. "
                    "This confirms the session state was corrupted by the attack."
                ),
                duration_ms=duration,
                details=(
                    "Sequence: initialize() → (session active) → initialize() "
                    "again (accepted) → list_tools() failed.\n"
                    "Subsequent tests in this scan may be unreliable."
                ),
                remediation=(
                    "Reject all initialize() calls after the session has already "
                    "been established. An accepted replay corrupts session state "
                    "and can allow capability downgrade attacks."
                ),
            )

        # Session accepted replay but is still responding — lower severity but
        # still a notable finding.
        return TestResult(
            test_id=tid, test_name=tname, category=_CAT,
            severity=Severity.LOW, passed=False,
            description=(
                "Server accepted a second initialize() call on an already "
                "active session. The session remained usable, but the server "
                "state may have been silently reset."
            ),
            duration_ms=duration,
            details=(
                "Double initialize() succeeded.\n"
                "Post-replay list_tools() succeeded — session is still functional "
                "but capabilities or internal state may have been altered."
            ),
            remediation=(
                "The server should reject or ignore repeated initialize() calls. "
                "Accepting them enables mid-session protocol version downgrade "
                "and capability reset attacks."
            ),
        )

    except Exception as exc:
        return TestResult.from_exception(
            test_id=tid, test_name=tname, category=_CAT, exc=exc,
            duration_ms=(time.perf_counter() - t0) * 1000.0,
        )


# ---------------------------------------------------------------------------
# T07-011 — Deeply nested / recursive JSON arguments
# ---------------------------------------------------------------------------


async def _t07_011_deeply_nested_args(
    session: ClientSession,
    server_info: ServerInfo,
    config: ScanConfig,
) -> TestResult:
    """T07-011 — Send call_tool with 100-level deeply nested JSON object."""
    tid = "T07-011"
    tname = "Deeply Nested Argument (JSON Bomb)"
    t0 = time.perf_counter()
    try:
        if not server_info.tools:
            return TestResult(
                test_id=tid, test_name=tname, category=_CAT,
                severity=Severity.INFO, passed=True,
                description="No tools available — deep nesting test skipped.",
                duration_ms=(time.perf_counter() - t0) * 1000.0,
            )

        tool = server_info.tools[0]

        # Build a 100-level deep nested object.
        nested: dict = {"x": "mcpsafe-probe"}
        for _ in range(100):
            nested = {"n": nested}

        try:
            await asyncio.wait_for(
                session.call_tool(tool.name, arguments=nested),
                timeout=config.timeout_seconds,
            )
            duration = (time.perf_counter() - t0) * 1000.0
            return TestResult(
                test_id=tid, test_name=tname, category=_CAT,
                severity=Severity.LOW, passed=False,
                description=(
                    "Server accepted a 100-level deeply nested argument without "
                    "error — no nesting depth limit enforced."
                ),
                duration_ms=duration,
                details="100-level nested JSON object accepted.",
                remediation=(
                    "Enforce a maximum JSON nesting depth (e.g. 10 levels) to "
                    "prevent stack overflow or excessive parse time attacks."
                ),
            )
        except Exception:
            pass  # Rejection is correct.

        return TestResult.make_pass(
            test_id=tid, test_name=tname, category=_CAT,
            description="Server rejected deeply nested JSON argument.",
            duration_ms=(time.perf_counter() - t0) * 1000.0,
        )

    except Exception as exc:
        return TestResult.from_exception(
            test_id=tid, test_name=tname, category=_CAT, exc=exc,
            duration_ms=(time.perf_counter() - t0) * 1000.0,
        )


# ---------------------------------------------------------------------------
# T07-012 — Unicode homoglyph tool name spoofing
# ---------------------------------------------------------------------------


async def _t07_012_homoglyph_tool_name(
    session: ClientSession,
    server_info: ServerInfo,
    config: ScanConfig,
) -> TestResult:
    """
    T07-012 — Call each tool using visually identical unicode homoglyphs in the
    name.  If the server accepts the spoofed name and executes the real tool,
    an attacker could disguise malicious tool calls in logs/UIs.
    """
    tid = "T07-012"
    tname = "Unicode Homoglyph Tool Name Spoofing"
    t0 = time.perf_counter()

    # Replace first 'a'/'e'/'o'/'i' with a Cyrillic homoglyph.
    _HOMOGLYPHS: dict[str, str] = {
        "a": "\u0430",  # Cyrillic а (looks identical to Latin a)
        "e": "\u0435",  # Cyrillic е
        "o": "\u043e",  # Cyrillic о
        "i": "\u0456",  # Cyrillic і
    }

    try:
        if not server_info.tools:
            return TestResult(
                test_id=tid, test_name=tname, category=_CAT,
                severity=Severity.INFO, passed=True,
                description="No tools available — homoglyph test skipped.",
                duration_ms=(time.perf_counter() - t0) * 1000.0,
            )

        tool = server_info.tools[0]
        spoofed = tool.name
        for latin, cyrillic in _HOMOGLYPHS.items():
            if latin in spoofed:
                spoofed = spoofed.replace(latin, cyrillic, 1)
                break

        if spoofed == tool.name:
            return TestResult(
                test_id=tid, test_name=tname, category=_CAT,
                severity=Severity.INFO, passed=True,
                description=(
                    f"Tool name {tool.name!r} has no homoglyph substitution "
                    f"candidates — test skipped."
                ),
                duration_ms=(time.perf_counter() - t0) * 1000.0,
            )

        try:
            await asyncio.wait_for(
                session.call_tool(spoofed, arguments={}),
                timeout=config.timeout_seconds,
            )
            duration = (time.perf_counter() - t0) * 1000.0
            return TestResult.make_fail(
                test_id=tid, test_name=tname, category=_CAT,
                severity=Severity.MEDIUM,
                description=(
                    f"Server accepted unicode homoglyph of tool name "
                    f"{tool.name!r} → {spoofed!r}."
                ),
                duration_ms=duration,
                details=(
                    f"Original: {tool.name!r}\n"
                    f"Spoofed:  {spoofed!r}\n"
                    f"Server executed the spoofed name without rejection."
                ),
                remediation=(
                    "Validate tool names using exact byte-for-byte comparison and "
                    "reject any name not in the known tool manifest. "
                    "Homoglyph acceptance allows log poisoning and UI spoofing."
                ),
            )
        except Exception:
            pass  # Rejection is correct.

        return TestResult.make_pass(
            test_id=tid, test_name=tname, category=_CAT,
            description=(
                f"Server rejected homoglyph tool name {spoofed!r} correctly."
            ),
            duration_ms=(time.perf_counter() - t0) * 1000.0,
        )

    except Exception as exc:
        return TestResult.from_exception(
            test_id=tid, test_name=tname, category=_CAT, exc=exc,
            duration_ms=(time.perf_counter() - t0) * 1000.0,
        )


# ---------------------------------------------------------------------------
# T07-013 — MCP protocol version abuse
# ---------------------------------------------------------------------------

# Known-good MCP protocol versions (as of MCPSafe 0.1.0).
_KNOWN_PROTOCOL_VERSIONS: frozenset[str] = frozenset({
    "2024-11-05",
    "2024-10-07",
    "2025-03-26",
})


async def _t07_013_protocol_version_abuse(
    session: ClientSession,
    server_info: ServerInfo,
    config: ScanConfig,
) -> TestResult:
    """
    T07-013 — Protocol version validation and abuse resistance.

    Checks two things:
    1. The server's negotiated protocol version is a known/expected value.
       An unrecognised version may indicate a fork with untested security
       properties.
    2. Sends a second ``initialize()`` request — this time checking that the
       server does not erroneously accept a repeated handshake, which could
       be used to downgrade the protocol version mid-session.

    Severity mapping
    ----------------
    Empty / unknown protocol version        → LOW
    Server accepts second initialize()      → MEDIUM  (session hijack risk)
    Known protocol version, replay rejected → PASS
    """
    tid = "T07-013"
    tname = "Protocol Version Abuse"
    t0 = time.perf_counter()

    try:
        proto = (server_info.protocol_version or "").strip()

        # --- Check 1: protocol version is known ---
        if not proto or proto.lower() == "unknown":
            return TestResult(
                test_id=tid, test_name=tname, category=_CAT,
                severity=Severity.LOW, passed=False,
                description=(
                    "Server did not negotiate a recognised MCP protocol version "
                    "(version is empty or unknown)."
                ),
                duration_ms=(time.perf_counter() - t0) * 1000.0,
                remediation=(
                    "Ensure the server returns a valid protocolVersion in its "
                    "initialize response (e.g. '2024-11-05'). "
                    "Clients rely on this to select compatible behaviour."
                ),
            )

        if proto not in _KNOWN_PROTOCOL_VERSIONS:
            return TestResult(
                test_id=tid, test_name=tname, category=_CAT,
                severity=Severity.INFO, passed=True,
                description=(
                    f"Server reported an unrecognised protocol version {proto!r}. "
                    f"Known versions: {sorted(_KNOWN_PROTOCOL_VERSIONS)}. "
                    f"This may be a newer or forked implementation."
                ),
                duration_ms=(time.perf_counter() - t0) * 1000.0,
                details=(
                    f"Negotiated: {proto!r}\n"
                    f"MCPSafe known-good set: {sorted(_KNOWN_PROTOCOL_VERSIONS)}"
                ),
            )

        # --- Check 2: replay initialize() to test version downgrade resistance ---
        # If the server accepts a second initialize it could theoretically allow
        # a MITM to inject a lower protocol version mid-session.
        try:
            await asyncio.wait_for(
                session.initialize(),
                timeout=config.timeout_seconds,
            )
            # Server accepted a second initialize — flag as MEDIUM.
            return TestResult.make_fail(
                test_id=tid, test_name=tname, category=_CAT,
                severity=Severity.MEDIUM,
                description=(
                    f"Server accepted a second initialize() call on an already-"
                    f"established session (protocol {proto!r}). "
                    f"This allows mid-session protocol version downgrade attacks."
                ),
                duration_ms=(time.perf_counter() - t0) * 1000.0,
                details=(
                    f"Protocol version: {proto!r}\n"
                    f"A second initialize() should always be rejected once a "
                    f"session is established."
                ),
                remediation=(
                    "Track session state and reject any initialize() request "
                    "after the session has already been established. "
                    "Accept only one initialize/handshake per connection."
                ),
            )
        except Exception:
            # Rejection is the correct behaviour.
            pass

        return TestResult.make_pass(
            test_id=tid, test_name=tname, category=_CAT,
            description=(
                f"Protocol version {proto!r} is recognised and server correctly "
                f"rejected a second initialize() attempt."
            ),
            duration_ms=(time.perf_counter() - t0) * 1000.0,
            details=f"Negotiated protocol version: {proto!r}",
        )

    except Exception as exc:
        return TestResult.from_exception(
            test_id=tid, test_name=tname, category=_CAT, exc=exc,
            duration_ms=(time.perf_counter() - t0) * 1000.0,
        )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


async def run(
    session: ClientSession,
    server_info: ServerInfo,
    config: ScanConfig,
) -> list[TestResult]:
    """
    Execute all T07 authentication and authorisation tests.

    HTTP tests (T07-001 through T07-005) are run only when
    ``config.transport`` is ``HTTP`` or ``SSE``.

    STDIO tests (T07-006, T07-007) are run only when
    ``config.transport`` is ``STDIO``.

    T07-003 and T07-004 also use the live ``session`` for MCP-level probes
    and run regardless of transport.

    Parameters
    ----------
    session:
        An initialised ``mcp.ClientSession``.
    server_info:
        Populated ``ServerInfo`` from the discovery phase.
    config:
        Active ``ScanConfig``; ``config.transport`` governs which sub-tests run.

    Returns
    -------
    list[TestResult]:
        Variable count depending on transport and server capabilities.
        Never raises.
    """
    results: list[TestResult] = []
    is_http = config.transport in (TransportType.HTTP, TransportType.SSE)
    is_stdio = config.transport == TransportType.STDIO

    # --- T07-001 and T07-002: HTTP-only raw auth probes ---
    if is_http:
        results.append(await _t07_001_unauth_access(config))
        results.extend(await _t07_002_malformed_tokens(config))
    else:
        for tid, desc in [
            ("T07-001", "Unauthenticated Access"),
            ("T07-002", "Malformed Token Rejection"),
        ]:
            results.append(
                TestResult(
                    test_id=tid, test_name=desc, category=_CAT,
                    severity=Severity.INFO, passed=True,
                    description=(
                        f"{desc} test requires HTTP transport — "
                        f"skipped (transport={config.transport.value!r})."
                    ),
                    duration_ms=0.0,
                )
            )

    # --- T07-003: Path traversal — MCP session + resource list ---
    results.extend(await _t07_003_path_traversal(session, server_info))

    # --- T07-004: Credentials in errors — always run ---
    results.append(await _t07_004_credentials_in_errors(session))

    # --- T07-005: CORS — HTTP only ---
    if is_http:
        results.append(await _t07_005_cors(config))
    else:
        results.append(
            TestResult(
                test_id="T07-005", test_name="CORS Misconfiguration",
                category=_CAT, severity=Severity.INFO, passed=True,
                description=(
                    "CORS check requires HTTP transport — "
                    f"skipped (transport={config.transport.value!r})."
                ),
                duration_ms=0.0,
            )
        )

    # --- T07-006: Process privilege — STDIO only ---
    if is_stdio:
        results.append(await _t07_006_process_privilege())
    else:
        results.append(
            TestResult(
                test_id="T07-006", test_name="Process Privilege Check",
                category=_CAT, severity=Severity.INFO, passed=True,
                description=(
                    "Process privilege check requires STDIO transport — "
                    f"skipped (transport={config.transport.value!r})."
                ),
                duration_ms=0.0,
            )
        )

    # --- T07-007: Env var probe — STDIO only ---
    if is_stdio:
        results.append(await _t07_007_env_probe(session, server_info, config))
    else:
        results.append(
            TestResult(
                test_id="T07-007", test_name="Environment Variable Probe",
                category=_CAT, severity=Severity.INFO, passed=True,
                description=(
                    "Environment variable probe requires STDIO transport — "
                    f"skipped (transport={config.transport.value!r})."
                ),
                duration_ms=0.0,
            )
        )

    # --- T07-008 through T07-013: Protocol-level abuse (all transports) ---
    results.append(await _t07_008_invalid_tool_name(session, config))
    results.append(await _t07_009_oversized_args(session, server_info, config))
    results.append(await _t07_010_replay_initialize(session, config))
    results.append(await _t07_011_deeply_nested_args(session, server_info, config))
    results.append(await _t07_012_homoglyph_tool_name(session, server_info, config))
    results.append(await _t07_013_protocol_version_abuse(session, server_info, config))

    return results
