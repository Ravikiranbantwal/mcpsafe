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

    return results
