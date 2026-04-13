"""
mcpsafe.transport
=================
Async context manager that opens an MCP connection over stdio **or** HTTP/SSE
and yields an ``mcp.ClientSession`` ready for use by the runner and test modules.

Usage
-----
    async with MCPConnection(config) as (session, conn_info):
        tools = await session.list_tools()

The caller never needs to know which transport is active — all MCP calls are
the same regardless.  Connection failures are caught here and re-raised as
``TransportError`` so the runner can produce a structured ``TestResult``
rather than a raw traceback.
"""

from __future__ import annotations

import asyncio
import os
import shlex
import sys
import time
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Optional
from urllib.parse import urlparse

import anyio
import httpx
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.sse import sse_client
from mcp.client.streamable_http import streamablehttp_client

from mcpsafe.models import (
    ConnectionInfo,
    ScanConfig,
    ServerInfo,
    TransportType,
)


# ---------------------------------------------------------------------------
# Custom exception
# ---------------------------------------------------------------------------

# Launchers that download and install packages before starting the server.
# They need a much longer timeout on first run (package download can take 30 s+).
# docker is included because container cold-start (image pull + init) can
# easily exceed the default timeout even with a local image cache.
_PACKAGE_LAUNCHERS: frozenset[str] = frozenset({"uvx", "npx", "bunx", "docker"})

# Multiplier applied to config.timeout_seconds for the MCP handshake when a
# package launcher is detected in the command.  Subsequent runs will be fast
# (cache hit) so this only matters on cold starts.
_LAUNCHER_TIMEOUT_MULTIPLIER: int = 4


def _unwrap_exception(exc: BaseException) -> str:
    """
    Produce a human-readable message from *exc*, even when it is an
    ``ExceptionGroup`` (raised by anyio TaskGroups on Python 3.11+).

    Strategy
    --------
    1. If *exc* is an ``ExceptionGroup`` / ``BaseExceptionGroup``, recurse
       into its ``.exceptions`` to find the deepest leaf exception.
    2. Otherwise walk the ``__cause__`` / ``__context__`` chain for a more
       informative root cause.
    3. Return ``"{ExcType}: {message}"`` for the innermost exception found.
    """
    # Unwrap ExceptionGroup (Python 3.11+ / anyio TaskGroups)
    if hasattr(exc, "exceptions") and exc.exceptions:  # type: ignore[union-attr]
        # Recurse into the first sub-exception (there is usually only one)
        return _unwrap_exception(exc.exceptions[0])  # type: ignore[union-attr]

    # Walk the cause/context chain to find the root
    root: BaseException = exc
    visited: set[int] = set()
    while True:
        inner = root.__cause__ or root.__context__
        if inner is None or id(inner) in visited:
            break
        visited.add(id(inner))
        # Stop unwrapping at another ExceptionGroup so we recurse properly
        if hasattr(inner, "exceptions") and inner.exceptions:
            return _unwrap_exception(inner)
        root = inner

    return f"{type(root).__name__}: {root}"


class TransportError(Exception):
    """
    Raised when MCPConnection cannot establish or maintain a connection.

    Attributes
    ----------
    message:
        Human-readable description of the failure.
    transport:
        Which transport type was attempted.
    cause:
        The original exception, if any.
    """

    def __init__(
        self,
        message: str,
        transport: TransportType,
        cause: Optional[BaseException] = None,
    ) -> None:
        super().__init__(message)
        self.transport = transport
        self.cause = cause

    def __str__(self) -> str:
        base = super().__str__()
        if self.cause:
            return f"{base} (caused by {type(self.cause).__name__}: {self.cause})"
        return base


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _parse_http_target(target: str) -> str:
    """
    Ensure the target URL has a scheme.  Defaults to ``http://`` when none
    is provided so users can write ``localhost:8080`` on the CLI.
    """
    parsed = urlparse(target)
    if not parsed.scheme:
        return f"http://{target}"
    return target


async def _probe_latency(session: ClientSession, timeout: float) -> float:
    """
    Call ``list_tools`` once and return the round-trip time in milliseconds.

    This serves as a lightweight liveness check immediately after connection.
    Raises ``TransportError`` on timeout or any MCP-level error.
    """
    t0 = time.perf_counter()
    try:
        with anyio.fail_after(timeout):
            await session.list_tools()
    except TimeoutError as exc:
        raise TransportError(
            f"Liveness probe timed out after {timeout}s",
            transport=TransportType.STDIO,  # overwritten by caller
            cause=exc,
        ) from exc
    except Exception as exc:
        raise TransportError(
            f"Liveness probe failed: {exc}",
            transport=TransportType.STDIO,
            cause=exc,
        ) from exc
    return (time.perf_counter() - t0) * 1000.0


# ---------------------------------------------------------------------------
# Public async context manager
# ---------------------------------------------------------------------------


@asynccontextmanager
async def MCPConnection(
    config: ScanConfig,
) -> AsyncGenerator[tuple[ClientSession, ConnectionInfo], None]:
    """
    Async context manager that opens an MCP connection and yields a ready-to-use
    ``(ClientSession, ConnectionInfo)`` tuple.

    Parameters
    ----------
    config:
        A fully-populated ``ScanConfig`` from the CLI / runner.

    Yields
    ------
    session:
        An initialised ``mcp.ClientSession``.  All MCP calls (``list_tools``,
        ``call_tool``, ``list_resources``, …) are made through this object.
    conn_info:
        Metadata about the connection (latency, TLS status, …) for the report.

    Raises
    ------
    TransportError:
        If the connection cannot be established within ``config.timeout_seconds``
        or if the liveness probe fails.
    """
    transport = config.transport

    if transport == TransportType.STDIO:
        async with _stdio_connection(config) as result:
            yield result
    elif transport in (TransportType.HTTP, TransportType.SSE):
        async with _http_sse_connection(config) as result:
            yield result
    else:
        raise TransportError(
            f"Unsupported transport: {transport!r}",
            transport=transport,
        )


# ---------------------------------------------------------------------------
# Stdio transport
# ---------------------------------------------------------------------------


@asynccontextmanager
async def _stdio_connection(
    config: ScanConfig,
) -> AsyncGenerator[tuple[ClientSession, ConnectionInfo], None]:
    """Open a stdio MCP connection and yield (session, conn_info)."""
    # Split "python my_server.py --flag" into command + args.
    # On Windows use simple split() to avoid shlex stripping backslashes
    # in paths; on Unix use shlex.split() for proper quote handling.
    if sys.platform == "win32":
        # Guard against accidental shell metacharacters in the target string.
        # Note: subprocess with a list (not shell=True) does NOT pass through a
        # shell, so these characters would become literal arguments rather than
        # being interpreted — but they almost certainly indicate a typo.
        _WIN_SHELL_CHARS = frozenset("&|;<>`")
        shell_chars_found = [c for c in config.target if c in _WIN_SHELL_CHARS]
        if shell_chars_found:
            raise TransportError(
                f"stdio target contains shell metacharacter(s) "
                f"{sorted(set(shell_chars_found))!r} — "
                f"use a plain command without shell operators.",
                transport=TransportType.STDIO,
            )
        parts = config.target.split()
    else:
        parts = shlex.split(config.target)

    if not parts:
        raise TransportError(
            "stdio target is empty — supply a command to run.",
            transport=TransportType.STDIO,
        )
    command, extra_args = parts[0], parts[1:]
    # Merge --env overrides on top of the current process environment so the
    # subprocess inherits PATH, USERPROFILE, etc. while still picking up any
    # extra vars the user passed via --env KEY=VALUE.
    merged_env: dict[str, str] = {**os.environ}
    if config.env:
        merged_env.update(config.env)

    params = StdioServerParameters(
        command=command,
        args=extra_args + list(config.args),
        env=merged_env,
    )

    # Package launchers (uvx, npx, bunx) may need to download the package on
    # first run.  Give them a much longer handshake window so a cold-start
    # doesn't look like a connection failure.
    is_launcher = command.lower() in _PACKAGE_LAUNCHERS
    init_timeout = (
        config.timeout_seconds * _LAUNCHER_TIMEOUT_MULTIPLIER
        if is_launcher
        else config.timeout_seconds
    )

    try:
        async with stdio_client(params) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                # Initialise the MCP handshake
                try:
                    with anyio.fail_after(init_timeout):
                        await session.initialize()
                except TimeoutError as exc:
                    hint = (
                        f" (launcher '{command}' may still be downloading the package "
                        f"— try again or increase --timeout)"
                        if is_launcher
                        else ""
                    )
                    raise TransportError(
                        f"stdio MCP handshake timed out after {init_timeout:.0f}s{hint}",
                        transport=TransportType.STDIO,
                        cause=exc,
                    ) from exc
                except Exception as exc:
                    raise TransportError(
                        f"stdio MCP handshake failed: {_unwrap_exception(exc)}",
                        transport=TransportType.STDIO,
                        cause=exc,
                    ) from exc

                # Liveness probe to measure initial latency
                try:
                    latency_ms = await _probe_latency(session, config.timeout_seconds)
                except TransportError as exc:
                    exc.transport = TransportType.STDIO
                    raise

                conn_info = ConnectionInfo(
                    transport=TransportType.STDIO,
                    target=config.target,
                    latency_ms=latency_ms,
                    tls_verified=None,
                )

                yield session, conn_info

    except TransportError:
        raise  # already structured — pass through
    except FileNotFoundError as exc:
        raise TransportError(
            f"stdio command not found: {config.target!r}",
            transport=TransportType.STDIO,
            cause=exc,
        ) from exc
    except PermissionError as exc:
        raise TransportError(
            f"stdio command not executable: {config.target!r}",
            transport=TransportType.STDIO,
            cause=exc,
        ) from exc
    except Exception as exc:
        err_str = _unwrap_exception(exc)
        # Docker on Windows: anyio's subprocess transport raises WouldBlock
        # because Docker Desktop's Windows named-pipe semantics are incompatible
        # with anyio's non-blocking pipe reads.  Give an actionable hint.
        if (
            command.lower() == "docker"
            and sys.platform == "win32"
            and ("wouldblock" in err_str.lower() or "would block" in err_str.lower())
        ):
            raise TransportError(
                f"Docker stdio transport failed on Windows (WouldBlock pipe error). "
                f"Docker Desktop's Windows named-pipe implementation is incompatible "
                f"with the MCP stdio client on Windows.\n\n"
                f"Workaround — run the same scan inside WSL2:\n"
                f"  wsl mcpsafe scan \"{config.target}\" --output all\n\n"
                f"Docker MCP scanning works correctly on Linux and macOS.",
                transport=TransportType.STDIO,
                cause=exc,
            ) from exc
        raise TransportError(
            f"Unexpected stdio transport error: {err_str}",
            transport=TransportType.STDIO,
            cause=exc,
        ) from exc


# ---------------------------------------------------------------------------
# HTTP / SSE transport
# ---------------------------------------------------------------------------


@asynccontextmanager
async def _http_sse_connection(
    config: ScanConfig,
) -> AsyncGenerator[tuple[ClientSession, ConnectionInfo], None]:
    """Open an HTTP/SSE MCP connection and yield (session, conn_info)."""
    base_url = _parse_http_target(config.target)

    # Build headers — merge auth token into Authorization if provided
    headers: dict[str, str] = dict(config.headers)
    if config.auth_token and "Authorization" not in headers:
        headers["Authorization"] = f"Bearer {config.auth_token}"

    # Detect TLS
    tls_verified: Optional[bool] = None
    server_header: Optional[str] = None

    if base_url.startswith("https://"):
        tls_verified = True  # httpx verifies by default; we record intent

    # Probe basic HTTP reachability before opening the SSE stream.
    try:
        with anyio.fail_after(config.timeout_seconds):
            async with httpx.AsyncClient(
                headers=headers,
                timeout=config.timeout_seconds,
                follow_redirects=True,
            ) as http:
                probe_url = base_url.rstrip("/") + "/"
                try:
                    resp = await http.get(probe_url)
                    server_header = resp.headers.get("server")
                except httpx.ConnectError as exc:
                    raise TransportError(
                        f"HTTP connection refused: {base_url}",
                        transport=config.transport,
                        cause=exc,
                    ) from exc
                except httpx.TimeoutException as exc:
                    raise TransportError(
                        f"HTTP probe timed out: {base_url}",
                        transport=config.transport,
                        cause=exc,
                    ) from exc
    except TransportError:
        raise
    except TimeoutError as exc:
        raise TransportError(
            f"HTTP probe timed out (outer): {base_url}",
            transport=config.transport,
            cause=exc,
        ) from exc

    # Resolve the final endpoint URL and whether to use Streamable HTTP or SSE.
    #
    # Rules (checked against the stripped URL):
    #   - ends with /sse   → legacy SSE client, use URL as-is
    #   - ends with /mcp   → Streamable HTTP client, use URL as-is
    #   - ends with /base  → Streamable HTTP at root (strip /base suffix)
    #                        Use this for servers like https://mcp.stripe.com/base
    #                        whose Streamable HTTP endpoint is at the root path.
    #   - anything else    → default to Streamable HTTP at <base>/mcp
    #
    stripped = base_url.rstrip("/")
    if stripped.endswith("/sse"):
        _use_streamable = False
        _endpoint_url = stripped
    elif stripped.endswith("/mcp"):
        _use_streamable = True
        _endpoint_url = stripped
    elif stripped.endswith("/base"):
        # Escape hatch: user appends /base to tell MCPSafe "use this root URL
        # as the Streamable HTTP endpoint without any path modification".
        # e.g.  https://mcp.stripe.com/base  →  https://mcp.stripe.com
        _use_streamable = True
        _endpoint_url = stripped[: -len("/base")]
    else:
        _use_streamable = True
        _endpoint_url = stripped + "/mcp"

    if _use_streamable:
        cm = streamablehttp_client(
            url=_endpoint_url,
            headers=headers,
            timeout=config.timeout_seconds,
        )
    else:
        cm = sse_client(
            url=_endpoint_url,
            headers=headers,
            timeout=config.timeout_seconds,
        )

    # _teardown_only is set to True immediately after the caller's `async with`
    # block exits normally (all tests ran).  Any transport error that surfaces
    # during cleanup — e.g. a 400 from a rate-limited HTTP server whose session
    # was invalidated by T07 auth tests — is silently swallowed so it does not
    # generate a spurious T00-001 CRITICAL finding after a successful scan.
    _teardown_only = False

    try:
        async with cm as streams:
            # streamablehttp_client returns 3-tuple (read, write, get_session_id)
            # sse_client returns 2-tuple (read, write)
            read_stream, write_stream = streams[0], streams[1]
            async with ClientSession(read_stream, write_stream) as session:
                try:
                    with anyio.fail_after(config.timeout_seconds):
                        await session.initialize()
                except TimeoutError as exc:
                    raise TransportError(
                        f"HTTP/SSE MCP handshake timed out after {config.timeout_seconds}s",
                        transport=config.transport,
                        cause=exc,
                    ) from exc
                except Exception as exc:
                    raise TransportError(
                        f"HTTP/SSE MCP handshake failed: {_unwrap_exception(exc)}",
                        transport=config.transport,
                        cause=exc,
                    ) from exc

                # Liveness probe
                try:
                    latency_ms = await _probe_latency(session, config.timeout_seconds)
                except TransportError as exc:
                    exc.transport = config.transport
                    raise

                conn_info = ConnectionInfo(
                    transport=config.transport,
                    target=_endpoint_url,
                    latency_ms=latency_ms,
                    tls_verified=tls_verified,
                    server_header=server_header,
                )

                yield session, conn_info

                # Mark that the caller's block exited normally — any subsequent
                # exception is from transport teardown, not from the tests.
                _teardown_only = True

    except TransportError:
        if _teardown_only:
            # Teardown error on an already-complete scan (e.g. 400/429 from a
            # rate-limited server invalidated by auth tests).  Suppress it so
            # the scan report is not polluted with a bogus connection failure.
            return
        raise
    except Exception as exc:
        if _teardown_only:
            # Same: swallow non-critical cleanup errors after tests are done.
            return
        raise TransportError(
            f"Unexpected HTTP/SSE transport error: {_unwrap_exception(exc)}",
            transport=config.transport,
            cause=exc,
        ) from exc


# ---------------------------------------------------------------------------
# Convenience: connect and return ServerInfo snapshot
# ---------------------------------------------------------------------------


async def discover_server_info(
    session: ClientSession,
    config: ScanConfig,
    conn_info: ConnectionInfo,
) -> ServerInfo:
    """
    Query the server for its full capability set and return a ``ServerInfo``.

    This is called by the runner immediately after ``MCPConnection`` yields so
    that every subsequent test module has a fully-populated ``ServerInfo`` to
    read from without making repeated discovery calls.

    Parameters
    ----------
    session:
        An initialised ``mcp.ClientSession`` (from ``MCPConnection``).
    config:
        The active ``ScanConfig``.
    conn_info:
        The ``ConnectionInfo`` returned by ``MCPConnection``.

    Returns
    -------
    ServerInfo:
        Populated with tools, resources, prompts, and capabilities.

    Raises
    ------
    TransportError:
        If any discovery call fails or times out.
    """
    # Import here to avoid circular imports at module load time.
    from mcpsafe.models import MCPPrompt, MCPResource, MCPTool, ServerInfo
    from mcpsafe.tests._helpers import sanitise_server_string as _san

    timeout = config.timeout_seconds

    async def _run(coro):  # type: ignore[no-untyped-def]
        try:
            with anyio.fail_after(timeout):
                return await coro
        except TimeoutError as exc:
            raise TransportError(
                "Discovery call timed out",
                transport=conn_info.transport,
                cause=exc,
            ) from exc
        except Exception as exc:
            raise TransportError(
                f"Discovery call failed: {exc}",
                transport=conn_info.transport,
                cause=exc,
            ) from exc

    # Parallel discovery — list_tools / list_resources / list_prompts
    tools_resp, resources_resp, prompts_resp = await asyncio.gather(
        _run(session.list_tools()),
        _run(session.list_resources()),
        _run(session.list_prompts()),
        return_exceptions=True,
    )

    # Tolerate servers that don't implement all capability groups.
    def _safe_list(resp: object, label: str) -> list:  # type: ignore[type-arg]
        if isinstance(resp, Exception):
            return []
        return getattr(resp, label, []) or []

    raw_tools = _safe_list(tools_resp, "tools")
    raw_resources = _safe_list(resources_resp, "resources")
    raw_prompts = _safe_list(prompts_resp, "prompts")

    # Sanitise all server-supplied strings at the point of ingestion so that
    # every downstream consumer (test modules, reporters, CLI) sees clean data.
    # This strips NUL bytes, ANSI escape codes, and other control characters
    # that could confuse log consumers or HTML renderers.
    tools = [
        MCPTool(
            name=_san(t.name, max_len=200),
            description=_san(t.description or "", max_len=1000),
            input_schema=t.inputSchema if hasattr(t, "inputSchema") else {},
        )
        for t in raw_tools
    ]

    resources = [
        MCPResource(
            uri=str(r.uri),
            name=_san(r.name, max_len=200),
            description=_san(r.description or "", max_len=500),
            mime_type=getattr(r, "mimeType", None),
        )
        for r in raw_resources
    ]

    prompts = [
        MCPPrompt(
            name=_san(p.name, max_len=200),
            description=_san(p.description or "", max_len=500),
            arguments=[
                {
                    "name": _san(a.name, max_len=100),
                    "description": _san(a.description or "", max_len=300),
                    "required": a.required,
                }
                for a in (p.arguments or [])
            ],
        )
        for p in raw_prompts
    ]

    # Pull server metadata from the session's initialisation result.
    init_result = getattr(session, "_initialize_result", None)
    server_name = "unknown"
    server_version = "unknown"
    protocol_version = "unknown"
    capabilities: dict = {}

    if init_result is not None:
        server_info_obj = getattr(init_result, "serverInfo", None)
        if server_info_obj:
            server_name = _san(getattr(server_info_obj, "name", "unknown") or "unknown", max_len=100)
            server_version = _san(getattr(server_info_obj, "version", "unknown") or "unknown", max_len=50)
        protocol_version = _san(getattr(init_result, "protocolVersion", "unknown") or "unknown", max_len=20)
        caps = getattr(init_result, "capabilities", None)
        if caps is not None:
            capabilities = vars(caps) if hasattr(caps, "__dict__") else {}

    return ServerInfo(
        name=server_name,
        version=server_version,
        protocol_version=protocol_version,
        transport=conn_info.transport,
        target=conn_info.target,
        tools=tools,
        resources=resources,
        prompts=prompts,
        capabilities=capabilities,
    )
