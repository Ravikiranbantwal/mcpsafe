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
import shlex
import sys
import time
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Optional
from urllib.parse import urlparse

import httpx
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.sse import sse_client

from mcpsafe.models import (
    ConnectionInfo,
    ScanConfig,
    ServerInfo,
    TransportType,
)


# ---------------------------------------------------------------------------
# Custom exception
# ---------------------------------------------------------------------------


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
        async with asyncio.timeout(timeout):
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
        parts = config.target.split()
    else:
        parts = shlex.split(config.target)
    command, extra_args = parts[0], parts[1:]
    params = StdioServerParameters(
        command=command,
        args=extra_args + list(config.args),
        env=config.env if config.env else None,
    )

    try:
        async with stdio_client(params) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                # Initialise the MCP handshake
                try:
                    async with asyncio.timeout(config.timeout_seconds):
                        await session.initialize()
                except TimeoutError as exc:
                    raise TransportError(
                        f"stdio MCP handshake timed out after {config.timeout_seconds}s",
                        transport=TransportType.STDIO,
                        cause=exc,
                    ) from exc
                except Exception as exc:
                    raise TransportError(
                        f"stdio MCP handshake failed: {exc}",
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
        raise TransportError(
            f"Unexpected stdio transport error: {exc}",
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
        async with asyncio.timeout(config.timeout_seconds):
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

    # Now open the SSE MCP stream.
    sse_url = base_url.rstrip("/") + "/sse"
    try:
        async with sse_client(
            url=sse_url,
            headers=headers,
            timeout=config.timeout_seconds,
        ) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                # MCP handshake
                try:
                    async with asyncio.timeout(config.timeout_seconds):
                        await session.initialize()
                except TimeoutError as exc:
                    raise TransportError(
                        f"HTTP/SSE MCP handshake timed out after {config.timeout_seconds}s",
                        transport=config.transport,
                        cause=exc,
                    ) from exc
                except Exception as exc:
                    raise TransportError(
                        f"HTTP/SSE MCP handshake failed: {exc}",
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
                    target=base_url,
                    latency_ms=latency_ms,
                    tls_verified=tls_verified,
                    server_header=server_header,
                )

                yield session, conn_info

    except TransportError:
        raise
    except Exception as exc:
        raise TransportError(
            f"Unexpected HTTP/SSE transport error: {exc}",
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

    timeout = config.timeout_seconds

    async def _run(coro):  # type: ignore[no-untyped-def]
        try:
            async with asyncio.timeout(timeout):
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

    tools = [
        MCPTool(
            name=t.name,
            description=t.description or "",
            input_schema=t.inputSchema if hasattr(t, "inputSchema") else {},
        )
        for t in raw_tools
    ]

    resources = [
        MCPResource(
            uri=r.uri,
            name=r.name,
            description=r.description or "",
            mime_type=getattr(r, "mimeType", None),
        )
        for r in raw_resources
    ]

    prompts = [
        MCPPrompt(
            name=p.name,
            description=p.description or "",
            arguments=[
                {"name": a.name, "description": a.description or "", "required": a.required}
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
            server_name = getattr(server_info_obj, "name", "unknown")
            server_version = getattr(server_info_obj, "version", "unknown")
        protocol_version = getattr(init_result, "protocolVersion", "unknown")
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
