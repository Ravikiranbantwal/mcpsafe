"""
mcpsafe.tests.t20_memory_leak
==============================
PERFORMANCE category — **Server memory-growth detection**.

Fires many calls at a lightweight tool and watches the *response-size*
trend over time as an indirect leak signal.  Because MCPSafe runs as a
separate process it cannot directly observe the server's RSS; instead
we use two heuristics that correlate with server-side leaks:

  1. **Response-size drift** — a server that appends to an ever-growing
     history buffer will return longer payloads over time.
  2. **Latency drift** — a server with GC pressure or fragmented heap
     will gradually slow down.

For stdio servers that MCPSafe launched itself, if ``psutil`` is
available we ALSO sample the subprocess RSS directly — the ground-truth
signal.  This is best-effort and silently skipped when unavailable.

Test inventory
--------------
T20-001   Response-size drift                   LOW/MEDIUM
T20-002   Latency drift                          LOW/MEDIUM
T20-003   Subprocess RSS growth (stdio, optional) MEDIUM/HIGH
T20-004   Summary

Public API
----------
    async def run(session, server_info, config) -> list[TestResult]
"""

from __future__ import annotations

import os
import time
from typing import Optional

import anyio
from mcp import ClientSession
from mcp.types import TextContent

from mcpsafe.models import (
    Category,
    ScanConfig,
    ServerInfo,
    Severity,
    TestResult,
    TransportType,
)
from mcpsafe.tests._helpers import RateLimiter, cap_response, looks_like_api_rejection

_CALLS = 40
_TIMEOUT_SEC = 5.0
_RSS_SAMPLE_EVERY = 10            # sample subprocess RSS every N calls
_SIZE_DRIFT_THRESHOLD = 1.5       # ratio of last-quartile mean / first-quartile mean
_LATENCY_DRIFT_THRESHOLD = 2.0    # ratio of last-quartile mean / first-quartile mean
_RSS_GROWTH_MB_PER_CALL = 0.25    # ≥ this many MB per call = MEDIUM, 2× = HIGH


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


def _pick_probe_tool(server_info: ServerInfo):
    """Pick the lightest-looking tool to hammer repeatedly."""
    for t in server_info.tools or []:
        schema = t.input_schema
        if isinstance(schema, dict):
            required = schema.get("required", []) or []
            if len(required) <= 1:
                return t
    return (server_info.tools or [None])[0]


def _quartile_mean(samples: list[float], lower: bool) -> float:
    if not samples:
        return 0.0
    n = len(samples)
    cut = max(1, n // 4)
    window = samples[:cut] if lower else samples[-cut:]
    return sum(window) / len(window)


def _subprocess_rss_sampler() -> Optional[object]:
    """
    Return a callable ``() -> int_bytes`` that samples the RSS of the MCPSafe-
    spawned stdio server subprocess, or ``None`` when not applicable.

    Detection strategy:
      * Requires ``psutil`` (optional dependency).
      * Iterates over direct children of the current process and picks the
        first one whose cmdline does NOT include "python" running mcpsafe
        itself.  This is best-effort; if ambiguous we return None.
    """
    try:
        import psutil  # type: ignore
    except Exception:
        return None

    try:
        me = psutil.Process(os.getpid())
        kids = me.children(recursive=True)
    except Exception:
        return None

    # Prefer children whose cmdline mentions common MCP server keywords.
    hints = ("mcp", "server", "npx", "uvx", "node", "python")
    best: Optional[int] = None
    for child in kids:
        try:
            cmd = " ".join(child.cmdline()).lower()
        except Exception:
            continue
        if any(h in cmd for h in hints) and "mcpsafe" not in cmd:
            best = child.pid
            break
    if best is None and kids:
        best = kids[0].pid

    if best is None:
        return None

    def _sample() -> int:
        try:
            return psutil.Process(best).memory_info().rss
        except Exception:
            return 0

    return _sample


async def run(
    session: ClientSession,
    server_info: ServerInfo,
    config: ScanConfig,
) -> list[TestResult]:
    """Execute T20 — Memory Leak Detection."""
    t_start = time.perf_counter()
    results: list[TestResult] = []
    limiter = RateLimiter(config)

    tool = _pick_probe_tool(server_info)
    if tool is None:
        results.append(
            TestResult(
                test_id="T20-004", test_name="Memory Leak — Summary",
                category=Category.PERFORMANCE,
                severity=Severity.INFO, passed=True,
                description="No tools to exercise; leak probe skipped.",
                duration_ms=(time.perf_counter() - t_start) * 1000.0,
            )
        )
        return results

    # Try to establish an RSS sampler (stdio only).
    rss_sampler = None
    if config.transport == TransportType.STDIO:
        rss_sampler = _subprocess_rss_sampler()

    sizes: list[int] = []
    latencies: list[float] = []
    rss_samples: list[int] = []
    errors = 0

    # Determine if tool needs a string arg — keep payloads small.
    schema = tool.input_schema if isinstance(tool.input_schema, dict) else {}
    props = schema.get("properties") or {}
    required = schema.get("required", []) or []
    args: dict[str, object] = {}
    for pname in required:
        pschema = props.get(pname) or {}
        ptype = pschema.get("type") if isinstance(pschema, dict) else None
        if ptype == "string":
            args[pname] = "ping"
        elif ptype in ("integer", "number"):
            args[pname] = 1
        elif ptype == "boolean":
            args[pname] = False
        elif ptype == "array":
            args[pname] = []
        elif ptype == "object":
            args[pname] = {}

    if rss_sampler is not None:
        try:
            rss_samples.append(rss_sampler())
        except Exception:
            rss_sampler = None

    for i in range(_CALLS):
        await limiter.acquire()
        t0 = time.perf_counter()
        try:
            with anyio.fail_after(_TIMEOUT_SEC):
                resp = await session.call_tool(tool.name, arguments=args)
            text = _extract_text(resp)
            sizes.append(len(text))
            latencies.append((time.perf_counter() - t0) * 1000.0)
        except Exception as exc:
            errors += 1
            if looks_like_api_rejection([str(exc)]):
                # API rejected us — can't continue this probe reliably.
                break

        if rss_sampler is not None and i % _RSS_SAMPLE_EVERY == 0:
            try:
                rss_samples.append(rss_sampler())
            except Exception:
                pass

    duration = (time.perf_counter() - t_start) * 1000.0

    if len(sizes) < 8:
        results.append(
            TestResult(
                test_id="T20-004", test_name="Memory Leak — Summary",
                category=Category.PERFORMANCE,
                severity=Severity.INFO, passed=True,
                description=(
                    f"Insufficient samples to evaluate leak ({len(sizes)} ok, "
                    f"{errors} errors). Probe skipped."
                ),
                duration_ms=duration,
            )
        )
        return results

    # ── T20-001 response-size drift ──────────────────────────────────
    size_low = _quartile_mean(sizes, lower=True)
    size_high = _quartile_mean(sizes, lower=False)
    size_ratio = (size_high / size_low) if size_low > 0 else 1.0
    if size_ratio >= _SIZE_DRIFT_THRESHOLD:
        sev = Severity.MEDIUM if size_ratio >= _SIZE_DRIFT_THRESHOLD * 1.5 else Severity.LOW
        results.append(
            TestResult(
                test_id="T20-001", test_name="Response-Size Drift",
                category=Category.PERFORMANCE, severity=sev, passed=False,
                description=(
                    f"Response sizes grew {size_ratio:.2f}× from first-quartile "
                    f"mean {size_low:.0f} bytes to last-quartile mean "
                    f"{size_high:.0f} bytes over {len(sizes)} calls. Likely "
                    f"indicates an unbounded server-side accumulator."
                ),
                duration_ms=duration,
            )
        )
    else:
        results.append(
            TestResult.make_pass(
                test_id="T20-001", test_name="Response-Size Drift",
                category=Category.PERFORMANCE,
                description=(
                    f"Response sizes stable "
                    f"({size_low:.0f}→{size_high:.0f} bytes, ratio {size_ratio:.2f}×)."
                ),
                duration_ms=duration,
            )
        )

    # ── T20-002 latency drift ────────────────────────────────────────
    lat_low = _quartile_mean(latencies, lower=True)
    lat_high = _quartile_mean(latencies, lower=False)
    lat_ratio = (lat_high / lat_low) if lat_low > 0 else 1.0
    if lat_ratio >= _LATENCY_DRIFT_THRESHOLD:
        sev = Severity.MEDIUM if lat_ratio >= _LATENCY_DRIFT_THRESHOLD * 1.5 else Severity.LOW
        results.append(
            TestResult(
                test_id="T20-002", test_name="Latency Drift",
                category=Category.PERFORMANCE, severity=sev, passed=False,
                description=(
                    f"Latency grew {lat_ratio:.2f}× from {lat_low:.1f}ms to "
                    f"{lat_high:.1f}ms mean across {len(latencies)} calls."
                ),
                duration_ms=duration,
            )
        )
    else:
        results.append(
            TestResult.make_pass(
                test_id="T20-002", test_name="Latency Drift",
                category=Category.PERFORMANCE,
                description=(
                    f"Latency stable ({lat_low:.1f}→{lat_high:.1f}ms, "
                    f"ratio {lat_ratio:.2f}×)."
                ),
                duration_ms=duration,
            )
        )

    # ── T20-003 RSS growth (optional) ────────────────────────────────
    if rss_samples and len(rss_samples) >= 3:
        baseline = rss_samples[0] / (1024 * 1024)
        peak = max(rss_samples) / (1024 * 1024)
        growth = peak - baseline
        per_call = growth / max(len(sizes), 1)
        if per_call >= _RSS_GROWTH_MB_PER_CALL * 2:
            results.append(
                TestResult(
                    test_id="T20-003", test_name="Subprocess RSS Growth",
                    category=Category.PERFORMANCE,
                    severity=Severity.HIGH, passed=False,
                    description=(
                        f"Server subprocess RSS grew {growth:.1f} MB across "
                        f"{len(sizes)} calls ({per_call*1024:.0f} KB/call). "
                        f"This is consistent with an unbounded leak."
                    ),
                    duration_ms=duration,
                    details=f"samples (MB): {[round(s/1e6,1) for s in rss_samples]}",
                )
            )
        elif per_call >= _RSS_GROWTH_MB_PER_CALL:
            results.append(
                TestResult(
                    test_id="T20-003", test_name="Subprocess RSS Growth",
                    category=Category.PERFORMANCE,
                    severity=Severity.MEDIUM, passed=False,
                    description=(
                        f"Server subprocess RSS grew {growth:.1f} MB across "
                        f"{len(sizes)} calls ({per_call*1024:.0f} KB/call)."
                    ),
                    duration_ms=duration,
                    details=f"samples (MB): {[round(s/1e6,1) for s in rss_samples]}",
                )
            )
        else:
            results.append(
                TestResult.make_pass(
                    test_id="T20-003", test_name="Subprocess RSS Growth",
                    category=Category.PERFORMANCE,
                    description=(
                        f"RSS stable: baseline {baseline:.1f} MB → peak {peak:.1f} MB "
                        f"across {len(sizes)} calls."
                    ),
                    duration_ms=duration,
                )
            )

    # ── Summary ──────────────────────────────────────────────────────
    bad = sum(1 for r in results if r.severity >= Severity.MEDIUM and not r.passed)
    if bad:
        results.append(
            TestResult.make_fail(
                test_id="T20-004", test_name="Memory Leak — Summary",
                category=Category.PERFORMANCE, severity=Severity.MEDIUM,
                description=f"{bad} memory/leak signal(s) detected. See T20-001/002/003.",
                duration_ms=duration,
            )
        )
    else:
        results.append(
            TestResult.make_pass(
                test_id="T20-004", test_name="Memory Leak — Summary",
                category=Category.PERFORMANCE,
                description=(
                    f"No memory growth signals over {len(sizes)} probe calls."
                ),
                duration_ms=duration,
            )
        )
    return results
