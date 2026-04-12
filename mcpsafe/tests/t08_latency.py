"""
mcpsafe.tests.t08_latency
==========================
PERFORMANCE category — Response-time benchmarking and cold-start detection.

This module runs **before** T05 (load tests) to establish a per-tool baseline.
Its T08-005 comparison is run **after** T05 by the runner, which calls
``compute_latency_comparison()`` directly and appends the result.

Module-level cache
------------------
``_baseline_latencies`` is populated by ``run()`` and read by
``compute_latency_comparison()``.  The runner must call ``run()`` before
``compute_latency_comparison()`` for the comparison to be meaningful.

Test inventory
--------------
T08-001  Per-tool baseline latency    5 calls each; mean/min/max; MEDIUM > 5 s.
T08-002  list_tools() latency         5 samples; MEDIUM > 1 s, HIGH > 5 s.
T08-003  Resource read latency        Up to 3 resources × 3 calls each.
T08-004  Cold-start detection         Ratio of call-1 to warm mean; INFO > 10×.
T08-005  Latency degradation          baseline mean vs T05 p95; HIGH > 10×.
         (run via compute_latency_comparison() after T05)

Public API
----------
    async def run(
        session: ClientSession,
        server_info: ServerInfo,
        config: ScanConfig,
        t05_results: Optional[List[TestResult]] = None,
    ) -> list[TestResult]

    async def compute_latency_comparison(
        t05_results: Optional[list[TestResult]],
    ) -> TestResult
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Optional

from mcp import ClientSession

from mcpsafe.models import (
    Category,
    MCPTool,
    ScanConfig,
    ServerInfo,
    Severity,
    TestResult,
)

# ---------------------------------------------------------------------------
# Module-level baseline cache
# ---------------------------------------------------------------------------

# tool_name → mean latency in milliseconds, populated by run()
_baseline_latencies: dict[str, float] = {}

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_CAT = Category.PERFORMANCE

_BASELINE_SAMPLES   = 5   # calls per tool for T08-001
_DISCOVERY_SAMPLES  = 5   # list_tools() calls for T08-002
_RESOURCE_SAMPLES   = 3   # calls per resource for T08-003
_MAX_RESOURCES      = 3   # max resources to benchmark in T08-003

_TOOL_HIGH_MS   = 30_000.0
_TOOL_MEDIUM_MS  = 5_000.0

_DISC_HIGH_MS    = 5_000.0
_DISC_MEDIUM_MS  = 1_000.0

_DEGRADATION_HIGH_RATIO   = 10.0
_DEGRADATION_MEDIUM_RATIO =  3.0
_COLD_START_RATIO         = 10.0

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _find_minimal_args(tool: MCPTool) -> dict:
    """
    Build the minimal valid argument dict for a tool.

    For required string params → supply a short placeholder value.
    For required integer params → supply 0.
    For required boolean params → supply False.
    Other required types → supply None (best effort).
    All optional params → omitted.
    """
    schema = tool.input_schema
    if not isinstance(schema, dict):
        return {}
    props = schema.get("properties")
    if not isinstance(props, dict):
        return {}
    required: list[str] = schema.get("required", []) or []

    _defaults: dict[str, object] = {
        "string":  "mcpsafe-latency-probe",
        "integer": 0,
        "number":  0,
        "boolean": False,
        "array":   [],
        "object":  {},
    }
    args: dict[str, object] = {}
    for pname in required:
        pschema = props.get(pname, {})
        ptype = pschema.get("type", "") if isinstance(pschema, dict) else ""
        args[pname] = _defaults.get(ptype, None)
    return args


async def _timed_call(
    session: ClientSession,
    tool_name: str,
    args: dict,
    timeout: float,
) -> float:
    """
    Execute one tool call and return its wall-clock duration in milliseconds.
    Raises on error — callers must catch.
    """
    t0 = time.perf_counter()
    await asyncio.wait_for(
        session.call_tool(tool_name, arguments=args),
        timeout=timeout,
    )
    return (time.perf_counter() - t0) * 1000.0


def _stats(samples: list[float]) -> dict:
    """Return a dict of {mean_ms, min_ms, max_ms, samples}."""
    return {
        "mean_ms": round(sum(samples) / len(samples), 2),
        "min_ms":  round(min(samples), 2),
        "max_ms":  round(max(samples), 2),
        "samples": [round(s, 2) for s in samples],
    }


def _severity_for_mean(mean_ms: float, high: float, medium: float) -> Severity:
    if mean_ms > high:
        return Severity.HIGH
    if mean_ms > medium:
        return Severity.MEDIUM
    return Severity.PASS


# ---------------------------------------------------------------------------
# T08-001 — Per-tool baseline latency
# ---------------------------------------------------------------------------


async def _t08_001_per_tool(
    session: ClientSession,
    server_info: ServerInfo,
    config: ScanConfig,
) -> list[TestResult]:
    """T08-001 — 5 latency samples per tool; populate _baseline_latencies."""
    global _baseline_latencies
    results: list[TestResult] = []

    if not server_info.tools:
        results.append(
            TestResult(
                test_id="T08-001-00", test_name="Per-Tool Baseline Latency",
                category=_CAT, severity=Severity.INFO, passed=True,
                description="No tools registered — per-tool latency benchmark skipped.",
                duration_ms=0.0,
            )
        )
        return results

    for idx, tool in enumerate(server_info.tools, start=1):
        tid = f"T08-001-{idx:02d}"
        tname = f"Baseline Latency: {tool.name}"
        t0 = time.perf_counter()
        try:
            args = _find_minimal_args(tool)
            samples: list[float] = []
            errors: list[str] = []

            for _ in range(_BASELINE_SAMPLES):
                try:
                    ms = await _timed_call(
                        session, tool.name, args, config.timeout_seconds
                    )
                    samples.append(ms)
                except Exception as exc:
                    errors.append(f"{type(exc).__name__}: {exc}")

            duration = (time.perf_counter() - t0) * 1000.0

            if not samples:
                results.append(
                    TestResult.make_fail(
                        test_id=tid, test_name=tname, category=_CAT,
                        severity=Severity.MEDIUM,
                        description=(
                            f"Tool {tool.name!r} failed all {_BASELINE_SAMPLES} "
                            f"latency probe calls."
                        ),
                        duration_ms=duration,
                        details="\n".join(errors[:5]),
                    )
                )
                continue

            st = _stats(samples)
            mean_ms = st["mean_ms"]
            # Populate module-level cache for T08-005.
            _baseline_latencies[tool.name] = mean_ms

            sev = _severity_for_mean(mean_ms, _TOOL_HIGH_MS, _TOOL_MEDIUM_MS)
            detail_json = json.dumps({tool.name: st}, indent=2)

            if sev == Severity.PASS:
                results.append(
                    TestResult.make_pass(
                        test_id=tid, test_name=tname, category=_CAT,
                        description=(
                            f"Tool {tool.name!r}: mean={mean_ms:.0f}ms  "
                            f"min={st['min_ms']:.0f}ms  max={st['max_ms']:.0f}ms "
                            f"({len(samples)} samples)."
                        ),
                        duration_ms=duration,
                        details=detail_json,
                    )
                )
            else:
                results.append(
                    TestResult(
                        test_id=tid, test_name=tname, category=_CAT,
                        severity=sev, passed=False,
                        description=(
                            f"Tool {tool.name!r} mean latency {mean_ms:.0f}ms "
                            f"{'> 30 s (HIGH)' if sev == Severity.HIGH else '> 5 s (MEDIUM)'}."
                        ),
                        duration_ms=duration,
                        details=detail_json,
                        remediation=(
                            "High baseline latency indicates the tool performs "
                            "blocking I/O or CPU-intensive work synchronously. "
                            "Profile the tool and add async processing or caching."
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
# T08-002 — Tool discovery latency
# ---------------------------------------------------------------------------


async def _t08_002_discovery_latency(
    session: ClientSession,
    config: ScanConfig,
) -> TestResult:
    """T08-002 — Measure list_tools() round-trip 5 times."""
    tid = "T08-002"
    tname = "Tool Discovery Latency"
    t0 = time.perf_counter()
    try:
        samples: list[float] = []
        errors: list[str] = []

        for _ in range(_DISCOVERY_SAMPLES):
            try:
                ts = time.perf_counter()
                await asyncio.wait_for(
                    session.list_tools(), timeout=config.timeout_seconds
                )
                samples.append((time.perf_counter() - ts) * 1000.0)
            except Exception as exc:
                errors.append(f"{type(exc).__name__}: {exc}")

        duration = (time.perf_counter() - t0) * 1000.0

        if not samples:
            return TestResult.make_fail(
                test_id=tid, test_name=tname, category=_CAT,
                severity=Severity.HIGH,
                description=f"All {_DISCOVERY_SAMPLES} list_tools() calls failed.",
                duration_ms=duration,
                details="\n".join(errors),
            )

        st = _stats(samples)
        mean_ms = st["mean_ms"]
        sev = _severity_for_mean(mean_ms, _DISC_HIGH_MS, _DISC_MEDIUM_MS)
        detail_json = json.dumps({"list_tools": st}, indent=2)

        if sev != Severity.PASS:
            label = "HIGH" if sev == Severity.HIGH else "MEDIUM"
            return TestResult(
                test_id=tid, test_name=tname, category=_CAT,
                severity=sev, passed=False,
                description=(
                    f"list_tools() mean {mean_ms:.0f}ms — "
                    f"slow discovery [{label}]."
                ),
                duration_ms=duration,
                details=detail_json,
                remediation=(
                    "Slow tool discovery degrades the LLM's startup experience. "
                    "Cache the tool manifest at server startup instead of "
                    "re-computing it on every list_tools() call."
                ),
            )

        return TestResult.make_pass(
            test_id=tid, test_name=tname, category=_CAT,
            description=(
                f"list_tools() mean={mean_ms:.0f}ms  "
                f"min={st['min_ms']:.0f}ms  max={st['max_ms']:.0f}ms."
            ),
            duration_ms=duration,
            details=detail_json,
        )

    except Exception as exc:
        return TestResult.from_exception(
            test_id=tid, test_name=tname, category=_CAT, exc=exc,
            duration_ms=(time.perf_counter() - t0) * 1000.0,
        )


# ---------------------------------------------------------------------------
# T08-003 — Resource read latency
# ---------------------------------------------------------------------------


async def _t08_003_resource_latency(
    session: ClientSession,
    server_info: ServerInfo,
    config: ScanConfig,
) -> list[TestResult]:
    """T08-003 — read_resource() latency for up to 3 resources."""
    results: list[TestResult] = []

    if not server_info.resources:
        results.append(
            TestResult(
                test_id="T08-003-00", test_name="Resource Read Latency",
                category=_CAT, severity=Severity.INFO, passed=True,
                description="No resources to benchmark.",
                duration_ms=0.0,
            )
        )
        return results

    for idx, resource in enumerate(server_info.resources[:_MAX_RESOURCES], start=1):
        tid = f"T08-003-{idx:02d}"
        tname = f"Resource Latency: {str(resource.uri)[:40]}"
        t0 = time.perf_counter()
        try:
            samples: list[float] = []
            errors: list[str] = []

            for _ in range(_RESOURCE_SAMPLES):
                try:
                    ts = time.perf_counter()
                    await asyncio.wait_for(
                        session.read_resource(str(resource.uri)),
                        timeout=config.timeout_seconds,
                    )
                    samples.append((time.perf_counter() - ts) * 1000.0)
                except Exception as exc:
                    errors.append(f"{type(exc).__name__}: {exc}")

            duration = (time.perf_counter() - t0) * 1000.0

            if not samples:
                results.append(
                    TestResult(
                        test_id=tid, test_name=tname, category=_CAT,
                        severity=Severity.INFO, passed=True,
                        description=(
                            f"Resource {str(resource.uri)!r} could not be read "
                            f"({len(errors)} errors) — latency not recorded."
                        ),
                        duration_ms=duration,
                        details="\n".join(errors[:3]),
                    )
                )
                continue

            st = _stats(samples)
            mean_ms = st["mean_ms"]
            sev = _severity_for_mean(mean_ms, _TOOL_HIGH_MS, _TOOL_MEDIUM_MS)
            detail_json = json.dumps({str(resource.uri): st}, indent=2)

            if sev == Severity.PASS:
                results.append(
                    TestResult.make_pass(
                        test_id=tid, test_name=tname, category=_CAT,
                        description=(
                            f"Resource {str(resource.uri)!r}: mean={mean_ms:.0f}ms  "
                            f"min={st['min_ms']:.0f}ms  max={st['max_ms']:.0f}ms."
                        ),
                        duration_ms=duration,
                        details=detail_json,
                    )
                )
            else:
                results.append(
                    TestResult(
                        test_id=tid, test_name=tname, category=_CAT,
                        severity=sev, passed=False,
                        description=(
                            f"Resource {str(resource.uri)!r} mean latency "
                            f"{mean_ms:.0f}ms."
                        ),
                        duration_ms=duration,
                        details=detail_json,
                        remediation=(
                            "High resource read latency suggests the resource "
                            "is fetched from a slow remote source on every call. "
                            "Add caching at the resource handler level."
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
# T08-004 — Cold-start detection
# ---------------------------------------------------------------------------


async def _t08_004_cold_start(
    session: ClientSession,
    server_info: ServerInfo,
    config: ScanConfig,
) -> TestResult:
    """T08-004 — Detect a cold-start latency spike on the first call."""
    tid = "T08-004"
    tname = "Cold Start Detection"
    t0 = time.perf_counter()
    try:
        if not server_info.tools:
            return TestResult(
                test_id=tid, test_name=tname, category=_CAT,
                severity=Severity.INFO, passed=True,
                description="No tools available — cold start test skipped.",
                duration_ms=(time.perf_counter() - t0) * 1000.0,
            )

        tool = server_info.tools[0]
        args = _find_minimal_args(tool)
        samples: list[float] = []
        errors: list[str] = []

        for call_num in range(1, 6):
            try:
                ms = await _timed_call(
                    session, tool.name, args, config.timeout_seconds
                )
                samples.append(ms)
            except Exception as exc:
                errors.append(f"Call {call_num}: {type(exc).__name__}: {exc}")

        duration = (time.perf_counter() - t0) * 1000.0

        if len(samples) < 2:
            return TestResult(
                test_id=tid, test_name=tname, category=_CAT,
                severity=Severity.INFO, passed=True,
                description=(
                    f"Insufficient samples for cold-start analysis "
                    f"({len(samples)} succeeded, {len(errors)} failed)."
                ),
                duration_ms=duration,
                details="\n".join(errors),
            )

        call1 = samples[0]
        warm_samples = samples[1:]
        warm_mean = sum(warm_samples) / len(warm_samples)

        # Guard against division by zero.
        ratio = call1 / warm_mean if warm_mean > 0 else 0.0

        detail_str = (
            f"Call 1 (cold): {call1:.0f}ms\n"
            f"Calls 2-{len(samples)} (warm): "
            + ", ".join(f"{s:.0f}ms" for s in warm_samples)
            + f"\nWarm mean: {warm_mean:.0f}ms  Ratio: {ratio:.1f}×"
        )

        if ratio > _COLD_START_RATIO:
            return TestResult(
                test_id=tid, test_name=tname, category=_CAT,
                severity=Severity.INFO, passed=True,
                description=(
                    f"Cold start detected: first call {call1:.0f}ms, "
                    f"warm mean {warm_mean:.0f}ms (ratio {ratio:.1f}×)."
                ),
                duration_ms=duration,
                details=(
                    f"Cold start detected: first call {call1:.0f}ms, "
                    f"warm mean {warm_mean:.0f}ms\n{detail_str}"
                ),
            )

        return TestResult.make_pass(
            test_id=tid, test_name=tname, category=_CAT,
            description=(
                f"No significant cold-start penalty detected "
                f"(ratio {ratio:.1f}×, threshold {_COLD_START_RATIO:.0f}×)."
            ),
            duration_ms=duration,
            details=detail_str,
        )

    except Exception as exc:
        return TestResult.from_exception(
            test_id=tid, test_name=tname, category=_CAT, exc=exc,
            duration_ms=(time.perf_counter() - t0) * 1000.0,
        )


# ---------------------------------------------------------------------------
# T08-005 — Latency degradation under load (separate from main run())
# ---------------------------------------------------------------------------


async def compute_latency_comparison(
    t05_results: Optional[list[TestResult]],
) -> TestResult:
    """
    T08-005 — Compare baseline mean latency vs T05 p95 load-test latency.

    Called by the runner **after** T05 completes, using the module-level
    ``_baseline_latencies`` dict populated by ``run()``.

    Parameters
    ----------
    t05_results:
        The ``list[TestResult]`` returned by ``t05_load.run()``, or ``None``
        if T05 was skipped.

    Returns
    -------
    TestResult:
        T08-005 with severity based on the degradation ratio.
    """
    tid = "T08-005"
    tname = "Latency Degradation Under Load"
    t0 = time.perf_counter()
    try:
        if not t05_results:
            return TestResult(
                test_id=tid, test_name=tname, category=_CAT,
                severity=Severity.INFO, passed=True,
                description=(
                    "Load test results not available for comparison."
                ),
                duration_ms=(time.perf_counter() - t0) * 1000.0,
            )

        if not _baseline_latencies:
            return TestResult(
                test_id=tid, test_name=tname, category=_CAT,
                severity=Severity.INFO, passed=True,
                description=(
                    "Baseline latencies not available — "
                    "run t08_latency.run() before this comparison."
                ),
                duration_ms=(time.perf_counter() - t0) * 1000.0,
            )

        # Extract p95 from T05-002 details (JSON encoded there).
        p95_ms: Optional[float] = None
        for r in t05_results:
            if r.test_id == "T05-002" and r.details:
                try:
                    data = json.loads(r.details)
                    p95_ms = float(data.get("p95_ms", 0))
                    break
                except (json.JSONDecodeError, ValueError, TypeError):
                    pass

        if p95_ms is None or p95_ms == 0:
            return TestResult(
                test_id=tid, test_name=tname, category=_CAT,
                severity=Severity.INFO, passed=True,
                description=(
                    "T05-002 (sequential latency) result not found or "
                    "contained no p95 data — comparison skipped."
                ),
                duration_ms=(time.perf_counter() - t0) * 1000.0,
            )

        # Use the mean of all baseline latencies as the comparison point.
        baseline_ms = sum(_baseline_latencies.values()) / len(_baseline_latencies)
        ratio = p95_ms / baseline_ms if baseline_ms > 0 else 0.0
        duration = (time.perf_counter() - t0) * 1000.0

        detail_str = (
            f"Baseline mean: {baseline_ms:.0f}ms  "
            f"Load p95: {p95_ms:.0f}ms  "
            f"Degradation ratio: {ratio:.1f}×"
        )

        if ratio > _DEGRADATION_HIGH_RATIO:
            return TestResult(
                test_id=tid, test_name=tname, category=_CAT,
                severity=Severity.HIGH, passed=False,
                description=(
                    f"10× latency degradation under load: "
                    f"baseline {baseline_ms:.0f}ms, load p95 {p95_ms:.0f}ms."
                ),
                duration_ms=duration,
                details=(
                    f"10x latency degradation under load: "
                    f"baseline {baseline_ms:.0f}ms, load p95 {p95_ms:.0f}ms\n"
                    f"{detail_str}"
                ),
                remediation=(
                    "The server slows down dramatically under concurrent load. "
                    "Profile for lock contention, synchronous I/O, or shared "
                    "state bottlenecks. Consider connection pooling or async "
                    "request handling."
                ),
            )

        if ratio > _DEGRADATION_MEDIUM_RATIO:
            return TestResult(
                test_id=tid, test_name=tname, category=_CAT,
                severity=Severity.MEDIUM, passed=False,
                description=(
                    f"3× latency degradation under load: "
                    f"baseline {baseline_ms:.0f}ms, load p95 {p95_ms:.0f}ms."
                ),
                duration_ms=duration,
                details=detail_str,
                remediation=(
                    "Latency triples under load. Investigate resource contention "
                    "and add async processing to flatten the latency curve."
                ),
            )

        return TestResult.make_pass(
            test_id=tid, test_name=tname, category=_CAT,
            description=(
                f"Latency stable under load: "
                f"baseline {baseline_ms:.0f}ms, load p95 {p95_ms:.0f}ms "
                f"(ratio {ratio:.1f}×)."
            ),
            duration_ms=duration,
            details=detail_str,
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
    t05_results: Optional[list[TestResult]] = None,
) -> list[TestResult]:
    """
    Execute T08-001 through T08-005.

    When called by the runner **without** ``t05_results``, T08-005 returns an
    INFO result and the module-level ``_baseline_latencies`` cache is populated.
    The runner then calls ``compute_latency_comparison(t05_results)`` after T05
    to get the real T08-005 result.

    When called directly **with** ``t05_results``, all 5 tests run fully in one
    call.

    Parameters
    ----------
    session:
        An initialised ``mcp.ClientSession``.
    server_info:
        Populated ``ServerInfo`` from the discovery phase.
    config:
        Active ``ScanConfig``.
    t05_results:
        Optional T05 results for T08-005 comparison.

    Returns
    -------
    list[TestResult]:
        T08-001 through T08-005 results.
    """
    results: list[TestResult] = []

    results.extend(await _t08_001_per_tool(session, server_info, config))
    results.append(await _t08_002_discovery_latency(session, config))
    results.extend(await _t08_003_resource_latency(session, server_info, config))
    results.append(await _t08_004_cold_start(session, server_info, config))

    # T08-005: either full comparison (if t05_results given) or INFO placeholder.
    results.append(await compute_latency_comparison(t05_results))

    return results
