"""
mcpsafe.tests.t11_timing_side_channel
======================================
SECURITY category — **Timing side-channel** enumeration detection.

Many servers accidentally leak "does this entry exist?" information through
response-time differences.  A tool like ``lookup_user(name)`` that returns:
    - 8 ms   when name does not exist
    - 90 ms  when name exists (DB lookup, permission check, render)

…lets an attacker enumerate valid users (or SKUs, file paths, tenant IDs,
…) without any authenticated read access.

Strategy
--------
For each tool with a string parameter we:
  1. Fire N calls with a "known-exists"-looking plausible value (``admin``,
     ``test``, ``example.com``, …).
  2. Fire N calls with random high-entropy strings that definitely do not
     exist.
  3. Compare the mean response time.  A ratio > 5× (with low variance) is
     flagged as a probable timing oracle.

Statistical robustness
----------------------
Network / OS jitter is large so we:
  * discard the slowest sample from each group (trim max)
  * require mean difference > 30 ms AND ratio > 5× to flag
  * require a minimum of 3 successful samples per group

Test inventory
--------------
T11-TOOL-{slug}        One per tool that accepts a string parameter.
T11-001                Summary verdict.

Public API
----------
    async def run(
        session: ClientSession,
        server_info: ServerInfo,
        config: ScanConfig,
    ) -> list[TestResult]
"""

from __future__ import annotations

import re
import secrets
import statistics
import time
from typing import Optional

import anyio
from mcp import ClientSession

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
    looks_like_api_rejection,
)

_CALL_TIMEOUT_SEC = 10.0
_SAMPLES_PER_GROUP = 4
_MIN_SUCCESSFUL_SAMPLES = 3
_RATIO_THRESHOLD = 5.0        # mean(exists)/mean(nonexists) must exceed this
_MIN_ABS_DIFF_MS = 30.0       # and the absolute gap must be ≥ this to avoid jitter FPs
_MAX_TEST_ID_LEN = 64
_MAX_TOOLS_PROBED = 6

# Plausible "known-exists"-looking values per parameter name/context.
# The attack relies on the server treating these as real identifiers.
_LIKELY_EXISTS_VALUES: tuple[str, ...] = (
    "admin", "root", "test", "user", "guest",
    "example.com", "localhost", "index.html",
    "1", "0",
)


def _slug(name: str, budget: int = 28) -> str:
    s = re.sub(r"[^a-z0-9]+", "_", (name or "unknown").lower()).strip("_")
    return (s or "unknown")[:budget] or "unknown"


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


def _nonexistent_value() -> str:
    """Generate a string so random no server could have it cached."""
    return f"mcpsafe-nx-{secrets.token_hex(10)}"


async def _time_call(
    session: ClientSession,
    tool_name: str,
    args: dict[str, object],
) -> Optional[float]:
    """
    Call *tool_name* with *args*, return elapsed milliseconds.

    Returns ``None`` on exception so callers can ignore failed samples.
    """
    t0 = time.perf_counter()
    try:
        with anyio.fail_after(_CALL_TIMEOUT_SEC):
            await session.call_tool(tool_name, arguments=args)
    except Exception:
        return None
    return (time.perf_counter() - t0) * 1000.0


def _trimmed_mean(samples: list[float]) -> float:
    """Mean of *samples* after removing the single largest outlier."""
    if not samples:
        return 0.0
    if len(samples) <= 2:
        return statistics.mean(samples)
    trimmed = sorted(samples)[:-1]  # drop max
    return statistics.mean(trimmed)


async def _probe_tool(
    session: ClientSession,
    tool: MCPTool,
    limiter: RateLimiter,
) -> TestResult:
    tid = f"T11-TOOL-{_slug(tool.name)}"
    if len(tid) > _MAX_TEST_ID_LEN:
        tid = tid[:_MAX_TEST_ID_LEN]
    tname = f"Timing Side-Channel → {tool.name}"
    t0 = time.perf_counter()

    pname = _first_string_param(tool)
    if not pname:
        return TestResult(
            test_id=tid, test_name=tname,
            category=Category.SECURITY, severity=Severity.INFO,
            passed=True,
            description=f"Tool {tool.name!r} has no string parameter; timing probe skipped.",
            duration_ms=(time.perf_counter() - t0) * 1000.0,
        )

    # ── Phase A: exists-like values ──────────────────────────────────────
    exists_samples: list[float] = []
    sample_errors: list[str] = []
    for plausible in _LIKELY_EXISTS_VALUES[:_SAMPLES_PER_GROUP]:
        await limiter.acquire()
        elapsed = await _time_call(session, tool.name, {pname: plausible})
        if elapsed is not None:
            exists_samples.append(elapsed)
        else:
            sample_errors.append(f"exists-probe({plausible!r}) failed")

    # ── Phase B: nonexistent values ──────────────────────────────────────
    nonexists_samples: list[float] = []
    for _ in range(_SAMPLES_PER_GROUP):
        await limiter.acquire()
        elapsed = await _time_call(session, tool.name, {pname: _nonexistent_value()})
        if elapsed is not None:
            nonexists_samples.append(elapsed)
        else:
            sample_errors.append("nonexists-probe failed")

    duration = (time.perf_counter() - t0) * 1000.0

    # Need enough successful samples to make a judgement.
    if (len(exists_samples) < _MIN_SUCCESSFUL_SAMPLES
            or len(nonexists_samples) < _MIN_SUCCESSFUL_SAMPLES):
        # If every error looks like API rejection, downgrade to INFO.
        if sample_errors and looks_like_api_rejection(sample_errors):
            return TestResult(
                test_id=tid, test_name=tname,
                category=Category.SECURITY, severity=Severity.INFO,
                passed=True,
                description=(
                    f"Tool {tool.name!r} rejected most timing probes "
                    f"(auth / validation). Timing analysis not possible."
                ),
                duration_ms=duration,
            )
        return TestResult(
            test_id=tid, test_name=tname,
            category=Category.SECURITY, severity=Severity.LOW,
            passed=False,
            description=(
                f"Tool {tool.name!r} produced too few successful timing samples "
                f"({len(exists_samples)} exists, {len(nonexists_samples)} nonexists) "
                f"to evaluate a side channel."
            ),
            duration_ms=duration,
            details="\n".join(sample_errors[:5]),
        )

    mean_exists = _trimmed_mean(exists_samples)
    mean_nonexists = _trimmed_mean(nonexists_samples)

    # Guard against divide-by-zero on ultra-fast servers.
    if mean_nonexists < 0.1:
        mean_nonexists = 0.1

    ratio = mean_exists / mean_nonexists
    abs_diff = abs(mean_exists - mean_nonexists)

    # Detect oracle: exists-values take meaningfully longer.
    if ratio >= _RATIO_THRESHOLD and abs_diff >= _MIN_ABS_DIFF_MS:
        return TestResult(
            test_id=tid, test_name=tname,
            category=Category.SECURITY, severity=Severity.MEDIUM,
            passed=False,
            description=(
                f"Tool {tool.name!r} exhibits a timing side-channel: calls "
                f"with plausible-looking values took {mean_exists:.1f} ms on "
                f"average vs {mean_nonexists:.1f} ms for random values "
                f"(ratio {ratio:.1f}×). Attackers can enumerate valid "
                f"identifiers without authentication."
            ),
            duration_ms=duration,
            details=(
                f"exists samples: {[round(s,1) for s in exists_samples]}\n"
                f"nonexists samples: {[round(s,1) for s in nonexists_samples]}\n"
                f"trimmed mean exists: {mean_exists:.1f} ms\n"
                f"trimmed mean nonexists: {mean_nonexists:.1f} ms\n"
                f"ratio: {ratio:.2f}×  absolute gap: {abs_diff:.1f} ms"
            ),
            remediation=(
                "Normalise response time regardless of lookup outcome. Options: "
                "(a) perform a dummy computation of equal cost on not-found paths, "
                "(b) add a small uniform random delay to every response, or "
                "(c) return a generic error rapidly without disclosing whether "
                "the identifier existed. Choice (a) is strongest against well-"
                "resourced attackers."
            ),
        )

    # No oracle detected — PASS with evidence.
    return TestResult.make_pass(
        test_id=tid, test_name=tname,
        category=Category.SECURITY,
        description=(
            f"Tool {tool.name!r} does not appear to leak timing information "
            f"(mean {mean_exists:.1f} ms vs {mean_nonexists:.1f} ms, "
            f"ratio {ratio:.2f}×)."
        ),
        duration_ms=duration,
    )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


async def run(
    session: ClientSession,
    server_info: ServerInfo,
    config: ScanConfig,
) -> list[TestResult]:
    """Execute T11 — Timing Side-Channel analysis."""
    t_start = time.perf_counter()
    results: list[TestResult] = []
    limiter = RateLimiter(config)

    candidates = [t for t in (server_info.tools or []) if _first_string_param(t)]
    candidates = candidates[:_MAX_TOOLS_PROBED]

    if not candidates:
        results.append(
            TestResult(
                test_id="T11-001",
                test_name="Timing Side-Channel — Summary",
                category=Category.SECURITY,
                severity=Severity.INFO, passed=True,
                description="No tools with string parameters; timing probe skipped.",
                duration_ms=(time.perf_counter() - t_start) * 1000.0,
            )
        )
        return results

    for tool in candidates:
        results.append(await _probe_tool(session, tool, limiter))

    # Summary
    bad = sum(1 for r in results if r.severity == Severity.MEDIUM and not r.passed)
    if bad == 0:
        results.append(
            TestResult.make_pass(
                test_id="T11-001",
                test_name="Timing Side-Channel — Summary",
                category=Category.SECURITY,
                description=(
                    f"Probed {len(candidates)} tool(s); no timing oracles detected."
                ),
                duration_ms=(time.perf_counter() - t_start) * 1000.0,
            )
        )
    else:
        results.append(
            TestResult.make_fail(
                test_id="T11-001",
                test_name="Timing Side-Channel — Summary",
                category=Category.SECURITY,
                severity=Severity.MEDIUM,
                description=(
                    f"{bad} of {len(candidates)} probed tool(s) exhibit a timing "
                    f"side-channel that could enable identifier enumeration."
                ),
                duration_ms=(time.perf_counter() - t_start) * 1000.0,
                remediation=(
                    "See per-tool T11-TOOL-* findings for specific remediation. "
                    "Constant-time lookup responses are the defensive goal."
                ),
            )
        )
    return results
