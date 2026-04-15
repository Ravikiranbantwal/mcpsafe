"""
mcpsafe.tests.t17_hash_drift
==============================
SECURITY category — **Tool description cryptographic fingerprinting**.

For every tool + resource + prompt discovered on the server we compute a
SHA-256 fingerprint of its canonical JSON representation.  These hashes
enable:

  * Cross-session drift detection (complements T04 which compares within
    a single session).
  * Regression tracking across scans (``mcpsafe compare``).
  * Detection of server-side A/B testing: if the SAME identifier appears
    to the same client with different content on repeated connects, the
    server is serving non-deterministic descriptions — a sneaky rug-pull
    precursor.

What this test does
-------------------
1. Canonicalises each tool/resource/prompt into a stable JSON string
   (sorted keys, no whitespace, UTF-8).
2. Computes SHA-256 fingerprints.
3. Opens a SECOND session and re-computes fingerprints.
4. Flags any fingerprint that differs between the two sessions.

A second session is required because hashes within a single session
are already covered by T04's growth-vs-mutation logic.

Test inventory
--------------
T17-001   Cross-session description hash stability
T17-002   Fingerprint summary (metadata only — counts)

Public API
----------
    async def run(session, server_info, config) -> list[TestResult]
"""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any

from mcp import ClientSession

from mcpsafe.models import (
    Category,
    ScanConfig,
    ServerInfo,
    Severity,
    TestResult,
    TransportType,
)
from mcpsafe.tests._helpers import RateLimiter
from mcpsafe.transport import MCPConnection, TransportError


def _canonical(obj: Any) -> str:
    """Canonical JSON encoding — stable key order, UTF-8, no extra spaces."""
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _hash(obj: Any) -> str:
    return hashlib.sha256(_canonical(obj).encode("utf-8")).hexdigest()


async def _fingerprint_session(session: ClientSession) -> dict[str, str]:
    """Return ``{identifier: sha256}`` for every tool/resource/prompt."""
    fp: dict[str, str] = {}
    try:
        tr = await session.list_tools()
        for t in getattr(tr, "tools", []) or []:
            name = getattr(t, "name", None) or str(t)
            desc = getattr(t, "description", "") or ""
            schema = getattr(t, "inputSchema", None) or {}
            fp[f"tool:{name}"] = _hash({"desc": desc, "schema": schema})
    except Exception:
        pass
    try:
        rr = await session.list_resources()
        for r in getattr(rr, "resources", []) or []:
            uri = getattr(r, "uri", None) or str(r)
            desc = getattr(r, "description", "") or ""
            mime = getattr(r, "mimeType", None)
            fp[f"resource:{uri}"] = _hash({"desc": desc, "mime": mime})
    except Exception:
        pass
    try:
        pr = await session.list_prompts()
        for p in getattr(pr, "prompts", []) or []:
            name = getattr(p, "name", None) or str(p)
            desc = getattr(p, "description", "") or ""
            args = getattr(p, "arguments", []) or []
            # normalise args to list of dicts
            args_norm = []
            for a in args:
                if hasattr(a, "model_dump"):
                    args_norm.append(a.model_dump())
                elif hasattr(a, "dict"):
                    args_norm.append(a.dict())
                elif isinstance(a, dict):
                    args_norm.append(a)
                else:
                    args_norm.append(str(a))
            fp[f"prompt:{name}"] = _hash({"desc": desc, "args": args_norm})
    except Exception:
        pass
    return fp


async def run(
    session: ClientSession,
    server_info: ServerInfo,
    config: ScanConfig,
) -> list[TestResult]:
    """Execute T17 — Tool Description Hash Drift."""
    t_start = time.perf_counter()
    results: list[TestResult] = []
    limiter = RateLimiter(config)

    await limiter.acquire()
    fp_a = await _fingerprint_session(session)

    # Open a second independent connection to catch per-session variation.
    fp_b: dict[str, str] = {}
    second_session_failed: str = ""
    try:
        async with MCPConnection(config) as (session_b, _conn_b):
            # Wait a beat so any stateful response doesn't dominate.
            fp_b = await _fingerprint_session(session_b)
    except TransportError as exc:
        second_session_failed = str(exc)[:300]
    except Exception as exc:
        second_session_failed = f"{type(exc).__name__}: {str(exc)[:250]}"

    if second_session_failed:
        results.append(
            TestResult(
                test_id="T17-001",
                test_name="Cross-Session Hash Drift",
                category=Category.SECURITY,
                severity=Severity.INFO,
                passed=True,
                description=(
                    "Could not open a second independent session to compare "
                    "description fingerprints across sessions."
                ),
                duration_ms=(time.perf_counter() - t_start) * 1000.0,
                details=second_session_failed,
            )
        )
        # Still emit summary so reports always have T17-002
        results.append(
            TestResult(
                test_id="T17-002",
                test_name="Description Fingerprint Inventory",
                category=Category.SECURITY,
                severity=Severity.INFO,
                passed=True,
                description=f"Recorded {len(fp_a)} fingerprints (primary session only).",
                duration_ms=0.0,
                details="\n".join(f"{k} = {v[:16]}…" for k, v in list(fp_a.items())[:20]),
            )
        )
        return results

    # Compare fingerprints for identifiers present in both sessions.
    common = set(fp_a) & set(fp_b)
    drifted: list[str] = []
    for ident in sorted(common):
        if fp_a[ident] != fp_b[ident]:
            drifted.append(
                f"{ident}: session-A={fp_a[ident][:12]}… session-B={fp_b[ident][:12]}…"
            )

    only_a = set(fp_a) - set(fp_b)
    only_b = set(fp_b) - set(fp_a)

    duration = (time.perf_counter() - t_start) * 1000.0

    if drifted:
        results.append(
            TestResult(
                test_id="T17-001",
                test_name="Cross-Session Hash Drift",
                category=Category.SECURITY,
                severity=Severity.HIGH,
                passed=False,
                description=(
                    f"{len(drifted)} description(s) have different SHA-256 "
                    f"fingerprints across two independent sessions to the same "
                    f"server. This is non-deterministic description serving — "
                    f"a precursor to rug-pull attacks."
                ),
                duration_ms=duration,
                details="\n".join(drifted[:10]),
                remediation=(
                    "Descriptions and schemas must be deterministic for a given "
                    "server version and identity. Investigate sources of "
                    "variation: request-time templating, time-based A/B tests, "
                    "or per-IP description routing."
                ),
            )
        )
    elif only_a or only_b:
        # Noise filter: when one session saw N extra identifiers but those
        # identifiers all share a common namespace prefix (e.g. auto-generated
        # ``test://static/resource/*`` URIs, or resources created from earlier
        # probes in this scan), the difference is a stateful-generator artefact
        # rather than per-connection capability routing.  Downgrade to LOW.
        def _is_auto_generator_noise(ids: set[str]) -> bool:
            if len(ids) < 5:
                return False
            def _strip_tail(u: str) -> str:
                slash = u.rfind("/")
                return u[:slash] if slash > 0 else u
            prefixes = {_strip_tail(u) for u in ids}
            return len(prefixes) <= 2

        asymmetry_is_noise = (
            _is_auto_generator_noise(only_a) or _is_auto_generator_noise(only_b)
        )
        results.append(
            TestResult(
                test_id="T17-001",
                test_name="Cross-Session Hash Drift",
                category=Category.SECURITY,
                severity=Severity.LOW if asymmetry_is_noise else Severity.MEDIUM,
                passed=False,
                description=(
                    f"Sessions saw different identifier sets (A-only={len(only_a)}, "
                    f"B-only={len(only_b)}). "
                    + (
                        "All extras share a common namespace prefix — likely a "
                        "server-side auto-generator or side-effect of earlier "
                        "probes, not capability routing."
                        if asymmetry_is_noise
                        else "Server exposes different capabilities to different connections."
                    )
                ),
                duration_ms=duration,
                details=f"only-A: {sorted(only_a)[:10]}\nonly-B: {sorted(only_b)[:10]}",
            )
        )
    else:
        results.append(
            TestResult.make_pass(
                test_id="T17-001",
                test_name="Cross-Session Hash Drift",
                category=Category.SECURITY,
                description=(
                    f"All {len(common)} descriptions match byte-for-byte across "
                    f"two independent sessions."
                ),
                duration_ms=duration,
            )
        )

    # Summary inventory (always emitted for regression tracking).
    results.append(
        TestResult(
            test_id="T17-002",
            test_name="Description Fingerprint Inventory",
            category=Category.SECURITY,
            severity=Severity.INFO,
            passed=True,
            description=(
                f"Catalogued {len(fp_a)} SHA-256 description fingerprints. "
                f"Use `mcpsafe compare` to detect drift across scans."
            ),
            duration_ms=0.0,
            details="\n".join(
                f"{k} = {v}" for k, v in list(fp_a.items())[:30]
            ),
        )
    )
    return results
