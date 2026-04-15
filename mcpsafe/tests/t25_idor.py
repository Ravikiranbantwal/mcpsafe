"""
mcpsafe.tests.t25_idor
========================
SECURITY category — **Insecure Direct Object Reference** probing.

If resource URIs or tool ID parameters use predictable numeric / user-named
identifiers, we should NOT be able to read other users' resources.

This module:

  1. Lists existing resources and extracts ID/name patterns.
  2. Constructs adjacent / sibling URIs by substituting common identifiers
     (admin, root, user1, 1, 2, …) into the pattern.
  3. Calls ``read_resource(forged_uri)`` and checks whether the server
     returns data.

Any successful read of a URI we did not originally see listed is flagged
as HIGH — we accessed a resource across an identity boundary.

Test inventory
--------------
T25-URI-###  per forged-URI probe
T25-001      Summary
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

_CALL_TIMEOUT_SEC = 10.0
_MAX_PROBES = 20

# Replacement candidates used for identifier swapping.
_IDENTITY_CANDIDATES: tuple[str, ...] = (
    "admin", "root", "user1", "user2", "guest", "test",
    "1", "2", "42", "100", "0",
)


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


def _swap_candidates(uri: str) -> list[str]:
    """
    Produce forged URIs by substituting common identifiers into the
    numeric / simple alphanumeric segments of *uri*.
    """
    forged: list[str] = []

    # Numeric ID substitution in path segments / query params.
    for match in re.finditer(r"(\d{1,6})", uri):
        orig = match.group(1)
        try:
            n = int(orig)
        except ValueError:
            continue
        # Try adjacent integers.
        for delta in (-1, 1, 10, 100):
            new_val = n + delta
            if new_val < 0:
                continue
            forged.append(uri[:match.start()] + str(new_val) + uri[match.end():])
        # Also try 0.
        forged.append(uri[:match.start()] + "0" + uri[match.end():])

    # Replace well-known identifier words with other candidates.
    lower = uri.lower()
    for orig in ("user", "users", "me", "self"):
        if orig in lower:
            idx = lower.find(orig)
            for cand in _IDENTITY_CANDIDATES:
                forged.append(uri[:idx] + cand + uri[idx + len(orig):])
    # Deduplicate while preserving order.
    seen: set[str] = set()
    uniq: list[str] = []
    for f in forged:
        if f != uri and f not in seen:
            seen.add(f)
            uniq.append(f)
    return uniq[:_MAX_PROBES]


async def _probe(
    session: ClientSession,
    idx: int,
    forged_uri: str,
    known_uris: set[str],
    limiter: RateLimiter,
) -> TestResult:
    tid = f"T25-URI-{idx:03d}"
    tname = f"IDOR probe: {forged_uri[:40]}"
    t0 = time.perf_counter()

    await limiter.acquire()
    try:
        with anyio.fail_after(_CALL_TIMEOUT_SEC):
            resp = await session.read_resource(forged_uri)
        text = _extract_text(resp)
        duration = (time.perf_counter() - t0) * 1000.0

        # If the server successfully returned non-trivial content for a URI
        # we did NOT originally see in list_resources, that's IDOR.
        if forged_uri in known_uris:
            return TestResult.make_pass(
                test_id=tid, test_name=tname, category=Category.SECURITY,
                description=f"URI {forged_uri!r} was in the original resource list — not IDOR.",
                duration_ms=duration,
            )
        if not text or len(text.strip()) < 20:
            return TestResult.make_pass(
                test_id=tid, test_name=tname, category=Category.SECURITY,
                description=f"Forged URI {forged_uri!r} returned empty/trivial response.",
                duration_ms=duration,
            )
        return TestResult(
            test_id=tid, test_name=tname,
            category=Category.SECURITY, severity=Severity.HIGH, passed=False,
            description=(
                f"Forged resource URI {forged_uri!r} returned content outside "
                f"the advertised resource list — potential IDOR access across "
                f"identity boundaries."
            ),
            duration_ms=duration,
            details=f"Response excerpt: {text[:300]!r}",
            remediation=(
                "Check resource authorisation on every read_resource call. Verify "
                "the caller's identity has permission to access the target URI, "
                "don't rely on URI unguessability."
            ),
        )
    except Exception as exc:
        duration = (time.perf_counter() - t0) * 1000.0
        err = str(exc)
        return TestResult.make_pass(
            test_id=tid, test_name=tname, category=Category.SECURITY,
            description=f"Forged URI correctly rejected.",
            duration_ms=duration, details=err[:200],
        )


async def run(
    session: ClientSession,
    server_info: ServerInfo,
    config: ScanConfig,
) -> list[TestResult]:
    """Execute T25 — IDOR probing."""
    t_start = time.perf_counter()
    results: list[TestResult] = []
    limiter = RateLimiter(config)

    resources = server_info.resources or []
    if not resources:
        results.append(TestResult(
            test_id="T25-001", test_name="IDOR — Summary",
            category=Category.SECURITY, severity=Severity.INFO, passed=True,
            description="Server does not expose resources — IDOR probe skipped.",
            duration_ms=(time.perf_counter() - t_start) * 1000.0,
        ))
        return results

    known_uris = {r.uri for r in resources if r.uri}

    # Build candidate probe URIs from every original resource.
    probe_uris: list[str] = []
    for r in resources[:4]:
        probe_uris.extend(_swap_candidates(r.uri))
    # Deduplicate across originals.
    seen: set[str] = set()
    uniq_probes: list[str] = []
    for u in probe_uris:
        if u not in seen:
            seen.add(u)
            uniq_probes.append(u)
    uniq_probes = uniq_probes[:_MAX_PROBES]

    if not uniq_probes:
        results.append(TestResult(
            test_id="T25-001", test_name="IDOR — Summary",
            category=Category.SECURITY, severity=Severity.INFO, passed=True,
            description=(
                f"Resource URIs have no numeric or user-token segments suitable "
                f"for IDOR substitution ({len(resources)} resources scanned)."
            ),
            duration_ms=(time.perf_counter() - t_start) * 1000.0,
        ))
        return results

    for i, forged in enumerate(uniq_probes, start=1):
        results.append(await _probe(session, i, forged, known_uris, limiter))

    bad = sum(1 for r in results if r.severity == Severity.HIGH and not r.passed)
    if bad:
        results.append(TestResult.make_fail(
            test_id="T25-001", test_name="IDOR — Summary",
            category=Category.SECURITY, severity=Severity.HIGH,
            description=f"{bad}/{len(uniq_probes)} forged URI(s) returned data.",
            duration_ms=(time.perf_counter() - t_start) * 1000.0,
        ))
    else:
        results.append(TestResult.make_pass(
            test_id="T25-001", test_name="IDOR — Summary",
            category=Category.SECURITY,
            description=f"{len(uniq_probes)} IDOR probe(s) sent, none returned out-of-list data.",
            duration_ms=(time.perf_counter() - t_start) * 1000.0,
        ))
    return results
