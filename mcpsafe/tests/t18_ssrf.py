"""
mcpsafe.tests.t18_ssrf
========================
SECURITY category — **Server-Side Request Forgery via resource URIs**.

An MCP server that naively proxies the URI supplied to ``resources/read``
becomes an SSRF primitive.  Attack payloads include:

  * Cloud metadata endpoints
      - AWS:  ``http://169.254.169.254/latest/meta-data/``
      - GCP:  ``http://metadata.google.internal/computeMetadata/v1/``
      - Azure: ``http://169.254.169.254/metadata/instance``
      - Alibaba, Oracle, DigitalOcean — same 169.254.169.254 link-local
  * Local file disclosure
      - ``file:///etc/passwd``, ``file:///proc/self/environ``
  * Internal service discovery
      - ``http://localhost:6379/`` (Redis), ``http://localhost:9200/`` (ES)
  * DNS rebinding via non-resolving TLDs

What this test does
-------------------
For each crafted URI we call ``session.read_resource(uri)``:
  - SUCCESS (any content returned) → CRITICAL; server is a real SSRF proxy.
  - Error that contains leaked data (tokens, env vars, IPs) → HIGH.
  - Clean rejection → PASS for that payload.

Test inventory
--------------
T18-SSRF-{payload-id}    One per SSRF payload.
T18-001                  Summary.

Public API
----------
    async def run(session, server_info, config) -> list[TestResult]
"""

from __future__ import annotations

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
    find_secrets,
    looks_like_api_rejection,
)

_CALL_TIMEOUT_SEC = 10.0

# (payload_id, label, uri)
_SSRF_PAYLOADS: tuple[tuple[str, str, str], ...] = (
    ("SSRF-001", "AWS metadata",
     "http://169.254.169.254/latest/meta-data/"),
    ("SSRF-002", "AWS IAM credentials",
     "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
    ("SSRF-003", "GCP metadata",
     "http://metadata.google.internal/computeMetadata/v1/"),
    ("SSRF-004", "Azure IMDS",
     "http://169.254.169.254/metadata/instance?api-version=2021-02-01"),
    ("SSRF-005", "Local /etc/passwd",
     "file:///etc/passwd"),
    ("SSRF-006", "Process env (Linux)",
     "file:///proc/self/environ"),
    ("SSRF-007", "Localhost Redis",
     "http://localhost:6379/"),
    ("SSRF-008", "Localhost Elasticsearch",
     "http://127.0.0.1:9200/"),
    ("SSRF-009", "SSH config",
     "file:///root/.ssh/id_rsa"),
    ("SSRF-010", "DNS rebind probe",
     "http://mcpsafe-ssrf-probe.invalid/"),
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


# Heuristics that suggest the server DID fetch the URI.
def _looks_like_real_metadata(text: str) -> Optional[str]:
    """Return a label when *text* looks like it came from a metadata endpoint."""
    if not text:
        return None
    t = text.lower()
    if "ami-id" in t or "instance-id" in t or "iam/security-credentials" in t:
        return "AWS metadata-like response"
    if "computemetadata" in t or "metadata-flavor" in t:
        return "GCP metadata-like response"
    if '"compute":' in t and ('"osprofile"' in t or '"subscriptionid"' in t):
        return "Azure IMDS-like response"
    if "root:x:0:0" in t or text.startswith("root:"):
        return "/etc/passwd content"
    if "path=" in t and ("home=" in t or "shell=" in t):
        return "/proc/self/environ content"
    if "redis_version:" in t or "# Server" in text[:500]:
        return "Redis INFO response"
    if '"cluster_name"' in t and '"tagline"' in t:
        return "Elasticsearch root response"
    return None


async def _probe(
    session: ClientSession,
    payload_id: str,
    label: str,
    uri: str,
    limiter: RateLimiter,
) -> TestResult:
    tid = f"T18-{payload_id}"
    tname = f"SSRF: {label}"
    t0 = time.perf_counter()

    await limiter.acquire()
    response_text: str = ""
    error_text: str = ""
    try:
        with anyio.fail_after(_CALL_TIMEOUT_SEC):
            resp = await session.read_resource(uri)
        response_text = _extract_text(resp)
    except Exception as exc:
        error_text = str(exc)[:4000]

    duration = (time.perf_counter() - t0) * 1000.0

    # Case 1: we got a success response — that alone is suspicious, but we
    # also need to see if it looks like it actually came from the target.
    if response_text:
        hit = _looks_like_real_metadata(response_text)
        if hit:
            return TestResult(
                test_id=tid, test_name=tname,
                category=Category.SECURITY, severity=Severity.CRITICAL,
                passed=False,
                description=(
                    f"Server fetched arbitrary URI and returned content that "
                    f"looks like {hit}. This is a confirmed SSRF primitive — "
                    f"an attacker can pivot to internal services via this MCP."
                ),
                duration_ms=duration,
                details=f"URI: {uri}\nResponse excerpt: {response_text[:500]!r}",
                remediation=(
                    "Apply an allow-list to resource URIs. Reject link-local IPs "
                    "(169.254.0.0/16), loopback, file://, and any scheme not "
                    "explicitly permitted. For HTTP(S) resolve the hostname and "
                    "reject private-range IPs."
                ),
            )
        # Success but content doesn't obviously match — still MEDIUM.
        return TestResult(
            test_id=tid, test_name=tname,
            category=Category.SECURITY, severity=Severity.MEDIUM,
            passed=False,
            description=(
                f"Server returned a non-empty response for the SSRF probe URI "
                f"{uri!r}. Unclear if the URI was actually fetched or the "
                f"server is echoing. Manual review recommended."
            ),
            duration_ms=duration,
            details=f"URI: {uri}\nResponse excerpt: {response_text[:400]!r}",
        )

    # Case 2: error path — check if it leaks secrets/data.
    if error_text:
        if looks_like_api_rejection([error_text]):
            return TestResult.make_pass(
                test_id=tid, test_name=tname,
                category=Category.SECURITY,
                description=f"SSRF probe correctly rejected: {label}.",
                duration_ms=duration,
                details=error_text[:200],
            )
        secret_hits = find_secrets(error_text)
        if secret_hits:
            return TestResult(
                test_id=tid, test_name=tname,
                category=Category.SECURITY, severity=Severity.HIGH,
                passed=False,
                description=(
                    f"SSRF probe {label} errored but the error message leaked "
                    f"{len(secret_hits)} secret-like pattern(s) — server is "
                    f"catching SSRF failures but still disclosing sensitive "
                    f"internal data in the error."
                ),
                duration_ms=duration,
                details=f"URI: {uri}\nSecrets: {secret_hits[:3]}",
                remediation=(
                    "Scrub error messages from SSRF-adjacent code paths. An "
                    "attacker who can influence the URI should never see "
                    "raw exception text from the networking layer."
                ),
            )
        return TestResult.make_pass(
            test_id=tid, test_name=tname,
            category=Category.SECURITY,
            description=f"SSRF probe {label} rejected without leaking data.",
            duration_ms=duration,
            details=error_text[:200],
        )

    # Case 3: empty success — server silently swallowed the URI.
    return TestResult.make_pass(
        test_id=tid, test_name=tname,
        category=Category.SECURITY,
        description=f"SSRF probe {label} returned empty; no data leaked.",
        duration_ms=duration,
    )


async def run(
    session: ClientSession,
    server_info: ServerInfo,
    config: ScanConfig,
) -> list[TestResult]:
    """Execute T18 — Resource URI SSRF."""
    t_start = time.perf_counter()
    results: list[TestResult] = []
    limiter = RateLimiter(config)

    # Only probe servers that actually expose a read-resource capability.
    # (Some MCP servers never support resources/read — testing them would just
    #  produce N "Method not found" INFO results.)
    has_resources = bool(server_info.resources) or (
        isinstance(server_info.capabilities, dict)
        and "resources" in server_info.capabilities
    )
    if not has_resources:
        results.append(
            TestResult(
                test_id="T18-001",
                test_name="SSRF — Summary",
                category=Category.SECURITY,
                severity=Severity.INFO,
                passed=True,
                description="Server does not expose resources/read; SSRF probes skipped.",
                duration_ms=(time.perf_counter() - t_start) * 1000.0,
            )
        )
        return results

    for pid, label, uri in _SSRF_PAYLOADS:
        results.append(await _probe(session, pid, label, uri, limiter))

    crit = sum(1 for r in results if r.severity == Severity.CRITICAL and not r.passed)
    high = sum(1 for r in results if r.severity == Severity.HIGH and not r.passed)
    if crit:
        results.append(
            TestResult.make_fail(
                test_id="T18-001", test_name="SSRF — Summary",
                category=Category.SECURITY, severity=Severity.CRITICAL,
                description=f"{crit} confirmed SSRF primitive(s) detected.",
                duration_ms=(time.perf_counter() - t_start) * 1000.0,
                remediation="See individual T18-SSRF-* findings for allow-list guidance.",
            )
        )
    elif high:
        results.append(
            TestResult.make_fail(
                test_id="T18-001", test_name="SSRF — Summary",
                category=Category.SECURITY, severity=Severity.HIGH,
                description=f"{high} probe(s) leaked secrets via error messages.",
                duration_ms=(time.perf_counter() - t_start) * 1000.0,
            )
        )
    else:
        results.append(
            TestResult.make_pass(
                test_id="T18-001", test_name="SSRF — Summary",
                category=Category.SECURITY,
                description=f"All {len(_SSRF_PAYLOADS)} SSRF probes safely rejected.",
                duration_ms=(time.perf_counter() - t_start) * 1000.0,
            )
        )
    return results
