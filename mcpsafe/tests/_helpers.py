"""
mcpsafe.tests._helpers
======================
Shared utilities used by multiple test modules.

Not part of the public API — import only from within ``mcpsafe.tests``.
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Response size cap  (memory exhaustion defence)
# ---------------------------------------------------------------------------

# Maximum bytes we accept from a single MCP tool call or resource read.
# A malicious server returning 500 MB would otherwise exhaust memory.
MAX_RESPONSE_BYTES: int = 1_048_576  # 1 MB


def cap_response(text: str) -> str:
    """
    Truncate *text* to ``MAX_RESPONSE_BYTES`` bytes (UTF-8).

    Applied to every MCP call result before further processing so a malicious
    server cannot exhaust memory by returning enormous payloads.
    """
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= MAX_RESPONSE_BYTES:
        return text
    return encoded[:MAX_RESPONSE_BYTES].decode("utf-8", errors="replace") + " …[truncated]"


# ---------------------------------------------------------------------------
# Server string sanitisation  (XSS / control-char defence)
# ---------------------------------------------------------------------------

# Compiled once at module load.
_CTRL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*[mGKHFABCDsu]")


def sanitise_server_string(value: str | None, max_len: int = 500) -> str:
    """
    Strip control characters and ANSI escape codes from a string received
    from an untrusted MCP server, then cap its length.

    This is applied to tool names, descriptions, server names, and any other
    server-supplied string that enters MCPSafe's reports or is used as a dict
    key / test ID — even though Jinja2 autoescape handles HTML injection, raw
    control characters (NUL, ESC, BEL …) can still confuse browsers or
    downstream log consumers.

    Parameters
    ----------
    value:
        String to sanitise (``None`` is accepted and returns ``""``).
    max_len:
        Maximum character length after sanitisation.

    Returns
    -------
    str:
        Sanitised, length-capped string.
    """
    if not value:
        return ""
    text = _ANSI_ESCAPE.sub("", value)
    text = _CTRL_CHARS.sub("", text)
    if len(text) > max_len:
        text = text[:max_len] + "…"
    return text


# ---------------------------------------------------------------------------
# API rejection detection
# ---------------------------------------------------------------------------

# Substrings (lowercase) that indicate an *external* API rejected a probe call
# due to missing/invalid credentials or missing required real-world parameters —
# NOT a server defect.  When every probe call for a given test fails with one of
# these patterns the result is downgraded to INFO so it does not inflate the
# overall severity score.
_API_REJECTION_PATTERNS: tuple[str, ...] = (
    "400", "401", "403", "404", "422", "429",
    "unauthorized", "unauthenticated", "forbidden",
    "authentication", "not found", "unprocessable",
    "validation", "requires", "missing", "invalid",
    "bad request", "no such", "does not exist",
    "credentials", "permission", "rate limit", "rate_limit",
    "ratelimit", "too many requests", "quota", "throttl",
    "must be", "is required", "not provided",
)


def looks_like_api_rejection(errors: list[str]) -> bool:
    """
    Return ``True`` when **every** error in *errors* looks like an external
    API rejecting the probe call (auth failure, missing params, rate limit, etc.)
    rather than a connectivity failure or server crash.

    Returns ``False`` when *errors* is empty.
    """
    if not errors:
        return False
    return all(
        any(pat in err.lower() for pat in _API_REJECTION_PATTERNS)
        for err in errors
    )


# ---------------------------------------------------------------------------
# Rate-limit aware call pacing  (used by T09–T12 for HTTP+auth servers)
# ---------------------------------------------------------------------------

import asyncio as _asyncio
import time as _time

from mcpsafe.models import ScanConfig as _ScanConfig, TransportType as _TransportType


class RateLimiter:
    """
    Token-bucket style pacing helper for tests that fire many calls in quick
    succession against an HTTP server that enforces rate limits.

    The limiter is a no-op for stdio transports (local process — no rate limit)
    and for HTTP servers without an auth token (public / unauth endpoints are
    usually not rate-limited by key).

    Parameters
    ----------
    config:
        The active ``ScanConfig`` — used to auto-detect whether rate limiting
        should kick in (HTTP + auth token present).
    requests_per_minute:
        Target rate when limiting is active. Default 60 req/min which is
        conservative enough for most API-key tiers (OpenAI, Anthropic, Stripe).
    """

    def __init__(
        self,
        config: _ScanConfig,
        requests_per_minute: int = 60,
    ) -> None:
        self._active: bool = (
            config.transport in (_TransportType.HTTP, _TransportType.SSE)
            and bool(config.auth_token or config.headers)
        )
        self._min_interval: float = 60.0 / max(requests_per_minute, 1)
        self._last_call: float = 0.0
        self._lock = _asyncio.Lock()

    @property
    def active(self) -> bool:
        """``True`` when pacing is applied (HTTP + credentials present)."""
        return self._active

    async def acquire(self) -> None:
        """
        Block until the next call slot is available.

        No-op when the limiter is inactive.  Serialised via an asyncio lock so
        concurrent calls observe a consistent schedule.
        """
        if not self._active:
            return
        async with self._lock:
            now = _time.perf_counter()
            wait = self._last_call + self._min_interval - now
            if wait > 0:
                await _asyncio.sleep(wait)
            self._last_call = _time.perf_counter()

    async def __aenter__(self) -> "RateLimiter":
        await self.acquire()
        return self

    async def __aexit__(self, *_exc: object) -> None:
        return None


# Secret-pattern library — shared by T02 (input echo) and T12 (error leakage).
#
# Each tuple is (label, compiled_pattern).  Patterns are tuned to require a
# key=value structure (or a high-entropy prefix) so they don't false-positive
# on free-text documentation that happens to mention "api_key" or "secret".
import re as _re

SECRET_PATTERNS: tuple[tuple[str, "_re.Pattern[str]"], ...] = (
    ("AWS Access Key",     _re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("AWS Secret",         _re.compile(r"aws[_\-]?secret[_\-]?access[_\-]?key\s*[:=]\s*[\"']?[A-Za-z0-9/+=]{40}")),
    ("GitHub Token",       _re.compile(r"\bghp_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b|\bgho_[A-Za-z0-9]{20,}\b|\bghs_[A-Za-z0-9]{20,}\b")),
    ("OpenAI Key",         _re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}\b")),
    ("Anthropic Key",      _re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b")),
    ("Stripe Key",         _re.compile(r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    ("Google API Key",     _re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Slack Token",        _re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b")),
    ("Private Key Block",  _re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("JWT",                _re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
    ("Bearer Token",       _re.compile(r"\bBearer\s+[A-Za-z0-9\-._~+/]{20,}={0,2}\b")),
    ("DB Connection URI",  _re.compile(r"\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis)://[^\s\"'<>]{8,}")),
    ("Env Var Assignment", _re.compile(r"(?i)(?:PASSWORD|PASSWD|SECRET|TOKEN|API[_\-]?KEY)\s*=\s*[^\s\"'<>]{8,}")),
    ("Unix /etc/passwd",   _re.compile(r"^[a-z_][a-z0-9_\-]*:[x*!]?:\d+:\d+:", _re.MULTILINE)),
    ("IPv4 Private",       _re.compile(r"\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b")),
)


def find_secrets(text: str) -> list[tuple[str, str]]:
    """
    Scan *text* for every pattern in ``SECRET_PATTERNS``.

    Returns a list of ``(label, matched_excerpt)`` tuples.  Each excerpt is
    truncated to 80 characters so evidence can be surfaced in reports without
    leaking the full credential value to readers of the JSON/HTML report.
    """
    findings: list[tuple[str, str]] = []
    if not text:
        return findings
    for label, pat in SECRET_PATTERNS:
        for m in pat.finditer(text):
            excerpt = m.group(0)
            if len(excerpt) > 80:
                excerpt = excerpt[:77] + "…"
            # Redact the middle of long hex/b64 looking secrets so the evidence
            # line in the report shows a finding without re-leaking the value.
            if len(excerpt) > 20 and any(ch.isalnum() for ch in excerpt):
                head, tail = excerpt[:6], excerpt[-4:]
                excerpt = f"{head}…[REDACTED]…{tail}"
            findings.append((label, excerpt))
    return findings
