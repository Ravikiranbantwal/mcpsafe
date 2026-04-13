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
