"""
mcpsafe.tests.t19_homoglyph
=============================
SECURITY category — **Unicode confusable / homoglyph tool impersonation**.

An attacker-controlled MCP server can register tools whose names look
identical to well-known safe tools but actually contain Unicode
"confusables" — characters from other scripts that render the same way:

  * ``read_file``     (Latin)
  * ``reаd_file``     (Cyrillic 'а' U+0430 — visually identical)
  * ``read_fıle``     (Turkish dotless 'ı' U+0131)
  * ``read_file``     (Full-width Latin — U+FF52 etc.)

An LLM that calls "read_file" by name may route to the impersonator
without the user realising.  This test:

1. Scans all tool names, resource names, and prompt names for characters
   outside basic ASCII identifier range.
2. Specifically detects characters that are Unicode "confusables" of
   ASCII letters (common Cyrillic/Greek/math-alphanumeric lookalikes).
3. Checks for mixed-script identifiers (single identifier blending
   Latin with another script) — a strong fraud signal.
4. Checks for zero-width and directional control characters in names
   (invisible characters that fool visual comparison).

Test inventory
--------------
T19-001  Non-ASCII in identifiers                LOW/MEDIUM
T19-002  Confusable/homoglyph characters         HIGH
T19-003  Mixed-script identifiers                HIGH
T19-004  Invisible / directional characters      HIGH
T19-005  Summary

Public API
----------
    async def run(session, server_info, config) -> list[TestResult]
"""

from __future__ import annotations

import time
import unicodedata
from typing import Iterable

from mcp import ClientSession

from mcpsafe.models import (
    Category,
    ScanConfig,
    ServerInfo,
    Severity,
    TestResult,
)


# Confusables: Unicode characters that look like ASCII letters.
# Sourced from Unicode Confusables (subset — the most common lookalikes).
_CONFUSABLES: dict[str, str] = {
    # Cyrillic lowercase → Latin
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
    "\u0441": "c", "\u0445": "x", "\u0443": "y", "\u0456": "i",
    "\u0458": "j", "\u04bb": "h", "\u0455": "s", "\u04cf": "l",
    "\u04ad": "t",
    # Cyrillic uppercase
    "\u0410": "A", "\u0412": "B", "\u0415": "E", "\u041a": "K",
    "\u041c": "M", "\u041d": "H", "\u041e": "O", "\u0420": "P",
    "\u0421": "C", "\u0422": "T", "\u0425": "X",
    # Greek
    "\u03bf": "o", "\u03b1": "a", "\u03bc": "u", "\u03c1": "p",
    "\u03c4": "t", "\u03c5": "u", "\u03bd": "v",
    # Latin-like special
    "\u0131": "i",  # dotless i
    "\u017f": "f",  # long s
    # Fullwidth (common in CJK-originated spoofing)
    "\uff41": "a", "\uff42": "b", "\uff43": "c", "\uff44": "d",
    "\uff45": "e", "\uff46": "f", "\uff52": "r",
}

# Zero-width & directional controls that are INVISIBLE but part of the identifier.
_INVISIBLE_CHARS: set[str] = {
    "\u200b",  # zero-width space
    "\u200c",  # zero-width non-joiner
    "\u200d",  # zero-width joiner
    "\u2060",  # word joiner
    "\ufeff",  # BOM / zero-width no-break space
    "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",   # directional overrides
    "\u2066", "\u2067", "\u2068", "\u2069",             # isolate controls
}


def _char_script(ch: str) -> str:
    """
    Return a coarse script label: 'Latin', 'Cyrillic', 'Greek', 'Common', 'Other'.
    """
    if ch.isascii() and (ch.isalnum() or ch in "_-"):
        return "Latin"
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return "Other"
    if "CYRILLIC" in name:
        return "Cyrillic"
    if "GREEK" in name:
        return "Greek"
    if "FULLWIDTH" in name:
        return "Fullwidth"
    if "HEBREW" in name:
        return "Hebrew"
    if "ARABIC" in name:
        return "Arabic"
    return "Other"


def _collect_identifiers(server_info: ServerInfo) -> list[tuple[str, str]]:
    """Return ``(category, identifier)`` for tools/resources/prompts."""
    ids: list[tuple[str, str]] = []
    for t in server_info.tools or []:
        ids.append(("tool", t.name))
    for r in server_info.resources or []:
        ids.append(("resource", r.name or r.uri))
    for p in server_info.prompts or []:
        ids.append(("prompt", p.name))
    return ids


async def run(
    session: ClientSession,
    server_info: ServerInfo,
    config: ScanConfig,
) -> list[TestResult]:
    """Execute T19 — Unicode Homoglyph Tool Impersonation detection."""
    t_start = time.perf_counter()
    results: list[TestResult] = []

    identifiers = _collect_identifiers(server_info)
    if not identifiers:
        results.append(
            TestResult(
                test_id="T19-005",
                test_name="Homoglyph Scan — Summary",
                category=Category.SECURITY,
                severity=Severity.INFO, passed=True,
                description="No identifiers to scan.",
                duration_ms=(time.perf_counter() - t_start) * 1000.0,
            )
        )
        return results

    # Per-check accumulators.
    nonascii: list[str] = []
    confusable_hits: list[str] = []
    mixed_script: list[str] = []
    invisible_hits: list[str] = []

    for kind, name in identifiers:
        if not name:
            continue

        scripts: set[str] = set()
        saw_nonascii = False
        saw_confusable = False
        saw_invisible = False

        for ch in name:
            if ch in _INVISIBLE_CHARS:
                saw_invisible = True
            if ch in _CONFUSABLES:
                saw_confusable = True
            if not ch.isascii():
                saw_nonascii = True
            scripts.add(_char_script(ch))

        # Mixed-script: Latin blended with Cyrillic/Greek/etc.
        filtered = {s for s in scripts if s not in ("Common",)}
        if "Latin" in filtered and len(filtered - {"Latin"}) > 0:
            # Find the foreign scripts.
            foreign = filtered - {"Latin"}
            mixed_script.append(f"{kind}:{name!r} mixes Latin+{sorted(foreign)}")

        if saw_invisible:
            invisible_hits.append(f"{kind}:{name!r}")
        if saw_confusable:
            # Show what the visually-equivalent ASCII would be.
            ascii_form = "".join(_CONFUSABLES.get(c, c) for c in name)
            confusable_hits.append(f"{kind}:{name!r} visually equivalent to {ascii_form!r}")
        if saw_nonascii:
            nonascii.append(f"{kind}:{name!r}")

    # ── T19-001 non-ASCII identifiers ─────────────────────────────────
    if nonascii:
        # Non-ASCII alone is LOW — legitimate for i18n. Only becomes HIGH with
        # confusables or mixed script, which are reported separately.
        results.append(
            TestResult(
                test_id="T19-001",
                test_name="Non-ASCII Identifiers",
                category=Category.SECURITY,
                severity=Severity.LOW,
                passed=False,
                description=(
                    f"{len(nonascii)} identifier(s) contain non-ASCII characters. "
                    f"Legitimate for internationalisation but a common vehicle "
                    f"for homoglyph impersonation."
                ),
                duration_ms=(time.perf_counter() - t_start) * 1000.0,
                details="\n".join(nonascii[:10]),
            )
        )
    else:
        results.append(
            TestResult.make_pass(
                test_id="T19-001", test_name="Non-ASCII Identifiers",
                category=Category.SECURITY,
                description="All identifiers are pure ASCII.",
            )
        )

    # ── T19-002 confusables ───────────────────────────────────────────
    if confusable_hits:
        results.append(
            TestResult(
                test_id="T19-002",
                test_name="Confusable / Homoglyph Characters",
                category=Category.SECURITY,
                severity=Severity.HIGH,
                passed=False,
                description=(
                    f"{len(confusable_hits)} identifier(s) use characters that "
                    f"are visually identical to ASCII letters but encoded as "
                    f"foreign-script codepoints. Strong fraud / impersonation signal."
                ),
                duration_ms=(time.perf_counter() - t_start) * 1000.0,
                details="\n".join(confusable_hits[:10]),
                remediation=(
                    "Reject tool registrations whose names contain Unicode "
                    "confusables. Normalise via ``unicodedata.normalize('NFKC', name)`` "
                    "AND require all characters to be in a single allowed script "
                    "(typically ASCII plus '_' and '-')."
                ),
            )
        )
    else:
        results.append(
            TestResult.make_pass(
                test_id="T19-002", test_name="Confusable / Homoglyph Characters",
                category=Category.SECURITY,
                description="No Unicode confusables detected in identifiers.",
            )
        )

    # ── T19-003 mixed-script identifiers ──────────────────────────────
    if mixed_script:
        results.append(
            TestResult(
                test_id="T19-003",
                test_name="Mixed-Script Identifiers",
                category=Category.SECURITY,
                severity=Severity.HIGH,
                passed=False,
                description=(
                    f"{len(mixed_script)} identifier(s) mix Latin with another "
                    f"script within the SAME name — a near-certain impersonation "
                    f"attempt (legitimate names would choose one script)."
                ),
                duration_ms=(time.perf_counter() - t_start) * 1000.0,
                details="\n".join(mixed_script[:10]),
                remediation=(
                    "Enforce single-script identifiers per Unicode TR#39 "
                    "'Moderately Restrictive' or stricter profile."
                ),
            )
        )
    else:
        results.append(
            TestResult.make_pass(
                test_id="T19-003", test_name="Mixed-Script Identifiers",
                category=Category.SECURITY,
                description="No mixed-script identifiers found.",
            )
        )

    # ── T19-004 invisible characters ──────────────────────────────────
    if invisible_hits:
        results.append(
            TestResult(
                test_id="T19-004",
                test_name="Invisible / Directional Characters",
                category=Category.SECURITY,
                severity=Severity.HIGH,
                passed=False,
                description=(
                    f"{len(invisible_hits)} identifier(s) contain zero-width or "
                    f"directional-control characters. These are invisible on "
                    f"display but affect equality comparison — a classic "
                    f"Trojan Source / invisible-character attack."
                ),
                duration_ms=(time.perf_counter() - t_start) * 1000.0,
                details="\n".join(invisible_hits[:10]),
                remediation=(
                    "Strip or reject identifiers containing characters in "
                    "Unicode categories Cf (format) and the BiDi override "
                    "set (U+202A–U+202E, U+2066–U+2069)."
                ),
            )
        )
    else:
        results.append(
            TestResult.make_pass(
                test_id="T19-004",
                test_name="Invisible / Directional Characters",
                category=Category.SECURITY,
                description="No invisible characters in identifiers.",
            )
        )

    # ── Summary ──────────────────────────────────────────────────────
    high_findings = sum(
        1 for r in results
        if r.severity >= Severity.HIGH and not r.passed
    )
    if high_findings:
        results.append(
            TestResult.make_fail(
                test_id="T19-005",
                test_name="Homoglyph Scan — Summary",
                category=Category.SECURITY,
                severity=Severity.HIGH,
                description=(
                    f"{high_findings} high-severity homoglyph/Unicode issue(s) "
                    f"detected — the server may be impersonating well-known tools."
                ),
                duration_ms=(time.perf_counter() - t_start) * 1000.0,
            )
        )
    else:
        results.append(
            TestResult.make_pass(
                test_id="T19-005",
                test_name="Homoglyph Scan — Summary",
                category=Category.SECURITY,
                description=(
                    f"Scanned {len(identifiers)} identifier(s); no impersonation "
                    f"signals detected."
                ),
                duration_ms=(time.perf_counter() - t_start) * 1000.0,
            )
        )
    return results
