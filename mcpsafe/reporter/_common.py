"""
mcpsafe.reporter._common
=========================
Internal utilities shared across all reporter backends
(JsonReporter, HtmlReporter, SarifReporter).

Keeping shared logic here prevents the three reporters from diverging —
a bug fixed here is fixed everywhere.

Public API
----------
    def server_slug(report: ScanReport) -> str
        Derive a short, filesystem-safe identifier for the scanned server.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from mcpsafe.models import ScanReport


def server_slug(report: ScanReport) -> str:
    """
    Derive a short, filesystem-safe slug for the scanned server.

    Strategy
    --------
    1. Use ``server_info.name`` if it is populated and not generic
       (e.g. the server returned a meaningful name during the MCP handshake).
    2. For HTTP targets, derive from the hostname.
    3. For stdio targets, extract the meaningful module/script name from the
       launch command — stripping interpreter prefixes (``python -m``,
       ``npx``, ``uvx``, ``bunx``), scoped npm-package prefixes
       (``@scope/``), and the common ``mcp-server-`` prefix.

    Returns
    -------
    str:
        1–40 ASCII alphanumeric/hyphen characters, never empty (falls back
        to ``"unknown"``).
    """
    si = report.server_info

    # 1. Try the server's declared name.
    declared = (si.name if si else None) or ""
    if declared and declared.lower() not in ("unknown", ""):
        slug = re.sub(r"[^a-z0-9]+", "-", declared.lower().strip())
        slug = slug.strip("-")[:40]
        if slug:
            return slug

    # 2. Fall back to the launch command / target URL.
    target = (si.target if si else None) or "unknown"

    # For HTTP targets, use the hostname.
    if target.startswith(("http://", "https://")):
        host = urlparse(target).hostname or target
        slug = re.sub(r"[^a-z0-9]+", "-", host.lower()).strip("-")[:40]
        return slug or "unknown"

    # For stdio targets, extract the meaningful binary/module name.
    parts = target.split()
    _INTERPRETERS = {"python", "python3", "python2", "node", "npx", "uvx", "bunx"}
    while parts and parts[0].lower() in _INTERPRETERS:
        parts.pop(0)
        # Drop npx/uvx flags: -y, --yes, -p <pkg>, etc.
        while parts and parts[0].startswith("-"):
            flag = parts.pop(0)
            if flag in ("-p", "--package") and parts:
                parts.pop(0)   # drop the value too
    if parts and parts[0] == "-m":
        parts.pop(0)
    name = parts[0] if parts else "unknown"
    # Handle scoped npm packages: @scope/server-name → server-name
    name = re.sub(r"^@[^/]+/", "", name)
    # Strip path separators and file extension
    name = name.replace("\\", "/").split("/")[-1]
    name = re.sub(r"\.(py|exe|js)$", "", name)
    # Strip common mcp-server prefix
    name = re.sub(r"^mcp[_-]server[_-]?", "", name)
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:40]
    return slug or "unknown"
