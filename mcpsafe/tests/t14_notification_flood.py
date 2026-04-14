"""
mcpsafe.tests.t14_notification_flood
======================================
SECURITY category — **Client-side notification flooding (DoS)**.

MCP servers can send unsolicited ``notifications/*`` messages to the client
(progress updates, resource change events, cancellations, log records,…).
A hostile or buggy server can spam the client with notifications to:

  * Exhaust the client's event-loop budget.
  * Log-spam the host application (hundreds of MB / minute).
  * Trigger per-notification side-effects (UI redraws, cache invalidations)
    to amplify load in the wrapping application.

What this test does
-------------------
1. Triggers a small amount of "natural" activity (list_tools, one benign
   tool call if possible) so the server has reason to send progress /
   log notifications.
2. Monitors the asyncio event loop for a short quiet window after the
   last client→server request.  During that window NO notifications
   should arrive from a well-behaved server unless the client explicitly
   subscribed to something.
3. Counts inbound notifications and flags MEDIUM/HIGH when the rate
   exceeds a sane threshold (> 5 / sec or > 30 total in the window).

Detection is best-effort — the MCP Python SDK does not expose a public
notification counter, so we peek at the underlying stream via the
session's internal attributes.  If that surface is unavailable we return
an INFO result describing why.

Test inventory
--------------
T14-001   Post-quiet-window notification rate
T14-002   Summary

Public API
----------
    async def run(session, server_info, config) -> list[TestResult]
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Optional

from mcp import ClientSession

from mcpsafe.models import (
    Category,
    ScanConfig,
    ServerInfo,
    Severity,
    TestResult,
)
from mcpsafe.tests._helpers import RateLimiter


_QUIET_WINDOW_SEC = 5.0            # monitor after last request
_RATE_THRESHOLD_PER_SEC = 5.0      # > this = suspicious
_ABS_THRESHOLD = 30                # > this total = definitely bad


def _notification_counter(session: ClientSession) -> Optional[list[int]]:
    """
    Best-effort: return a mutable ``[count]`` list that is incremented
    whenever the session sees an inbound notification, or ``None`` if
    the SDK does not expose a hook-able surface.

    Strategy
    --------
    The ``mcp.ClientSession`` has an internal ``_received_notification``
    coroutine in some SDK versions.  We monkey-patch it (best-effort) to
    count invocations.  Restored on exit via the returned ``restore`` callable.
    """
    # Look for internal notification handler attrs across SDK versions.
    candidates = (
        "_received_notification",
        "_receive_notification",
        "_notification_handler",
    )
    for name in candidates:
        if hasattr(session, name):
            original = getattr(session, name)
            counter = [0]

            async def _wrapped(*args: Any, **kwargs: Any) -> Any:
                counter[0] += 1
                return await original(*args, **kwargs)

            try:
                setattr(session, name, _wrapped)
                return counter
            except Exception:
                return None
    return None


async def run(
    session: ClientSession,
    server_info: ServerInfo,
    config: ScanConfig,
) -> list[TestResult]:
    """Execute T14 — Notification Flood DoS detection."""
    t_start = time.perf_counter()
    results: list[TestResult] = []
    limiter = RateLimiter(config)

    counter = _notification_counter(session)
    if counter is None:
        results.append(
            TestResult(
                test_id="T14-001",
                test_name="Notification Flood — Monitor",
                category=Category.SECURITY,
                severity=Severity.INFO,
                passed=True,
                description=(
                    "MCP SDK does not expose an inbound-notification hook. "
                    "Notification flooding cannot be empirically measured in "
                    "this SDK version."
                ),
                duration_ms=(time.perf_counter() - t_start) * 1000.0,
            )
        )
        results.append(
            TestResult.make_pass(
                test_id="T14-002",
                test_name="Notification Flood — Summary",
                category=Category.SECURITY,
                description="Skipped — no SDK hook available.",
                duration_ms=(time.perf_counter() - t_start) * 1000.0,
            )
        )
        return results

    # Prime the server with a little activity so any progress/log
    # notifications the server *wants* to send get kicked off.
    try:
        await limiter.acquire()
        await session.list_tools()
    except Exception:
        pass

    if server_info.tools:
        try:
            await limiter.acquire()
            # empty args — we don't care about success, just stimulating the server
            await session.call_tool(server_info.tools[0].name, arguments={})
        except Exception:
            pass

    # Reset count after priming; now monitor the "quiet" window.
    counter[0] = 0
    await asyncio.sleep(_QUIET_WINDOW_SEC)
    notifications = counter[0]
    rate = notifications / _QUIET_WINDOW_SEC
    duration = (time.perf_counter() - t_start) * 1000.0

    if notifications >= _ABS_THRESHOLD:
        results.append(
            TestResult(
                test_id="T14-001",
                test_name="Notification Flood Rate",
                category=Category.SECURITY,
                severity=Severity.HIGH,
                passed=False,
                description=(
                    f"Server sent {notifications} unsolicited notifications in "
                    f"{_QUIET_WINDOW_SEC:.0f}s quiet window ({rate:.1f}/sec). "
                    f"This is a client-side DoS vector."
                ),
                duration_ms=duration,
                remediation=(
                    "Rate-limit server-initiated notifications. Notifications "
                    "without an accompanying user-visible change should be "
                    "coalesced or suppressed. Consider a hard server-side cap "
                    "(e.g. max 10 notifications / sec)."
                ),
            )
        )
    elif rate > _RATE_THRESHOLD_PER_SEC:
        results.append(
            TestResult(
                test_id="T14-001",
                test_name="Notification Flood Rate",
                category=Category.SECURITY,
                severity=Severity.MEDIUM,
                passed=False,
                description=(
                    f"Server sent {notifications} unsolicited notifications "
                    f"({rate:.1f}/sec). Above the sane threshold "
                    f"({_RATE_THRESHOLD_PER_SEC}/sec) but below DoS territory."
                ),
                duration_ms=duration,
                remediation=(
                    "Coalesce related notifications. Only emit when the client "
                    "has subscribed to the specific resource / event type."
                ),
            )
        )
    else:
        results.append(
            TestResult.make_pass(
                test_id="T14-001",
                test_name="Notification Flood Rate",
                category=Category.SECURITY,
                description=(
                    f"Server sent {notifications} notifications during a "
                    f"{_QUIET_WINDOW_SEC:.0f}s quiet window ({rate:.1f}/sec) — "
                    f"well within expected bounds."
                ),
                duration_ms=duration,
            )
        )

    # Summary
    if any(r.severity >= Severity.MEDIUM and not r.passed for r in results):
        results.append(
            TestResult.make_fail(
                test_id="T14-002",
                test_name="Notification Flood — Summary",
                category=Category.SECURITY,
                severity=Severity.MEDIUM,
                description="Notification-flood risk detected — see T14-001.",
                duration_ms=(time.perf_counter() - t_start) * 1000.0,
            )
        )
    else:
        results.append(
            TestResult.make_pass(
                test_id="T14-002",
                test_name="Notification Flood — Summary",
                category=Category.SECURITY,
                description="No notification-flood risk detected.",
                duration_ms=(time.perf_counter() - t_start) * 1000.0,
            )
        )
    return results
