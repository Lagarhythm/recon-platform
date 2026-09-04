"""Adaptive back-off controller (Evasion Layer, PRD 7.6)."""

from __future__ import annotations

import time

from recon.net.backoff import BackoffController
from recon.net.rate_limit import RateLimiter


def test_single_429_cuts_rate_and_starts_cooldown():
    b = BackoffController(10.0, cooldown_seconds=5.0)
    new = b.record(throttled=True)
    assert new < 10.0
    assert b.extra_delay() > 0
    assert b.trips == 1


def test_rate_never_exceeds_base_on_recovery():
    b = BackoffController(10.0, cooldown_seconds=0.0, recover_factor=3.0)
    b.record(throttled=True)
    for _ in range(20):
        r = b.record(throttled=False)
    assert r <= 10.0


def test_rising_connection_errors_trip_backoff():
    b = BackoffController(20.0, window=10, trip_ratio=0.3)
    # 4 of the last 10 are connection errors -> over the 0.3 trip ratio
    for _ in range(6):
        b.record(throttled=False, connection_error=False)
    for _ in range(4):
        last = b.record(throttled=False, connection_error=True)
    assert last < 20.0
    assert b.trips >= 1


def test_burst_of_failures_in_one_window_is_a_single_trip():
    # Regression: an unreachable host used to re-arm the cool-down on *every*
    # request, so each following request ate a full extra_delay() sleep and the
    # scan effectively stalled. A burst inside one window must count as one trip.
    b = BackoffController(10.0, window=4, trip_ratio=0.3, cooldown_seconds=30.0)
    for _ in range(40):
        b.record(throttled=False, connection_error=True)
    assert b.trips == 1
    assert b.extra_delay() <= 30.0


def test_healthy_traffic_keeps_full_rate():
    b = BackoffController(10.0)
    for _ in range(50):
        r = b.record(throttled=False)
    assert r == 10.0
    assert b.trips == 0
    assert b.extra_delay() == 0.0


def test_rate_limiter_update_rate_takes_effect():
    rl = RateLimiter(100.0)
    rl.update_rate(1.0)
    t0 = time.monotonic()
    import asyncio

    async def _drain():
        await rl.acquire()
        await rl.acquire()

    asyncio.run(_drain())
    # second token should have cost ~1s at 1 rps (allow slack)
    assert time.monotonic() - t0 >= 0.5
