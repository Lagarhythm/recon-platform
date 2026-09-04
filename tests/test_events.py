"""Scan event bus: replay backlog + the 'synced' marker the live view relies on."""

from __future__ import annotations

import pytest

from recon.orchestrator.events import ScanEventBus


@pytest.mark.asyncio
async def test_subscribe_replays_backlog_then_a_synced_marker():
    bus = ScanEventBus()
    await bus.publish("run1", "module_started", module="dns")
    await bus.publish("run1", "checkpoint_reached")

    q = bus.subscribe("run1")
    drained = []
    while not q.empty():
        drained.append(q.get_nowait())

    types = [e["type"] for e in drained]
    assert types == ["module_started", "checkpoint_reached", "synced"]
    # a late live event lands after the marker
    await bus.publish("run1", "scan_completed")
    assert q.get_nowait()["type"] == "scan_completed"


@pytest.mark.asyncio
async def test_synced_marker_sent_even_with_no_backlog():
    bus = ScanEventBus()
    q = bus.subscribe("fresh")
    assert q.get_nowait() == {"type": "synced"}
