"""In-process pub/sub for live scan progress (WebSocket fan-out)."""

from __future__ import annotations

import asyncio
import contextlib
from collections import defaultdict
from typing import Any

_MAX_QUEUE = 500


class ScanEventBus:
    def __init__(self) -> None:
        self._subs: dict[str, set[asyncio.Queue]] = defaultdict(set)
        # small replay buffer so a late WebSocket subscriber catches up
        self._recent: dict[str, list[dict[str, Any]]] = defaultdict(list)

    def subscribe(self, scan_run_id: str) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=_MAX_QUEUE)
        self._subs[scan_run_id].add(q)
        for evt in self._recent.get(scan_run_id, []):
            with contextlib.suppress(asyncio.QueueFull):
                q.put_nowait(evt)
        # Marks the end of the replay backlog: a client uses it to tell a
        # historical event (e.g. a stale 'checkpoint_reached') from a live one,
        # so replay can update the table without re-triggering navigation.
        with contextlib.suppress(asyncio.QueueFull):
            q.put_nowait({"type": "synced"})
        return q

    def unsubscribe(self, scan_run_id: str, q: asyncio.Queue) -> None:
        self._subs[scan_run_id].discard(q)
        if not self._subs[scan_run_id]:
            self._subs.pop(scan_run_id, None)

    async def publish(self, scan_run_id: str, event_type: str, **data: Any) -> None:
        event = {"type": event_type, **data}
        buf = self._recent[scan_run_id]
        buf.append(event)
        if len(buf) > 100:
            del buf[:-100]
        for q in list(self._subs.get(scan_run_id, ())):
            with contextlib.suppress(asyncio.QueueFull):
                q.put_nowait(event)

    def clear(self, scan_run_id: str) -> None:
        self._recent.pop(scan_run_id, None)


event_bus = ScanEventBus()
