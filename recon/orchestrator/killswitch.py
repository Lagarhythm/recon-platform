"""Global kill switch (PRD gap: emergency stop).

One switch that halts every active module immediately. Modules cooperatively
check ``kill_switch.raise_if_engaged()`` at their request boundary and await
``kill_switch.wait_clear()`` where appropriate.

Phase 1 state is process-local. Phase 3 (real scan execution) will also
persist the engaged state so a restart does not silently resume scanning
after an emergency stop.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone


class KillSwitchEngaged(RuntimeError):
    """Raised inside modules when the operator has hit the global stop."""


class KillSwitch:
    def __init__(self) -> None:
        # _clear is SET when scanning is permitted, CLEAR when halted.
        self._clear = asyncio.Event()
        self._clear.set()
        self.reason: str | None = None
        self.engaged_at: datetime | None = None
        self.engaged_by: str | None = None

    @property
    def is_engaged(self) -> bool:
        return not self._clear.is_set()

    def engage(self, reason: str, by_user: str | None = None) -> None:
        self._clear.clear()
        self.reason = reason
        self.engaged_by = by_user
        self.engaged_at = datetime.now(timezone.utc)

    def reset(self, by_user: str | None = None) -> None:
        self._clear.set()
        self.reason = None
        self.engaged_at = None
        self.engaged_by = None

    def raise_if_engaged(self) -> None:
        if self.is_engaged:
            raise KillSwitchEngaged(self.reason or "global stop engaged")

    async def wait_clear(self) -> None:
        await self._clear.wait()

    def status(self) -> dict[str, object]:
        return {
            "engaged": self.is_engaged,
            "reason": self.reason,
            "engaged_at": self.engaged_at.isoformat() if self.engaged_at else None,
            "engaged_by": self.engaged_by,
        }


# Process-wide singleton.
kill_switch = KillSwitch()
