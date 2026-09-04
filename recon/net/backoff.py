"""Adaptive back-off (PRD Section 7.6).

Watches recent request outcomes. When the target starts signalling distress
(HTTP 429, or a rising rate of connection resets/timeouts) the effective
request rate is cut and a cool-down is imposed, then recovered slowly toward
the RoE's configured ceiling. The tool never exceeds that ceiling.
"""

from __future__ import annotations

import time
from collections import deque


class BackoffController:
    def __init__(
        self,
        base_rate: float,
        *,
        window: int = 20,
        trip_ratio: float = 0.3,
        floor_ratio: float = 0.1,
        cut_factor: float = 0.5,
        recover_factor: float = 1.4,
        cooldown_seconds: float = 15.0,
    ) -> None:
        self.base_rate = max(base_rate, 0.01)
        self.current_rate = self.base_rate
        self._outcomes: deque[bool] = deque(maxlen=window)  # True = distress
        self._trip_ratio = trip_ratio
        self._floor = self.base_rate * floor_ratio
        self._cut = cut_factor
        self._recover = recover_factor
        self._cooldown_s = cooldown_seconds
        self._cooldown_until = 0.0
        self.trips = 0

    def _distress_ratio(self) -> float:
        if not self._outcomes:
            return 0.0
        return sum(self._outcomes) / len(self._outcomes)

    def record(self, *, throttled: bool, connection_error: bool = False) -> float:
        """Feed one request outcome; returns the new effective rate."""
        distress = throttled or connection_error
        self._outcomes.append(distress)
        now = time.monotonic()

        if throttled or self._distress_ratio() >= self._trip_ratio:
            # Debounce: a burst of failures inside one cool-down window is one
            # trip, not one per request. Without this a target that stays
            # unhappy keeps pushing the cool-down forward and every subsequent
            # request eats a full `extra_delay()` sleep - the scan never moves.
            in_active_cooldown = now < self._cooldown_until
            if not in_active_cooldown:
                self.current_rate = max(self._floor, self.current_rate * self._cut)
                self._cooldown_until = now + self._cooldown_s
                self.trips += 1
            self._outcomes.clear()
        elif now >= self._cooldown_until and self.current_rate < self.base_rate:
            self.current_rate = min(self.base_rate, self.current_rate * self._recover)

        return self.current_rate

    def extra_delay(self) -> float:
        """Seconds of additional pause to apply while cooling down."""
        return max(0.0, self._cooldown_until - time.monotonic())
