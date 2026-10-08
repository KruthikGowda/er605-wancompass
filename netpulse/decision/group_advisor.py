"""Monitor-only stability gate for per-group WAN recommendations."""

from __future__ import annotations

import math


class GroupAdvisor:
    """Require a stable, repeated WAN lead before describing it as actionable advice.

    This class never applies a router change. Its short-lived state intentionally resets when
    NetPulse restarts, when a group's saved route changes, or when probe samples stop arriving.
    """

    def __init__(self, hold_seconds: float = 180, max_sample_gap_seconds: float = 30,
                 minimum_observations: int = 3):
        self.hold_seconds = max(0.0, float(hold_seconds))
        self.max_sample_gap_seconds = max(1.0, float(max_sample_gap_seconds))
        self.minimum_observations = max(2, int(minimum_observations))
        self._pending: dict[int, dict] = {}

    def update(self, group_id: int, current: str, recommendation: dict | None,
               now: float) -> dict | None:
        """Return a pending/stable monitor-only candidate, or None when evidence is unsuitable."""
        if (isinstance(group_id, bool) or not isinstance(group_id, int) or group_id < 1
                or isinstance(now, bool) or not isinstance(now, (int, float))
                or not math.isfinite(float(now))):
            return None
        current = str(current or "").upper()
        if current not in ("AUTO", "WAN1", "WAN2") or not isinstance(recommendation, dict):
            self._pending.pop(group_id, None)
            return None
        candidate = str(recommendation.get("wan", "")).upper()
        if candidate not in ("WAN1", "WAN2") or candidate == current:
            self._pending.pop(group_id, None)
            return None

        previous = self._pending.get(group_id)
        sample_at = float(now)
        if (previous is None or previous["current"] != current
                or previous["candidate"] != candidate
                or sample_at <= previous["last_at"]
                or sample_at - previous["last_at"] > self.max_sample_gap_seconds):
            state = {"current": current, "candidate": candidate, "since": sample_at,
                     "last_at": sample_at, "observations": 1}
        else:
            state = dict(previous)
            state["last_at"] = sample_at
            state["observations"] += 1
        self._pending[group_id] = state

        held = max(0.0, sample_at - state["since"])
        ready = held >= self.hold_seconds and state["observations"] >= self.minimum_observations
        return {
            "current": current,
            "candidate": candidate,
            "status": "stable" if ready else "pending",
            "ready": ready,
            "observations": state["observations"],
            "held_seconds": int(held),
            "required_seconds": int(self.hold_seconds),
        }

    def retain(self, group_ids) -> None:
        """Discard candidates for groups that have been deleted."""
        keep = {int(group_id) for group_id in group_ids
                if not isinstance(group_id, bool) and isinstance(group_id, int)}
        self._pending = {group_id: state for group_id, state in self._pending.items()
                         if group_id in keep}
