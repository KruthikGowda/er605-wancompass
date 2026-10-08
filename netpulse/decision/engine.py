"""Pick which WAN critical devices *should* use.

Consumes Evaluations only; never measures anything itself. Rules, in order:

1. Current WAN OFFLINE and another WAN is up      -> switch now (emergency).
2. Best alternative isn't clearly better           -> stay (hysteresis).
3. Best alternative was BAD/OFFLINE recently       -> stay (conservative recovery).
4. Advantage hasn't persisted for hold_seconds     -> stay.
5. Within cooldown_seconds of the last switch      -> stay.
6. Otherwise                                       -> switch.
"""

from __future__ import annotations

from dataclasses import dataclass

from netpulse.config import DecisionConfig
from netpulse.health.evaluator import Evaluation, State

UNHEALTHY = (State.BAD, State.OFFLINE)


@dataclass
class Decision:
    switch: bool
    current: str
    target: str
    reason: str
    emergency: bool = False


class DecisionEngine:
    def __init__(self, cfg: DecisionConfig, initial_wan: str):
        self.cfg = cfg
        self.current = initial_wan
        self.last_switch = float("-inf")
        self.advantage_since: dict[str, float] = {}
        self.last_unhealthy: dict[str, float] = {}

    def decide(self, now: float, evals: dict[str, Evaluation]) -> Decision:
        for name, e in evals.items():
            if e.state in UNHEALTHY:
                self.last_unhealthy[name] = now

        cur = evals[self.current]
        others = [e for n, e in evals.items() if n != self.current and e.state not in (State.OFFLINE, State.UNKNOWN)]

        if cur.state == State.OFFLINE:
            if not others:
                self.advantage_since.clear()
                return self._stay("all WANs offline")
            best = max(others, key=lambda e: e.score)
            return self._switch(now, best.wan, f"{self.current} OFFLINE, failing over to {best.wan}", emergency=True)

        if cur.state == State.UNKNOWN or not others:
            # No usable comparison right now: a lead must be re-proven from fresh data afterwards.
            self.advantage_since.clear()
            return self._stay("waiting for data")

        best = max(others, key=lambda e: e.score)
        advantage = best.score - cur.score
        if advantage < self.cfg.min_score_advantage:
            self.advantage_since.pop(best.wan, None)
            return self._stay(f"no meaningful difference ({cur.score:.0f} vs {best.score:.0f})")

        since_bad = now - self.last_unhealthy.get(best.wan, float("-inf"))
        if since_bad < self.cfg.recovery_seconds:
            self.advantage_since.pop(best.wan, None)
            return self._stay(f"{best.wan} recovering, stable {since_bad:.0f}/{self.cfg.recovery_seconds:.0f}s")

        held = now - self.advantage_since.setdefault(best.wan, now)
        if held < self.cfg.hold_seconds:
            return self._stay(f"{best.wan} +{advantage:.0f} held {held:.0f}/{self.cfg.hold_seconds:.0f}s")

        since_switch = now - self.last_switch
        if since_switch < self.cfg.cooldown_seconds:
            return self._stay(f"cooldown {since_switch:.0f}/{self.cfg.cooldown_seconds:.0f}s")

        return self._switch(now, best.wan, f"{best.wan} advantage +{advantage:.0f} persisted {held:.0f}s")

    def _stay(self, reason: str) -> Decision:
        return Decision(False, self.current, self.current, reason)

    def _switch(self, now: float, target: str, reason: str, emergency: bool = False) -> Decision:
        d = Decision(True, self.current, target, reason, emergency)
        self.current = target
        self.last_switch = now
        self.advantage_since.clear()
        return d
