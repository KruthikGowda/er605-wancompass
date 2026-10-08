"""Per-WAN health state and 0-100 quality score."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from statistics import median

from netpulse.config import Thresholds
from netpulse.health import metrics
from netpulse.health.baseline import Baselines
from netpulse.health.metrics import Cycle, WanMetrics

MIN_CYCLES = 3
STABILITY_WINDOW = 3600  # state changes in the last hour count against the score


class State(str, Enum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    BAD = "BAD"
    OFFLINE = "OFFLINE"
    UNKNOWN = "UNKNOWN"


@dataclass
class Evaluation:
    wan: str
    ts: float
    state: State
    score: float
    metrics: WanMetrics
    rtt_ratio: float | None = None  # current RTT / learned baseline
    reasons: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    local_problem: bool = False   # the Pi can't test this line (its own fault, not the ISP's)


def _clamp(x: float) -> float:
    return max(0.0, min(1.0, x))


def rtt_deviation(wan: str, m: WanMetrics, baselines: Baselines) -> tuple[float | None, float | None]:
    """Median (ratio, increase_ms) versus baseline across targets with a trusted baseline."""
    ratios, increases = [], []
    for t in m.targets:
        b = baselines.get(wan, t.target)
        if t.rtt_ms is None or b is None or not b.ready or b.value <= 0:
            continue
        ratios.append(t.rtt_ms / b.value)
        increases.append(t.rtt_ms - b.value)
    if not ratios:
        return None, None
    return median(ratios), median(increases)


def classify(m: WanMetrics, ratio: float | None, increase: float | None, th: Thresholds) -> tuple[State, list[str]]:
    reasons: list[str] = []
    rtt = m.rtt_ms
    jit = m.jitter_ms
    big_increase = increase is not None and increase >= th.min_rtt_increase_ms

    if m.loss_pct >= th.bad_loss_pct:
        reasons.append(f"loss {m.loss_pct:.0f}% >= {th.bad_loss_pct:g}%")
    if rtt is not None and rtt >= th.bad_rtt_ms:
        reasons.append(f"RTT {rtt:.0f} ms >= {th.bad_rtt_ms:g} ms")
    if ratio is not None and big_increase and ratio >= th.bad_rtt_factor:
        reasons.append(f"RTT {ratio:.1f}x baseline")
    if reasons:
        return State.BAD, reasons

    if m.loss_pct >= th.degraded_loss_pct:
        reasons.append(f"loss {m.loss_pct:.0f}% >= {th.degraded_loss_pct:g}%")
    if rtt is not None and rtt >= th.degraded_rtt_ms:
        reasons.append(f"RTT {rtt:.0f} ms >= {th.degraded_rtt_ms:g} ms")
    if ratio is not None and big_increase and ratio >= th.degraded_rtt_factor:
        reasons.append(f"RTT {ratio:.1f}x baseline")
    if jit is not None and jit >= th.degraded_jitter_ms:
        reasons.append(f"jitter {jit:.0f} ms >= {th.degraded_jitter_ms:g} ms")
    if reasons:
        return State.DEGRADED, reasons
    return State.HEALTHY, []


def score(m: WanMetrics, ratio: float | None, state_changes: int) -> float:
    """Availability 40, loss 30, latency 15, jitter 10, stability 5."""
    availability = 40 * m.availability_pct / 100
    loss = 30 * _clamp(1 - m.loss_pct / 20)
    if ratio is not None:
        latency = 15 * _clamp((4 - ratio) / (4 - 1.2))
    elif m.rtt_ms is not None:
        latency = 15 * _clamp((250 - m.rtt_ms) / (250 - 60))
    else:
        latency = 0.0
    jitter = 10 * _clamp(1 - (m.jitter_ms or 0) / 50) if m.rtt_ms is not None else 0.0
    stability = 5 * _clamp(1 - state_changes / 6)
    return round(availability + loss + latency + jitter + stability, 1)


class WanTracker:
    """Rolling window of probe cycles for one WAN, plus its state history."""

    def __init__(self, wan: str, window_seconds: float, thresholds: Thresholds):
        self.wan = wan
        self.window = window_seconds
        self.th = thresholds
        self.cycles: deque[Cycle] = deque()
        self.consecutive_failures = 0
        self.state = State.UNKNOWN
        self.state_since = 0.0
        self.transitions: deque[float] = deque()
        self.last_errors: list[str] = []
        self.local_failures = 0   # consecutive cycles where the Pi couldn't even send (not the ISP's fault)

    def add(self, cycle: Cycle) -> None:
        self.last_errors = sorted({r.error for r in cycle.results.values() if r.error})
        if cycle.results and all(r.error and not r.received for r in cycle.results.values()):
            # Every ping failed to start (e.g. the Pi lost its probe address). This says nothing about
            # the ISP, so keep it out of the loss/latency window and out of the outage counter.
            self.local_failures += 1
            return
        self.local_failures = 0
        self.cycles.append(cycle)
        while self.cycles and self.cycles[0].ts < cycle.ts - self.window:
            self.cycles.popleft()
        self.consecutive_failures = self.consecutive_failures + 1 if cycle.all_failed else 0

    def cycles_since(self, ts: float) -> list[Cycle]:
        return [c for c in self.cycles if c.ts >= ts]

    def evaluate(self, now: float, baselines: Baselines) -> Evaluation:
        m = metrics.compute(list(self.cycles))
        ratio, increase = rtt_deviation(self.wan, m, baselines)

        if self.local_failures >= self.th.offline_cycles:
            state = State.UNKNOWN
            reasons = ["the Pi can't send tests on this line"]
        elif self.local_failures and self.state != State.UNKNOWN:
            state, reasons = self.state, ["checking: the Pi couldn't send tests this cycle"]
        elif self.consecutive_failures >= self.th.offline_cycles:
            state = State.OFFLINE
            reasons = [f"all {len(m.targets)} targets failed for {self.consecutive_failures} cycles"]
        elif self.consecutive_failures and self.state not in (State.UNKNOWN, State.OFFLINE):
            # Nothing answered this cycle but an outage isn't confirmed yet: hold the current state
            # instead of briefly calling the line "slow" and then "down" 20 seconds later.
            state, reasons = self.state, ["checking: no answer in the last cycle"]
        elif m.cycles < MIN_CYCLES:
            state, reasons = State.UNKNOWN, ["collecting data"]
        else:
            state, reasons = classify(m, ratio, increase, self.th)

        if state != self.state:
            self.state, self.state_since = state, now
            self.transitions.append(now)
        while self.transitions and self.transitions[0] < now - STABILITY_WINDOW:
            self.transitions.popleft()

        s = 0.0 if state == State.OFFLINE else score(m, ratio, max(0, len(self.transitions) - 1))
        ev = Evaluation(self.wan, now, state, s, m, ratio, reasons, list(self.last_errors))
        ev.local_problem = self.local_failures >= self.th.offline_cycles
        return ev
