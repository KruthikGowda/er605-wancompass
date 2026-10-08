"""Turn raw probe cycles into loss / RTT / jitter numbers.

WAN-level numbers are the *median across targets*, so a single misbehaving
target (e.g. 9.9.9.9 having a bad day) can't drag a healthy WAN down.
"""

from __future__ import annotations

from dataclasses import dataclass
from statistics import median
from typing import Iterable, Mapping

from netpulse.probes.icmp import ProbeResult


@dataclass
class Cycle:
    ts: float
    results: Mapping[str, ProbeResult]  # target -> result

    @property
    def all_failed(self) -> bool:
        return all(r.received == 0 for r in self.results.values())


@dataclass
class TargetStats:
    target: str
    sent: int
    received: int
    loss_pct: float
    rtt_ms: float | None
    jitter_ms: float | None


@dataclass
class WanMetrics:
    cycles: int
    loss_pct: float
    rtt_ms: float | None
    jitter_ms: float | None
    availability_pct: float  # % of cycles where at least one target answered
    targets: list[TargetStats]


def jitter(rtts: list[float]) -> float | None:
    """Mean absolute difference between consecutive RTTs (RFC 3550 style, unsmoothed)."""
    if len(rtts) < 2:
        return None
    return sum(abs(b - a) for a, b in zip(rtts, rtts[1:])) / (len(rtts) - 1)


def target_stats(target: str, results: Iterable[ProbeResult]) -> TargetStats:
    results = list(results)
    sent = sum(r.sent for r in results)
    received = sum(r.received for r in results)
    rtts = [x for r in results for x in r.rtts]
    jitters = [j for r in results if (j := jitter(r.rtts)) is not None]
    return TargetStats(
        target=target,
        sent=sent,
        received=received,
        loss_pct=100.0 if sent == 0 else 100.0 * (sent - received) / sent,
        rtt_ms=median(rtts) if rtts else None,
        jitter_ms=sum(jitters) / len(jitters) if jitters else None,
    )


def compute(cycles: list[Cycle]) -> WanMetrics:
    targets = sorted({t for c in cycles for t in c.results})
    stats = [target_stats(t, (c.results[t] for c in cycles if t in c.results)) for t in targets]

    rtts = [s.rtt_ms for s in stats if s.rtt_ms is not None]
    jitters = [s.jitter_ms for s in stats if s.jitter_ms is not None]
    up = sum(1 for c in cycles if not c.all_failed)
    return WanMetrics(
        cycles=len(cycles),
        loss_pct=median([s.loss_pct for s in stats]) if stats else 100.0,
        rtt_ms=median(rtts) if rtts else None,
        jitter_ms=median(jitters) if jitters else None,
        availability_pct=100.0 * up / len(cycles) if cycles else 0.0,
        targets=stats,
    )
