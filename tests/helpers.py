from netpulse.health.metrics import Cycle
from netpulse.probes.icmp import ProbeResult

TARGETS = ("1.1.1.1", "8.8.8.8", "9.9.9.9")


def result(target: str, rtt: float | None, sent: int = 5, received: int | None = None) -> ProbeResult:
    received = sent if received is None else received
    rtts = [] if rtt is None else [rtt] * received
    return ProbeResult(target, sent, received if rtt is not None else 0, rtts)


def cycle(ts: float, rtts: dict[str, float | None], received: dict[str, int] | None = None) -> Cycle:
    received = received or {}
    return Cycle(ts, {t: result(t, r, received=received.get(t)) for t, r in rtts.items()})


def uniform(ts: float, rtt: float | None, received: int | None = None) -> Cycle:
    return cycle(ts, {t: rtt for t in TARGETS}, {t: received for t in TARGETS} if received is not None else None)
