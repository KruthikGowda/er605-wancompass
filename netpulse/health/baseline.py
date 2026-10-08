"""Learn what "normal" latency looks like for each WAN + target.

WAN2 shouldn't be called bad just because its usual RTT is higher than WAN1's,
so degradation is judged partly as a ratio against this learned baseline.

During the first ~5 minutes the baseline is the best (lowest) clean median RTT
seen, so starting NetPulse in the middle of a bad spell can't teach it that the
bad spell is normal. After that it's a slow exponential moving average; samples
well above the baseline are learned much more slowly, so a bad evening doesn't
become the new normal, but a permanent ISP routing change is still absorbed over
a day or so.
"""

from __future__ import annotations

from dataclasses import dataclass
from statistics import median

from netpulse.probes.icmp import ProbeResult

FAST_ALPHA = 1 / 360     # ~1 hour of 10 s cycles
SLOW_ALPHA = 1 / 8640    # ~1 day, used for samples that look degraded
WARMUP_SAMPLES = 30      # ~5 min before the baseline is trusted
SPIKE_FACTOR = 1.5


@dataclass
class Baseline:
    value: float
    samples: int = 1

    @property
    def ready(self) -> bool:
        return self.samples >= WARMUP_SAMPLES


class Baselines:
    def __init__(self, initial: dict[tuple[str, str], Baseline] | None = None):
        self._data: dict[tuple[str, str], Baseline] = dict(initial or {})

    def get(self, wan: str, target: str) -> Baseline | None:
        return self._data.get((wan, target))

    def items(self):
        return self._data.items()

    def update(self, wan: str, result: ProbeResult) -> None:
        # Only learn from cycles with no loss: lossy cycles are not "normal".
        if not result.rtts or result.received < result.sent:
            return
        sample = median(result.rtts)
        key = (wan, result.target)
        b = self._data.get(key)
        if b is None:
            self._data[key] = Baseline(sample)
            return
        if not b.ready:
            # Warm-up: keep the best time seen. A line's real capability is its fast times, and
            # this can't be dragged up if NetPulse happens to start during a bad spell.
            b.value = min(b.value, sample)
        else:
            alpha = SLOW_ALPHA if sample > b.value * SPIKE_FACTOR else FAST_ALPHA
            b.value += alpha * (sample - b.value)
        b.samples += 1
