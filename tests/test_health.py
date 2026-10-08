import unittest

from netpulse.config import Thresholds
from netpulse.health.baseline import WARMUP_SAMPLES, Baseline, Baselines
from netpulse.health.evaluator import State, WanTracker

from tests.helpers import TARGETS, cycle, uniform


def tracker():
    return WanTracker("WAN1", 300, Thresholds())


def learned(rtt: float) -> Baselines:
    return Baselines({("WAN1", t): Baseline(rtt, WARMUP_SAMPLES) for t in TARGETS})


def feed(tr, cycles, baselines=None):
    baselines = baselines or Baselines()
    e = None
    for c in cycles:
        tr.add(c)
        e = tr.evaluate(c.ts, baselines)
    return e


class Evaluate(unittest.TestCase):
    def test_unknown_until_enough_data(self):
        e = feed(tracker(), [uniform(0, 20)])
        self.assertEqual(e.state, State.UNKNOWN)

    def test_good_latency_is_healthy(self):
        e = feed(tracker(), [uniform(i * 10, 25) for i in range(10)], learned(25))
        self.assertEqual(e.state, State.HEALTHY)
        self.assertGreater(e.score, 90)

    def test_high_absolute_latency_is_bad(self):
        e = feed(tracker(), [uniform(i * 10, 300) for i in range(10)])
        self.assertEqual(e.state, State.BAD)

    def test_latency_relative_to_baseline(self):
        # 110 ms is under the absolute 120 ms limit but 4.4x the learned 25 ms.
        e = feed(tracker(), [uniform(i * 10, 110) for i in range(10)], learned(25))
        self.assertEqual(e.state, State.BAD)
        self.assertAlmostEqual(e.rtt_ratio, 4.4)

    def test_higher_normal_latency_is_not_penalised(self):
        # A WAN whose normal is 45 ms is healthy at 45 ms.
        e = feed(tracker(), [uniform(i * 10, 45) for i in range(10)], learned(45))
        self.assertEqual(e.state, State.HEALTHY)

    def test_small_absolute_increase_ignored(self):
        # 7 ms -> 20 ms is ~2.9x but only +13 ms: not degraded.
        e = feed(tracker(), [uniform(i * 10, 20) for i in range(10)], learned(7))
        self.assertEqual(e.state, State.HEALTHY)

    def test_packet_loss_degraded_and_bad(self):
        e = feed(tracker(), [uniform(i * 10, 30, received=5 if i % 2 else 4) for i in range(10)])
        self.assertEqual(e.state, State.DEGRADED)  # 10% loss
        e = feed(tracker(), [uniform(i * 10, 30, received=4) for i in range(10)])
        self.assertEqual(e.state, State.BAD)  # 20% loss

    def test_one_failing_target_does_not_fail_wan(self):
        cycles = [cycle(i * 10, {"1.1.1.1": 30, "8.8.8.8": 8, "9.9.9.9": None}) for i in range(10)]
        e = feed(tracker(), cycles)
        self.assertEqual(e.state, State.HEALTHY)

    def test_total_failure_goes_offline_after_confirmation(self):
        tr = tracker()
        feed(tr, [uniform(i * 10, 25) for i in range(5)])
        e = feed(tr, [uniform(50, None), uniform(60, None)])
        self.assertNotEqual(e.state, State.OFFLINE)  # 2 failures: not yet
        e = feed(tr, [uniform(70, None)])
        self.assertEqual(e.state, State.OFFLINE)
        self.assertEqual(e.score, 0)

    def test_recovers_from_offline(self):
        tr = tracker()
        feed(tr, [uniform(i * 10, None) for i in range(4)])
        e = feed(tr, [uniform(40, 25)])
        self.assertNotEqual(e.state, State.OFFLINE)


class LearnBaseline(unittest.TestCase):
    def test_learns_and_resists_spikes(self):
        from netpulse.probes.icmp import ProbeResult

        b = Baselines()
        for _ in range(100):
            b.update("WAN1", ProbeResult("1.1.1.1", 5, 5, [25.0] * 5))
        for _ in range(30):
            b.update("WAN1", ProbeResult("1.1.1.1", 5, 5, [200.0] * 5))
        self.assertLess(b.get("WAN1", "1.1.1.1").value, 30)

    def test_ignores_lossy_cycles(self):
        from netpulse.probes.icmp import ProbeResult

        b = Baselines()
        b.update("WAN1", ProbeResult("1.1.1.1", 5, 3, [300.0] * 3))
        self.assertIsNone(b.get("WAN1", "1.1.1.1"))


if __name__ == "__main__":
    unittest.main()
