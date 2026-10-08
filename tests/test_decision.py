import unittest

from netpulse.config import DecisionConfig
from netpulse.decision.engine import DecisionEngine
from netpulse.health.evaluator import Evaluation, State
from netpulse.health.metrics import WanMetrics

CFG = DecisionConfig(min_score_advantage=15, hold_seconds=180, cooldown_seconds=600, recovery_seconds=600)


def ev(wan: str, score: float, state: State = State.HEALTHY) -> Evaluation:
    return Evaluation(wan, 0, state, score, WanMetrics(10, 0, 20, 2, 100, []))


def run(engine, start, end, wan1, wan2, step=10):
    """Feed the same evaluations every `step` seconds; return the first switch (or None)."""
    t = start
    while t <= end:
        d = engine.decide(t, {"WAN1": wan1, "WAN2": wan2})
        if d.switch:
            return t, d
        t += step
    return None


class Decide(unittest.TestCase):
    def test_small_difference_never_switches(self):
        e = DecisionEngine(CFG, "WAN1")
        self.assertIsNone(run(e, 0, 3600, ev("WAN1", 92), ev("WAN2", 94)))

    def test_large_temporary_difference_does_not_switch(self):
        e = DecisionEngine(CFG, "WAN1")
        self.assertIsNone(run(e, 0, 120, ev("WAN1", 60), ev("WAN2", 95)))
        # advantage disappears -> hold timer resets
        self.assertIsNone(run(e, 130, 200, ev("WAN1", 90), ev("WAN2", 95)))
        self.assertIsNone(run(e, 210, 380, ev("WAN1", 60), ev("WAN2", 95)))

    def test_large_sustained_difference_switches_after_hold(self):
        e = DecisionEngine(CFG, "WAN1")
        t, d = run(e, 0, 600, ev("WAN1", 60), ev("WAN2", 95))
        self.assertEqual(t, 180)
        self.assertEqual((d.current, d.target, d.emergency), ("WAN1", "WAN2", False))
        self.assertEqual(e.current, "WAN2")

    def test_current_offline_switches_immediately(self):
        e = DecisionEngine(CFG, "WAN1")
        t, d = run(e, 0, 60, ev("WAN1", 0, State.OFFLINE), ev("WAN2", 90))
        self.assertEqual(t, 0)
        self.assertTrue(d.emergency)

    def test_emergency_ignores_cooldown(self):
        e = DecisionEngine(CFG, "WAN1")
        run(e, 0, 0, ev("WAN1", 0, State.OFFLINE), ev("WAN2", 90))  # -> WAN2 at t=0
        t, d = run(e, 10, 60, ev("WAN1", 90), ev("WAN2", 0, State.OFFLINE))
        self.assertEqual((t, d.target), (10, "WAN1"))

    def test_both_offline_stays(self):
        e = DecisionEngine(CFG, "WAN1")
        self.assertIsNone(run(e, 0, 600, ev("WAN1", 0, State.OFFLINE), ev("WAN2", 0, State.OFFLINE)))

    def test_recovered_wan_return_is_delayed(self):
        e = DecisionEngine(CFG, "WAN2")
        # WAN1 is BAD until t=100, then looks great.
        run(e, 0, 100, ev("WAN1", 30, State.BAD), ev("WAN2", 70))
        t, d = run(e, 110, 2000, ev("WAN1", 98), ev("WAN2", 70))
        # must wait recovery (600 s after t=100) + hold (180 s)
        self.assertGreaterEqual(t, 100 + 600 + 180)
        self.assertEqual(d.target, "WAN1")

    def test_gap_without_data_restarts_the_hold(self):
        # Found by fuzzing: Example ISP A looked better, then couldn't be measured for a while; the hold timer
        # kept running through the gap and one good reading afterwards caused a switch.
        e = DecisionEngine(CFG, "WAN2")
        self.assertIsNone(run(e, 0, 60, ev("WAN1", 95), ev("WAN2", 50, State.BAD)))
        self.assertIsNone(run(e, 70, 200, ev("WAN1", 0, State.UNKNOWN), ev("WAN2", 50, State.BAD)))
        t, _ = run(e, 210, 1000, ev("WAN1", 95), ev("WAN2", 50, State.BAD))
        self.assertEqual(t, 210 + 180, "needs a full fresh hold after the gap")

    def test_cooldown_blocks_non_emergency_switch(self):
        e = DecisionEngine(CFG, "WAN1")
        run(e, 0, 200, ev("WAN1", 60), ev("WAN2", 95))  # switches to WAN2 at 180
        result = run(e, 190, 700, ev("WAN1", 95), ev("WAN2", 60))
        # hold done at 370, but cooldown lasts until 180 + 600 = 780
        self.assertIsNone(result)
        t, _ = run(e, 710, 1000, ev("WAN1", 95), ev("WAN2", 60))
        self.assertEqual(t, 780)


if __name__ == "__main__":
    unittest.main()
