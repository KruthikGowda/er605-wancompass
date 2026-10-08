"""Randomised checks of the decision engine's safety rules.

Hundreds of random health sequences (lines drifting between healthy, slow, bad, down and
unknown, sometimes flapping) are fed step by step. After every step the rules must hold:

1. Never recommend a line that is down or unknown.
2. An emergency switch only happens when the current line is down.
3. A normal switch needs: a big enough score lead at this moment, held for the whole hold time,
   no switch of any kind within the cooldown, and a target that hasn't been bad/down recently.
4. Never "switch" to the line already in use.
"""

import random
import unittest

from netpulse.config import DecisionConfig
from netpulse.decision.engine import DecisionEngine
from netpulse.health.evaluator import Evaluation, State
from netpulse.health.metrics import WanMetrics

CFG = DecisionConfig(min_score_advantage=15, hold_seconds=180, cooldown_seconds=600, recovery_seconds=600)
STEP = 10
SCORE_RANGE = {State.HEALTHY: (88, 100), State.DEGRADED: (60, 88), State.BAD: (25, 60),
               State.OFFLINE: (0, 0), State.UNKNOWN: (0, 100)}
# Mostly sticky states with occasional changes; some runs flap hard.
TRANSITIONS = {
    State.HEALTHY: [(State.HEALTHY, 0.97), (State.DEGRADED, 0.02), (State.OFFLINE, 0.005), (State.UNKNOWN, 0.005)],
    State.DEGRADED: [(State.DEGRADED, 0.9), (State.HEALTHY, 0.05), (State.BAD, 0.04), (State.OFFLINE, 0.01)],
    State.BAD: [(State.BAD, 0.9), (State.DEGRADED, 0.06), (State.OFFLINE, 0.03), (State.HEALTHY, 0.01)],
    State.OFFLINE: [(State.OFFLINE, 0.9), (State.BAD, 0.05), (State.HEALTHY, 0.05)],
    State.UNKNOWN: [(State.UNKNOWN, 0.8), (State.HEALTHY, 0.2)],
}


def pick(rng, choices):
    r, acc = rng.random(), 0.0
    for value, p in choices:
        acc += p
        if r < acc:
            return value
    return choices[0][0]


def ev(wan, state, score):
    return Evaluation(wan, 0, state, score, WanMetrics(30, 0, 20, 2, 100, []))


class DecisionFuzz(unittest.TestCase):
    RUNS, STEPS = 400, 500

    def test_safety_rules_hold_for_random_sequences(self):
        switches = emergencies = 0
        for seed in range(self.RUNS):
            rng = random.Random(seed)
            flappy = seed % 5 == 0
            states = {"WAN1": State.HEALTHY, "WAN2": State.HEALTHY}
            engine = DecisionEngine(CFG, rng.choice(["WAN1", "WAN2"]))
            history: list[tuple[float, dict]] = []     # (t, {wan: (state, score)})
            last_switch = float("-inf")
            for i in range(self.STEPS):
                t = 1_000_000.0 + i * STEP
                for w in states:
                    if flappy and rng.random() < 0.2:
                        states[w] = rng.choice(list(SCORE_RANGE))
                    else:
                        states[w] = pick(rng, TRANSITIONS[states[w]])
                snap = {w: (s, rng.uniform(*SCORE_RANGE[s])) for w, s in states.items()}
                history.append((t, snap))
                current = engine.current
                d = engine.decide(t, {w: ev(w, s, sc) for w, (s, sc) in snap.items()})
                where = f"seed {seed} step {i}"
                self.assertIn(engine.current, states, where)
                if not d.switch:
                    self.assertEqual(engine.current, current, where)
                    continue

                switches += 1
                target, (tstate, tscore) = d.target, snap[d.target]
                cstate, cscore = snap[current]
                self.assertNotEqual(target, current, f"{where}: switched to the line already in use")
                self.assertNotIn(tstate, (State.OFFLINE, State.UNKNOWN), f"{where}: recommended a {tstate.value} line")
                if d.emergency:
                    emergencies += 1
                    self.assertEqual(cstate, State.OFFLINE, f"{where}: emergency switch while current was {cstate.value}")
                else:
                    self.assertGreaterEqual(t - last_switch, CFG.cooldown_seconds, f"{where}: switched during cooldown")
                    self.assertGreaterEqual(tscore - cscore, CFG.min_score_advantage, f"{where}: lead too small now")
                    for ht, hsnap in history:
                        if t - CFG.hold_seconds <= ht <= t:
                            lead = hsnap[target][1] - hsnap[current][1]
                            self.assertGreaterEqual(lead, CFG.min_score_advantage, f"{where}: lead not held at {ht}")
                        if t - CFG.recovery_seconds < ht <= t:
                            self.assertNotIn(hsnap[target][0], (State.BAD, State.OFFLINE),
                                             f"{where}: target was {hsnap[target][0].value} at {ht}, within recovery time")
                last_switch = t
                history = history[-(CFG.recovery_seconds // STEP + 2):]
        # Make sure the fuzzing actually exercised both kinds of switch.
        self.assertGreater(switches, 50)
        self.assertGreater(emergencies, 10)


if __name__ == "__main__":
    unittest.main()
