"""Clock jumps and restarts.

The Pi has no battery-backed clock: after boot it can start with an old time and jump forward
when it syncs over the network, sometimes after NetPulse is already running. NTP can also nudge
the clock back a little. Restarts (upgrades, power cuts) must keep what NetPulse has learned.
"""

import tempfile
import unittest

from netpulse.router.watch import RouterWatch
from netpulse.storage import sqlite
from tests.harness import Scenario, local
from tests.test_router import FakeClient


class Base(unittest.TestCase):
    def scenario(self, start, tmpdir=None, **overrides) -> Scenario:
        if tmpdir is None:
            tmp = tempfile.TemporaryDirectory()
            self.addCleanup(tmp.cleanup)
            tmpdir = tmp.name
        s = Scenario(tmpdir, start, {}, overrides)
        self.addCleanup(s.close)
        return s


class ClockJumps(Base):
    def test_forward_jump_after_ntp_sync_is_calm(self):
        s = self.scenario(local(6), telegram={"digest_time": ""})
        s.run(10 * 60)
        s.clock.t += 6 * 3600          # the clock suddenly catches up by six hours
        s.run(10 * 60)
        self.assertEqual(s.outbox.texts(), [], "no alerts just because the clock moved")
        self.assertEqual((s.state("WAN1"), s.state("WAN2")), ("HEALTHY", "HEALTHY"))
        self.assertLessEqual(len(s.mon.trackers["WAN1"].cycles), 31, "old cycles dropped from the window")

    def test_forward_jump_across_digest_time_sends_one_digest(self):
        s = self.scenario(local(6), telegram={"digest_time": "09:00"})
        s.run(5 * 60)
        s.clock.t += 4 * 3600          # 06:05 -> 10:05, past the 09:00 digest
        s.run(30 * 60)
        self.assertEqual(len([t for t in s.outbox.texts() if "daily summary" in t]), 1)

    def test_small_backward_step_is_harmless(self):
        s = self.scenario(local(12), telegram={"digest_time": ""})
        s.run(10 * 60)
        s.clock.t -= 120
        s.run(10 * 60)
        self.assertEqual(s.outbox.texts(), [])
        self.assertEqual(s.state("WAN1"), "HEALTHY")

    def test_router_reboot_detection_ignores_wall_clock_jumps(self):
        client = FakeClient()
        w = RouterWatch(client, {"WAN1": "Example ISP A", "WAN2": "Example ISP B"}, poll_minutes=10)
        mono = 1000.0
        self.assertEqual(w.tick(1_000_000.0, mono=mono), [])
        client.uptime += 60
        mono += 60
        # Wall clock jumps six hours during those 60 real seconds: not a router restart.
        events = w.tick(1_000_000.0 + 6 * 3600, mono=mono)
        self.assertEqual([e for e in events if "restarted" in (e.alert or "")], [])
        client.uptime = 20            # and a real restart is still caught
        mono += 60
        events = w.tick(1_000_000.0 + 6 * 3600 + 60, mono=mono)
        self.assertTrue(any("restarted" in (e.alert or "") for e in events))


class Restarts(Base):
    def test_restart_keeps_baselines_digest_state_and_history(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        first = self.scenario(local(9, 30), tmpdir=tmp.name, telegram={"digest_time": "09:00"})
        first.run(20 * 60)
        self.assertEqual(len([t for t in first.outbox.texts() if "daily summary" in t]), 1)
        first.close()

        second = self.scenario(local(9, 52), tmpdir=tmp.name, telegram={"digest_time": "09:00"})
        # Learned "normal" latency survives: judged against it straight away.
        self.assertTrue(second.mon.baselines.get("WAN1", "1.1.1.1").ready)
        second.run(20 * 60)
        self.assertEqual([t for t in second.outbox.texts() if "daily summary" in t], [],
                         "the day's summary was already sent before the restart")
        self.assertIsNotNone(second.evals["WAN1"].rtt_ratio)
        minutes = sqlite.period_summary(second.cfg.db_path, 0, 2**62)["wans"]["WAN1"]["minutes"]
        self.assertGreaterEqual(sum(minutes.values()), 38, "history from both runs is kept")


if __name__ == "__main__":
    unittest.main()
