"""Failure injection: when something other than an ISP breaks, NetPulse must keep running and
must not blame the ISP."""

import sqlite3
import tempfile
import time
import unittest
from unittest import mock

from netpulse.notifications.telegram import TelegramBot
from netpulse.storage import sqlite
from tests.harness import Condition, Scenario, local

BIND_ERROR = "ping: bind: Cannot assign requested address"


def window(start, end, inside, outside=Condition()):
    return lambda t: inside if start <= t < end else outside


class Base(unittest.TestCase):
    def scenario(self, start, scripts=None, **overrides) -> Scenario:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        s = Scenario(tmp.name, start, scripts or {}, overrides)
        self.addCleanup(s.close)
        return s


class PiCannotSendTests(Base):
    """The Pi loses its .201 address (e.g. after a network change): pings can't even start."""

    def setUp(self):
        start = local(12)
        self.s = self.scenario(start, {"WAN1": window(start + 300, start + 900, Condition(local_error=BIND_ERROR))},
                               telegram={"digest_time": ""})
        self.s.run(25 * 60)

    def test_does_not_blame_the_isp(self):
        texts = self.s.outbox.texts()
        self.assertFalse(any("Example ISP A is DOWN" in t for t in texts), texts)
        problem = [t for t in texts if t.startswith("⚠️ NetPulse can't test Example ISP A")]
        self.assertEqual(len(problem), 1, texts)
        self.assertIn(BIND_ERROR, problem[0])
        self.assertIn("problem on the Pi", problem[0])
        self.assertTrue(any(t.startswith("✅ NetPulse can test Example ISP A again") for t in texts), texts)

    def test_no_failover_and_no_fake_outage_in_history(self):
        decisions = [e for e in sqlite.events_between(self.s.cfg.db_path, 0, 2**62, ("decision",))]
        self.assertEqual(decisions, [])
        summ = sqlite.period_summary(self.s.cfg.db_path, 0, 2**62)
        self.assertEqual(summ["wans"]["WAN1"]["minutes"].get("OFFLINE", 0), 0)
        # After it's fixed, the line is healthy again without a "was bad" story.
        self.assertEqual(self.s.state("WAN1"), "HEALTHY")
        self.assertFalse(any("Example ISP A is healthy again (was" in t for t in self.s.outbox.texts()))


class DatabaseTrouble(Base):
    def test_locked_database_for_a_minute_loses_nothing_important(self):
        start = local(12)
        s = self.scenario(start, {"WAN2": window(start + 120, start + 600, Condition(down=True))},
                          telegram={"digest_time": ""})
        s.run(3 * 60)
        real = s.storage.write_minute
        calls = {"n": 0}

        def flaky(*a, **k):
            calls["n"] += 1
            if calls["n"] <= 2:
                raise sqlite3.OperationalError("database is locked")
            return real(*a, **k)

        with mock.patch.object(s.storage, "write_minute", flaky):
            s.run(5 * 60)                       # must not raise out of the service loop
        s.run(3 * 60)
        events = [e["message"] for e in sqlite.events_between(s.cfg.db_path, 0, 2**62, ("state", "decision"))]
        self.assertTrue(any("-> OFFLINE" in m for m in events), "events from the failed minutes are kept and saved later")


class TelegramTrouble(unittest.TestCase):
    def test_unreachable_telegram_never_blocks_monitoring(self):
        bot = TelegramBot("1:x", "42", {"help": lambda: "h"}, api_base="http://127.0.0.1:9")  # nothing listens
        bot.start()
        self.addCleanup(bot.stop)
        t0 = time.monotonic()
        for i in range(150):                 # more than the outbox holds
            bot.send(f"alert {i}")
        self.assertLess(time.monotonic() - t0, 0.5, "send() must return immediately")


if __name__ == "__main__":
    unittest.main()
