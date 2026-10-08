"""A year of data: storage stays bounded and the dashboard/report stay fast.

Default run: 30 days of realistic data (seconds). Set NETPULSE_SLOW=1 for the full 400 days.
"""

import os
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

from netpulse.storage import sqlite
from netpulse.storage.sqlite import RETENTION_DAYS, TARGET_RETENTION_DAYS, Storage
from netpulse.web import report

SLOW = os.environ.get("NETPULSE_SLOW") == "1"
MAX_STEADY_MB = 150
QUERY_BUDGET_S = 3.0          # generous: must also hold on a Pi 3


def fill(path: str, days: int, now: int) -> None:
    s = Storage(path)
    for day in range(days):
        rows, trows = [], []
        for i in range(1440):
            ts = now - (day * 1440 + i) * 60
            bad = 20 * 60 <= (ts % 86400) < 22 * 60   # a daily bad spell, like a real evening
            for w in ("WAN1", "WAN2"):
                st = "BAD" if bad and w == "WAN1" else "HEALTHY"
                rows.append((ts, w, st, 55.5 if st == "BAD" else 99.1, 12.5 if st == "BAD" else 0.0,
                             85.25 if st == "BAD" else 7.25, 3.5, 100.0))
                for t in ("1.1.1.1", "8.8.8.8", "9.9.9.9"):
                    trows.append((ts, w, t, 0.0, 12.75, 0.55))
        events = [(now - day * 86400, "state", "WAN1", "Example ISP A (WAN1): HEALTHY -> BAD (loss 12% >= 15%)")]
        s.write_minute(rows, events, [], trows)
    s.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    s.close()


def timed(fn):
    t0 = time.perf_counter()
    out = fn()
    return out, time.perf_counter() - t0


class Scale(unittest.TestCase):
    DAYS = 400 if SLOW else 30

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.path = str(Path(cls.tmp.name) / "big.db")
        cls.now = int(time.time()) // 60 * 60
        fill(cls.path, cls.DAYS, cls.now)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_steady_state_size_is_bounded(self):
        s = Storage(self.path)
        s.prune(self.now + 60)
        # The test loads everything before the first prune; in service, pruning runs daily from day one
        # and SQLite reuses freed pages, so the file never balloons. VACUUM gives that steady-state size.
        s.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        s.db.execute("VACUUM")
        wan_rows = s.db.execute("SELECT COUNT(*) FROM wan_minute").fetchone()[0]
        target_rows = s.db.execute("SELECT COUNT(*) FROM target_minute").fetchone()[0]
        s.close()
        size_mb = os.path.getsize(self.path) / 1e6
        # Project to steady state from the measured bytes per row.
        per_row = size_mb / (wan_rows + target_rows)
        steady = per_row * (2 * 1440 * RETENTION_DAYS + 6 * 1440 * TARGET_RETENTION_DAYS)
        print(f"\n  {self.DAYS} days -> {size_mb:.1f} MB on disk; projected steady state {steady:.0f} MB")
        self.assertLess(steady, MAX_STEADY_MB)
        self.assertLessEqual(target_rows, 6 * 1440 * (TARGET_RETENTION_DAYS + 1), "per-server detail is pruned")

    def test_dashboard_and_report_queries_stay_fast(self):
        since = lambda days: self.now - days * 86400
        checks = {
            "history, month view": lambda: sqlite.history(self.path, since(30), 3600),
            "history, week view": lambda: sqlite.history(self.path, since(7), 840),
            "uptime table, month": lambda: sqlite.state_minutes(self.path, since(30)),
            "per-server, week": lambda: sqlite.target_history(self.path, since(7), 840, "1.1.1.1"),
            "daily digest": lambda: sqlite.period_summary(self.path, since(1), self.now),
            "ISP report, month": lambda: report.to_html(report.build(self.path, {"WAN1": "Example ISP A"}, {}, 30)),
            "events": lambda: sqlite.recent_events(self.path, 60),
        }
        for name, fn in checks.items():
            out, secs = timed(fn)
            self.assertTrue(out, name)
            self.assertLess(secs, QUERY_BUDGET_S, f"{name} took {secs:.2f}s")

    def test_prune_keeps_what_it_should(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = str(Path(tmp.name) / "p.db")
        s = Storage(path)
        now = 10_000_000_000
        old_target = now - (TARGET_RETENTION_DAYS + 1) * 86400
        old_all = now - (RETENTION_DAYS + 1) * 86400
        s.write_minute([(old_target, "WAN1", "HEALTHY", 99, 0, 7, 1, 100), (old_all, "WAN1", "HEALTHY", 99, 0, 7, 1, 100)],
                       [(old_all, "state", "WAN1", "x")], [],
                       [(old_target, "WAN1", "1.1.1.1", 0, 7, 1), (now, "WAN1", "1.1.1.1", 0, 7, 1)])
        s.prune(now)
        wan_ts = [r[0] for r in s.db.execute("SELECT ts FROM wan_minute")]
        target_ts = [r[0] for r in s.db.execute("SELECT ts FROM target_minute")]
        events = s.db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        s.close()
        self.assertEqual(wan_ts, [old_target], "per-ISP history older than 30 days is kept")
        self.assertEqual(target_ts, [now], "per-server detail older than 30 days is dropped")
        self.assertEqual(events, 0, "events older than the retention period are dropped")


if __name__ == "__main__":
    unittest.main()
