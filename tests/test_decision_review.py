from __future__ import annotations

import sqlite3
import tempfile
import unittest
from io import StringIO
from contextlib import closing
from datetime import datetime
from pathlib import Path
from unittest import mock

from netpulse.storage.sqlite import Storage
from netpulse.decision.review import summarize
from tools.decision_review import main


class DecisionReview(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db_path = str(Path(self.tmp.name) / "netpulse.db")
        Storage(self.db_path).close()

    def add_event(self, ts, kind="decision", message="sensitive details must not be read", wan="WAN1"):
        with closing(sqlite3.connect(self.db_path)) as db:
            db.execute("INSERT INTO events(ts, kind, wan, message) VALUES (?, ?, ?, ?)",
                       (ts, kind, wan, message))
            db.commit()

    def add_metric(self, ts, wan, state, score):
        with closing(sqlite3.connect(self.db_path)) as db:
            db.execute("INSERT INTO wan_minute(ts, wan, state, score) VALUES (?, ?, ?, ?)",
                       (ts, wan, state, score))
            db.commit()

    def test_counts_decisions_per_local_day_without_returning_event_text(self):
        self.add_event(900)
        self.add_event(901)
        self.add_event(902, kind="device", message="private device label")
        self.add_event(1000)

        result = summarize(self.db_path, days=1, now=86400 + 10)

        self.assertEqual(result["total"], 3)
        self.assertEqual(result["daily"], {datetime.fromtimestamp(900).date().isoformat(): 3})
        self.assertNotIn("message", result)

    def test_detail_limit_keeps_total_counts_and_returns_newest_details_in_order(self):
        for timestamp in (100, 200, 300):
            self.add_event(timestamp, message=f"WOULD SWITCH Example ISP A (WAN1) -> Example ISP B (WAN2): {timestamp}",
                           wan="WAN2")

        result = summarize(self.db_path, days=1, now=86400, recommendation_limit=2)

        self.assertEqual(result["total"], 3)
        self.assertEqual([item["ts"] for item in result["recommendations"]], [200, 300])

    def test_rejects_invalid_detail_limits(self):
        for limit in (0, -1, 101, True, 1.5):
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                summarize(self.db_path, days=1, now=86400, recommendation_limit=limit)

    def test_ignores_events_outside_window_and_future_events(self):
        self.add_event(0)
        self.add_event(86400 + 10)
        self.add_event(86400 + 11)

        result = summarize(self.db_path, days=1, now=86400 + 11)

        self.assertEqual(result["total"], 1)

    def test_follow_up_does_not_use_measurements_after_report_end(self):
        self.add_event(1000, message="WOULD SWITCH Example ISP A (WAN1) -> Example ISP B (WAN2): reason", wan="WAN2")
        self.add_metric(1290, "WAN1", "BAD", 20)
        self.add_metric(1290, "WAN2", "HEALTHY", 80)

        result = summarize(self.db_path, days=1, now=1200)

        self.assertEqual(result["recommendations"][0]["follow_up"], [None, None])

    def test_adds_only_sanitized_recent_wan_context_for_manual_review(self):
        self.add_event(1000, message=("WOULD SWITCH Example ISP A (WAN1) -> Example ISP B (WAN2): "
                                     "WAN1 OFFLINE, failing over to WAN2. Device Laptop 192.0.2.4"),
                       wan="WAN2")
        self.add_metric(960, "WAN1", "OFFLINE", 0)
        self.add_metric(960, "WAN2", "HEALTHY", 91.2)

        result = summarize(self.db_path, days=1, now=1100)

        self.assertEqual(result["recommendations"], [{
            "ts": 1000, "source": "WAN1", "target": "WAN2", "kind": "outage failover",
            "source_state": "OFFLINE", "source_score": 0.0,
            "target_state": "HEALTHY", "target_score": 91.2, "metrics_age_seconds": 40,
            "follow_up": [None, None],
        }])
        self.assertNotIn("message", result["recommendations"][0])
        self.assertNotIn("Laptop", str(result["recommendations"]))
        self.assertNotIn("192.0.2.4", str(result["recommendations"]))

    def test_adds_paired_later_wan_samples_without_claiming_recommendation_success(self):
        self.add_event(1000, message=("WOULD SWITCH Example ISP A (WAN1) -> Example ISP B (WAN2): "
                                     "WAN1 OFFLINE, failing over to WAN2."), wan="WAN2")
        self.add_metric(960, "WAN1", "OFFLINE", 0)
        self.add_metric(960, "WAN2", "HEALTHY", 91)
        self.add_metric(1290, "WAN1", "BAD", 20)
        self.add_metric(1310, "WAN2", "HEALTHY", 80)
        self.add_metric(1890, "WAN1", "HEALTHY", 82)
        self.add_metric(1910, "WAN2", "HEALTHY", 75)

        result = summarize(self.db_path, days=1, now=2000)
        follow_up = result["recommendations"][0]["follow_up"]

        self.assertEqual(follow_up, [
            {
                "after_seconds": 300, "source_state": "BAD", "source_score": 20.0,
                "target_state": "HEALTHY", "target_score": 80.0,
                "target_minus_source_score": 60.0, "sample_offset_seconds": 10,
            },
            {
                "after_seconds": 900, "source_state": "HEALTHY", "source_score": 82.0,
                "target_state": "HEALTHY", "target_score": 75.0,
                "target_minus_source_score": -7.0, "sample_offset_seconds": 10,
            },
        ])
        self.assertNotIn("message", result["recommendations"][0])

    def test_cli_renders_later_samples_without_leaking_event_text(self):
        now = 1_700_000_000
        decision_ts = now - 1000
        self.add_event(decision_ts, message=("WOULD SWITCH Example ISP A (WAN1) -> Example ISP B (WAN2): "
                                     "private device address 192.0.2.55"), wan="WAN2")
        self.add_metric(decision_ts - 40, "WAN1", "BAD", 20)
        self.add_metric(decision_ts - 40, "WAN2", "HEALTHY", 90)
        self.add_metric(decision_ts + 300, "WAN1", "BAD", 18)
        self.add_metric(decision_ts + 300, "WAN2", "HEALTHY", 82)
        output = StringIO()

        with (mock.patch("netpulse.decision.review.time.time", return_value=now),
              mock.patch("sys.stdout", output)):
            self.assertEqual(main(["--db", self.db_path, "--days", "1"]), 0)

        rendered = output.getvalue()
        self.assertIn("about 5 min later", rendered)
        self.assertIn("WAN2 minus WAN1 score +64.0", rendered)
        self.assertIn("no paired WAN samples", rendered)
        self.assertIn("not proof a recommendation was correct", rendered)
        self.assertNotIn("192.0.2.55", rendered)
        self.assertNotIn("private device address", rendered)

    def test_stale_or_noncanonical_wan_context_is_not_reported(self):
        self.add_event(1000, message="WOULD SWITCH Example ISP A -> Example ISP B: private text", wan="Example ISP B")
        self.add_metric(879, "WAN1", "OFFLINE", 0)
        self.add_metric(879, "WAN2", "HEALTHY", 90)

        result = summarize(self.db_path, days=1, now=1100)

        self.assertIsNone(result["recommendations"][0]["source"])
        self.assertIsNone(result["recommendations"][0]["target"])
        self.assertIsNone(result["recommendations"][0]["source_state"])
        self.assertIsNone(result["recommendations"][0]["target_state"])
        self.assertEqual(result["recommendations"][0]["kind"], "trigger unavailable")

    def test_classifies_sustained_quality_recommendation_without_raw_reason(self):
        self.add_event(1000, message=("WOULD SWITCH Example ISP A (WAN1) -> Example ISP B (WAN2): "
                                     "WAN2 advantage +22 persisted 200s. Secret"), wan="WAN2")

        result = summarize(self.db_path, days=1, now=1100)

        self.assertEqual(result["recommendations"][0]["kind"], "sustained quality advantage")
        self.assertNotIn("Secret", str(result["recommendations"]))

    def test_rejects_invalid_windows_without_touching_database(self):
        for days in (0, -1, 91, True, 1.5):
            with self.subTest(days=days), self.assertRaises(ValueError):
                summarize(self.db_path, days=days, now=86400)

    def test_missing_database_is_not_created(self):
        missing = str(Path(self.tmp.name) / "missing.db")

        with self.assertRaises(sqlite3.OperationalError):
            summarize(missing, now=86400)
        self.assertFalse(Path(missing).exists())

if __name__ == "__main__":
    unittest.main()
