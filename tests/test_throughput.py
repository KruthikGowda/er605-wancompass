import unittest

from netpulse.decision.throughput import compare_recent_samples, latest_recent_success


class RecentThroughput(unittest.TestCase):
    NOW = 1_800_000_000.0

    def test_latest_success_per_wan_includes_loaded_ping_and_age(self):
        rows = [
            {"wan": "WAN1", "ts": self.NOW - 600, "down_mbps": 90,
             "up_mbps": 12, "loaded_ms": 80, "idle_ms": 20},
            {"wan": "WAN1", "ts": self.NOW - 30, "down_mbps": 110,
             "up_mbps": 15, "loaded_ms": 95, "idle_ms": 18},
            {"wan": "WAN2", "ts": self.NOW - 120, "down_mbps": 140,
             "up_mbps": 10, "error": None},
        ]
        result = latest_recent_success(rows, self.NOW)
        self.assertEqual(result["WAN1"], {"down_mbps": 110.0, "up_mbps": 15.0,
                                           "loaded_ms": 95.0, "idle_ms": 18.0,
                                           "age_seconds": 30})
        self.assertIsNone(result["WAN2"]["loaded_ms"])

    def test_failed_stale_future_and_malformed_results_are_omitted(self):
        base = {"wan": "WAN1", "ts": self.NOW - 20, "down_mbps": 10, "up_mbps": 1}
        rows = [
            {**base, "error": "timeout"},
            {**base, "ts": self.NOW - 86401},
            {**base, "ts": self.NOW + 1},
            {**base, "down_mbps": float("nan")},
            {**base, "down_mbps": True},
            {**base, "wan": ""},
        ]
        self.assertEqual(latest_recent_success(rows, self.NOW), {})

    def test_newer_failed_result_does_not_replace_recent_success(self):
        rows = [
            {"wan": "WAN1", "ts": self.NOW - 90, "down_mbps": 50, "up_mbps": 5},
            {"wan": "WAN1", "ts": self.NOW - 10, "down_mbps": 0,
             "up_mbps": 0, "error": "server error"},
        ]
        self.assertEqual(latest_recent_success(rows, self.NOW)["WAN1"]["down_mbps"], 50.0)

    def test_close_pair_compares_download_and_upload_separately(self):
        samples = {
            "WAN1": {"age_seconds": 40, "down_mbps": 100, "up_mbps": 25},
            "WAN2": {"age_seconds": 100, "down_mbps": 120, "up_mbps": 18},
        }
        self.assertEqual(compare_recent_samples(samples), {
            "wan1": "WAN1", "wan2": "WAN2", "sample_skew_seconds": 60,
            "download_winner": "WAN2", "upload_winner": "WAN1",
            "download_gap_mbps": 20.0, "upload_gap_mbps": 7.0,
            "download_advantage_pct": 16.7, "upload_advantage_pct": 28.0,
        })

    def test_old_or_unpaired_tests_are_not_ranked(self):
        one = {"WAN1": {"age_seconds": 10, "down_mbps": 100, "up_mbps": 20}}
        far_apart = {**one, "WAN2": {"age_seconds": 1000, "down_mbps": 200, "up_mbps": 30}}
        self.assertIsNone(compare_recent_samples(one))
        self.assertIsNone(compare_recent_samples(far_apart))


if __name__ == "__main__":
    unittest.main()
