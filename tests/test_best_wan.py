import unittest

from netpulse.decision.best_wan import recommend, recommend_group


class BestWanRecommendation(unittest.TestCase):
    NOW = 1_800_000_000.0

    def rec(self, rows, updated_marker=True, **kwargs):
        updated = self.NOW if updated_marker else None
        return recommend(rows, updated, self.NOW, **kwargs)

    def test_lowest_rtt_wins_between_healthy_wans(self):
        result = self.rec([
            {"name": "WAN1", "state": "HEALTHY", "rtt_ms": 30, "loss_pct": 0},
            {"name": "WAN2", "state": "HEALTHY", "rtt_ms": 12, "loss_pct": 0},
        ])
        self.assertEqual(result["wan"], "WAN2")

    def test_healthy_link_precedes_faster_degraded_link(self):
        result = self.rec([
            {"name": "WAN1", "state": "HEALTHY", "rtt_ms": 70, "loss_pct": 0},
            {"name": "WAN2", "state": "DEGRADED", "rtt_ms": 8, "loss_pct": 2},
        ])
        self.assertEqual(result["wan"], "WAN1")

    def test_degraded_link_is_used_only_when_no_healthy_link_exists(self):
        result = self.rec([
            {"name": "WAN1", "state": "DEGRADED", "rtt_ms": 22, "loss_pct": 1},
            {"name": "WAN2", "state": "DEGRADED", "rtt_ms": 11, "loss_pct": 0},
        ])
        self.assertEqual(result["wan"], "WAN2")
        self.assertIn("no healthy link", result["reason"])

    def test_tiny_rtt_difference_retains_current_wan(self):
        result = self.rec([
            {"name": "WAN1", "state": "HEALTHY", "rtt_ms": 20, "loss_pct": 0},
            {"name": "WAN2", "state": "HEALTHY", "rtt_ms": 21, "loss_pct": 0},
        ], current_wan="WAN2")
        self.assertEqual(result["wan"], "WAN2")
        self.assertIn("within 2 ms", result["reason"])

    def test_rtt_difference_outside_tie_band_selects_faster_wan(self):
        result = self.rec([
            {"name": "WAN1", "state": "HEALTHY", "rtt_ms": 20, "loss_pct": 0},
            {"name": "WAN2", "state": "HEALTHY", "rtt_ms": 23, "loss_pct": 0},
        ], current_wan="WAN2")
        self.assertEqual(result["wan"], "WAN1")

    def test_loss_breaks_equal_rtt_tie(self):
        result = self.rec([
            {"name": "WAN1", "state": "HEALTHY", "rtt_ms": 20, "loss_pct": 3},
            {"name": "WAN2", "state": "HEALTHY", "rtt_ms": 20, "loss_pct": 0},
        ])
        self.assertEqual(result["wan"], "WAN2")

    def test_stale_future_missing_and_invalid_samples_are_unknown(self):
        row = {"name": "WAN1", "state": "HEALTHY", "rtt_ms": 20, "loss_pct": 0}
        self.assertIsNone(recommend([row], self.NOW - 61, self.NOW))
        self.assertIsNone(recommend([row], self.NOW + 1, self.NOW))
        self.assertIsNone(self.rec([{**row, "rtt_ms": None}]))
        self.assertIsNone(self.rec([{**row, "state": "OFFLINE"}]))
        self.assertIsNone(self.rec([{**row, "loss_pct": float("nan")}]))
        self.assertIsNone(self.rec([row], updated_marker=False))

    def test_comparable_two_way_speed_winner_breaks_only_a_ping_tie(self):
        rows = [
            {"name": "WAN1", "state": "HEALTHY", "rtt_ms": 20, "loss_pct": 0,
             "jitter_ms": 2},
            {"name": "WAN2", "state": "HEALTHY", "rtt_ms": 21, "loss_pct": 0,
             "jitter_ms": 1},
        ]
        speed = {"download_winner": "WAN2", "upload_winner": "WAN2",
                 "download_advantage_pct": 20, "upload_advantage_pct": 20}

        result = recommend_group(rows, self.NOW, self.NOW, "WAN1", speed)

        self.assertEqual(result["wan"], "WAN2")
        self.assertIn("throughput", result["reason"])

    def test_speed_winner_cannot_override_conflicting_stale_or_worse_network_evidence(self):
        rows = [
            {"name": "WAN1", "state": "HEALTHY", "rtt_ms": 20, "loss_pct": 0,
             "jitter_ms": 1},
            {"name": "WAN2", "state": "HEALTHY", "rtt_ms": 21, "loss_pct": 1,
             "jitter_ms": 3},
        ]
        conflicts = {"download_winner": "WAN2", "upload_winner": "WAN1"}
        winner = {"download_winner": "WAN2", "upload_winner": "WAN2",
                  "download_advantage_pct": 20, "upload_advantage_pct": 20}

        self.assertEqual(recommend_group(rows, self.NOW, self.NOW, "WAN1", conflicts)["wan"],
                         "WAN1")
        self.assertEqual(recommend_group(rows, self.NOW, self.NOW, "WAN1", winner)["wan"],
                         "WAN1")
        self.assertEqual(recommend_group(rows, self.NOW, self.NOW + 3,
                                         "WAN1", winner)["wan"], "WAN1")

    def test_speed_winner_cannot_override_health_tier_or_meaningful_ping_gap(self):
        speed = {"download_winner": "WAN2", "upload_winner": "WAN2",
                 "download_advantage_pct": 20, "upload_advantage_pct": 20}
        health_difference = [
            {"name": "WAN1", "state": "HEALTHY", "rtt_ms": 80, "loss_pct": 0},
            {"name": "WAN2", "state": "DEGRADED", "rtt_ms": 10, "loss_pct": 2},
        ]
        ping_difference = [
            {"name": "WAN1", "state": "HEALTHY", "rtt_ms": 20, "loss_pct": 0},
            {"name": "WAN2", "state": "HEALTHY", "rtt_ms": 24, "loss_pct": 0},
        ]

        self.assertEqual(recommend_group(health_difference, self.NOW, self.NOW,
                                         "AUTO", speed)["wan"], "WAN1")
        self.assertEqual(recommend_group(ping_difference, self.NOW, self.NOW,
                                         "AUTO", speed)["wan"], "WAN1")

    def test_small_throughput_difference_does_not_break_ping_tie(self):
        rows = [
            {"name": "WAN1", "state": "HEALTHY", "rtt_ms": 20, "loss_pct": 0},
            {"name": "WAN2", "state": "HEALTHY", "rtt_ms": 21, "loss_pct": 0},
        ]
        speed = {"download_winner": "WAN2", "upload_winner": "WAN2",
                 "download_advantage_pct": 2.5, "upload_advantage_pct": 14.9}
        self.assertEqual(recommend_group(rows, self.NOW, self.NOW,
                                         "WAN1", speed)["wan"], "WAN1")


if __name__ == "__main__":
    unittest.main()
