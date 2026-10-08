import unittest

from netpulse.decision.group_advisor import GroupAdvisor


class GroupAdvisorTests(unittest.TestCase):
    def setUp(self):
        self.advisor = GroupAdvisor(hold_seconds=30, max_sample_gap_seconds=15,
                                    minimum_observations=3)

    def test_candidate_is_monitor_only_until_three_observations_and_hold_complete(self):
        first = self.advisor.update(4, "WAN2", {"wan": "WAN1"}, 100)
        second = self.advisor.update(4, "WAN2", {"wan": "WAN1"}, 115)
        third = self.advisor.update(4, "WAN2", {"wan": "WAN1"}, 130)

        self.assertEqual(first["status"], "pending")
        self.assertEqual(second["observations"], 2)
        self.assertFalse(second["ready"])
        self.assertEqual(third["status"], "stable")
        self.assertTrue(third["ready"])
        self.assertEqual(third["candidate"], "WAN1")

    def test_candidate_resets_when_route_or_recommendation_changes(self):
        self.advisor.update(4, "WAN2", {"wan": "WAN1"}, 100)
        changed = self.advisor.update(4, "WAN2", {"wan": "WAN2"}, 110)
        self.assertIsNone(changed)

        self.advisor.update(4, "WAN2", {"wan": "WAN1"}, 120)
        moved = self.advisor.update(4, "WAN1", {"wan": "WAN2"}, 130)
        self.assertEqual(moved["current"], "WAN1")
        self.assertEqual(moved["candidate"], "WAN2")
        self.assertEqual(moved["observations"], 1)

    def test_stale_or_nonincreasing_samples_restart_the_hold(self):
        self.advisor.update(4, "AUTO", {"wan": "WAN1"}, 100)
        gap = self.advisor.update(4, "AUTO", {"wan": "WAN1"}, 116)
        self.assertEqual(gap["observations"], 1)
        backwards = self.advisor.update(4, "AUTO", {"wan": "WAN1"}, 115)
        self.assertEqual(backwards["observations"], 1)
        self.assertEqual(backwards["held_seconds"], 0)

    def test_mixed_routes_invalid_candidates_and_removed_groups_are_not_advised(self):
        self.advisor.update(4, "WAN2", {"wan": "WAN1"}, 100)
        self.assertIsNone(self.advisor.update(4, "MIXED", {"wan": "WAN1"}, 105))
        self.assertIsNone(self.advisor.update(4, "WAN2", None, 110))
        self.advisor.update(5, "WAN2", {"wan": "WAN1"}, 100)
        self.advisor.retain([5])
        self.assertNotIn(4, self.advisor._pending)
        self.assertIn(5, self.advisor._pending)


if __name__ == "__main__":
    unittest.main()
