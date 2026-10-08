import unittest

from netpulse.router.control import summarize_group_routes


class GroupRouteReadback(unittest.TestCase):
    NOW = 1_800_000_000.0
    A = "AA-BB-CC-DD-EE-01"
    B = "AA-BB-CC-DD-EE-02"

    def raw(self, rows, checked_at=None):
        return {"policy_routes": rows,
                "policy_routes_checked_at": self.NOW if checked_at is None else checked_at}

    def row(self, mac, route, state="on"):
        return {"name": f"NP_R_{mac.replace('-', '')}", "interfaces": route, "state": state}

    def test_all_member_rules_match_saved_preferences(self):
        result = summarize_group_routes(
            self.raw([self.row(self.A, "WAN1"), self.row(self.B, "WAN2")]),
            [self.A, self.B], {self.A: {"route": "WAN1"}, self.B: {"route": "WAN2"}}, self.NOW)
        self.assertEqual(result, {"observed_route": "MIXED", "route_drift_count": 0,
                                  "route_unknown_count": 0, "route_stale_count": 0,
                                  "route_readback": "matches"})

    def test_drift_and_ambiguous_rows_are_separated(self):
        result = summarize_group_routes(
            self.raw([self.row(self.A, "WAN2"), self.row(self.B, "WAN1"),
                      self.row(self.B, "WAN2")]),
            [self.A, self.B], {self.A: {"route": "WAN1"}, self.B: {"route": "WAN1"}}, self.NOW)
        self.assertEqual(result["route_readback"], "unavailable")
        self.assertEqual(result["route_unknown_count"], 1)
        self.assertEqual(result["route_drift_count"], 1)

    def test_valid_drift_is_reported(self):
        result = summarize_group_routes(
            self.raw([self.row(self.A, "WAN2"), self.row(self.B, "WAN1")]),
            [self.A, self.B], {self.A: {"route": "WAN1"}, self.B: {"route": "WAN1"}}, self.NOW)
        self.assertEqual(result["route_readback"], "drift")
        self.assertEqual(result["route_drift_count"], 1)

    def test_stale_and_future_readbacks_do_not_confirm_route_state(self):
        member_routes = {self.A: {"route": "WAN1"}}
        row = [self.row(self.A, "WAN1")]
        stale = summarize_group_routes(self.raw(row, self.NOW - 1201), [self.A],
                                       member_routes, self.NOW)
        future = summarize_group_routes(self.raw(row, self.NOW + 1), [self.A],
                                        member_routes, self.NOW)
        self.assertEqual(stale["route_readback"], "stale")
        self.assertEqual(future["route_readback"], "stale")

    def test_missing_snapshot_is_unavailable(self):
        result = summarize_group_routes({}, [self.A], {}, self.NOW)
        self.assertEqual(result["route_readback"], "unavailable")


if __name__ == "__main__":
    unittest.main()
