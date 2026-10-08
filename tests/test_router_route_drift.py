"""Read-only alerts when an ER605 NP_ route drifts from NetPulse's saved preference."""

import tempfile
import unittest
from types import SimpleNamespace

from netpulse.storage import sqlite
from tests.harness import Scenario, local


class RouterRouteDriftAlerts(unittest.TestCase):
    MAC = "AA-BB-CC-DD-EE-01"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.s = Scenario(self.tmp.name, local(12))
        self.addCleanup(self.s.close)
        sqlite.set_device_label(self.s.cfg.db_path, self.MAC, "Office laptop")
        sqlite.set_device_route(self.s.cfg.db_path, self.MAC, "192.168.0.50", "WAN2",
                                int(self.s.clock()), "owner", "AUTO", "applied")
        self.raw = {
            "clients": [], "reservations": [],
            "policy_routes": [{"name": "NP_R_AABBCCDDEE01", "state": "on", "interfaces": "WAN1"}],
            "policy_routes_checked_at": self.s.clock(),
        }
        self.s.mon.router = SimpleNamespace(snap=SimpleNamespace(raw=self.raw, checked_at=self.s.clock()))

    def test_notifies_once_on_drift_and_again_when_rule_returns_to_saved_state(self):
        self.s.mon.on_router_events(self.s.clock(), [])
        self.assertEqual(len(self.s.outbox.texts()), 1)
        self.assertIn("route rule changed for Office laptop", self.s.outbox.texts()[0])
        self.assertIn("Saved preference: WAN2; last observed router rule: WAN1", self.s.outbox.texts()[0])
        self.assertIn("did not change the router", self.s.outbox.texts()[0])

        self.raw["policy_routes_checked_at"] = self.s.clock() + 600
        self.s.mon.on_router_events(self.s.clock() + 600, [])
        self.assertEqual(len(self.s.outbox.texts()), 1, "persistent drift should not spam every poll")

        self.raw["policy_routes"] = [{"name": "NP_R_AABBCCDDEE01", "state": "on", "interfaces": "WAN2"}]
        self.raw["policy_routes_checked_at"] = self.s.clock() + 1200
        self.s.mon.on_router_events(self.s.clock() + 1200, [])
        self.assertEqual(len(self.s.outbox.texts()), 2)
        self.assertIn("matches its saved NetPulse preference again", self.s.outbox.texts()[1])

    def test_unavailable_or_ambiguous_route_read_does_not_alert_or_clear_state(self):
        self.raw["policy_routes"] = None
        self.raw["policy_routes_checked_at"] = None
        self.s.mon.on_router_events(self.s.clock(), [])
        self.assertEqual(self.s.outbox.texts(), [])

        self.raw["policy_routes"] = [
            {"name": "NP_R_AABBCCDDEE01", "state": "on", "interfaces": "WAN1"},
            {"name": "NP_R_AABBCCDDEE01", "state": "on", "interfaces": "WAN2"}]
        self.raw["policy_routes_checked_at"] = self.s.clock() + 600
        self.s.mon.on_router_events(self.s.clock() + 600, [])
        self.assertEqual(self.s.outbox.texts(), [], "duplicate rows are ambiguous, not confirmed drift")


if __name__ == "__main__":
    unittest.main()
