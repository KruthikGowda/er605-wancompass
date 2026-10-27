"""Recovery runs before scheduled route changes and requires fresh router access."""
from types import SimpleNamespace
from unittest import TestCase, mock

from netpulse.main import Monitor
from netpulse.router.control import ControlError


class ControlMaintenance(TestCase):
    def setUp(self):
        self.events = []
        self.monitor = Monitor.__new__(Monitor)
        self.monitor.router = SimpleNamespace(
            snap=SimpleNamespace(ok=True),
            refresh_uptime=lambda: self.events.append("refresh") or True)
        self.monitor.router_control = SimpleNamespace(
            route_transaction=SimpleNamespace(pending_count=1),
            recover_pending_routes=lambda: self.events.append("routes"),
            expire_due_routes=lambda now: self.events.append(("expiry", now)) or 2)
        self.monitor.bandwidth_control = SimpleNamespace(
            pending_count=1,
            recover_pending=lambda: self.events.append("bandwidth") or {"pending": False})

    def test_pending_recovery_precedes_expiry(self):
        self.assertEqual(self.monitor.maintain_router_controls(42), 2)
        self.assertEqual(self.events, ["refresh", "routes", "bandwidth", ("expiry", 42)])

    def test_failed_or_stale_router_read_defers_every_write(self):
        self.monitor.router.snap.ok = False
        self.assertEqual(self.monitor.maintain_router_controls(42), 0)
        self.assertEqual(self.events, [])
        self.monitor.router.snap.ok = True
        self.monitor.router.refresh_uptime = lambda: False
        self.assertEqual(self.monitor.maintain_router_controls(42), 0)
        self.assertEqual(self.events, [])

    def test_unresolved_cap_recovery_prevents_expiry(self):
        self.monitor.bandwidth_control.recover_pending = lambda: {"pending": True}
        with self.assertRaisesRegex(ControlError, "recovery remains unresolved"):
            self.monitor.maintain_router_controls(42)
        self.assertEqual(self.events, ["refresh", "routes"])

    def test_route_recovery_failure_prevents_caps_and_expiry(self):
        self.monitor.router_control.recover_pending_routes = mock.Mock(side_effect=ControlError("locked"))
        with self.assertRaisesRegex(ControlError, "locked"):
            self.monitor.maintain_router_controls(42)
        self.assertEqual(self.events, ["refresh"])

    def test_no_pending_work_keeps_normal_expiry_path(self):
        self.monitor.router_control.route_transaction.pending_count = 0
        self.monitor.bandwidth_control.pending_count = 0
        self.assertEqual(self.monitor.maintain_router_controls(42), 2)
        self.assertEqual(self.events, [("expiry", 42)])
