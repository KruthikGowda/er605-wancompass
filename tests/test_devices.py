"""Router DHCP inventory is read-only and new-device alerts establish a quiet first-scan baseline."""

import unittest
import tempfile
from types import SimpleNamespace

from netpulse.health.evaluator import Evaluation, State
from netpulse.health.metrics import WanMetrics
from tests.harness import Scenario, local


class NewDeviceAlerts(unittest.TestCase):
    def test_device_activity_is_quiet_by_default_but_keeps_inventory_history(self):
        start = local(12)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        s = Scenario(tmp.name, start)
        self.addCleanup(s.close)
        existing = {"name": "Example NAS", "macaddr": "aa-bb-cc-dd-ee-01", "ipaddr": "192.168.0.107"}
        snap = SimpleNamespace(raw={"clients": [existing]}, checked_at=start)
        s.mon.router = SimpleNamespace(snap=snap)
        s.mon.on_router_events(start, [])
        joined = {"name": "New sensor", "macaddr": "aa-bb-cc-dd-ee-02", "ipaddr": "192.168.0.125"}
        snap.checked_at = start + 600
        snap.raw = {"clients": [existing, joined]}
        s.mon.on_router_events(start + 600, [])
        self.assertFalse(any("New DHCP lease listed" in text for text in s.outbox.texts()))
        self.assertTrue(any("New DHCP lease listed" in event[3] for event in s.mon.pending_events))

    def test_unreviewed_firmware_lock_creates_one_critical_owner_notice(self):
        from unittest.mock import Mock

        start = local(12)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        s = Scenario(tmp.name, start, overrides={"telegram": {"device_activity_notifications": True}})
        self.addCleanup(s.close)
        s.mon.router = SimpleNamespace(snap=SimpleNamespace(raw={}, checked_at=start))
        s.mon.router_control = SimpleNamespace(claim_firmware_review_notice=Mock(side_effect=[{
            "version": "2.4.0 Build 20261001", "reason": "version needs review",
        }, None]))
        real_alert = s.mon.alerter.alert
        s.mon.alerter.alert = Mock(wraps=real_alert)

        s.mon.on_router_events(start, [])
        s.mon.on_router_events(start + 60, [])

        firmware_alerts = [text for text in s.outbox.texts() if "firmware" in text.lower()]
        self.assertEqual(len(firmware_alerts), 1)
        self.assertTrue(all("manual route controls are locked" in text for text in firmware_alerts))
        self.assertTrue(all("⚠️" in text for text in firmware_alerts))
        s.mon.alerter.alert.assert_called_once_with(
            "⚠️ ER605 firmware 2.4.0 Build 20261001 needs review; NetPulse manual route controls are locked "
            "until the owner reviews the version in the dashboard.",
            key="router-firmware-review", critical=True, now=start)
        self.assertEqual(len([event for event in s.mon.pending_events
                              if "firmware" in event[3].lower()]), 1)

    def test_baselines_existing_clients_then_alerts_once_for_a_new_mac(self):
        start = local(12)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        s = Scenario(tmp.name, start, overrides={"telegram": {"device_activity_notifications": True}})
        self.addCleanup(s.close)
        clients = [{"name": "Example NAS", "macaddr": "aa-bb-cc-dd-ee-01", "ipaddr": "192.168.0.107"}]
        snap = SimpleNamespace(raw={"clients": clients}, checked_at=start)
        s.mon.router = SimpleNamespace(snap=snap)
        s.mon.on_router_events(start, [])
        self.assertFalse(any("New DHCP lease listed" in text for text in s.outbox.texts()))

        snap.checked_at = start + 600
        snap.raw = {"clients": clients + [{"name": "New sensor", "macaddr": "aa-bb-cc-dd-ee-02",
                                            "ipaddr": "192.168.0.125"}]}
        s.mon.on_router_events(start + 600, [])
        self.assertEqual([t for t in s.outbox.texts() if "New DHCP lease listed" in t],
                         ["🆕 New DHCP lease listed by the ER605: New sensor (192.168.0.125)"])
        s.mon.on_router_events(start + 601, [])
        self.assertEqual(len([t for t in s.outbox.texts() if "New DHCP lease listed" in t]), 1)

    def test_syslog_gives_fast_hint_and_suppresses_duplicate_from_next_lease_scan(self):
        from netpulse.router.syslog import DhcpAllocation

        start = local(12)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        s = Scenario(tmp.name, start, overrides={"telegram": {"device_activity_notifications": True}})
        self.addCleanup(s.close)
        mac = "AA-BB-CC-DD-EE-02"
        s.mon.on_router_syslog_allocation(DhcpAllocation("192.168.0.125", mac), start + 1)
        self.assertEqual(len([t for t in s.outbox.texts() if "DHCP allocation" in t]), 1)
        self.assertEqual(s.mon.syslog_device_events, 1)
        self.assertEqual(s.mon.syslog_known_renewals_suppressed, 0)

        snap = SimpleNamespace(raw={"clients": [{"name": "New sensor", "macaddr": mac,
                                                   "ipaddr": "192.168.0.125"}]}, checked_at=start + 2)
        s.mon.router = SimpleNamespace(snap=snap)
        s.mon.on_router_events(start + 2, [])
        self.assertFalse(any("New DHCP lease listed" in t for t in s.outbox.texts()))
        self.assertEqual(len([t for t in s.outbox.texts() if "DHCP allocation" in t]), 1)

    def test_known_same_ip_dhcp_renewal_does_not_create_arrival_alert(self):
        from netpulse.router.syslog import DhcpAllocation

        start = local(12)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        s = Scenario(tmp.name, start, overrides={"telegram": {"device_activity_notifications": True}})
        self.addCleanup(s.close)
        mac = "AA-BB-CC-DD-EE-02"
        snap = SimpleNamespace(raw={"clients": [{"name": "Sensor", "macaddr": mac,
                                                   "ipaddr": "192.168.0.125"}]}, checked_at=start)
        s.mon.router = SimpleNamespace(snap=snap)
        s.mon.on_router_events(start, [])
        with self.assertLogs("netpulse", level="INFO") as captured:
            s.mon.on_router_syslog_allocation(DhcpAllocation("192.168.0.125", mac), start + 30)
        self.assertEqual(captured.output, ["INFO:netpulse:accepted ER605 DHCP allocation syslog hint"])
        self.assertFalse(any("DHCP allocation" in t or "New DHCP lease listed" in t
                             for t in s.outbox.texts()))
        self.assertEqual(s.mon.syslog_device_events, 0)
        self.assertEqual(s.mon.syslog_known_renewals_suppressed, 1)

    def test_missing_and_returned_device_alerts_wait_for_three_valid_scans(self):
        start = local(12)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        s = Scenario(tmp.name, start, overrides={"telegram": {"device_activity_notifications": True}})
        self.addCleanup(s.close)
        nas = {"name": "Example NAS", "macaddr": "aa-bb-cc-dd-ee-01", "ipaddr": "192.168.0.107"}
        laptop = {"name": "Work laptop", "macaddr": "aa-bb-cc-dd-ee-02", "ipaddr": "192.168.0.108"}
        snap = SimpleNamespace(raw={"clients": [nas, laptop]}, checked_at=start)
        s.mon.router = SimpleNamespace(snap=snap)
        s.mon.on_router_events(start, [])
        for scan in range(1, 4):
            snap.checked_at = start + scan * 600
            snap.raw = {"clients": [nas]}
            s.mon.on_router_events(start + scan * 600, [])
        self.assertEqual([m for m in s.outbox.texts() if "no longer listed" in m],
                         ["📴 DHCP lease no longer listed by the ER605: Work laptop (192.168.0.108)"])
        snap.checked_at = start + 2400
        snap.raw = {"clients": [nas, laptop]}
        s.mon.on_router_events(start + 2400, [])
        self.assertEqual([m for m in s.outbox.texts() if "listed again" in m],
                         ["🟢 DHCP lease listed again by the ER605: Work laptop (192.168.0.108)"])


class LanPresenceAlerts(unittest.TestCase):
    def test_ping_departure_alert_uses_rotated_batch_interval(self):
        from tests.harness import Scenario
        import tempfile

        start = local(12)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        s = Scenario(tmp.name, start, overrides={"telegram": {"device_activity_notifications": True}})
        self.addCleanup(s.close)
        mac = "AA-BB-CC-DD-EE-02"
        clients = [{"name": "--", "macaddr": mac, "ipaddr": "192.168.0.120"}]
        clients.extend({"name": "other", "macaddr": f"02-00-00-00-00-{i:02X}",
                        "ipaddr": f"192.168.0.{(i % 200) + 1}"} for i in range(1, 129))
        s.mon.router = SimpleNamespace(snap=SimpleNamespace(raw={"clients": clients}))

        result = {mac: {"ip": "192.168.0.120", "response": True, "checked_at": start}}
        s.mon.on_presence_scan(result, start, scan_rounds=2)
        for i in range(1, 4):
            sample = {mac: {"ip": "192.168.0.120", "response": False,
                            "checked_at": start + 120 * i}}
            s.mon.on_presence_scan(sample, start + 120 * i, scan_rounds=2)

        alert = next(text for text in s.outbox.texts() if "stopped replying" in text)
        self.assertIn("3 missed checks (about 4–6 minutes at this inventory size)", alert)

    def test_unknown_ping_behavior_stays_unknown_then_confirmed_transitions_are_cautious(self):
        from tests.harness import Scenario
        import tempfile

        start = local(12)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        s = Scenario(tmp.name, start, overrides={"telegram": {"device_activity_notifications": True}})
        self.addCleanup(s.close)
        mac = "AA-BB-CC-DD-EE-02"
        device = {"name": "--", "macaddr": mac, "ipaddr": "192.168.0.120"}
        s.mon.router = SimpleNamespace(snap=SimpleNamespace(raw={"clients": [device]}))

        no_reply = {mac: {"ip": "192.168.0.120", "response": False, "checked_at": start}}
        for i in range(4):
            s.mon.on_presence_scan(no_reply, start + i * 60)
        self.assertFalse(any("stopped replying" in text for text in s.outbox.texts()))
        self.assertEqual(s.mon.device_presence.snapshot()[mac]["state"], "unknown")

        reply = {mac: {"ip": "192.168.0.120", "response": True, "checked_at": start + 300}}
        s.mon.on_presence_scan(reply, start + 300)
        for i in range(1, 4):
            s.mon.on_presence_scan({mac: {**no_reply[mac], "checked_at": start + 300 + i * 60}},
                                   start + 300 + i * 60)
        self.assertEqual([t for t in s.outbox.texts() if "stopped replying" in t], [
            "📡 Device stopped replying to LAN ping: Unnamed device (DD-EE-02) (192.168.0.120). "
            "Confirmed after 3 missed checks (about 2–3 minutes at this inventory size). It may be asleep or "
            "filtering ping; this does not confirm it is offline."
        ])
        s.mon.on_presence_scan({mac: {**reply[mac], "checked_at": start + 600}}, start + 600)
        self.assertFalse(any("replying to LAN ping again" in text for text in s.outbox.texts()))
        self.assertEqual(s.mon.device_presence.snapshot()[mac]["recovery_replies"], 1)
        s.mon.on_presence_scan({mac: {**reply[mac], "checked_at": start + 660}}, start + 660)
        self.assertIn("Device is replying to LAN ping again", s.outbox.texts()[-1])

    def test_ping_flaps_keep_every_event_but_rate_limit_each_alert_type(self):
        from tests.harness import Scenario
        import tempfile

        start = local(12)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        s = Scenario(tmp.name, start, overrides={"telegram": {"device_activity_notifications": True}})
        self.addCleanup(s.close)
        mac = "AA-BB-CC-DD-EE-12"
        device = {"name": "Phone", "macaddr": mac, "ipaddr": "192.168.0.121"}
        s.mon.router = SimpleNamespace(snap=SimpleNamespace(raw={"clients": [device]}))

        def sample(response, offset):
            s.mon.on_presence_scan({mac: {
                "ip": "192.168.0.121", "response": response,
                "checked_at": start + offset,
            }}, start + offset)

        sample(True, 0)
        for offset in (60, 120, 180):
            sample(False, offset)
        for offset in (240, 300):
            sample(True, offset)
        for offset in (360, 420, 480):
            sample(False, offset)
        for offset in (540, 600):
            sample(True, offset)

        self.assertEqual(len(s.outbox.texts()), 2)
        self.assertEqual(len([event for event in s.mon.pending_events
                              if event[1] == "device_presence"]), 4)
        self.assertEqual(s.outbox.texts()[0].split(":", 1)[0], "📡 Device stopped replying to LAN ping")
        self.assertTrue(s.outbox.texts()[1].startswith("🟢 Device is replying to LAN ping again"))


class RouteExpiryAlerts(unittest.TestCase):
    def test_owner_gets_warning_if_expired_pin_cannot_be_verified_as_auto(self):
        import tempfile

        start = local(12)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        s = Scenario(tmp.name, start)
        self.addCleanup(s.close)
        mac = "AA-BB-CC-DD-EE-02"
        from netpulse.storage import sqlite
        sqlite.set_device_label(s.cfg.db_path, mac, "Office laptop")

        s.mon.on_route_expiry_failure(start, {"mac": mac, "ip": "192.168.0.121", "route": "WAN2"})

        self.assertEqual(s.outbox.texts(), [
            "⚠️ Timed WAN preference for Office laptop (192.168.0.121) expired, but NetPulse could not "
            "verify return to Auto. The previous WAN2 pin may still affect this device; NetPulse will "
            "retry. See route history in the dashboard."
        ])


class WanOutageRouterContext(unittest.TestCase):
    def test_outage_alert_includes_only_fresh_router_status_as_separate_evidence(self):
        import tempfile

        start = local(12)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        s = Scenario(tmp.name, start)
        self.addCleanup(s.close)
        failed = Evaluation("WAN1", start, State.OFFLINE, 0,
                           WanMetrics(3, 100, None, None, 0, []), reasons=["all targets failed"])
        s.mon.router = SimpleNamespace(
            snap=SimpleNamespace(ok=True, checked_at=start - 120,
                                 links={"WAN1": SimpleNamespace(up=True, interface_up=False)}),
            poll_seconds=600)

        alert = s.mon._alert_text(failed, State.HEALTHY, 60, {"WAN1": failed}, now=start)
        self.assertIn("ER605 last reported Example ISP A WAN status Online 2 min ago", alert)
        self.assertIn("separate from physical carrier and NetPulse Internet probes", alert)
        self.assertIn("ER605 interface flag: down", alert)
        self.assertIn("raw flag does not confirm physical carrier or Internet reachability", alert)

        s.mon.router.snap.checked_at = start - 1201
        stale_alert = s.mon._alert_text(failed, State.HEALTHY, 60, {"WAN1": failed}, now=start)
        self.assertNotIn("ER605 last reported", stale_alert)

        s.mon.router.snap.checked_at = start + 3600
        future_alert = s.mon._alert_text(failed, State.HEALTHY, 60, {"WAN1": failed}, now=start)
        self.assertNotIn("ER605 last reported", future_alert)


if __name__ == "__main__":
    unittest.main()
