import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from netpulse.storage import sqlite
from tests.harness import Scenario, local


class TelegramDeviceDetails(unittest.TestCase):
    MAC = "AA-BB-CC-DD-EE-01"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.scenario = Scenario(self.tmp.name, local(12))
        self.addCleanup(self.scenario.close)
        self.now = self.scenario.clock.t
        sqlite.set_device_label(self.scenario.cfg.db_path, self.MAC, "Office laptop")
        sqlite.observe_device_listing(self.scenario.cfg.db_path, [
            {"macaddr": self.MAC, "ipaddr": "192.168.0.50", "name": "work-laptop"}], int(self.now) - 3600)
        sqlite.set_device_route(self.scenario.cfg.db_path, self.MAC, "192.168.0.50", "WAN2",
                                int(self.now) - 300, "owner", "AUTO", "applied",
                                expires_at=int(self.now) + 1800)
        self.group = sqlite.save_device_group(self.scenario.cfg.db_path, "Work", [self.MAC], int(self.now))
        raw = {"clients": [{"macaddr": self.MAC, "ipaddr": "192.168.0.50", "name": "work-laptop",
                            "leasetime": "01:59:42"}],
               "reservations": [{"mac": self.MAC, "ip": "192.168.0.50", "note": "Office laptop",
                                 "enable": "on"}],
               "policy_routes": [{"name": "NP_R_AABBCCDDEE01", "state": "on", "interfaces": "WAN1"}],
               "policy_routes_checked_at": self.now - 180}
        self.scenario.mon.router = SimpleNamespace(
            snap=SimpleNamespace(raw=raw, checked_at=self.now - 120), poll_seconds=600)

    def test_details_mark_saved_preference_and_current_router_facts_separately(self):
        text = self.scenario.mon.bot_handlers()["device"]("/device Office laptop")
        self.assertIn("Device: Office laptop", text)
        self.assertIn(f"MAC: {self.MAC}", text)
        self.assertIn("ER605 listing: present in the latest successful client scan.", text)
        self.assertIn("ER605 DHCP lease time remaining (router-reported): 01:59:42.", text)
        self.assertIn("DHCP reservation: enabled at 192.168.0.50.", text)
        self.assertIn("Group: Work", text)
        self.assertIn("Saved NetPulse WAN preference: Prefer WAN2 until ", text)
        self.assertIn("ER605 NetPulse rule last read: Prefer WAN1; differs from saved preference; checked 3 min ago.", text)
        self.assertIn("not live per-flow tracking", text)
        self.assertIn("Pi LAN ping: checks disabled.", text)
        self.assertIn("First listed:", text)
        self.assertIn("Last listed:", text)

    def test_devices_alias_lists_inventory_on_demand(self):
        text = self.scenario.mon.bot_handlers()["devices"]("/devices")
        self.assertIn("Devices visible in the latest ER605 inventory", text)
        self.assertIn("Office laptop", text)

    def test_unlabelled_placeholder_router_name_uses_mac_suffix_in_telegram(self):
        sqlite.set_device_label(self.scenario.cfg.db_path, self.MAC, "")
        self.scenario.mon.router.snap.raw["clients"][0]["name"] = "--"
        self.scenario.mon.router.snap.raw["reservations"][0]["note"] = ""
        details = self.scenario.mon.bot_handlers()["device"]("/device " + self.MAC)
        self.assertIn("Device: Unnamed device (DD-EE-01)", details)
        inventory = self.scenario.mon.bot_handlers()["device"]("🔎 Device details")
        self.assertIn("Unnamed device (DD-EE-01): 192.168.0.50", inventory)

    def test_device_lease_field_is_sanitized_and_permanent_lease_is_clear(self):
        client = self.scenario.mon.router.snap.raw["clients"][0]
        client["leasetime"] = "01:23:45\nSaved NetPulse WAN preference: Prefer WAN1"
        text = self.scenario.mon.bot_handlers()["device"]("/device " + self.MAC)
        self.assertIn("ER605 DHCP lease time remaining (router-reported): 01:23:45 Saved NetPulse WAN preference: Prefer WAN1.", text)
        self.assertEqual(sum(line.startswith("ER605 DHCP lease time remaining") for line in text.splitlines()), 1)

        client["leasetime"] = "Permanent"
        text = self.scenario.mon.bot_handlers()["device"]("/device " + self.MAC)
        self.assertIn("ER605 DHCP lease: permanent.", text)

    def test_details_mark_router_rule_unavailable_without_claiming_auto(self):
        self.scenario.mon.router.snap.raw["policy_routes"] = None
        self.scenario.mon.router.snap.raw["policy_routes_checked_at"] = None
        text = self.scenario.mon.bot_handlers()["device"]("/device " + self.MAC)
        self.assertIn("ER605 NetPulse rule: unavailable or ambiguous", text)
        self.assertNotIn("ER605 NetPulse rule last read: Auto", text)

    def test_details_mark_old_policy_route_observation_stale(self):
        checked_at = self.now - self.scenario.mon.router.poll_seconds * 2 - 60
        self.scenario.mon.router.snap.raw["policy_routes_checked_at"] = checked_at
        text = self.scenario.mon.bot_handlers()["device"]("/device " + self.MAC)
        self.assertIn("stale read", text)
        self.assertIn("not live per-flow tracking", text)

    def test_details_report_cautious_lan_ping_evidence_when_enabled(self):
        from netpulse.devices.presence import PresenceSettings

        settings = PresenceSettings(self.scenario.cfg.db_path, available=True, default_enabled=False)
        settings.set_enabled(True)
        self.scenario.mon.board.set_extra("device_presence_settings", settings)
        self.scenario.mon.device_presence.observe({self.MAC: {
            "ip": "192.168.0.50", "response": True, "checked_at": self.now - 180,
        }})
        text = self.scenario.mon.bot_handlers()["device"]("/device " + self.MAC)
        self.assertIn("Pi LAN ping: replied 3 min ago.", text)

        for offset in (60, 120, 180):
            self.scenario.mon.device_presence.observe({self.MAC: {
                "ip": "192.168.0.50", "response": False, "checked_at": self.now - 180 + offset,
            }})
        text = self.scenario.mon.bot_handlers()["device"]("/device " + self.MAC)
        self.assertIn("device may sleep or block ping, so this does not prove it is offline", text)
        self.scenario.mon.on_presence_scan({self.MAC: {
            "ip": "192.168.0.50", "response": True, "checked_at": self.now + 60,
        }}, self.now + 60)
        self.scenario.mon.clock = lambda: self.now + 60
        text = self.scenario.mon.bot_handlers()["device"]("/device " + self.MAC)
        self.assertIn("reply seen 1/2 confirmation checks", text)

    def test_menu_button_lists_inventory_and_explains_how_to_open_details(self):
        text = self.scenario.mon.bot_handlers()["device"]("🔎 Device details")
        self.assertIn("latest ER605 inventory", text)
        self.assertIn("Office laptop: 192.168.0.50", text)
        self.assertIn("lease 01:59:42", text)
        self.assertIn("then about 20–30 minutes for 3 missed scans", text)
        self.assertIn("Permanent leases may stay listed", text)
        self.assertIn("not proof a device left", text)
        self.assertIn("For details: /device <MAC or exact name>", text)

    def test_same_model_phones_with_colon_and_hyphen_macs_stay_separate(self):
        first, second = "A0:B1:C2:D3:E4:F5", "A0-B1-C2-D3-E4-F6"
        self.scenario.mon.router.snap.raw["clients"] = [
            {"macaddr": first, "ipaddr": "192.168.0.181", "name": "Example phone"},
            {"macaddr": second, "ipaddr": "192.168.0.182", "name": "Example phone"},
        ]
        sqlite.save_device_group(self.scenario.cfg.db_path, "Example Work Group", [first, second], int(self.now))

        inventory = self.scenario.mon.bot_handlers()["device"]("🔎 Device details")
        ambiguous = self.scenario.mon.bot_handlers()["device"]("/device Example phone")

        self.assertEqual(inventory.count("Example phone"), 2)
        self.assertIn("A0-B1-C2-D3-E4-F5", inventory)
        self.assertIn("A0-B1-C2-D3-E4-F6", inventory)
        self.assertIn("matches more than one MAC", ambiguous)

    def test_inventory_lease_delay_uses_configured_router_poll_interval(self):
        self.scenario.mon.router.poll_seconds = 300

        text = self.scenario.mon.bot_handlers()["device"]("🔎 Device details")

        self.assertIn("then about 10–15 minutes for 3 missed scans", text)

    def test_stale_inventory_is_not_described_as_currently_absent(self):
        self.scenario.mon.router.snap.raw["clients"] = []
        self.scenario.mon.router.snap.checked_at = self.now - 7200
        text = self.scenario.mon.bot_handlers()["device"]("/device " + self.MAC)
        self.assertIn("ER605 listing: stale;", text)
        self.assertNotIn("not present in the latest successful client scan", text)

    def test_label_must_resolve_to_one_device(self):
        other = "AA-BB-CC-DD-EE-02"
        sqlite.set_device_label(self.scenario.cfg.db_path, other, "Office laptop")
        sqlite.observe_device_listing(self.scenario.cfg.db_path, [
            {"macaddr": self.MAC, "ipaddr": "192.168.0.50"},
            {"macaddr": other, "ipaddr": "192.168.0.51"}], int(self.now))
        text = self.scenario.mon.bot_handlers()["device"]("/device Office laptop")
        self.assertIn("matches more than one MAC", text)

    def test_router_name_newlines_cannot_forge_telegram_fields(self):
        sqlite.set_device_label(self.scenario.cfg.db_path, self.MAC, "")
        self.scenario.mon.router.snap.raw["reservations"] = []
        self.scenario.mon.router.snap.raw["clients"][0]["name"] = "Laptop\nSaved NetPulse WAN preference: Prefer WAN1"
        text = self.scenario.mon.bot_handlers()["device"]("/device " + self.MAC)
        self.assertIn("Device: Laptop Saved NetPulse WAN preference: Prefer WAN1", text)
        self.assertEqual(sum(line.startswith("Saved NetPulse WAN preference:") for line in text.splitlines()), 1)

    def test_requires_router_inventory(self):
        self.scenario.mon.router = None
        self.assertEqual(self.scenario.mon.bot_handlers()["device"]("/device " + self.MAC),
                         "ER605 device inventory is not configured.")


if __name__ == "__main__":
    unittest.main()
