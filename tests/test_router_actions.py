"""Combined owner-reviewed route actions and their reservation boundary."""
from __future__ import annotations

import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

from netpulse.router.actions import ActionControl, MAX_PENDING
from netpulse.router.control import ControlError, RouterControl
from netpulse.storage import sqlite
from netpulse.storage.sqlite import Storage
from tests.test_router_control import FakeControlClient, MAC


class CombinedActions(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.db = str(Path(temp.name) / "actions.db")
        Storage(self.db).close()
        self.client = FakeControlClient()
        self.client.forms[("dhcps", "client")] = [
            {"name": "Work laptop", "macaddr": MAC, "ipaddr": "192.168.0.150", "leasetime": "1h"}]
        self.client.forms[("dhcps", "reservation")] = []
        now = time.time()
        self.router = SimpleNamespace(client=self.client, api_lock=threading.RLock(), poll_seconds=60,
            snap=SimpleNamespace(checked_at=now, uptime_at=now, uptime=1000,
                firmware_version="2.3.3 Build 20251029 Rel.18054",
                raw={"balance_basic": {"balance_state": "on"},
                     "clients": self.client.forms[("dhcps", "client")], "reservations": [],
                     "lan_scopes": [{"name": "IP_LAN", "scope": "192.168.0.0/24"}],
                     "dhcp_settings": {"ipaddr_start": "192.168.0.100", "ipaddr_end": "192.168.0.199"},
                     "policy_routes": [], "policy_routes_checked_at": now}))
        self.routes = RouterControl(self.router, self.db, enabled=True,
                                    kill_switch=str(Path(temp.name) / "disabled"))
        self.routes.is_local_device = lambda _mac: False
        self.routes._refresh_transaction_uptime = lambda: None
        self.actions = ActionControl(self.routes)

    def bandwidth_provider(self):
        client = self.client
        class Provider:
            changed = False
            checks = 0
            def state(self):
                return {"enabled": True, "cleanup_enabled": True}
            def records(self):
                return []
            def preview(self, targets, actor, **kwargs):
                self.targets, self.actor, self.parameters = targets, actor, kwargs
                return {"token": "private-cap-review", "fingerprint": "cap-before-state",
                        "effect": "Limit each selected device to 5 Mbps on WAN2."}
            def check_review(self, token, actor):
                self.checks += 1
                if self.changed:
                    raise ValueError("Bandwidth before-state changed")
            def apply(self, token, actor, check_unchanged):
                assert token == "private-cap-review" and actor == self.actor
                check_unchanged()
                assert any(row.get("mac") == MAC for row in client.forms[("dhcps", "reservation")])
                assert any(row.get("name") == "NP_G_" + MAC.replace("-", "")
                           for row in client.forms[("ipgroup", "ipgroup_reservation")])
                return {"applied": True, "count": len(self.targets), "members": self.targets}
        provider = Provider()
        self.actions.bandwidth = provider
        return provider

    def test_bandwidth_review_prepares_reservation_and_address_without_changing_wan(self):
        provider = self.bandwidth_provider()
        review = self.actions.preview(macs=[MAC], action="bandwidth_wan2_5m", actor="owner")
        self.assertEqual(review["reservation_count"], 1)
        self.assertEqual(self.client.writes, [])
        self.assertEqual(provider.parameters["down_kbps"], 5000)
        self.assertEqual(provider.parameters["up_kbps"], 5000)
        self.assertEqual(self.actions.apply(review["token"], "owner")["count"], 1)
        self.assertEqual(provider.checks, 1)
        self.assertEqual(self.client.forms[("policy_route", "policy_route")], [])
        with self.assertRaises(ControlError):
            self.actions.apply(review["token"], "owner")

    def test_changed_bandwidth_review_stops_before_automatic_reservation(self):
        provider = self.bandwidth_provider()
        review = self.actions.preview(macs=[MAC], action="bandwidth_wan2_5m", actor="owner")
        provider.changed = True
        with self.assertRaisesRegex(ValueError, "before-state changed"):
            self.actions.apply(review["token"], "owner")
        self.assertEqual(self.client.writes, [])

    def test_bandwidth_fingerprint_binds_provider_review_and_requires_same_owner(self):
        self.bandwidth_provider()
        review = self.actions.preview(macs=[MAC], action="bandwidth_wan2_5m", actor="owner")
        with self.assertRaisesRegex(ControlError, "actor differs"):
            self.actions.apply(review["token"], "another-owner")
        self.assertEqual(self.client.writes, [])
        pending = {"action": "bandwidth_wan2_5m", "actor": "owner", "duration_seconds": 0,
                   "targets": [], "bandwidth_fingerprint": "first"}
        first = self.actions._fingerprint(pending)
        pending["bandwidth_fingerprint"] = "changed-cap-state"
        self.assertNotEqual(first, self.actions._fingerprint(pending))

    def test_preview_is_read_only_and_combines_missing_reservation_with_route(self):
        preview = self.actions.preview(macs=[MAC], action="prefer_wan1", actor="owner")
        self.assertEqual(preview["reservation_count"], 1)
        self.assertEqual(preview["members"], [{"mac": MAC, "ip": "192.168.0.150",
                                               "name": "Work laptop", "reservation_needed": True,
                                               "current": "AUTO"}])
        self.assertEqual(self.client.writes, [])

    def test_fingerprint_is_stable_across_previews_and_binds_group_version(self):
        first = self.actions.preview(macs=[MAC], action="prefer_wan1", actor="owner")
        second = self.actions.preview(macs=[MAC], action="prefer_wan1", actor="owner")
        self.assertNotEqual(first["token"], second["token"])
        self.assertEqual(first["fingerprint"], second["fingerprint"])
        group = sqlite.save_device_group(self.db, "Work", [MAC], int(time.time()))
        group_first = self.actions.preview(group_id=group["id"], action="prefer_wan1", actor="owner")
        sqlite.save_device_group(self.db, "Work", [MAC], group["updated_at"] + 1, group["id"])
        group_second = self.actions.preview(group_id=group["id"], action="prefer_wan1", actor="owner")
        self.assertNotEqual(group_first["fingerprint"], group_second["fingerprint"])

    def test_pause_effect_states_ipv4_scope_and_service_dependent_timed_cleanup(self):
        until_resumed = ActionControl._effect("pause", [], 0)
        timed = ActionControl._effect("pause", [], 3600)
        self.assertIn("IPv4", until_resumed)
        self.assertIn("IPv6 and other paths are not controlled", until_resumed)
        self.assertIn("1 hour", timed)
        self.assertIn("service must be running", timed)

    def test_mixed_reserved_and_unreserved_selection_reviews_one_reservation(self):
        other = "AA-BB-CC-DD-EE-02"
        self.client.forms[("dhcps", "client")].append(
            {"name": "Tablet", "macaddr": other, "ipaddr": "192.168.0.151", "leasetime": "1h"})
        self.client.forms[("dhcps", "reservation")] = [
            {"mac": MAC, "ip": "192.168.0.150", "note": "Work laptop", "enable": "on"}]
        self.router.snap.raw["reservations"] = self.client.forms[("dhcps", "reservation")]
        preview = self.actions.preview(macs=[MAC, other], action="prefer_wan2", actor="owner")
        self.assertEqual(preview["reservation_count"], 1)
        self.assertEqual([member["reservation_needed"] for member in preview["members"]],
                         [False, True])
        self.assertEqual(self.client.writes, [])

    def test_preflight_does_not_make_full_router_status_or_wan_data_look_newer(self):
        preview = self.actions.preview(macs=[MAC], action="prefer_wan1", actor="owner")
        pending = self.actions._pending[preview["token"]]
        checked_at = time.time() - 100
        self.router.snap.checked_at = checked_at
        self.actions._fresh_preflight(pending)
        self.assertEqual(self.router.snap.checked_at, checked_at)

    def test_foreign_actor_cannot_apply_and_consumes_review_token(self):
        preview = self.actions.preview(macs=[MAC], action="prefer_wan1", actor="owner")
        with self.assertRaisesRegex(ControlError, "actor differs"):
            self.actions.apply(preview["token"], "other owner")
        with self.assertRaisesRegex(ControlError, "expired or was already used"):
            self.actions.apply(preview["token"], "owner")
        self.assertEqual(self.client.writes, [])

    def test_malformed_device_and_empty_actor_cannot_create_a_preview(self):
        for kwargs, message in (({"macs": ["not-a-mac"], "actor": "owner"}, "unique, valid devices"),
                                ({"macs": [MAC], "actor": ""}, "actor is required")):
            with self.subTest(kwargs=kwargs):
                with self.assertRaisesRegex(ControlError, message):
                    self.actions.preview(action="prefer_wan1", **kwargs)
        self.assertEqual(self.actions._pending, {})
        self.assertEqual(self.client.writes, [])

    def test_pending_preview_queue_is_bounded(self):
        expiry = time.time() + 60
        self.actions._pending = {f"pending-{i}": {"expires": expiry} for i in range(MAX_PENDING)}
        with self.assertRaisesRegex(ControlError, "Too many pending action previews"):
            self.actions.preview(macs=[MAC], action="prefer_wan1", actor="owner")
        self.assertEqual(len(self.actions._pending), MAX_PENDING)
        self.assertEqual(self.client.writes, [])

    def test_changed_lease_after_review_aborts_before_reservation_write(self):
        preview = self.actions.preview(macs=[MAC], action="prefer_wan1", actor="owner")
        self.client.forms[("dhcps", "client")][0]["ipaddr"] = "192.168.0.151"
        with self.assertRaisesRegex(ControlError, "lease or name changed"):
            self.actions.apply(preview["token"], "owner")
        self.assertEqual(self.client.writes, [])

    def test_management_device_is_rejected_before_automatic_reservation(self):
        with self.assertRaisesRegex(ControlError, "connected management device"):
            self.actions.preview(macs=[MAC], action="prefer_wan1", actor="owner",
                                 management_ip="192.168.0.150")
        self.assertEqual(self.client.writes, [])

    def test_management_path_change_after_review_blocks_reservation_write(self):
        preview = self.actions.preview(macs=[MAC], action="prefer_wan1", actor="owner",
                                       management_ip="192.168.0.180")
        self.client.forms[("dhcps", "client")][0]["ipaddr"] = "192.168.0.180"
        with self.assertRaisesRegex(ControlError, "lease or name changed"):
            self.actions.apply(preview["token"], "owner")
        self.assertEqual(self.client.writes, [])

    def test_expired_pending_previews_are_pruned_on_next_review(self):
        first = self.actions.preview(macs=[MAC], action="prefer_wan1", actor="owner")
        self.actions._pending[first["token"]]["expires"] = 0
        second = self.actions.preview(macs=[MAC], action="prefer_wan1", actor="owner")
        self.assertNotIn(first["token"], self.actions._pending)
        self.assertIn(second["token"], self.actions._pending)

    def test_route_failure_reports_and_keeps_created_reservation(self):
        self.client.fail_add_form = ("policy_route", "policy_route")
        preview = self.actions.preview(macs=[MAC], action="prefer_wan1", actor="owner")
        with self.assertRaisesRegex(ControlError, "reservation.*remain active"):
            self.actions.apply(preview["token"], "owner")
        reservations = self.client.forms[("dhcps", "reservation")]
        self.assertEqual([(r["mac"], r["ip"]) for r in reservations],
                         [(MAC, "192.168.0.150")])

    def test_group_membership_drift_aborts_without_writes(self):
        group = sqlite.save_device_group(self.db, "Work", [MAC], int(time.time()))
        preview = self.actions.preview(group_id=group["id"], action="prefer_wan1", actor="owner")
        sqlite.save_device_group(self.db, "Work", [], int(time.time()) + 1, group["id"])
        with self.assertRaisesRegex(ControlError, "membership changed"):
            self.actions.apply(preview["token"], "owner")
        self.assertEqual(self.client.writes, [])

    def test_group_route_capture_race_discards_new_member_preview(self):
        other = "AA-BB-CC-DD-EE-02"
        self.client.forms[("dhcps", "reservation")] = [
            {"mac": other, "ip": "192.168.0.151", "note": "Tablet", "enable": "on"}]
        self.router.snap.raw["reservations"] = self.client.forms[("dhcps", "reservation")]
        group = sqlite.save_device_group(self.db, "Work", [MAC], int(time.time()))
        preview = self.actions.preview(group_id=group["id"], action="prefer_wan1", actor="owner")
        real_preview_group = self.routes.preview_group
        applied_groups = []
        self.routes.apply_group = lambda token: applied_groups.append(token)

        def preview_after_membership_edit(*args, **kwargs):
            sqlite.save_device_group(self.db, "Work", [MAC, other], int(time.time()) + 1,
                                     group["id"])
            return real_preview_group(*args, **kwargs)

        self.routes.preview_group = preview_after_membership_edit
        with self.assertRaisesRegex(ControlError, "reservation.*remain active"):
            self.actions.apply(preview["token"], "owner")

        self.assertEqual(applied_groups, [])
        self.assertFalse(self.routes._pending_groups)
        self.assertEqual([write[0] for write in self.client.writes], ["add-dhcp-reservation"])
        self.assertEqual(self.client.forms[("policy_route", "policy_route")], [])

    def test_success_is_single_use_and_rejects_unverified_only_mode(self):
        preview = self.actions.preview(macs=[MAC], action="prefer_wan1", actor="owner")
        result = self.actions.apply(preview["token"], "owner")
        self.assertEqual((result["action"], result["count"], len(result["members"])),
                         ("prefer_wan1", 1, 1))
        writes = list(self.client.writes)
        with self.assertRaisesRegex(ControlError, "Strict WAN routing is disabled in config"):
            self.actions.preview(macs=[MAC], action="only_wan1", actor="owner")
        with self.assertRaisesRegex(ControlError, "expired or was already used"):
            self.actions.apply(preview["token"], "owner")
        self.assertEqual(self.client.writes, writes)


if __name__ == "__main__":
    unittest.main()
