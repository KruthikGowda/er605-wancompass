"""Staged pause controller tests; all router calls use an in-memory fake."""
from __future__ import annotations

import tempfile
import time
import unittest
import sqlite3
from contextlib import contextmanager
from types import SimpleNamespace

from netpulse.router.control import ControlError
from netpulse.router.pause import FIRMWARE, PauseControl
from netpulse.router.er605 import valid_pause_acl_row
from netpulse.storage import sqlite

MAC = "AA-BB-CC-DD-EE-01"
IP = "192.168.0.135"


def rule(mac=MAC):
    from secrets import token_hex
    return {"name": "NP_PAUSE_" + token_hex(16).upper(), "policy": "DROP", "service": "ALL",
            "iptype": "ipv4", "zone": "LAN", "is_src": "ipgroup",
            "src": "NP_G_" + mac.replace("-", ""), "is_dst": "ipgroup",
            "dest": "IPGROUP_ANY", "time": "Any",
            "states": ["new", "established", "related", "invalid"],
            "position": "", "flag": "1", "user": "1"}


class FakeClient:
    host = "192.168.0.1"

    def __init__(self):
        self.calls = 0
        self.active_sessions = 0
        self.acls = []
        self.mismatch_add = False
        self.clients = [{"macaddr": MAC, "ipaddr": IP, "hostname": "Test handset"}]
        self.reservations = [{"mac": MAC, "ip": IP, "enable": "on"}]
        self.ipscopes = [{"name": "NP_I_AABBCCDDEE01", "type": "range", "scope": f"{IP}-{IP}"}]
        self.ipgroups = [{"name": "NP_G_AABBCCDDEE01", "rule_scope": ["NP_I_AABBCCDDEE01"]}]
        self.after_add = None
        self.after_delete = None

    @contextmanager
    def session(self):
        self.calls += 1
        self.active_sessions += 1
        try:
            yield self
        finally:
            self.active_sessions -= 1

    def get(self, module, form):
        if (module, form) == ("dhcps", "client"):
            return list(self.clients)
        if (module, form) == ("dhcps", "reservation"):
            return list(self.reservations)
        if (module, form) == ("ipgroup", "ipscope_reservation"):
            return list(self.ipscopes)
        if (module, form) == ("ipgroup", "ipgroup_reservation"):
            return list(self.ipgroups)
        if (module, form) == ("ipgroup", "ipscope_list"):
            return [{"name": "IP_LAN", "scope": "192.168.0.0/24"}]
        raise AssertionError((module, form))

    def read_pause_acl_rows(self):
        return [dict(r) for r in self.acls]

    def add_pause_acl_rule(self, rows, new):
        self.acls.append(dict(new))
        if self.mismatch_add:
            self.acls[-1]["policy"] = "ACCEPT"
        result = dict(new)
        result["zone"] = ["LAN"]
        result.pop("position")
        if self.mismatch_add:
            result["policy"] = "ACCEPT"
        if self.after_add:
            self.after_add()
        return result

    def delete_pause_acl_rule(self, name, expected):
        matches = [r for r in self.acls if r.get("name") == name]
        if len(matches) != 1 or not PauseControl._same_rule(matches[0], expected):
            raise RuntimeError("changed or ambiguous")
        self.acls = [r for r in self.acls if r.get("name") != name]
        if self.after_delete:
            self.after_delete()


class FakeRouteControl:
    def __init__(self, client, firmware=FIRMWARE, checked_at=None):
        self.client = client
        self.router = SimpleNamespace(client=client, poll_seconds=60,
            snap=SimpleNamespace(checked_at=time.time() if checked_at is None else checked_at,
                                 firmware_version=firmware, raw={"ok": True}))
        self._router_write_lock = __import__("threading").RLock()
        self.kill_switch = ""
        self.fail_refresh = False
        self.refreshes = 0

    @staticmethod
    def is_local_device(_mac):
        return False

    @staticmethod
    def _client_mac(row):
        from netpulse.devices.identity import normalize_mac
        return normalize_mac(row.get("macaddr", row.get("mac", "")))

    @staticmethod
    def local_device_macs():
        return set()

    def state(self):
        return {"enabled": True, "reason": ""}

    def _refresh_transaction_uptime(self):
        self.refreshes += 1
        if self.client.active_sessions:
            raise AssertionError("uptime refresh must run outside the active router session")
        if self.fail_refresh:
            raise ControlError("fresh uptime unavailable")


class PauseControlTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = self.temp.name + "/state.sqlite"
        self.client = FakeClient()
        self.routes = FakeRouteControl(self.client)
        self.routes.kill_switch = self.path + ".disabled"
        self.control = PauseControl(self.routes, self.path, enabled=True)

    def tearDown(self):
        self.temp.cleanup()

    def test_pause_preview_confirm_and_resume_after_disabled(self):
        preview = self.control.preview(MAC, actor="owner", duration_seconds=900)
        result = self.control.apply(preview["token"], actor="owner")
        self.assertTrue(result["applied"])
        self.assertEqual(result["results"][0]["status"], "paused")
        self.assertEqual(len(self.control.records()), 1)
        self.assertTrue(valid_pause_acl_row(self.client.acls[0]))

        self.control.enabled = False
        resume = self.control.preview(MAC, action="resume", actor="owner")
        result = self.control.apply(resume["token"], actor="owner")
        self.assertEqual(result["results"][0]["status"], "resumed")
        self.assertEqual(self.control.records(), [])
        self.assertEqual(self.client.acls, [])

    def test_saved_pause_cleanup_does_not_require_current_lease_or_ip_objects(self):
        preview = self.control.preview(MAC, actor="owner")
        self.control.apply(preview["token"], actor="owner")
        saved = self.control.store.get(MAC)
        self.control.store.put(dict(saved, status="error"))
        self.client.clients = []
        self.client.reservations = []
        self.client.ipscopes = []
        self.client.ipgroups = []
        self.control.enabled = False
        resume = self.control.preview(MAC, action="resume", actor="owner")
        self.assertEqual(resume["members"][0]["ip"], IP)
        result = self.control.apply(resume["token"], actor="owner")
        self.assertTrue(result["applied"])
        self.assertEqual(self.control.records(), [])
        self.assertEqual(self.client.acls, [])

    def test_disabled_and_unsupported_firmware_never_reach_router(self):
        self.control.enabled = False
        with self.assertRaises(ControlError):
            self.control.preview(MAC)
        self.assertEqual(self.client.calls, 0)
        self.control.enabled = True
        self.routes.router.snap.firmware_version = "unknown"
        with self.assertRaises(ControlError):
            self.control.preview(MAC)
        self.assertEqual(self.client.calls, 0)

    def test_token_is_single_use_and_actor_bound(self):
        p = self.control.preview(MAC, actor="Alice")
        with self.assertRaises(ControlError):
            self.control.apply(p["token"], actor="Bob")
        with self.assertRaises(ControlError):
            self.control.apply(p["token"], actor="Alice")
        self.assertEqual(self.client.acls, [])

    def test_two_previews_cannot_overwrite_or_remove_first_pause(self):
        first = self.control.preview(MAC, actor="owner")
        second = self.control.preview(MAC, actor="owner")
        self.control.apply(first["token"], actor="owner")
        saved = self.control.store.get(MAC)
        rows = self.client.read_pause_acl_rows()
        with self.assertRaisesRegex(ControlError, "appeared after review"):
            self.control.apply(second["token"], actor="owner")
        self.assertEqual(self.control.store.get(MAC), saved)
        self.assertEqual(self.client.read_pause_acl_rows(), rows)

    def test_unknown_route_safety_state_fails_closed(self):
        self.routes.state = lambda: None
        self.assertFalse(self.control.state()["cleanup_enabled"])
        with self.assertRaises(ControlError):
            self.control.preview(MAC)
        self.assertEqual(self.client.calls, 0)

    def test_expiry_rejects_invalid_clock_values(self):
        for value in (True, "123", float("nan"), float("inf")):
            self.assertEqual(self.control.expire_due(now=value), 0)

    def test_uptime_refresh_failure_blocks_pause_acl_add(self):
        self.routes.fail_refresh = True
        preview = self.control.preview(MAC)
        with self.assertRaises(ControlError):
            self.control.apply(preview["token"])
        self.assertEqual(self.routes.refreshes, 1)
        self.assertEqual(self.client.acls, [])
        self.assertEqual(self.control.records(), [])

    def test_uptime_refresh_failure_blocks_expiry_delete_and_keeps_intent(self):
        preview = self.control.preview(MAC, duration_seconds=900)
        self.control.apply(preview["token"])
        self.routes.fail_refresh = True
        self.routes.refreshes = 0
        rec = self.control.records()[0]
        rec["expires_at"] = int(time.time()) + 10
        rec["boot_id"] = "another-boot"
        rec["expires_monotonic"] = time.monotonic() + 1000
        self.control.store.put(rec)
        self.assertEqual(self.control.expire_due(now=rec["expires_at"] + 1), 0)
        self.assertEqual(self.routes.refreshes, 1)
        self.assertEqual(len(self.client.acls), 1)
        self.assertEqual(self.control.store.get(MAC)["status"], "error")

    def test_protected_management_and_ambiguous_candidate_are_rejected(self):
        self.control.protected_macs.add(MAC)
        with self.assertRaises(ControlError):
            self.control.preview(MAC)
        self.control.protected_macs.clear()
        with self.assertRaises(ControlError):
            self.control.preview(MAC, management_ip=IP)
        self.client.get = lambda module, form: (FakeClient.get(self.client, module, form) * 2
            if (module, form) == ("dhcps", "client") else FakeClient.get(self.client, module, form))
        with self.assertRaises(ControlError):
            self.control.preview(MAC)

    def test_mismatched_add_readback_keeps_error_intent(self):
        self.client.mismatch_add = True
        preview = self.control.preview(MAC)
        with self.assertRaises(Exception):
            self.control.apply(preview["token"])
        records = self.control.records()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["status"], "error")

    def test_stale_router_snapshot_blocks_reads(self):
        self.routes.router.snap.checked_at = time.time() - 999
        with self.assertRaises(ControlError):
            self.control.preview(MAC)
        self.assertEqual(self.client.calls, 0)

    def test_router_lock_protects_saved_cleanup_when_route_control_is_not_ready(self):
        self.routes.state = lambda: {"enabled": False, "reason": "router recovery lock"}
        self.assertFalse(self.control.state()["cleanup_enabled"])
        with self.assertRaises(ControlError):
            self.control.preview(MAC)
        self.assertEqual(self.client.calls, 0)

    def test_current_pi_lease_does_not_make_another_household_device_ineligible(self):
        pi_mac = "AA-BB-CC-DD-EE-99"
        self.routes.local_device_macs = lambda: {pi_mac}
        self.client.clients.append({"macaddr": pi_mac, "ipaddr": "192.168.0.157", "hostname": "NetPulse Pi"})
        self.assertEqual(self.control.preview(MAC)["ip"], IP)

    def test_group_membership_change_rolls_back_completed_pause(self):
        second = "AA-BB-CC-DD-EE-02"
        second_ip = "192.168.0.136"
        db = sqlite3.connect(self.path)
        db.executescript(sqlite.SCHEMA)
        db.close()
        group = sqlite.save_device_group(self.path, "Family", [MAC, second], int(time.time()))
        self.client.clients.append({"macaddr": second, "ipaddr": second_ip, "hostname": "Second handset"})
        self.client.reservations.append({"mac": second, "ip": second_ip, "enable": "on"})
        self.client.ipscopes.append({"name": "NP_I_AABBCCDDEE02", "type": "range", "scope": f"{second_ip}-{second_ip}"})
        self.client.ipgroups.append({"name": "NP_G_AABBCCDDEE02", "rule_scope": ["NP_I_AABBCCDDEE02"]})
        preview = self.control.preview_group(group["id"], "pause", "owner", 3600)
        self.client.after_add = lambda: sqlite.save_device_group(self.path, "Family", [MAC],
                                                                  int(time.time()), group["id"])
        with self.assertRaisesRegex(ControlError, "Group membership changed"):
            self.control.apply(preview["token"], "owner")
        self.assertEqual(self.client.acls, [])
        self.assertEqual(self.control.records(), [])

    def test_group_resume_rollback_restores_exact_prior_deadline_and_rule(self):
        second = "AA-BB-CC-DD-EE-02"
        second_ip = "192.168.0.136"
        db = sqlite3.connect(self.path)
        db.executescript(sqlite.SCHEMA)
        db.close()
        group = sqlite.save_device_group(self.path, "Family", [MAC, second], int(time.time()))
        self.client.clients.append({"macaddr": second, "ipaddr": second_ip, "hostname": "Second handset"})
        self.client.reservations.append({"mac": second, "ip": second_ip, "enable": "on"})
        self.client.ipscopes.append({"name": "NP_I_AABBCCDDEE02", "type": "range", "scope": f"{second_ip}-{second_ip}"})
        self.client.ipgroups.append({"name": "NP_G_AABBCCDDEE02", "rule_scope": ["NP_I_AABBCCDDEE02"]})
        pause = self.control.preview_group(group["id"], "pause", "owner", 3600)
        self.control.apply(pause["token"], "owner")
        prior = self.control.store.get(MAC)
        original_acl = next(r.copy() for r in self.client.acls if r["src"] == "NP_G_AABBCCDDEE01")

        resume = self.control.preview_group(group["id"], "resume", "owner")
        self.client.after_delete = lambda: sqlite.save_device_group(self.path, "Family", [MAC],
                                                                      int(time.time()), group["id"])
        with self.assertRaisesRegex(ControlError, "Group membership changed"):
            self.control.apply(resume["token"], "owner")
        restored = self.control.store.get(MAC)
        self.assertEqual(restored, prior)
        self.assertIn(original_acl, self.client.acls)

    def test_expiry_uses_epoch_after_restart_and_never_deletes_changed_rule(self):
        p = self.control.preview(MAC, duration_seconds=900)
        self.control.apply(p["token"])
        rec = self.control.records()[0]
        rec["expires_at"] = int(time.time()) + 10
        rec["boot_id"] = "another-boot"
        rec["expires_monotonic"] = time.monotonic() + 1000
        self.control.store.put(rec)
        self.assertEqual(self.control.expire_due(now=rec["expires_at"] + 1), 1)
        self.assertEqual(self.control.records(), [])

        p = self.control.preview(MAC, duration_seconds=900)
        self.control.apply(p["token"])
        rec = self.control.records()[0]
        rec["expires_at"] = int(time.time()) + 10
        rec["boot_id"] = "another-boot"
        rec["expires_monotonic"] = time.monotonic() + 1000
        self.control.store.put(rec)
        self.client.acls[0]["policy"] = "ACCEPT"
        self.assertEqual(self.control.expire_due(now=rec["expires_at"] + 1), 0)
        self.assertEqual(len(self.client.acls), 1)
        self.assertEqual(len(self.control.drain_failures()), 1)
        self.assertEqual(self.control.drain_failures(), [])


if __name__ == "__main__":
    unittest.main()
