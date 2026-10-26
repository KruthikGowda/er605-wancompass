"""Strict ER605 Only-mode route tests use firmware-shaped synthetic state only."""
from __future__ import annotations

import tempfile
import threading
import time
import unittest
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

from netpulse.router.control import (ControlError, RouterControl, observed_netpulse_route)
from netpulse.router.actions import ActionControl
from netpulse.router.er605 import RouterError
from netpulse.storage import sqlite
from netpulse.storage.sqlite import Storage
from tests.test_router_control import FakeControlClient, MAC, IP, GROUP_NAME

MAC_B = "AA-BB-CC-DD-EE-02"
IP_B = "192.168.0.51"
STRICT_FIRMWARE = "2.3.3 Build 20251029 Rel.18054"


class FailSecondWanUpdate(FakeControlClient):
    fail_name = None

    def set_row(self, module, form, index, key, old, new):
        if ((module, form) == ("policy_route", "policy_route") and self.fail_name
                and self.forms[(module, form)][index].get("name") == self.fail_name
                and new.get("interfaces") == "WAN2"):
            raise RouterError("injected second member route failure")
        return super().set_row(module, form, index, key, old, new)


class FailSecondAndStrictRestore(FailSecondWanUpdate):
    def set_row(self, module, form, index, key, old, new):
        if ((module, form) == ("policy_route", "policy_route")
                and new.get("mode") == "Only" and new.get("interfaces") == "WAN1"):
            raise RouterError("injected strict rollback failure")
        return super().set_row(module, form, index, key, old, new)


class StrictWanControls(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.db = str(Path(temp.name) / "strict.db")
        Storage(self.db).close()
        self.client = FakeControlClient()
        now = time.time()
        self.router = SimpleNamespace(client=self.client, api_lock=threading.RLock(), poll_seconds=60,
            snap=SimpleNamespace(checked_at=now, uptime_at=now, uptime=1000,
                firmware_version=STRICT_FIRMWARE,
                raw={"balance_basic": {"balance_state": "on"}, "clients": [],
                     "reservations": deepcopy(self.client.forms[("dhcps", "reservation")]),
                     "policy_routes": [], "policy_routes_checked_at": now}))
        self.control = RouterControl(self.router, self.db, enabled=True,
            kill_switch=str(Path(temp.name) / "disabled"), strict_wan_enabled=True)
        self.control.is_local_device = lambda _mac: False
        self.control._refresh_transaction_uptime = lambda: None

    def test_only_mode_is_distinct_and_unknown_modes_are_not_inferred(self):
        raw = {"policy_routes": [{"name": "NP_R_AABBCCDDEE01", "state": "on",
                                  "interfaces": "WAN1", "mode": "Only"}]}
        self.assertEqual(observed_netpulse_route(raw, MAC)["route"], "WAN1_ONLY")
        raw["policy_routes"][0]["mode"] = "Unrecognized"
        self.assertIsNone(observed_netpulse_route(raw, MAC)["route"])
        raw["policy_routes"][0].pop("mode")
        self.assertIsNone(observed_netpulse_route(raw, MAC)["route"])

    def test_default_off_or_unreviewed_firmware_rejects_strict_preview(self):
        self.control.strict_wan_enabled = False
        self.assertFalse(self.control.state()["strict_wan_available"])
        with self.assertRaisesRegex(ControlError, "disabled in config"):
            self.control.preview(MAC, "WAN1_ONLY", "owner")
        self.assertEqual(self.client.writes, [])

        self.control.strict_wan_enabled = True
        self.router.snap.firmware_version = "2.4.0 Build 20261001"
        self.assertFalse(self.control.state()["enabled"])
        with self.assertRaises(ControlError):
            self.control.preview(MAC, "WAN1_ONLY", "owner")
        self.assertEqual(self.client.writes, [])

    def test_stale_and_unknown_route_modes_never_preview_as_priority(self):
        self.router.snap.raw["policy_routes"] = [{"name": "NP_R_AABBCCDDEE01", "state": "on",
            "interfaces": "WAN1", "mode": "Only"}]
        self.router.snap.raw["policy_routes_checked_at"] = time.time() - 301
        with self.assertRaisesRegex(ControlError, "device route is stale"):
            self.control.preview(MAC, "WAN2", "owner")
        self.router.snap.raw["policy_routes_checked_at"] = time.time()
        self.router.snap.raw["policy_routes"][0]["mode"] = "Unknown"
        with self.assertRaisesRegex(ControlError, "could not be read"):
            self.control.preview(MAC, "WAN2", "owner")
        self.assertEqual(self.client.writes, [])

    def test_only_preview_warns_no_fallback_and_apply_reads_back_exact_mode(self):
        preview = self.control.preview(MAC, "WAN1_ONLY", "owner", 3600)
        self.assertIn("no WAN fallback", preview["effect"])
        self.assertIn("no IPv4 Internet through this router", preview["effect"])
        self.assertIn("IPv6 and other paths are not controlled", preview["effect"])
        self.assertEqual(self.client.writes, [])
        result = self.control.apply(preview["token"])
        row = self.client.forms[("policy_route", "policy_route")][0]
        self.assertEqual(result["route"], "WAN1_ONLY")
        self.assertEqual((row["interfaces"], row["mode"], row["state"]), ("WAN1", "Only", "on"))
        self.assertEqual(sqlite.device_routes(self.db)[MAC]["route"], "WAN1_ONLY")
        self.assertIsNotNone(sqlite.device_routes(self.db)[MAC]["expires_at"])

    def test_wrong_mode_readback_is_failed_not_saved_as_preference(self):
        class WrongModeClient(FakeControlClient):
            def add_row(self, module, form, rows, new):
                if (module, form) == ("policy_route", "policy_route"):
                    new = dict(new, mode="Priority")
                return super().add_row(module, form, rows, new)

        self.client = WrongModeClient()
        self.router.client = self.client
        self.control.client = self.client
        self.router.snap.raw["reservations"] = deepcopy(self.client.forms[("dhcps", "reservation")])
        preview = self.control.preview(MAC, "WAN1_ONLY", "owner")
        with self.assertRaisesRegex(RouterError, "requested WAN route mode"):
            self.control.apply(preview["token"])
        self.assertEqual(sqlite.device_routes(self.db), {})
        self.assertEqual(self.client.forms[("policy_route", "policy_route")], [])

    def test_timed_strict_route_expires_to_auto_even_if_feature_flag_is_off(self):
        self.client.forms[("policy_route", "policy_route")] = [{
            "name": "NP_R_AABBCCDDEE01", "src_ipgroup": GROUP_NAME, "dst_ipgroup": "IPGROUP_ANY",
            "interfaces": "WAN2", "mode": "Only", "state": "on", "index": 1}]
        now = int(time.time())
        sqlite.set_device_route(self.db, MAC, IP, "WAN2_ONLY", now - 100, "owner", "AUTO", "applied",
                                "strict timed route", expires_at=now - 1,
                                expires_monotonic=time.monotonic() - 1, boot_id=self.control._boot_id)
        raw = dict(self.router.snap.raw, policy_routes=deepcopy(self.client.forms[("policy_route", "policy_route")]),
                   policy_routes_checked_at=time.time())
        self.router.snap.raw = raw
        self.control.strict_wan_enabled = False
        self.assertEqual(self.control.expire_due_routes(now=now, monotonic_now=time.monotonic()), 1)
        self.assertEqual(self.client.forms[("policy_route", "policy_route")][0]["state"], "off")
        self.assertEqual(sqlite.device_routes(self.db)[MAC]["route"], "AUTO")

    def test_group_rollback_restores_strict_mode_and_original_expiry(self):
        temp_client = FailSecondWanUpdate()
        now = time.time()
        reservations = [
            {"mac": MAC, "ip": IP, "enable": "on", "note": "Laptop"},
            {"mac": MAC_B, "ip": IP_B, "enable": "on", "note": "Phone"},
        ]
        temp_client.forms[("dhcps", "reservation")] = deepcopy(reservations)
        routes = []
        for mac, ip, index in ((MAC, IP, 1), (MAC_B, IP_B, 2)):
            suffix = mac.replace("-", "")
            routes.append({"name": f"NP_R_{suffix}", "src_ipgroup": f"NP_G_{suffix}",
                           "dst_ipgroup": "IPGROUP_ANY", "interfaces": "WAN1", "mode": "Only",
                           "state": "on", "index": index})
        temp_client.forms[("policy_route", "policy_route")] = deepcopy(routes)
        temp_client.fail_name = f"NP_R_{MAC_B.replace('-', '')}"
        self.router.client = temp_client
        self.control.client = temp_client
        self.router.snap.raw.update({"reservations": deepcopy(reservations), "policy_routes": deepcopy(routes),
                                     "policy_routes_checked_at": now})
        wall, mono = int(now) + 1800, time.monotonic() + 1800
        for mac, ip in ((MAC, IP), (MAC_B, IP_B)):
            sqlite.set_device_route(self.db, mac, ip, "WAN1_ONLY", int(now), "owner", "AUTO", "applied",
                                    "strict timed", expires_at=wall, expires_monotonic=mono,
                                    boot_id=self.control._boot_id)
        group = sqlite.save_device_group(self.db, "Work", [MAC, MAC_B], int(now))
        preview = self.control.preview_group(group["id"], "WAN2", "owner")
        with self.assertRaisesRegex(ControlError, "restored and verified"):
            self.control.apply_group(preview["token"])
        self.assertTrue(all(r["mode"] == "Only" and r["interfaces"] == "WAN1"
                            for r in temp_client.forms[("policy_route", "policy_route")]))
        saved = sqlite.device_routes(self.db)
        self.assertEqual({saved[m]["route"] for m in (MAC, MAC_B)}, {"WAN1_ONLY"})
        self.assertEqual(saved[MAC]["expires_at"], wall)
        self.assertEqual(saved[MAC]["expires_monotonic"], mono)

    def test_group_partial_rollback_failure_is_reported_without_claiming_restore(self):
        temp_client = FailSecondAndStrictRestore()
        now = time.time()
        reservations = [
            {"mac": MAC, "ip": IP, "enable": "on", "note": "Laptop"},
            {"mac": MAC_B, "ip": IP_B, "enable": "on", "note": "Phone"},
        ]
        temp_client.forms[("dhcps", "reservation")] = deepcopy(reservations)
        rows = []
        for mac, index in ((MAC, 1), (MAC_B, 2)):
            suffix = mac.replace("-", "")
            rows.append({"name": f"NP_R_{suffix}", "src_ipgroup": f"NP_G_{suffix}",
                         "dst_ipgroup": "IPGROUP_ANY", "interfaces": "WAN1", "mode": "Only",
                         "state": "on", "index": index})
        temp_client.forms[("policy_route", "policy_route")] = deepcopy(rows)
        temp_client.fail_name = f"NP_R_{MAC_B.replace('-', '')}"
        self.router.client = temp_client
        self.control.client = temp_client
        self.router.snap.raw.update({"reservations": deepcopy(reservations), "policy_routes": deepcopy(rows),
                                     "policy_routes_checked_at": now})
        for mac, ip in ((MAC, IP), (MAC_B, IP_B)):
            sqlite.set_device_route(self.db, mac, ip, "WAN1_ONLY", int(now), "owner", "AUTO", "applied")
        group = sqlite.save_device_group(self.db, "Work", [MAC, MAC_B], int(now))
        preview = self.control.preview_group(group["id"], "WAN2", "owner")
        with self.assertRaisesRegex(ControlError, "Rollback failed for"):
            self.control.apply_group(preview["token"])
        current = {row["name"]: (row["interfaces"], row["mode"])
                   for row in temp_client.forms[("policy_route", "policy_route")]}
        self.assertEqual(current[f"NP_R_{MAC.replace('-', '')}"], ("WAN2", "Priority"))
        self.assertEqual(current[f"NP_R_{MAC_B.replace('-', '')}"], ("WAN1", "Only"))

    def test_multi_device_action_restores_original_strict_routes_and_expiry(self):
        temp_client = FailSecondWanUpdate()
        now = time.time()
        reservations = [
            {"mac": MAC, "ip": IP, "enable": "on", "note": "Laptop"},
            {"mac": MAC_B, "ip": IP_B, "enable": "on", "note": "Phone"},
        ]
        rows = []
        for mac, index in ((MAC, 1), (MAC_B, 2)):
            suffix = mac.replace("-", "")
            rows.append({"name": f"NP_R_{suffix}", "src_ipgroup": f"NP_G_{suffix}",
                         "dst_ipgroup": "IPGROUP_ANY", "interfaces": "WAN1", "mode": "Only",
                         "state": "on", "index": index})
        temp_client.forms[("dhcps", "reservation")] = deepcopy(reservations)
        temp_client.forms[("policy_route", "policy_route")] = deepcopy(rows)
        temp_client.fail_name = f"NP_R_{MAC_B.replace('-', '')}"
        self.router.client = temp_client
        self.control.client = temp_client
        self.router.snap.raw.update({"reservations": deepcopy(reservations), "policy_routes": deepcopy(rows),
                                     "policy_routes_checked_at": now})
        wall, mono = int(now) + 1200, time.monotonic() + 1200
        for mac, ip in ((MAC, IP), (MAC_B, IP_B)):
            sqlite.set_device_route(self.db, mac, ip, "WAN1_ONLY", int(now), "owner", "AUTO", "applied",
                                    "strict timed", expires_at=wall, expires_monotonic=mono,
                                    boot_id=self.control._boot_id)
        actions = ActionControl(self.control)
        preview = actions.preview(macs=[MAC, MAC_B], action="prefer_wan2", actor="owner")
        with self.assertRaisesRegex(ControlError, "completed device routes were restored and verified"):
            actions.apply(preview["token"], "owner")
        self.assertTrue(all(row["mode"] == "Only" and row["interfaces"] == "WAN1"
                            for row in temp_client.forms[("policy_route", "policy_route")]))
        saved = sqlite.device_routes(self.db)
        self.assertEqual({saved[m]["route"] for m in (MAC, MAC_B)}, {"WAN1_ONLY"})
        self.assertEqual(saved[MAC]["expires_at"], wall)
        self.assertEqual(saved[MAC]["expires_monotonic"], mono)

    def test_strict_route_prevents_smart_group_enablement(self):
        group = sqlite.save_device_group(self.db, "Work", [MAC], int(time.time()))
        sqlite.set_device_route(self.db, MAC, IP, "WAN1_ONLY", int(time.time()), "owner", "AUTO", "applied")
        with self.assertRaisesRegex(ControlError, "Restore every strict Only route"):
            self.control.set_group_smart_routing(group["id"], True)

    def test_smart_recommendation_cannot_replace_an_existing_strict_route(self):
        group = sqlite.save_device_group(self.db, "Work", [MAC], int(time.time()))
        sqlite.set_device_route(self.db, MAC, IP, "WAN1_ONLY", int(time.time()), "owner", "AUTO", "applied")
        sqlite.set_group_smart_routing(self.db, group["id"], True)
        with self.assertRaisesRegex(ControlError, "Smart routing is paused while this group"):
            self.control.apply_smart_group_route(group["id"], "WAN2")


if __name__ == "__main__":
    unittest.main()
