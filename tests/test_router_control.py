"""Route control safety checks, including timed expiry and reservation validation."""

from __future__ import annotations

import sqlite3
import tempfile
import threading
import time
import unittest
from copy import deepcopy
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from netpulse.router.control import ControlError, RouterControl, observed_netpulse_route
from netpulse.router.er605 import RouterError
from netpulse.storage import sqlite
from netpulse.storage.sqlite import Storage


MAC = "AA-BB-CC-DD-EE-01"
IP = "192.168.0.50"
ROUTE_NAME = "NP_R_AABBCCDDEE01"
GROUP_NAME = "NP_G_AABBCCDDEE01"


class ObservedNetpulseRoute(unittest.TestCase):
    def test_observes_enabled_disabled_missing_and_ambiguous_rows(self):
        mac = "AA-BB-CC-DD-EE-01"
        raw = {"policy_routes": [{"name": "NP_R_AABBCCDDEE01", "state": "on", "interfaces": "WAN2"}],
               "policy_routes_checked_at": 123}
        self.assertEqual(observed_netpulse_route(raw, mac), {"route": "WAN2", "checked_at": 123})
        self.assertEqual(observed_netpulse_route(raw, mac.replace("-", ":").lower()),
                         {"route": "WAN2", "checked_at": 123})
        raw["policy_routes"][0]["state"] = "off"
        self.assertEqual(observed_netpulse_route(raw, mac)["route"], "AUTO")
        raw["policy_routes"] = []
        self.assertEqual(observed_netpulse_route(raw, mac)["route"], "AUTO")
        raw["policy_routes"] = [
            {"name": "NP_R_AABBCCDDEE01", "state": "on", "interfaces": "WAN1"},
            {"name": "NP_R_AABBCCDDEE01", "state": "on", "interfaces": "WAN2"}]
        self.assertIsNone(observed_netpulse_route(raw, mac)["route"])
        self.assertIsNone(observed_netpulse_route({}, mac)["route"])


def active_row(interface="WAN1"):
    return {
        "name": ROUTE_NAME, "service_type": "all", "src_ipgroup": GROUP_NAME,
        "dst_ipgroup": "IPGROUP_ANY", "interfaces": interface, "timeobj": "Any",
        "mode": "Priority", "comment": "NetPulse", "state": "on", "index": 1,
    }


class FakeClient:
    def __init__(self, route=None, balance=True):
        self.routes = [] if route is None else [route]
        self.balance = balance
        self.session_count = 0
        self.writes = []
        self.stale_readback_once = False
        self.make_stale_after_disable = False

    @contextmanager
    def session(self):
        self.session_count += 1
        yield self

    def get(self, module, form, params=None):
        if (module, form) == ("balance", "balance_basic"):
            return {"balance_state": "on" if self.balance else "off"}
        if (module, form) == ("policy_route", "policy_route"):
            if self.stale_readback_once:
                self.stale_readback_once = False
                return [active_row()]
            return [dict(row) for row in self.routes]
        raise AssertionError(f"unexpected read {module}/{form}")

    def set_row(self, module, form, index, key, old, new):
        self.writes.append((module, form, index, key, dict(old), dict(new)))
        self.routes[index] = dict(new)
        if new.get("state") == "off" and self.make_stale_after_disable:
            self.stale_readback_once = True
            self.make_stale_after_disable = False


class FakeControlClient:
    """Mutable firmware-shaped forms for full RouterControl preview/apply tests."""
    def __init__(self):
        self.forms = {
            ("balance", "balance_basic"): {"balance_state": "on"},
            ("dhcps", "client"): [],
            ("dhcps", "reservation"): [{"mac": MAC, "ip": IP, "enable": "on", "note": "Laptop"}],
            ("dhcps", "lan"): {"ipaddr_start": "192.168.0.100", "ipaddr_end": "192.168.0.199"},
            ("ipgroup", "ipscope_list"): [{"name": "IP_LAN", "scope": "192.168.0.0/24"}],
            ("ipgroup", "ipscope_reservation"): [],
            ("ipgroup", "ipgroup_reservation"): [],
            ("policy_route", "policy_route"): [],
        }
        self.host = "192.168.0.1"
        self.session_count = 0
        self.writes = []
        self.fail_add_form = None
        self.fail_reservation_add = False

    @contextmanager
    def session(self):
        self.session_count += 1
        yield self

    def get(self, module, form, params=None):
        key = (module, form)
        if key not in self.forms:
            raise AssertionError(f"unexpected router form read: {key}")
        return deepcopy(self.forms[key])

    def add_row(self, module, form, rows, new):
        self.writes.append(("add", module, form, deepcopy(new)))
        if self.fail_add_form == (module, form):
            raise RouterError("injected add failure")
        row = deepcopy(new)
        rows.append(row)
        self.forms[(module, form)] = deepcopy(rows)
        return deepcopy(row)

    def set_row(self, module, form, index, key, old, new):
        self.writes.append(("set", module, form, index, key, deepcopy(old), deepcopy(new)))
        row = deepcopy(new)
        self.forms[(module, form)][index] = row
        return deepcopy(row)

    def delete_row(self, module, form, name):
        self.writes.append(("delete", module, form, name))
        self.forms[(module, form)] = [row for row in self.forms[(module, form)]
                                      if row.get("name") != name]

    def add_dhcp_reservation(self, rows, new):
        self.writes.append(("add-dhcp-reservation", deepcopy(new)))
        if self.fail_reservation_add:
            raise RouterError("injected reservation failure")
        row = {**deepcopy(new), "id": "9001", "ip_bind": "on"}
        rows.append(row)
        self.forms[("dhcps", "reservation")] = deepcopy(rows)
        return deepcopy(row)


class TimedRouteExpiry(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = str(Path(self.tmp.name) / "control.db")
        Storage(self.db).close()
        sqlite.set_device_route(self.db, MAC, IP, "WAN1", 100, "owner", "AUTO", "applied",
                                "temporary route", expires_at=1000)
        self.client = FakeClient(active_row())
        now = time.time()
        self.router = SimpleNamespace(client=self.client, poll_seconds=600,
            snap=SimpleNamespace(checked_at=now, uptime_at=now, uptime=1000,
                                 firmware_version="2.3.3 Build 20251029 Rel.18054",
                                 raw={"balance_basic": {"balance_state": "on"}}))
        self.control = RouterControl(self.router, self.db, enabled=True,
                                     kill_switch=str(Path(self.tmp.name) / "disabled"))
        self.control.is_local_device = lambda _mac: False

    def test_failed_acl_recovery_locks_controls_across_controller_restart(self):
        self.assertTrue(self.control.state()["enabled"])
        self.control._firmware_store.set("pi_acl_recovery_failed", "1")
        status = self.control.state()
        self.assertFalse(status["enabled"])
        self.assertTrue(status["acl_recovery_failed"])
        with self.assertRaises(ControlError):
            self.control.preview(MAC, "WAN2", "owner")
        self.assertEqual(self.client.writes, [])
        restarted = RouterControl(self.router, self.db, enabled=True, kill_switch=self.control.kill_switch)
        self.assertFalse(restarted.state()["enabled"])
        self.control._firmware_store.set("pi_acl_recovery_failed", "0")
        self.assertTrue(restarted.state()["enabled"])

    def test_firmware_change_locks_controls_across_restart_until_exact_version_is_reviewed(self):
        initial = self.control.state()
        self.assertTrue(initial["enabled"])
        self.assertEqual(initial["accepted_firmware_version"], "2.3.3 Build 20251029 Rel.18054")

        self.router.snap.firmware_version = "2.4.0 Build 20261001"
        changed = self.control.state()
        self.assertFalse(changed["enabled"])
        self.assertTrue(changed["firmware_review_required"])
        self.assertIn("needs review", changed["reason"])
        self.assertEqual(self.client.writes, [])
        self.assertEqual(self.control.claim_firmware_review_notice(), {
            "version": "2.4.0 Build 20261001",
            "reason": changed["firmware_reason"],
        })
        self.assertIsNone(self.control.claim_firmware_review_notice())

        restarted_control = RouterControl(self.router, self.db, enabled=True,
                                          kill_switch=str(Path(self.tmp.name) / "disabled"))
        self.assertFalse(restarted_control.state()["enabled"])
        self.assertIsNone(restarted_control.claim_firmware_review_notice())
        with self.assertRaisesRegex(ControlError, "version changed"):
            restarted_control.accept_firmware("2.3.3 Build 20251029 Rel.18054", True)
        unlocked = restarted_control.accept_firmware("2.4.0 Build 20261001", True)
        self.assertTrue(unlocked["enabled"])
        self.assertFalse(unlocked["firmware_review_required"])
        self.assertIn("ER605 firmware version reviewed: 2.4.0 Build 20261001",
                      [event["message"] for event in sqlite.recent_events(self.db, 10)])

    def test_missing_firmware_version_locks_without_router_write(self):
        self.router.snap.firmware_version = None
        state = self.control.state()
        self.assertFalse(state["enabled"])
        self.assertTrue(state["firmware_review_required"])
        self.assertIn("could not be read", state["reason"])
        missing_notice = self.control.claim_firmware_review_notice()
        self.assertEqual(missing_notice["version"], None)
        self.assertEqual(missing_notice["reason"], state["firmware_reason"])
        self.assertEqual(self._firmware_notice_marker(), "unavailable")
        self.assertEqual(self.client.writes, [])

    def test_firmware_review_rejects_future_dated_router_sample(self):
        self.router.snap.firmware_version = "2.4.0 Build 20261001"
        self.router.snap.checked_at = time.time() + 3600
        with self.assertRaisesRegex(ControlError, "fresh authenticated firmware read"):
            self.control.accept_firmware("2.4.0 Build 20261001", True)
        self.assertEqual(self._firmware_notice_marker(), None)
        self.assertEqual(self.client.writes, [])

    def _firmware_notice_marker(self):
        return self.control._firmware_store.get("router_firmware_notice")

    def test_expiry_disables_and_reads_back_exact_route_then_audits_auto(self):
        self.assertEqual(self.control.expire_due_routes(now=2000), 1)
        self.assertEqual(self.client.session_count, 1)
        self.assertEqual(len(self.client.writes), 1)
        module, form, index, key, old, new = self.client.writes[0]
        self.assertEqual((module, form, index, key),
                         ("policy_route", "policy_route", 0, "key-0"))
        self.assertEqual((old["state"], new["state"]), ("on", "off"))
        saved = sqlite.device_routes(self.db)[MAC]
        self.assertEqual(saved["route"], "AUTO")
        self.assertIsNone(saved["expires_at"])
        audit = sqlite.router_control_history(self.db)[0]
        self.assertEqual((audit["old_route"], audit["new_route"], audit["result"]),
                         ("WAN1", "AUTO", "applied"))

    def test_changed_wan_is_left_untouched_and_expiry_is_deferred(self):
        self.client.routes = [active_row("WAN2")]
        with self.assertLogs("netpulse.router.control", level="ERROR"):
            self.assertEqual(self.control.expire_due_routes(now=2000), 0)
        self.assertEqual(self.client.writes, [])
        self.assertEqual(sqlite.device_routes(self.db)[MAC]["route"], "WAN1")

    def test_mismatched_readback_restores_the_active_route_and_defers(self):
        self.client.make_stale_after_disable = True
        with self.assertLogs("netpulse.router.control", level="ERROR"):
            self.assertEqual(self.control.expire_due_routes(now=2000), 0)
        self.assertEqual([write[5]["state"] for write in self.client.writes], ["off", "on"])
        self.assertEqual(self.client.routes[0]["state"], "on")
        self.assertEqual(sqlite.device_routes(self.db)[MAC]["route"], "WAN1")
        self.assertEqual(self.control._expiry_retry_after[MAC], 2300)
        history = sqlite.router_control_history(self.db)
        self.assertEqual((history[0]["old_route"], history[0]["new_route"], history[0]["result"]),
                         ("WAN1", "AUTO", "failed"))
        self.assertIn("prior pin may still affect this device", history[0]["detail"])
        self.assertEqual(self.control.drain_expiry_failures(), [{"mac": MAC, "ip": IP, "route": "WAN1"}])
        self.assertEqual(self.control.drain_expiry_failures(), [])

    def test_expiry_reconciles_database_after_router_rule_is_disabled_but_audit_write_fails(self):
        save = sqlite.set_device_route
        attempts = 0

        def locked_once(*args, **kwargs):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise sqlite3.OperationalError("database is locked")
            return save(*args, **kwargs)

        with mock.patch.object(sqlite, "set_device_route", side_effect=locked_once):
            with self.assertLogs("netpulse.router.control", level="ERROR"):
                self.assertEqual(self.control.expire_due_routes(now=2000), 0)
        # The router write/read-back succeeded, while the saved timed preference remains for retry.
        self.assertEqual(self.client.routes[0]["state"], "off")
        self.assertEqual(sqlite.device_routes(self.db)[MAC]["route"], "WAN1")
        self.assertEqual(len(self.client.writes), 1)

        self.control._expiry_retry_after[MAC] = 0
        self.assertEqual(self.control.expire_due_routes(now=2400), 1)
        self.assertEqual(self.client.routes[0]["state"], "off")
        self.assertEqual(sqlite.device_routes(self.db)[MAC]["route"], "AUTO")
        self.assertEqual(len(self.client.writes), 1)

    def test_repeated_expiry_failures_do_not_duplicate_the_initial_audit(self):
        self.client.make_stale_after_disable = True
        with self.assertLogs("netpulse.router.control", level="ERROR"):
            self.control.expire_due_routes(now=2000)
        self.control._expiry_retry_after[MAC] = 0
        self.client.make_stale_after_disable = True
        with self.assertLogs("netpulse.router.control", level="ERROR"):
            self.control.expire_due_routes(now=2400)
        failed = [entry for entry in sqlite.router_control_history(self.db) if entry["result"] == "failed"]
        self.assertEqual(len(failed), 1)

    def test_locked_controls_do_not_log_in_or_change_expired_route(self):
        Path(self.control.kill_switch).touch()
        self.assertEqual(self.control.expire_due_routes(now=2000), 0)
        self.assertEqual(self.client.session_count, 0)
        self.assertEqual(self.client.writes, [])
        self.assertEqual(sqlite.device_routes(self.db)[MAC]["route"], "WAN1")

    def test_router_reboot_settle_guard_defers_expiry_without_login(self):
        self.router.snap.uptime = 10
        self.assertFalse(self.control.state()["enabled"])
        self.assertEqual(self.control.expire_due_routes(now=2000), 0)
        self.assertEqual(self.client.session_count, 0)
        self.assertEqual(self.client.writes, [])
        self.assertEqual(sqlite.device_routes(self.db)[MAC]["route"], "WAN1")

    def test_stale_router_snapshot_defers_expiry_without_login(self):
        self.router.snap.checked_at = time.time() - 2000
        self.assertFalse(self.control.state()["enabled"])
        self.assertEqual(self.control.expire_due_routes(now=2000), 0)
        self.assertEqual(self.client.session_count, 0)
        self.assertEqual(self.client.writes, [])
        self.assertEqual(sqlite.device_routes(self.db)[MAC]["route"], "WAN1")

    def test_wall_clock_jumps_do_not_change_same_boot_monotonic_expiry(self):
        boot_id = "test-boot"
        self.control._boot_id = boot_id
        sqlite.set_device_route(self.db, MAC, IP, "WAN1", 100, "owner", "AUTO", "applied",
                                "temporary route", expires_at=1100,
                                expires_monotonic=2000.0, boot_id=boot_id)
        # Wall clock is six hours ahead, but only 500 real seconds have elapsed.
        self.assertEqual(self.control.expire_due_routes(now=21600, monotonic_now=1500.0), 0)
        self.assertEqual(self.client.session_count, 0)
        self.assertEqual(sqlite.device_routes(self.db)[MAC]["route"], "WAN1")
        # The wall clock then steps backward; monotonic expiry still occurs on time.
        self.assertEqual(self.control.expire_due_routes(now=900, monotonic_now=2000.0), 1)

    def test_timed_route_expired_while_service_was_down_returns_to_auto_after_restart(self):
        wall = int(time.time())
        monotonic = time.monotonic()
        boot = "same-pi-boot"
        sqlite.set_device_route(self.db, MAC, IP, "WAN1", wall, "owner", "AUTO", "applied",
                                "temporary route", expires_at=wall + 30,
                                expires_monotonic=monotonic + 30, boot_id=boot)

        # A fresh controller instance represents systemd restarting NetPulse after an outage.
        resumed = RouterControl(self.router, self.db, enabled=True,
                                kill_switch=str(Path(self.tmp.name) / "disabled"))
        resumed._boot_id = boot
        resumed.is_local_device = lambda _mac: False
        self.assertEqual(resumed.expire_due_routes(now=wall + 31, monotonic_now=monotonic + 31), 1)
        self.assertEqual(self.client.routes[0]["state"], "off")
        self.assertEqual(sqlite.device_routes(self.db)[MAC]["route"], "AUTO")
        self.assertEqual(sqlite.device_routes(self.db)[MAC]["route"], "AUTO")

    def test_live_load_balancing_off_defers_expiry(self):
        self.client.balance = False
        with self.assertLogs("netpulse.router.control", level="ERROR"):
            self.assertEqual(self.control.expire_due_routes(now=2000), 0)
        self.assertEqual(self.client.writes, [])
        self.assertEqual(sqlite.device_routes(self.db)[MAC]["route"], "WAN1")

    def test_missing_router_rule_confirms_auto_without_creating_a_rule(self):
        self.client.routes = []
        self.assertEqual(self.control.expire_due_routes(now=2000), 1)
        self.assertEqual(self.client.writes, [])
        self.assertEqual(sqlite.device_routes(self.db)[MAC]["route"], "AUTO")

    def test_pi_mac_is_never_touched_by_expiry(self):
        self.control.is_local_device = lambda _mac: True
        with self.assertLogs("netpulse.router.control", level="ERROR"):
            self.assertEqual(self.control.expire_due_routes(now=2000), 0)
        self.assertEqual(self.client.session_count, 0)
        self.assertEqual(self.client.writes, [])
        self.assertEqual(sqlite.device_routes(self.db)[MAC]["route"], "WAN1")


class RouteReservationAddressValidation(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.db = str(Path(tmp.name) / "address.db")
        Storage(self.db).close()
        client = SimpleNamespace(host="192.168.0.1")
        router = SimpleNamespace(client=client, poll_seconds=60, snap=SimpleNamespace())
        self.control = RouterControl(router, self.db)
        self.control.is_local_device = lambda _mac: False

    def test_ipv6_reservation_is_rejected_with_control_specific_reason(self):
        reservation = {"mac": MAC, "ip": "fd00::50", "enable": "on"}
        with self.assertRaisesRegex(ControlError, "require an IPv4 reservation"):
            self.control._reservation([], [reservation], MAC)

    def test_private_ipv4_reservation_remains_eligible(self):
        reservation = {"mac": MAC, "ip": IP, "enable": "on"}
        result, address = self.control._reservation([], [reservation], MAC)
        self.assertEqual(result, reservation)
        self.assertEqual(address, IP)


class RouteControlApply(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.db = str(Path(tmp.name) / "apply.db")
        Storage(self.db).close()
        self.client = FakeControlClient()
        now = time.time()
        self.router = SimpleNamespace(client=self.client, api_lock=threading.RLock(), poll_seconds=60,
            snap=SimpleNamespace(checked_at=now, uptime_at=now, uptime=1000,
                firmware_version="2.3.3 Build 20251029 Rel.18054",
                raw={"balance_basic": {"balance_state": "on"},
                     "clients": [],
                     "reservations": deepcopy(self.client.forms[("dhcps", "reservation")]),
                     "policy_routes": [], "policy_routes_checked_at": now}))
        self.control = RouterControl(self.router, self.db, enabled=True,
                                     kill_switch=str(Path(tmp.name) / "disabled"))
        self.control.is_local_device = lambda _mac: False

    def test_route_control_uses_same_lock_as_router_monitor(self):
        self.assertIs(self.control._router_write_lock, self.router.api_lock)

    def test_future_router_sample_locks_controls_and_future_policy_read_blocks_preview(self):
        self.router.snap.checked_at = time.time() + 3600
        self.assertFalse(self.control.state()["enabled"])
        self.assertIn("fresh authenticated ER605 status", self.control.state()["reason"])

        self.router.snap.checked_at = time.time()
        self.router.snap.raw["policy_routes_checked_at"] = time.time() + 3600
        with self.assertRaisesRegex(ControlError, "device route is stale"):
            self.control.preview(MAC, "WAN1", "owner")
        self.assertEqual(self.client.writes, [])

    def test_preview_is_read_only_and_apply_creates_verified_isolated_rule(self):
        self.control._expiry_audited.add(MAC)
        self.control._expiry_retry_after[MAC] = time.time() + 300
        preview = self.control.preview(MAC, "WAN1", "owner")
        self.assertEqual(preview["ip"], IP)
        self.assertEqual(preview["current"], "AUTO")
        self.assertIn("saved on the ER605", preview["effect"])
        self.assertIn("WAN online detection", preview["effect"])
        self.assertIn("stays on the ER605 until changed", preview["effect"])
        self.assertEqual(self.client.writes, [])

        timed = self.control.preview(MAC, "WAN2", "owner", 3600)
        self.assertIn("NetPulse must be running at the timed expiry", timed["effect"])
        self.assertIn("rule remains until NetPulse returns", timed["effect"])

        result = self.control.apply(preview["token"])
        self.assertTrue(result["applied"])
        self.assertEqual(result["route"], "WAN1")
        ip_rows = self.client.forms[("ipgroup", "ipscope_reservation")]
        groups = self.client.forms[("ipgroup", "ipgroup_reservation")]
        routes = self.client.forms[("policy_route", "policy_route")]
        self.assertEqual(ip_rows[0]["scope"], f"{IP}-{IP}")
        self.assertEqual(groups[0]["rule_scope"], [ip_rows[0]["name"]])
        self.assertEqual(routes[0]["src_ipgroup"], GROUP_NAME)
        self.assertEqual((routes[0]["interfaces"], routes[0]["mode"], routes[0]["state"]),
                         ("WAN1", "Priority", "on"))
        self.assertEqual(sqlite.device_routes(self.db)[MAC]["route"], "WAN1")
        self.assertNotIn(MAC, self.control._expiry_audited)
        self.assertNotIn(MAC, self.control._expiry_retry_after)
        audit = sqlite.router_control_history(self.db)[0]
        self.assertEqual((audit["old_route"], audit["new_route"], audit["result"]),
                         ("AUTO", "WAN1", "applied"))

    def test_apply_rechecks_reservation_and_stale_preview_makes_no_write(self):
        preview = self.control.preview(MAC, "WAN2", "owner")
        self.client.forms[("dhcps", "reservation")][0]["ip"] = "192.168.0.51"
        with self.assertRaisesRegex(ControlError, "reservation changed"):
            self.control.apply(preview["token"])
        self.assertEqual(self.client.writes, [])
        self.assertEqual(self.client.forms[("policy_route", "policy_route")], [])

    def test_apply_rejects_saved_route_changed_after_preview_before_router_login(self):
        preview = self.control.preview(MAC, "WAN2", "owner")
        sqlite.set_device_route(self.db, MAC, IP, "WAN1", int(time.time()), "owner",
                                "AUTO", "applied")

        with self.assertRaisesRegex(ControlError, "saved device route changed after preview"):
            self.control.apply(preview["token"])

        self.assertEqual(self.client.session_count, 0)
        self.assertEqual(self.client.writes, [])
        self.assertEqual(self.client.forms[("policy_route", "policy_route")], [])

    def test_preview_reports_live_router_route_and_saved_preference_when_they_differ(self):
        sqlite.set_device_route(self.db, MAC, IP, "WAN1", int(time.time()), "owner",
                                "AUTO", "applied")
        self.client.forms[("policy_route", "policy_route")] = [active_row("WAN2")]
        self.router.snap.raw["policy_routes"] = [active_row("WAN2")]

        preview = self.control.preview(MAC, "WAN1", "owner")

        self.assertEqual(preview["current"], "WAN2")
        self.assertEqual(preview["saved_current"], "WAN1")
        self.assertIn("NetPulse saved preference: WAN1; ER605 currently reports: WAN2", preview["effect"])

    def test_apply_rejects_live_router_route_changed_after_review(self):
        preview = self.control.preview(MAC, "WAN1", "owner")
        self.client.forms[("policy_route", "policy_route")] = [active_row("WAN2")]

        with self.assertRaisesRegex(ControlError, "device route changed after review"):
            self.control.apply(preview["token"])

        self.assertEqual(self.client.writes, [])
        self.assertEqual(self.client.forms[("policy_route", "policy_route")], [active_row("WAN2")])

    def test_auto_confirmation_disables_only_the_existing_netpulse_route(self):
        initial = self.control.preview(MAC, "WAN1", "owner")
        self.control.apply(initial["token"])
        to_auto = self.control.preview(MAC, "AUTO", "owner")
        self.assertEqual(to_auto["current"], "WAN1")
        result = self.control.apply(to_auto["token"])
        row = self.client.forms[("policy_route", "policy_route")][0]
        self.assertEqual(result["route"], "AUTO")
        self.assertEqual(row["name"], ROUTE_NAME)
        self.assertEqual(row["state"], "off")
        self.assertEqual(sqlite.device_routes(self.db)[MAC]["route"], "AUTO")

    def test_failed_rule_creation_cleans_up_new_dependencies(self):
        self.client.fail_add_form = ("policy_route", "policy_route")
        preview = self.control.preview(MAC, "WAN1", "owner")
        with self.assertRaisesRegex(RouterError, "injected add failure"):
            self.control.apply(preview["token"])
        self.assertEqual(self.client.forms[("ipgroup", "ipscope_reservation")], [])
        self.assertEqual(self.client.forms[("ipgroup", "ipgroup_reservation")], [])
        self.assertEqual(self.client.forms[("policy_route", "policy_route")], [])
        audit = sqlite.router_control_history(self.db)[0]
        self.assertEqual((audit["new_route"], audit["result"]), ("WAN1", "failed"))


class ReservationControlApply(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.db = str(Path(tmp.name) / "reservation.db")
        Storage(self.db).close()
        self.client = FakeControlClient()
        self.client.forms[("dhcps", "client")] = [
            {"name": "Office laptop", "macaddr": MAC, "ipaddr": "192.168.0.150", "leasetime": "1h"}
        ]
        self.client.forms[("dhcps", "reservation")] = []
        now = time.time()
        self.router = SimpleNamespace(client=self.client, api_lock=threading.RLock(), poll_seconds=60,
            snap=SimpleNamespace(checked_at=now, uptime_at=now, uptime=1000,
                firmware_version="2.3.3 Build 20251029 Rel.18054",
                raw={"balance_basic": {"balance_state": "on"},
                     "clients": deepcopy(self.client.forms[("dhcps", "client")]),
                     "reservations": [],
                     "lan_scopes": [{"name": "IP_LAN", "scope": "192.168.0.0/24"}],
                     "dhcp_settings": {"ipaddr_start": "192.168.0.100",
                                       "ipaddr_end": "192.168.0.199"}}))
        self.control = RouterControl(self.router, self.db, enabled=True,
                                     kill_switch=str(Path(tmp.name) / "disabled"))
        self.control.is_local_device = lambda _mac: False

    def test_reservation_control_uses_same_lock_as_router_monitor(self):
        self.assertIs(self.control._router_write_lock, self.router.api_lock)

    def test_preview_is_read_only_then_confirm_adds_reservation_with_binding_off(self):
        preview = self.control.preview_reservation(MAC, "Work laptop", "owner")
        self.assertEqual((preview["ip"], preview["device"]), ("192.168.0.150", "Work laptop"))
        self.assertIn("IP-MAC binding stays off", preview["effect"])
        self.assertEqual(self.client.writes, [])

        result = self.control.apply_reservation(preview["token"])
        reservation = self.client.forms[("dhcps", "reservation")][0]
        self.assertTrue(result["applied"])
        self.assertEqual((result["mac"], result["ip"], result["reservation_id"]),
                         (MAC, "192.168.0.150", "9001"))
        self.assertEqual((reservation["enable"], reservation["bind"], reservation["interface"]),
                         ("on", "0", "LAN1"))
        self.assertEqual(reservation["note"], "NetPulse: Work laptop")
        self.assertEqual(self.router.snap.raw["reservations"][0]["bind"], "0")
        self.assertIn("DHCP reservation create", sqlite.events_between(self.db, 0, 2**62, ("router",))[0]["message"])

    def test_changed_lease_after_preview_is_rejected_before_router_write(self):
        preview = self.control.preview_reservation(MAC, "Work laptop", "owner")
        self.client.forms[("dhcps", "client")][0]["ipaddr"] = "192.168.0.151"
        with self.assertRaisesRegex(ControlError, "lease or name changed"):
            self.control.apply_reservation(preview["token"])
        self.assertEqual(self.client.writes, [])
        self.assertEqual(self.client.forms[("dhcps", "reservation")], [])

    def test_non_ipv4_router_scope_or_dhcp_pool_fails_closed_before_login(self):
        for field, value in (
                ("lan_scopes", [{"name": "IP_LAN", "scope": "fd00::/64"}]),
                ("dhcp_settings", {"ipaddr_start": "fd00::100", "ipaddr_end": "fd00::199"})):
            with self.subTest(field=field):
                self.router.snap.raw[field] = value
                with self.assertRaisesRegex(ControlError, "safely read an IPv4 LAN and DHCP pool"):
                    self.control.preview_reservation(MAC, "Work laptop", "owner")
                self.assertEqual(self.client.session_count, 0)
                self.assertEqual(self.client.writes, [])
                self.router.snap.raw[field] = (
                    [{"name": "IP_LAN", "scope": "192.168.0.0/24"}]
                    if field == "lan_scopes" else
                    {"ipaddr_start": "192.168.0.100", "ipaddr_end": "192.168.0.199"})

    def test_invalid_dhcp_pool_bounds_fail_closed_before_login(self):
        for pool in (
                {"ipaddr_start": "192.168.0.180", "ipaddr_end": "192.168.0.100"},
                {"ipaddr_start": "192.168.1.100", "ipaddr_end": "192.168.1.199"},
                {"ipaddr_start": "192.168.0.0", "ipaddr_end": "192.168.0.199"},
                {"ipaddr_start": "192.168.0.100", "ipaddr_end": "192.168.0.255"}):
            with self.subTest(pool=pool):
                self.router.snap.raw["dhcp_settings"] = pool
                with self.assertRaisesRegex(ControlError, "safely read an IPv4 LAN and DHCP pool"):
                    self.control.preview_reservation(MAC, "Work laptop", "owner")
                self.assertEqual(self.client.session_count, 0)
                self.assertEqual(self.client.writes, [])
        self.router.snap.raw["dhcp_settings"] = {"ipaddr_start": "192.168.0.100",
                                                   "ipaddr_end": "192.168.0.199"}

    def test_router_reservation_failure_is_audited_without_claiming_success(self):
        self.client.fail_reservation_add = True
        preview = self.control.preview_reservation(MAC, "Work laptop", "owner")
        with self.assertRaisesRegex(RouterError, "injected reservation failure"):
            self.control.apply_reservation(preview["token"])
        self.assertEqual(self.client.forms[("dhcps", "reservation")], [])
        event = sqlite.events_between(self.db, 0, 2**62, ("router",))[0]["message"]
        self.assertIn("DHCP reservation create for", event)
        self.assertIn("(failed, owner)", event)


if __name__ == "__main__":
    unittest.main()
