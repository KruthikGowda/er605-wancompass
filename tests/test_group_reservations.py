"""Reviewed batch DHCP reservation workflow for named device groups."""

from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
import tempfile
import threading
import time
import unittest
from unittest import mock
from pathlib import Path
from types import SimpleNamespace

from netpulse.router.control import ControlError, RouterControl
from netpulse.router.er605 import RouterError
from netpulse.storage import sqlite
from netpulse.storage.sqlite import Storage


MACS = ("AA-BB-CC-DD-EE-01", "AA-BB-CC-DD-EE-02", "AA-BB-CC-DD-EE-03")
IPS = ("192.168.0.150", "192.168.0.151", "192.168.0.152")


class FakeReservationClient:
    def __init__(self, clients, reservations):
        self.forms = {
            ("balance", "balance_basic"): {"balance_state": "on"},
            ("dhcps", "client"): deepcopy(clients),
            ("dhcps", "reservation"): deepcopy(reservations),
            ("dhcps", "lan"): {"ipaddr_start": "192.168.0.100", "ipaddr_end": "192.168.0.199"},
            ("ipgroup", "ipscope_list"): [{"name": "IP_LAN", "scope": "192.168.0.0/24"}],
        }
        self.host = "192.168.0.1"
        self.writes = []
        self.reservation_write_count = 0
        self.fail_on_write = None

    @contextmanager
    def session(self):
        yield self

    def get(self, module, form, params=None):
        return deepcopy(self.forms[(module, form)])

    def add_dhcp_reservation(self, rows, new):
        self.reservation_write_count += 1
        self.writes.append(deepcopy(new))
        if self.reservation_write_count == self.fail_on_write:
            raise RouterError("simulated reservation write failure")
        row = {**deepcopy(new), "id": str(9000 + self.reservation_write_count)}
        rows.append(row)
        self.forms[("dhcps", "reservation")] = deepcopy(rows)
        return deepcopy(row)


class GroupReservations(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = str(Path(self.tmp.name) / "group-reservations.db")
        Storage(self.db).close()
        now = time.time()
        clients = [{"macaddr": mac, "ipaddr": ip, "name": f"Phone {i + 1}"}
                   for i, (mac, ip) in enumerate(zip(MACS, IPS))]
        reservations = [{"id": "1", "mac": MACS[0], "ip": IPS[0],
                         "enable": "on", "bind": "0", "note": "Phone 1"}]
        self.client = FakeReservationClient(clients, reservations)
        self.router = SimpleNamespace(
            client=self.client, api_lock=threading.RLock(), poll_seconds=60,
            snap=SimpleNamespace(checked_at=now, uptime_at=now, uptime=1000,
                firmware_version="2.3.3 Build 20251029 Rel.18054",
                raw={"balance_basic": {"balance_state": "on"}, "clients": clients,
                     "reservations": reservations,
                     "lan_scopes": [{"name": "IP_LAN", "scope": "192.168.0.0/24"}],
                     "dhcp_settings": {"ipaddr_start": "192.168.0.100",
                                       "ipaddr_end": "192.168.0.199"}}),
        )
        self.router.refresh_uptime = lambda: setattr(self.router.snap, "uptime_at", time.time()) or True
        self.control = RouterControl(self.router, self.db, enabled=True,
                                     kill_switch=str(Path(self.tmp.name) / "controls.disabled"))
        self.control.is_local_device = lambda _mac: False
        self.group = sqlite.save_device_group(self.db, "Example Work Group", list(MACS), int(now))
        for i, mac in enumerate(MACS):
            sqlite.set_device_label(self.db, mac, f"Phone {i + 1}")

    def test_preview_lists_existing_and_new_reservations_without_router_writes(self):
        preview = self.control.preview_group_reservations(self.group["id"])

        self.assertEqual(preview["group"], "Example Work Group")
        self.assertEqual(preview["count"], 2)
        self.assertEqual([(row["mac"], row["ip"], row["status"]) for row in preview["members"]], [
            (MACS[0], IPS[0], "already reserved"),
            (MACS[1], IPS[1], "will be reserved"),
            (MACS[2], IPS[2], "will be reserved"),
        ])
        self.assertTrue(preview["token"])
        self.assertEqual(self.client.writes, [])
        self.assertEqual(len(self.control._pending_reservations), 2)

    def test_group_preview_uses_router_hostname_without_local_label_and_keeps_override(self):
        sqlite.set_device_label(self.db, MACS[1], "")
        sqlite.set_device_label(self.db, MACS[2], "Media room display")
        clients = self.client.forms[("dhcps", "client")]
        clients[1]["name"] = "ER605 client hostname"
        clients[2]["name"] = "Router device name"
        self.client.forms[("dhcps", "client")] = deepcopy(clients)
        self.router.snap.raw["clients"] = deepcopy(clients)

        preview = self.control.preview_group_reservations(self.group["id"])

        self.assertEqual(preview["members"][1]["name"], "ER605 client hostname")
        self.assertEqual(preview["members"][2]["name"], "Media room display")
        self.assertEqual(self.client.writes, [])

        self.control.apply_group_reservations(preview["token"])

        self.assertEqual([row["note"] for row in self.client.writes], [
            "NetPulse: ER605 client hostname", "NetPulse: Media room display",
        ])

    def test_long_group_reservation_batch_renews_only_internal_member_previews(self):
        preview = self.control.preview_group_reservations(self.group["id"])
        start = time.time()
        current = [start]
        refresh_calls = []
        last_refresh = [start]

        def refresh_uptime():
            refresh_calls.append(current[0])
            self.router.snap.uptime += int(current[0] - last_refresh[0])
            last_refresh[0] = current[0]
            self.router.snap.uptime_at = current[0]
            return True

        self.router.refresh_uptime = refresh_uptime
        add_reservation = self.client.add_dhcp_reservation

        def slow_add(rows, new):
            result = add_reservation(rows, new)
            current[0] += 65
            return result

        self.client.add_dhcp_reservation = slow_add
        with mock.patch("time.time", side_effect=lambda: current[0]):
            result = self.control.apply_group_reservations(preview["token"])

        self.assertGreater(current[0] - start, 120)
        self.assertEqual(result["count"], 2)
        self.assertGreaterEqual(len(refresh_calls), 3)
        self.assertEqual([row["mac"] for row in self.client.writes], list(MACS[1:]))

    def test_group_reservation_batch_rejects_changed_lease_or_name_before_current_write(self):
        for change in ("ip", "name"):
            with self.subTest(change=change):
                if change == "name":
                    sqlite.set_device_label(self.db, MACS[1], "")
                preview = self.control.preview_group_reservations(self.group["id"])
                original = deepcopy(self.router.snap.raw["clients"])
                if change == "ip":
                    self.router.snap.raw["clients"][1]["ipaddr"] = "192.168.0.177"
                else:
                    self.router.snap.raw["clients"][1]["name"] = "New router name"
                write_count = len(self.client.writes)
                with self.assertRaisesRegex(ControlError, "Stopped after 0 of 2 new reservations"):
                    self.control.apply_group_reservations(preview["token"])
                self.assertEqual(len(self.client.writes), write_count)
                self.router.snap.raw["clients"] = original
                if change == "name":
                    sqlite.set_device_label(self.db, MACS[1], "Phone 2")

    def test_colon_form_router_macs_keep_two_same_model_phones_distinct(self):
        clients = self.client.forms[("dhcps", "client")]
        for row in clients[:2]:
            row["macaddr"] = row["macaddr"].replace("-", ":").lower()
            row["name"] = "Example phone"
        reservations = self.client.forms[("dhcps", "reservation")]
        reservations[0]["mac"] = reservations[0]["mac"].replace("-", ":").lower()
        self.client.forms[("dhcps", "client")] = deepcopy(clients)
        self.client.forms[("dhcps", "reservation")] = deepcopy(reservations)
        self.router.snap.raw["clients"] = deepcopy(clients)
        self.router.snap.raw["reservations"] = deepcopy(reservations)

        preview = self.control.preview_group_reservations(self.group["id"])

        self.assertEqual([(row["mac"], row["status"]) for row in preview["members"]], [
            (MACS[0], "already reserved"),
            (MACS[1], "will be reserved"),
            (MACS[2], "will be reserved"),
        ])
        result = self.control.apply_group_reservations(preview["token"])
        self.assertEqual(result["count"], 2)
        self.assertEqual([row["mac"] for row in self.client.writes], list(MACS[1:]))
        self.assertEqual(len(set(row["mac"] for row in self.client.writes)), 2)

    def test_confirm_adds_and_verifies_only_missing_reservations(self):
        preview = self.control.preview_group_reservations(self.group["id"])

        result = self.control.apply_group_reservations(preview["token"])

        self.assertEqual((result["applied"], result["group"], result["count"]),
                         (True, "Example Work Group", 2))
        rows = self.client.forms[("dhcps", "reservation")]
        self.assertEqual([row["mac"] for row in rows], list(MACS))
        self.assertTrue(all(row["enable"] == "on" and row["bind"] == "0" for row in rows))
        self.assertEqual(len(self.client.writes), 2)
        self.assertIn("No WAN routes were changed", result["detail"])

    def test_membership_change_invalidates_batch_before_any_write(self):
        preview = self.control.preview_group_reservations(self.group["id"])
        sqlite.save_device_group(self.db, "Example Work Group", [MACS[0]], int(time.time()), self.group["id"])

        with self.assertRaisesRegex(ControlError, "membership changed"):
            self.control.apply_group_reservations(preview["token"])

        self.assertEqual(self.client.writes, [])
        self.assertEqual(self.control._pending_reservations, {})

    def test_partial_failure_stops_and_keeps_verified_reservations(self):
        preview = self.control.preview_group_reservations(self.group["id"])
        self.client.fail_on_write = 2

        with self.assertRaisesRegex(ControlError, "Stopped after 1 of 2 new reservations") as raised:
            self.control.apply_group_reservations(preview["token"])

        rows = self.client.forms[("dhcps", "reservation")]
        self.assertEqual([row["mac"] for row in rows], [MACS[0], MACS[1]])
        self.assertIn("Phone 2 at 192.168.0.151", str(raised.exception))
        self.assertEqual(self.control._pending_reservations, {})
        self.assertEqual(len(self.client.writes), 2)

    def test_disabled_reservation_is_flagged_without_blocking_other_members(self):
        self.router.snap.raw["reservations"].append({
            "id": "2", "mac": MACS[1], "ip": IPS[1], "enable": "off", "note": "old",
        })

        preview = self.control.preview_group_reservations(self.group["id"])

        self.assertEqual(preview["count"], 1)
        self.assertEqual(preview["skipped"], 1)
        self.assertEqual(preview["members"][1]["status"],
                         "needs attention · disabled or duplicate reservation in Omada")
        self.assertEqual(self.client.writes, [])
        result = self.control.apply_group_reservations(preview["token"])
        self.assertEqual(result["count"], 1)
        self.assertEqual([row["mac"] for row in self.client.writes], [MACS[2]])

    def test_unlisted_member_is_reported_while_listed_members_remain_reservable(self):
        self.router.snap.raw["clients"] = self.router.snap.raw["clients"][:2]

        preview = self.control.preview_group_reservations(self.group["id"])

        self.assertEqual(preview["count"], 1)
        self.assertEqual(preview["skipped"], 1)
        self.assertEqual([(row["mac"], row["ip"], row["status"]) for row in preview["members"]], [
            (MACS[0], IPS[0], "already reserved"),
            (MACS[1], IPS[1], "will be reserved"),
            (MACS[2], "", "not currently listed in the ER605 DHCP clients"),
        ])
        self.assertIn("must appear in the ER605 DHCP client list first", preview["effect"])
        self.assertEqual(self.client.writes, [])
        self.assertEqual(len(self.control._pending_reservations), 1)

        result = self.control.apply_group_reservations(preview["token"])

        self.assertEqual(result["count"], 1)
        self.assertEqual([row["mac"] for row in self.client.writes], [MACS[1]])

    def test_group_preview_reports_all_unlisted_members_without_a_write_token(self):
        self.router.snap.raw["clients"] = []

        preview = self.control.preview_group_reservations(self.group["id"])

        self.assertEqual(preview["count"], 0)
        self.assertEqual(preview["skipped"], 2)
        self.assertEqual(preview["token"], "")
        self.assertEqual([row["status"] for row in preview["members"]], [
            "already reserved",
            "not currently listed in the ER605 DHCP clients",
            "not currently listed in the ER605 DHCP clients",
        ])
        self.assertEqual(self.client.writes, [])

    def test_all_reserved_group_returns_no_apply_token(self):
        rows = self.client.forms[("dhcps", "reservation")]
        for mac, ip in zip(MACS[1:], IPS[1:]):
            rows.append({"id": str(len(rows) + 1), "mac": mac, "ip": ip,
                         "enable": "on", "bind": "0", "note": "Reserved"})
        self.client.forms[("dhcps", "reservation")] = deepcopy(rows)
        self.router.snap.raw["reservations"] = deepcopy(rows)

        preview = self.control.preview_group_reservations(self.group["id"])

        self.assertEqual(preview["count"], 0)
        self.assertEqual(preview["token"], "")
        self.assertEqual(self.client.writes, [])


if __name__ == "__main__":
    unittest.main()
