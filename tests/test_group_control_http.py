"""Complete group route workflow through RouterControl and the production HTTPS client."""

import tempfile
import time
import unittest
import json
from unittest import mock
from pathlib import Path
from types import SimpleNamespace

from netpulse.router.control import ControlError, RouterControl
from netpulse.router.er605 import ER605Client
from netpulse.router.watch import RouterWatch
from netpulse.storage import sqlite
from netpulse.storage.sqlite import Storage
from tests.fake_er605 import FakeER605, load_fixture


MACS = ("AA-BB-CC-DD-EE-01", "AA-BB-CC-DD-EE-02")
IPS = ("192.168.0.50", "192.168.0.51")


class GroupRouteOverHTTPS(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = str(Path(self.tmp.name) / "group-http.db")
        Storage(self.db).close()
        fixture = load_fixture()
        clients = [{"macaddr": mac, "ipaddr": ip, "name": f"Device {i + 1}"}
                   for i, (mac, ip) in enumerate(zip(MACS, IPS))]
        reservations = [{"id": str(i + 1), "mac": mac, "ip": ip, "note": f"Device {i + 1}",
                         "enable": "on", "bind": "0", "interface": "LAN1"}
                        for i, (mac, ip) in enumerate(zip(MACS, IPS))]
        fixture.update({
            "balance/balance_basic": {"balance_state": "on"},
            "balance/balance_global": {"balance_state": "on"},
            "dhcps/client": clients,
            "dhcps/reservation": reservations,
            "dhcps/lan": {"ipaddr_start": "192.168.0.100", "ipaddr_end": "192.168.0.199"},
            "ipgroup/ipscope_list": [{"name": "IP_LAN", "scope": "192.168.0.0/24"}],
            "ipgroup/ipscope_reservation": [],
            "ipgroup/ipgroup_reservation": [],
            "policy_route/policy_route": [],
        })
        self.fake = FakeER605(fixture=fixture)
        self.addCleanup(self.fake.close)
        client = ER605Client(self.fake.host, "admin", "correct horse", self.fake.fingerprint(), timeout=5)
        now = time.time()
        self.router = RouterWatch(client, {"WAN1": "Example ISP A", "WAN2": "Example ISP B"}, poll_minutes=1)
        self.router.snap.checked_at = now
        self.router.snap.uptime_at = now
        self.router.snap.uptime = 10_000
        self.router.snap.firmware_version = "2.3.3 Build 20251029 Rel.18054"
        self.router.snap.raw = {"balance_basic": {"balance_state": "on"},
                                "clients": clients, "reservations": reservations,
                                "policy_routes": [], "policy_routes_checked_at": now}
        self.control = RouterControl(self.router, self.db, enabled=True,
                                     kill_switch=str(Path(self.tmp.name) / "controls.disabled"))
        self.control.is_local_device = lambda _mac: False
        self.group = sqlite.save_device_group(self.db, "Work", list(MACS), int(now))

    def _expand_to_eight_members(self):
        members = list(MACS) + [f"AA-BB-CC-DD-EE-{i:02X}" for i in range(3, 9)]
        ips = list(IPS) + [f"192.168.0.{50 + i}" for i in range(2, 8)]
        clients = [{"macaddr": mac, "ipaddr": ip, "name": f"Device {i + 1}"}
                   for i, (mac, ip) in enumerate(zip(members, ips))]
        reservations = [{"id": str(i + 1), "mac": mac, "ip": ip, "note": f"Device {i + 1}",
                         "enable": "on", "bind": "0", "interface": "LAN1"}
                        for i, (mac, ip) in enumerate(zip(members, ips))]
        self.fake.fixture["dhcps/client"] = clients
        self.fake.fixture["dhcps/reservation"] = reservations
        self.router.snap.raw.update({"clients": clients, "reservations": reservations})
        self.group = sqlite.save_device_group(self.db, "Work", members, int(time.time()), self.group["id"])
        return members

    def _use_virtual_transaction_clock(self, seconds_per_mutation=12):
        start = time.time()
        current = [start]
        calls = []
        self.fake.boot = start - 10_000
        original_public_info = self.router.client.public_info

        def tracked_public_info():
            calls.append(current[0])
            return original_public_info()

        self.router.client.public_info = tracked_public_info
        original_route = self.fake._route

        def advance_after_mutation(path, headers, form):
            result = original_route(path, headers, form)
            try:
                body = json.loads(form.get("data", ["{}"])[0])
            except (TypeError, ValueError):
                body = {}
            if body.get("method") in {"add", "set", "delete"}:
                current[0] += seconds_per_mutation
            return result

        self.fake._route = advance_after_mutation
        status_calls = []
        original_status_refresh = self.router.refresh_control_status

        def tracked_status_refresh(*args, **kwargs):
            status_calls.append(current[0])
            return original_status_refresh(*args, **kwargs)

        self.router.refresh_control_status = tracked_status_refresh
        return start, current, calls, status_calls

    def test_group_preview_and_apply_create_verified_isolated_rules_for_each_member(self):
        preview = self.control.preview_group(self.group["id"], "WAN1", "telegram owner")
        self.assertEqual([m["mac"] for m in preview["members"]], list(MACS))
        self.assertEqual(self.fake.requests, [])  # preview uses the latest read-only scan

        result = self.control.apply_group(preview["token"])

        self.assertEqual((result["applied"], result["count"], result["route"]), (True, 2, "WAN1"))
        self.assertEqual({mac: row["route"] for mac, row in sqlite.device_routes(self.db).items()},
                         {MACS[0]: "WAN1", MACS[1]: "WAN1"})
        for i, mac in enumerate(MACS):
            suffix = mac.replace("-", "")
            ip_row = next(r for r in self.fake.fixture["ipgroup/ipscope_reservation"]
                          if r["name"] == f"NP_I_{suffix}")
            group_row = next(r for r in self.fake.fixture["ipgroup/ipgroup_reservation"]
                             if r["name"] == f"NP_G_{suffix}")
            route_row = next(r for r in self.fake.fixture["policy_route/policy_route"]
                             if r["name"] == f"NP_R_{suffix}")
            self.assertEqual(ip_row["scope"], f"{IPS[i]}-{IPS[i]}")
            self.assertEqual(group_row["rule_scope"], [f"NP_I_{suffix}"])
            self.assertEqual((route_row["src_ipgroup"], route_row["interfaces"], route_row["state"]),
                             (f"NP_G_{suffix}", "WAN1", "on"))
        audit = sqlite.device_group_history(self.db)[0]
        self.assertEqual((audit["route"], audit["result"], audit["count"]), ("WAN1", "applied", 2))
        self.assertEqual(self.fake.logouts, 2)

    def test_second_member_failure_cleans_partial_objects_and_rolls_back_first_member(self):
        self.fake.fail_mutation = ("policy_route/policy_route", "add", 2)
        preview = self.control.preview_group(self.group["id"], "WAN1", "dashboard")

        with self.assertRaisesRegex(ControlError, "restored and verified"):
            self.control.apply_group(preview["token"])

        routes = self.fake.fixture["policy_route/policy_route"]
        self.assertEqual(len(routes), 1)
        self.assertEqual((routes[0]["name"], routes[0]["state"]),
                         (f"NP_R_{MACS[0].replace('-', '')}", "off"))
        self.assertEqual([r["name"] for r in self.fake.fixture["ipgroup/ipscope_reservation"]],
                         [f"NP_I_{MACS[0].replace('-', '')}"])
        self.assertEqual([r["name"] for r in self.fake.fixture["ipgroup/ipgroup_reservation"]],
                         [f"NP_G_{MACS[0].replace('-', '')}"])
        self.assertEqual(sqlite.device_routes(self.db)[MACS[0]]["route"], "AUTO")
        self.assertNotIn(MACS[1], sqlite.device_routes(self.db))
        audit = sqlite.device_group_history(self.db)[0]
        self.assertEqual((audit["result"], audit["count"]), ("failed", 2))

    def test_long_group_apply_refreshes_uptime_between_members(self):
        members = self._expand_to_eight_members()
        preview = self.control.preview_group(self.group["id"], "WAN1", "dashboard")
        start, current, uptime_calls, status_calls = self._use_virtual_transaction_clock(18)

        with mock.patch("time.time", side_effect=lambda: current[0]):
            result = self.control.apply_group(preview["token"])

        elapsed = current[0] - start
        self.assertGreater(elapsed, 120)
        self.assertLess(elapsed, 1200, "the configured authenticated status sample remains within its existing gate")
        self.assertGreaterEqual(len(uptime_calls), len(members) + 1)
        self.assertGreaterEqual(len(status_calls), 1, "an authenticated status refresh protects the existing freshness gate")
        self.assertLessEqual(current[0] - self.router.snap.checked_at, 300)
        self.assertEqual((result["applied"], result["count"]), (True, len(members)))
        self.assertEqual({row["route"] for row in sqlite.device_routes(self.db).values()}, {"WAN1"})

    def test_long_group_rollback_refreshes_uptime_until_all_prior_members_are_restored(self):
        members = self._expand_to_eight_members()
        self.fake.fail_mutation = ("ipgroup/ipscope_reservation", "add", 7)
        preview = self.control.preview_group(self.group["id"], "WAN1", "dashboard")
        start, current, uptime_calls, status_calls = self._use_virtual_transaction_clock(18)

        with mock.patch("time.time", side_effect=lambda: current[0]):
            with self.assertRaisesRegex(ControlError, "restored and verified"):
                self.control.apply_group(preview["token"])

        elapsed = current[0] - start
        self.assertGreater(elapsed, 300)
        self.assertLess(elapsed, 1200)
        self.assertGreaterEqual(len(uptime_calls), len(members) + 1)
        self.assertGreaterEqual(len(status_calls), 1)
        route_rows = self.fake.fixture["policy_route/policy_route"]
        self.assertEqual(len(route_rows), 6)
        self.assertTrue(all(row["state"] == "off" for row in route_rows))
        self.assertEqual(len(sqlite.device_routes(self.db)), 6)

    def test_group_apply_fails_closed_on_reboot_invalid_uptime_and_kill_switch(self):
        preview = self.control.preview_group(self.group["id"], "WAN1", "dashboard")
        self.router.client.public_info = lambda: {"uptime": 100}
        with self.assertRaisesRegex(ControlError, "controls were locked"):
            self.control.apply_group(preview["token"])
        self.assertEqual(self.fake.requests, [])

        self.router.snap.uptime = 10_000
        self.router.client.public_info = lambda: {"uptime": 10_000}
        self.assertTrue(self.router.refresh_uptime())
        preview = self.control.preview_group(self.group["id"], "WAN1", "dashboard")
        self.router.client.public_info = lambda: {"uptime": "unknown"}
        with self.assertRaisesRegex(ControlError, "fresh ER605 uptime"):
            self.control.apply_group(preview["token"])
        self.assertEqual(self.fake.requests, [])

        self.router.client.public_info = lambda: {"uptime": 10_001}
        self.assertTrue(self.router.refresh_uptime())
        preview = self.control.preview_group(self.group["id"], "WAN1", "dashboard")
        Path(self.control.kill_switch).touch()
        with self.assertRaisesRegex(ControlError, "controls were locked"):
            self.control.apply_group(preview["token"])
        self.assertEqual(self.fake.requests, [])

    def test_outer_group_review_still_expires_after_its_existing_120_second_ttl(self):
        preview = self.control.preview_group(self.group["id"], "WAN1", "dashboard")
        expired_now = time.time() + 121

        with mock.patch("time.time", return_value=expired_now):
            with self.assertRaisesRegex(ControlError, "expired or was already used"):
                self.control.apply_group(preview["token"])

        self.assertEqual(self.fake.requests, [])

    def test_uptime_refresh_defers_reboot_events_to_the_main_tick(self):
        self.router.snap.uptime = 10_000
        self.router._uptime_mono = 100.0
        self.router._next_full = time.time() + 1000
        self.router.client.public_info = lambda: {"uptime": 900}

        self.assertTrue(self.router.refresh_uptime(now=1000.0, mono=200.0))
        self.assertIsNone(self.router.snap.checked_at)
        self.assertFalse(self.control.state()["enabled"],
                         "a reboot invalidates the prior authenticated status and firmware sample")
        events = self.router.tick(1001.0, mono=201.0)

        self.assertTrue(any("Router restarted" in event.message for event in events))

    def test_authenticated_refresh_respects_pause_and_login_backoff(self):
        self.router.pause(60)
        before = len(self.fake.requests)

        self.assertFalse(self.router.refresh_control_status())
        self.assertEqual(len(self.fake.requests), before)

        self.router.resume()
        self.router.client._password = "incorrect password"
        now = time.time()
        self.assertFalse(self.router.refresh_control_status(now=now))
        failed_logins = self.fake.failed_logins
        self.assertEqual(failed_logins, 1)
        self.assertGreater(self.router._login_blocked_until, now)

        self.assertFalse(self.router.refresh_control_status(now=now + 10))
        self.assertEqual(self.fake.failed_logins, failed_logins,
                         "a queued refresh must not retry while auth backoff is active")

    def test_timed_group_override_gives_every_member_an_expiry(self):
        started = int(time.time())
        preview = self.control.preview_group(self.group["id"], "WAN2", "telegram owner", 3600)
        self.assertIn("if the Pi is offline", preview["effect"])
        self.assertIn("until NetPulse returns", preview["effect"])
        result = self.control.apply_group(preview["token"])
        saved = sqlite.device_routes(self.db)
        self.assertEqual(result["expiry_label"], "1 hour")
        self.assertEqual({saved[mac]["route"] for mac in MACS}, {"WAN2"})
        expiries = [saved[mac]["expires_at"] for mac in MACS]
        self.assertTrue(all(started + 3600 <= expiry <= started + 3605 for expiry in expiries))
        self.assertLessEqual(max(expiries) - min(expiries), 5)

    def test_smart_routing_requires_eligible_matching_readback_without_writing(self):
        result = self.control.set_group_smart_routing(self.group["id"], True)
        self.assertTrue(result["enabled"])
        self.assertEqual(result["members"], 2)
        self.assertEqual(self.fake.requests, [])
        saved = sqlite.device_groups(self.db)[0]
        self.assertTrue(saved["smart_routing_enabled"])
        self.assertIsNotNone(saved["smart_enabled_at"])

    def test_smart_route_uses_verified_group_transaction_and_persists_cooldown(self):
        self.control.set_group_smart_routing(self.group["id"], True)
        result = self.control.apply_smart_group_route(self.group["id"], "WAN1", int(time.time()))
        self.assertTrue(result["applied"])
        self.assertEqual(result["count"], 2)
        self.assertEqual({row["route"] for row in sqlite.device_routes(self.db).values()}, {"WAN1"})
        saved_group = sqlite.device_groups(self.db)[0]
        self.assertTrue(saved_group["smart_routing_enabled"])
        self.assertIsNotNone(saved_group["smart_last_action_at"])
        with self.assertRaisesRegex(ControlError, "15-minute"):
            self.control.apply_smart_group_route(self.group["id"], "WAN2", int(time.time()) + 1)

    def test_smart_route_does_not_start_while_router_checks_are_paused(self):
        self.control.set_group_smart_routing(self.group["id"], True)
        self.router.pause(60)
        requests_before = list(self.fake.requests)

        result = self.control.apply_smart_group_route(
            self.group["id"], "WAN1", int(time.time()))

        self.assertFalse(result["applied"])
        self.assertIn("paused", result["detail"])
        self.assertTrue(sqlite.device_groups(self.db)[0]["smart_routing_enabled"])
        self.assertEqual(sqlite.device_routes(self.db), {})
        self.assertEqual(self.fake.requests, requests_before)

    def test_manual_group_override_disables_smart_routing(self):
        self.control.set_group_smart_routing(self.group["id"], True)
        preview = self.control.preview_group(self.group["id"], "WAN2", "dashboard")
        self.control.apply_group(preview["token"])
        self.assertFalse(sqlite.device_groups(self.db)[0]["smart_routing_enabled"])


if __name__ == "__main__":
    unittest.main()
