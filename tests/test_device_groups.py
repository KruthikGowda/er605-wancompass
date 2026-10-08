import tempfile
import unittest
import http.client
import json
import time
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from netpulse.router.control import ControlError, RouterControl
from netpulse.storage import sqlite
from netpulse.storage.sqlite import Storage
from netpulse.web import app as web
from tests.harness import Scenario, local


class GroupRouteActions(unittest.TestCase):
    A = "AA-BB-CC-DD-EE-01"
    B = "AA-BB-CC-DD-EE-02"

    def _preview(self, mac, route, actor, expiry_seconds=0):
        self.serial += 1
        token = f"t{self.serial}"
        self.previews[token] = (mac, route)
        return {"token": token, "ip": "192.168.0.10" if mac == self.A else "192.168.0.11",
                "current": self.live[mac], "observed_current": self.live[mac],
                "saved_current": sqlite.device_routes(self.db).get(mac, {}).get("route", "AUTO")}

    def _apply(self, token):
        mac, route = self.previews.pop(token)
        if mac == self.fail_mac and route == "WAN1":
            raise ControlError("simulated router write failure")
        if mac == self.fail_rollback_mac and route == "WAN2":
            raise ControlError("simulated group rollback failure")
        old = sqlite.device_routes(self.db).get(mac, {}).get("route", "AUTO")
        sqlite.set_device_route(self.db, mac, "192.168.0.10" if mac == self.A else "192.168.0.11",
                                route, 200, "test", old, "applied")
        self.live[mac] = route
        self.router.snap.raw["policy_routes"] = self._policy_routes()
        self.router.snap.raw["policy_routes_checked_at"] = time.time()
        if self.change_group_after_first_apply and mac == self.A and route == "WAN1":
            self.change_group_after_first_apply = False
            sqlite.save_device_group(self.db, "Work", [self.A], 101, self.group["id"])
        if self.fail_after_write_mac == mac and route == "WAN1":
            raise ControlError("simulated failure after member write")
        return {"applied": True}

    def _policy_routes(self):
        return [{"name": f"NP_R_{mac.replace('-', '')}", "state": "on", "interfaces": route}
                for mac, route in self.live.items() if route in ("WAN1", "WAN2")]

    def setUp(self):
        super().setUp()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = str(Path(self.tmp.name) / "groups.db")
        Storage(self.db).close()
        self.group = sqlite.save_device_group(self.db, "Work", [self.A, self.B], 100)
        sqlite.set_device_route(self.db, self.A, "192.168.0.10", "AUTO", 100, "test", "AUTO", "applied")
        sqlite.set_device_route(self.db, self.B, "192.168.0.11", "WAN2", 100, "test", "AUTO", "applied")
        checked_at = time.time()
        self.router = SimpleNamespace(
            client=None,
            poll_seconds=60,
            refresh_uptime=lambda: True,
            refresh_control_status=lambda: True,
            snap=SimpleNamespace(raw={"policy_routes": [],
                                      "policy_routes_checked_at": checked_at},
                                 checked_at=checked_at,
                                 uptime_at=checked_at,
                                 uptime=10_000))
        self.control = RouterControl(self.router, self.db)
        self.control.state = lambda: {"enabled": True}
        self.control._cached_device = lambda mac: ({"note": mac},
            "192.168.0.10" if mac == self.A else "192.168.0.11")
        self.live = {self.A: "AUTO", self.B: "WAN2"}
        self.router.snap.raw["policy_routes"] = self._policy_routes()
        self.serial = 0
        self.fail_mac = None
        self.fail_after_write_mac = None
        self.fail_rollback_mac = None
        self.change_group_after_first_apply = False
        self.previews = {}
        self.control.preview = self._preview
        self.control.apply = self._apply

    def test_preview_lists_every_member_and_exact_prior_routes(self):
        preview = self.control.preview_group(self.group["id"], "WAN1", "dashboard", 3600)
        self.assertEqual(preview["group"], "Work")
        self.assertEqual([m["mac"] for m in preview["members"]], [self.A, self.B])
        self.assertEqual([m["current"] for m in preview["members"]], ["AUTO", "WAN2"])
        self.assertEqual(preview["expiry_label"], "1 hour")

    def test_preview_includes_each_members_saved_route_expiry(self):
        expiry = 5000
        sqlite.set_device_route(self.db, self.B, "192.168.0.11", "WAN2", 200,
                                "test", "AUTO", "applied", expires_at=expiry)
        preview = self.control.preview_group(self.group["id"], "WAN1", "dashboard")
        self.assertIsNone(preview["members"][0]["current_expires_at"])
        self.assertEqual(preview["members"][1]["current_expires_at"], expiry)

    def test_success_applies_all_member_preferences(self):
        preview = self.control.preview_group(self.group["id"], "WAN1", "dashboard")
        result = self.control.apply_group(preview["token"])
        self.assertTrue(result["applied"])
        self.assertEqual(result["count"], 2)
        self.assertEqual({mac: row["route"] for mac, row in sqlite.device_routes(self.db).items()},
                         {self.A: "WAN1", self.B: "WAN1"})
        self.assertEqual(sqlite.device_group_history(self.db)[0]["result"], "applied")

    def test_member_failure_rolls_back_prior_members(self):
        self.fail_mac = self.B
        preview = self.control.preview_group(self.group["id"], "WAN1", "dashboard")
        with self.assertRaisesRegex(ControlError, "restored and verified"):
            self.control.apply_group(preview["token"])
        routes = sqlite.device_routes(self.db)
        self.assertEqual(routes[self.A]["route"], "AUTO")
        self.assertEqual(routes[self.B]["route"], "WAN2")
        self.assertEqual(sqlite.device_group_history(self.db)[0]["result"], "failed")

    def test_member_not_restored_by_its_own_failure_is_identified_in_group_error(self):
        self.fail_after_write_mac = self.B
        self.fail_rollback_mac = self.B
        preview = self.control.preview_group(self.group["id"], "WAN1", "dashboard")
        with self.assertLogs("netpulse.router.control", level="ERROR"):
            with self.assertRaises(ControlError) as raised:
                self.control.apply_group(preview["token"])
        self.assertIn("Rollback failed", str(raised.exception))
        self.assertIn(self.B, str(raised.exception))
        self.assertIn("observed WAN1", str(raised.exception))
        self.assertEqual(self.live, {self.A: "AUTO", self.B: "WAN1"})
        self.assertEqual(sqlite.device_groups(self.db)[0]["members"], [self.A, self.B])

    def test_group_retries_a_failed_member_rollback_and_restores_all_prior_routes(self):
        self.fail_after_write_mac = self.B
        preview = self.control.preview_group(self.group["id"], "WAN1", "dashboard")
        with self.assertRaisesRegex(ControlError, "failed member and previously changed members were restored"):
            self.control.apply_group(preview["token"])
        self.assertEqual(self.live, {self.A: "AUTO", self.B: "WAN2"})
        self.assertEqual({mac: row["route"] for mac, row in sqlite.device_routes(self.db).items()},
                         {self.A: "AUTO", self.B: "WAN2"})

    def test_changed_membership_invalidates_preview(self):
        preview = self.control.preview_group(self.group["id"], "WAN1", "dashboard")
        sqlite.save_device_group(self.db, "Work", [self.A], 101, self.group["id"])
        with self.assertRaisesRegex(ControlError, "membership changed"):
            self.control.apply_group(preview["token"])

    def test_membership_change_mid_apply_rolls_back_completed_members(self):
        preview = self.control.preview_group(self.group["id"], "WAN1", "dashboard")
        self.change_group_after_first_apply = True
        with self.assertRaisesRegex(ControlError, "restored and verified"):
            self.control.apply_group(preview["token"])
        routes = sqlite.device_routes(self.db)
        self.assertEqual(routes[self.A]["route"], "AUTO")
        self.assertEqual(routes[self.B]["route"], "WAN2")
        self.assertEqual(self.live, {self.A: "AUTO", self.B: "WAN2"})
        self.assertEqual(self.control._pending, {})
        self.assertEqual(sqlite.device_group_history(self.db)[0]["result"], "failed")

    def test_unroutable_member_blocks_entire_preview(self):
        self.control._cached_device = lambda mac: (_ for _ in ()).throw(ControlError("needs reservation")) if mac == self.B else ({}, "192.168.0.10")
        with self.assertRaisesRegex(ControlError, "reservation"):
            self.control.preview_group(self.group["id"], "WAN1", "dashboard")
        self.assertEqual(self.control._pending_groups, {})

    def test_stale_router_policy_read_blocks_group_preview(self):
        self.router.snap.raw["policy_routes_checked_at"] = time.time() - 301

        with self.assertRaisesRegex(ControlError, "current device route is stale"):
            self.control.preview_group(self.group["id"], "WAN1", "dashboard")

        self.assertEqual(self.control._pending_groups, {})

    def test_future_router_policy_read_blocks_group_preview(self):
        self.router.snap.raw["policy_routes_checked_at"] = time.time() + 3600

        with self.assertRaisesRegex(ControlError, "current device route is stale"):
            self.control.preview_group(self.group["id"], "WAN1", "dashboard")

        self.assertEqual(self.control._pending_groups, {})


class GroupApi(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = str(Path(self.tmp.name) / "api.db")
        Storage(self.db).close()
        self.board = web.StatusBoard()
        self.server = web.start("127.0.0.1", 0, self.board, self.db)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.host, self.port = self.server.server_address

    def request(self, method, path, body=None):
        conn = http.client.HTTPConnection(self.host, self.port, timeout=5)
        headers = {"Origin": f"http://{self.host}:{self.port}"}
        data = None
        if body is not None:
            data = json.dumps(body)
            headers["Content-Type"] = "application/json"
        conn.request(method, path, body=data, headers=headers)
        response = conn.getresponse()
        result = response.status, json.loads(response.read() or b"{}")
        conn.close()
        return result

    def test_group_crud_and_single_group_membership_constraint(self):
        a = "AA-BB-CC-DD-EE-01"
        b = "AA-BB-CC-DD-EE-02"
        status, group = self.request("POST", "/api/device-groups/save", {"name": "Work", "members": [a, b]})
        self.assertEqual(status, 200)
        self.assertEqual(group["members"], [a, b])
        self.assertEqual(self.request("POST", "/api/device-groups/save", {"name": "Media", "members": [a]})[0], 409)
        self.assertEqual(self.request("GET", "/api/device-groups")[1]["groups"][0]["name"], "Work")
        self.assertEqual(self.request("POST", "/api/device-groups/delete", {"id": group["id"]})[0], 200)
        self.assertEqual(self.request("GET", "/api/device-groups")[1]["groups"], [])

    def test_two_same_model_phones_remain_separate_group_members_by_mac(self):
        first = "AA-BB-CC-DD-EE-01"
        second = "AA-BB-CC-DD-EE-02"
        sqlite.set_device_label(self.db, first, "Example phone")
        sqlite.set_device_label(self.db, second, "Example phone")

        group = sqlite.save_device_group(self.db, "Example Work Group", [first, second], 100)

        self.assertEqual(sqlite.device_labels(self.db), {
            first: "Example phone", second: "Example phone",
        })
        self.assertEqual(group["members"], [first, second])
        self.assertEqual(len(set(group["members"])), 2)

    def test_smart_route_endpoint_requires_explicit_owner_selection(self):
        group = sqlite.save_device_group(self.db, "Example Work Group", ["AA-BB-CC-DD-EE-01"], 100)
        control = SimpleNamespace(set_group_smart_routing=mock.Mock(return_value={
            "group": "Example Work Group", "enabled": True, "members": 1, "route": "AUTO",
        }))
        self.board.set_extra("router_control", control)
        status, result = self.request("POST", "/api/device-groups/smart-routing",
                                      {"id": group["id"], "enabled": True})
        self.assertEqual(status, 200)
        self.assertTrue(result["enabled"])
        control.set_group_smart_routing.assert_called_once_with(group["id"], True, "dashboard")
        self.assertEqual(self.request("POST", "/api/device-groups/smart-routing",
                                      {"id": True, "enabled": True})[0], 409)

    def test_cross_origin_group_writes_are_rejected(self):
        conn = http.client.HTTPConnection(self.host, self.port, timeout=5)
        conn.request("POST", "/api/device-groups/save", body=json.dumps({"name":"x", "members":[]}),
                     headers={"Origin":"http://evil.example", "Content-Type":"application/json"})
        response = conn.getresponse()
        self.assertEqual(response.status, 403)
        conn.close()

    def test_device_api_reports_mixed_route_expiries_for_groups(self):
        members = ["AA-BB-CC-DD-EE-01", "AA-BB-CC-DD-EE-02"]
        group = sqlite.save_device_group(self.db, "Temporary", members, 100)
        for mac, expiry in zip(members, (1000, 2000)):
            sqlite.set_device_route(self.db, mac, "192.168.0.10", "WAN1", 100,
                                    "owner", "AUTO", "applied", expires_at=expiry)
        status, data = self.request("GET", "/api/devices")
        self.assertEqual(status, 200)
        self.assertEqual(data["groups"][0]["id"], group["id"])
        self.assertEqual(data["groups"][0]["route"], "WAN1")
        self.assertTrue(data["groups"][0]["expiry_mixed"])

    def test_device_api_exposes_stable_monitor_only_group_advice(self):
        group = sqlite.save_device_group(self.db, "Example Work Group",
                                        ["AA-BB-CC-DD-EE-01"], 100)
        advice = {"current": "WAN1", "candidate": "WAN2", "status": "stable", "ready": True,
                  "observations": 19, "held_seconds": 180, "required_seconds": 180}
        self.board.publish({"group_recommendations": {group["id"]: advice}})

        status, data = self.request("GET", "/api/devices")

        self.assertEqual(status, 200)
        self.assertEqual(data["groups"][0]["monitor_advice"], advice)


class TelegramGroupCommands(unittest.TestCase):
    def test_smart_group_command_requires_exact_group_and_explicit_on_or_off(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        scenario = Scenario(tmp.name, local(12))
        self.addCleanup(scenario.close)
        group = sqlite.save_device_group(scenario.cfg.db_path, "Example Work Group",
                                         ["AA-BB-CC-DD-EE-01"], 100)
        control = SimpleNamespace(set_group_smart_routing=mock.Mock(side_effect=lambda _id, enabled, _actor: {
            "group": "Example Work Group", "enabled": enabled, "members": 1, "route": "AUTO",
        }))
        scenario.mon.router_control = control
        handler = scenario.mon.bot_handlers()["group_smart"]
        self.assertIn("Usage:", handler("/group_smart Example Work Group"))
        self.assertIn("No exact group", handler("/group_smart Example Work Group device on"))
        self.assertIn("No route changed", handler("/group_smart Example Work Group on"))
        self.assertIn("disabled", handler("/group_smart Example Work Group off"))
        self.assertEqual(control.set_group_smart_routing.call_args_list, [
            mock.call(group["id"], True, "telegram owner"),
            mock.call(group["id"], False, "telegram owner"),
        ])

    def test_group_reservation_preview_and_confirmation_keep_same_model_phones_separate(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        scenario = Scenario(tmp.name, local(12))
        self.addCleanup(scenario.close)
        macs = ["A0-B1-C2-D3-E4-F5", "A0-B1-C2-D3-E4-F6"]
        group = sqlite.save_device_group(scenario.cfg.db_path, "Example Work Group", macs, 100)
        preview = {
            "token": "reservation-batch-token", "expires_in": 120, "group": "Example Work Group",
            "count": 2, "effect": "Automatic DHCP remains enabled; WAN routes are unchanged.",
            "members": [
                {"name": "Example phone", "ip": "192.168.0.181", "mac": macs[0],
                 "status": "will be reserved"},
                {"name": "Example phone", "ip": "192.168.0.182", "mac": macs[1],
                 "status": "will be reserved"},
            ],
        }
        control = SimpleNamespace(
            preview_group_reservations=mock.Mock(return_value=preview),
            apply_group_reservations=mock.Mock(return_value={
                "group": "Example Work Group", "count": 2,
                "detail": "Each reservation was read back and verified; WAN routes were unchanged.",
            }),
        )
        scenario.mon.router_control = control
        handlers = scenario.mon.bot_handlers()

        chooser = handlers["group_reserve"]("🧾 Reserve group")
        self.assertIn("/group_reserve exact group name", chooser)
        self.assertIn("Example Work Group", chooser)

        message = handlers["group_reserve"]("/group_reserve Example Work Group")

        self.assertEqual(message.count("Example phone"), 2)
        self.assertIn(f"192.168.0.181 · {macs[0]} · will be reserved", message)
        self.assertIn(f"192.168.0.182 · {macs[1]} · will be reserved", message)
        self.assertIn("/group_reserve_confirm reservation-batch-token", message)
        control.preview_group_reservations.assert_called_once_with(group["id"], "telegram owner")
        result = handlers["group_reserve_confirm"]("/group_reserve_confirm reservation-batch-token")
        self.assertIn("created and verified 2 DHCP reservation(s)", result)
        control.apply_group_reservations.assert_called_once_with("reservation-batch-token")

    def test_owner_group_list_preview_and_confirm(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        scenario = Scenario(tmp.name, local(12))
        self.addCleanup(scenario.close)
        group = sqlite.save_device_group(scenario.cfg.db_path, "Work devices",
                                         ["AA-BB-CC-DD-EE-01"], 100)
        sqlite.insert_speedtest(scenario.cfg.db_path, {
            "ts": int(time.time()) - 30, "wan": "WAN2", "trigger": "manual",
            "down_mbps": 140, "up_mbps": 20, "idle_ms": 15, "loaded_ms": 99,
            "error": None,
        })
        sqlite.insert_speedtest(scenario.cfg.db_path, {
            "ts": int(time.time()) - 45, "wan": "WAN1", "trigger": "manual",
            "down_mbps": 100, "up_mbps": 30, "idle_ms": 23, "loaded_ms": 105,
            "error": None,
        })
        preview_data = {"token": "group-token", "group": "Work devices",
                        "expiry_label": "Until changed", "effect": "All member devices affected.",
                        "members": [{"name": "Laptop", "ip": "192.168.0.10",
                                     "mac": "AA-BB-CC-DD-EE-01", "current": "WAN2",
                                     "current_expires_at": 2_000_000_000}]}
        control = SimpleNamespace(
            preview_group=mock.Mock(side_effect=lambda _group_id, route, _actor, _expiry:
                                    {**preview_data, "route": route}),
            apply_group=mock.Mock(return_value={"group": "Work devices", "route": "WAN1", "count": 1,
                                                "detail": "All member routes verified."}))
        scenario.mon.router_control = control
        scenario.board.set_extra("router_raw", {
            "clients": [{"macaddr": "AA-BB-CC-DD-EE-01", "bind": "0", "leasetime": "1h"}],
            "reservations": [],
            "policy_routes": [], "policy_routes_checked_at": time.time(),
        })
        stable_advice = {"current": "AUTO", "candidate": "WAN2", "status": "stable",
                         "ready": True, "observations": 19, "held_seconds": 180,
                         "required_seconds": 180}
        wan_status = {"updated": time.time(), "wans": [
            {"name": "WAN1", "state": "HEALTHY", "rtt_ms": 31.2, "loss_pct": 0},
            {"name": "WAN2", "state": "HEALTHY", "rtt_ms": 14.8, "loss_pct": 0},
        ]}
        scenario.board.publish({**wan_status,
                                "group_recommendations": {group["id"]: stable_advice}})
        handlers = scenario.mon.bot_handlers()
        group_list = handlers["groups"]()
        self.assertIn("Work devices", group_list)
        self.assertIn("/group_reserve exact group name", group_list)
        self.assertIn("Saved NetPulse route preference: Auto balance", group_list)
        self.assertIn("Router rule read-back: all observed ER605 rules match saved preferences",
                      group_list)
        self.assertIn(f"Group WAN suggestion: {scenario.mon.display('WAN2')}, 14.8 ms, "
                      "0.0% loss; healthy-link probe latency. Monitor only; nothing was changed.",
                      group_list)
        self.assertIn("DHCP reservation coverage: 0/1", group_list)
        self.assertIn("Route preview separately checks every member's eligibility", group_list)
        self.assertIn("may break a close-ping tie only", group_list)
        self.assertIn("Monitor-only candidate: Prefer Example ISP B (WAN2); stable for 3 min. No route was changed.",
                      group_list)
        self.assertIn("Recent speed tests (last 24h; may break a close-ping tie only)", group_list)
        self.assertIn("140.0/20.0 Mbps down/up, loaded ping 99.0 ms", group_list)
        self.assertIn("fastest download Example ISP B (WAN2); fastest upload Example ISP A (WAN1)", group_list)
        pending = {**stable_advice, "ready": False}
        scenario.board.publish({**wan_status, "group_recommendations": {group["id"]: pending}})
        pending_suggestion = handlers["group_suggest"]("/group_suggest Work devices")
        self.assertIn("no stable monitor-only WAN suggestion", pending_suggestion)
        control.preview_group.assert_not_called()
        scenario.board.publish({**wan_status,
                                "group_recommendations": {group["id"]: stable_advice}})
        suggested = handlers["group_suggest"]("/group_suggest Work devices")
        self.assertIn("Stable monitor-only suggestion: WAN2", suggested)
        self.assertIn("Review suggested group route: Work devices", suggested)
        self.assertIn("Target: WAN2 · duration: Until changed", suggested)
        self.assertIn("/group_confirm group-token", suggested)
        control.preview_group.assert_called_once_with(group["id"], "WAN2", "telegram owner", 3600)
        control.preview_group.reset_mock()
        response = handlers["group_route"]("/group_route Work devices WAN1")
        self.assertIn("/group_confirm group-token", response)
        self.assertIn("WAN2 until ", response)
        control.preview_group.assert_called_once_with(group["id"], "WAN1", "telegram owner", 3600)
        handlers["group_route"]("/group_route Work devices WAN1 forever")
        control.preview_group.assert_called_with(group["id"], "WAN1", "telegram owner", 0)
        confirmed = handlers["group_confirm"]("/group_confirm group-token")
        self.assertIn("applied to 1 devices", confirmed)
        control.apply_group.assert_called_once_with("group-token")
        preview_data["members"] = [
            {"name": "x" * 48, "ip": "192.168.0.10", "mac": "AA-BB-CC-DD-EE-01", "current": "WAN1"}
            for _ in range(100)
        ]
        too_large = handlers["group_route"]("/group_route Work devices WAN1")
        self.assertIn("Use the dashboard", too_large)
        self.assertNotIn("/group_confirm", too_large)


if __name__ == "__main__":
    unittest.main()
