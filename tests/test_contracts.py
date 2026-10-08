"""Regression contracts: exact message wording (golden files), the JSON the dashboard relies on,
the dashboard's own consistency, and the Telegram bot over real HTTP against a fake Telegram.

Golden files live in tests/golden/. When a wording change is intended, regenerate with:
    NETPULSE_UPDATE_GOLDEN=1 python -m unittest tests.test_contracts
and review the diff before committing.
"""

import http.client
import base64
import hashlib
import json
import re
import sqlite3
import tempfile
import time
import unittest
from contextlib import closing
from dataclasses import replace
from pathlib import Path
from unittest import mock

from netpulse import main, summary
from netpulse.notifications.base import DEVICE_NOTICE_CATEGORY
from netpulse.notifications.telegram import TelegramBot
from netpulse.storage import sqlite
from netpulse.storage.sqlite import KeyValueFile, Storage
from netpulse.web import app as web
from tools import web_setup
from tests.harness import Condition, FakeTelegram, Scenario, assert_golden, fake_speed, local

ROOT = Path(__file__).resolve().parent.parent


def window(start, end, inside, outside=Condition()):
    return lambda t: inside if start <= t < end else outside


class Base(unittest.TestCase):
    def scenario(self, start, scripts=None, **overrides) -> Scenario:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        s = Scenario(tmp.name, start, scripts or {}, overrides)
        self.addCleanup(s.close)
        return s


class PiOfflineSafety(unittest.TestCase):
    """NetPulse remains low-privilege and cannot erase router-owned forwarding state."""

    def test_service_restart_policy_and_shutdown_do_not_clear_er605_rules(self):
        unit = (ROOT / "systemd" / "netpulse.service").read_text(encoding="utf-8")
        service = unit.split("[Service]", 1)[1].split("[Install]", 1)[0]
        self.assertRegex(service, r"(?m)^Restart=on-failure$")
        self.assertNotRegex(service, r"(?m)^ExecStop(?:Post)?=")
        self.assertRegex(service, r"(?m)^User=netpulse$")
        self.assertRegex(service, r"(?m)^Group=netpulse$")
        self.assertRegex(service, r"(?m)^AmbientCapabilities=CAP_NET_RAW CAP_NET_BIND_SERVICE$")
        self.assertRegex(service, r"(?m)^CapabilityBoundingSet=CAP_NET_RAW CAP_NET_BIND_SERVICE$")
        for setting in (
            "NoNewPrivileges=yes", "ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes",
            "PrivateDevices=yes", "ProtectKernelTunables=yes", "ProtectKernelModules=yes",
            "ProtectControlGroups=yes", "RestrictSUIDSGID=yes", "LockPersonality=yes",
            "StateDirectory=netpulse", "ReadOnlyPaths=/etc/netpulse",
            "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK",
        ):
            self.assertIn(setting, service)

        source = (ROOT / "netpulse" / "main.py").read_text(encoding="utf-8")
        shutdown = source.split("    finally:\n        if syslog_transport:", 1)[1].split(
            "\n\n\ndef _make_router", 1)[0]
        self.assertIn("route_expiry_task.cancel()", shutdown)
        self.assertNotIn("router_control", shutdown)
        self.assertNotIn("router_client", shutdown)


class GoldenMessages(Base):
    """What people actually read in Telegram. Any change here should be deliberate."""

    def test_outage_alerts(self):
        start = local(11)
        s = self.scenario(start, {"WAN2": window(start + 300, start + 1020, Condition(down=True))},
                          telegram={"digest_time": ""})
        s.run(40 * 60)
        assert_golden(self, "alerts_outage", "\n---\n".join(s.outbox.texts()))

    def test_slow_evening_alerts(self):
        start = local(20)
        s = self.scenario(start, {"WAN1": window(start + 300, start + 1500, Condition(rtt_mult=4.5, loss=0.2))},
                          telegram={"digest_time": ""})
        s.run(40 * 60)
        assert_golden(self, "alerts_slow_evening", "\n---\n".join(s.outbox.texts()))

    def test_status_message(self):
        s = self.scenario(local(12), telegram={"digest_time": ""})
        s.run(10 * 60)
        assert_golden(self, "status_healthy", summary.status_text(s.board.get()))

    def test_daily_digest(self):
        start = local(7)
        s = self.scenario(start, {"WAN1": window(start + 1800, start + 2700, Condition(rtt_mult=4, loss=0.15))},
                          telegram={"digest_time": "09:00"})
        s.run(2 * 3600 + 10 * 60)   # past 09:00
        digests = [t for t in s.outbox.texts() if "daily summary" in t]
        self.assertEqual(len(digests), 1)
        assert_golden(self, "digest", digests[0])

    def test_speed_results(self):
        results = [fake_speed("WAN1", "", "manual", set()).to_dict(), fake_speed("WAN2", "", "manual", set()).to_dict()]
        text = summary.speed_text(results, {"WAN1": "Example ISP A", "WAN2": "Example ISP B"}, {"WAN1": 200.0, "WAN2": None})
        assert_golden(self, "speed_results", text)

    def test_help(self):
        assert_golden(self, "help", main.HELP)


SCHEMAS = {
    "/api/status": {
        "mode": str, "updated": float, "targets": list, "headline": dict, "wans": list,
        "muted_until": float, "alert_policy": dict, "speedtest_running": bool,
    },
    "wan": {
        "name": str, "label": str, "state": str, "state_since": float, "score": float, "loss_pct": float,
        "rtt_ms": float, "jitter_ms": float, "availability_pct": float, "reasons": list, "why": list,
        "errors": list, "targets": list, "connectivity": dict,
    },
    "/api/history?hours=1": {"hours": float, "bucket": int, "points": list, "state_minutes": dict},
    "point": {"ts": int, "wan": str, "score": float, "loss_pct": float, "rtt_ms": float, "jitter_ms": float},
    "/api/events?limit=5": list,
    "/api/decisions?days=7": {
        "days": int, "start": int, "end": int, "total": int, "daily": dict,
        "recommendations": list, "omitted_recommendations": int,
    },
    "/api/devices": {"configured": bool, "ready": bool, "updated": float,
                      "inventory_stale": bool, "inventory_age_seconds": float,
                      "scan_interval_seconds": float, "missing_confirmation_scans": int,
                      "syslog": dict,
                      "presence_enabled": bool, "presence_available": bool,
                      "presence_probe_interval_seconds": int,
                      "presence_probe_cycle_seconds": int,
                      "presence_inventory_supported": bool,
                      "presence_confirm_misses": int, "devices": list},
    "/api/system": {"enabled": bool, "health": dict},
    "/api/speedtests?days=30": {
        "running": bool, "results": list, "usual": dict, "plans": dict, "data_usage": dict,
    },
}


class ApiContract(Base):
    """The dashboard reads these fields; removing or renaming one must fail a test."""

    def setUp(self):
        self.s = self.scenario(local(12), telegram={"digest_time": ""})
        self.s.run(5 * 60)
        self.server = web.start("127.0.0.1", 0, self.s.board, self.s.cfg.db_path)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def get(self, path):
        c = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=5)
        c.request("GET", path)
        r = c.getresponse()
        body = r.read()
        c.close()
        self.assertEqual(r.status, 200, path)
        return body

    def post(self, path, body, origin=None):
        host = f"127.0.0.1:{self.server.server_address[1]}"
        headers = {"Content-Type": "application/json"}
        if origin is not None:
            headers["Origin"] = origin
        c = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=5)
        c.request("POST", path, body=json.dumps(body), headers=headers)
        r = c.getresponse()
        result = r.status, r.read()
        c.close()
        return result

    def check(self, obj, schema, where):
        for key, typ in schema.items():
            self.assertIn(key, obj, f"{where}: missing '{key}'")
            if obj[key] is not None:
                ok = isinstance(obj[key], typ) or (typ is float and isinstance(obj[key], int))
                self.assertTrue(ok, f"{where}.{key}: expected {typ.__name__}, got {type(obj[key]).__name__}")

    def test_status(self):
        s = json.loads(self.get("/api/status"))
        self.check(s, SCHEMAS["/api/status"], "status")
        self.assertEqual(s["alert_policy"], {
            "telegram_enabled": False, "device_activity_notifications": False,
            "quiet_start": "23:00", "quiet_end": "07:00",
            "suppressed_since_start": {"mute": 0, "quiet_hours": 0, "rate_limited": 0},
            "device_notice_suppressed_since_start": {"mute": 0, "quiet_hours": 0, "rate_limited": 0},
            "delivery_since_start": None,
        })
        self.assertEqual(set(s["headline"]), {"level", "emoji", "text"})
        self.assertEqual([w["name"] for w in s["wans"]], ["WAN1", "WAN2"])
        for w in s["wans"]:
            self.check(w, SCHEMAS["wan"], f"status.wans[{w['name']}]")

    def test_status_exposes_privacy_safe_telegram_delivery_counts(self):
        delivery = {"accepted": 2, "failed": 1, "queue_dropped": 0, "queued": 3}
        self.s.mon.alerter.notifier.delivery_stats = lambda: delivery
        self.s.mon.cfg = replace(
            self.s.mon.cfg,
            telegram=replace(self.s.mon.cfg.telegram, enabled=True),
        )
        self.s.run(10)
        status = json.loads(self.get("/api/status"))
        self.assertEqual(status["alert_policy"]["delivery_since_start"], delivery)

    def test_history(self):
        h = json.loads(self.get("/api/history?hours=1"))
        self.check(h, SCHEMAS["/api/history?hours=1"], "history")
        self.assertTrue(h["points"])
        self.check(h["points"][0], SCHEMAS["point"], "history.points[0]")
        target = json.loads(self.get("/api/history?hours=1&target=1.1.1.1"))
        self.assertTrue(target["points"])

    def test_events_speed_report(self):
        self.assertIsInstance(json.loads(self.get("/api/events?limit=5")), list)
        review = json.loads(self.get("/api/decisions?days=7"))
        self.check(review, SCHEMAS["/api/decisions?days=7"], "decision review")
        self.assertEqual(review["total"], 0)
        self.check(json.loads(self.get("/api/speedtests?days=30")), SCHEMAS["/api/speedtests?days=30"], "speedtests")
        self.assertIn(b"Internet connection report", self.get("/report?days=1"))
        self.assertTrue(self.get("/api/report.csv?days=1").startswith(b"record_type,timestamp,end_time,isp,wan"))
        self.assertIn(b"<title>NetPulse</title>", self.get("/"))
        system = json.loads(self.get("/api/system"))
        self.check(system, SCHEMAS["/api/system"], "system")
        self.assertFalse(system["enabled"])

    def test_decision_review_api_returns_only_sanitized_paired_wan_samples(self):
        now = int(time.time())
        decision_ts = now - 1000
        with closing(sqlite3.connect(self.s.cfg.db_path)) as db:
            db.execute("INSERT INTO events(ts, kind, wan, message) VALUES (?, ?, ?, ?)",
                       (decision_ts, "decision", "WAN2",
                        "WOULD SWITCH Example ISP A (WAN1) -> Example ISP B (WAN2): "
                        "WAN1 OFFLINE, failing over to WAN2. private device 192.0.2.77"))
            for wan, state, score in (("WAN1", "OFFLINE", 0), ("WAN2", "HEALTHY", 90)):
                db.execute("INSERT INTO wan_minute(ts, wan, state, score) VALUES (?, ?, ?, ?)",
                           (decision_ts - 30, wan, state, score))
            for wan, state, score in (("WAN1", "BAD", 25), ("WAN2", "HEALTHY", 82)):
                db.execute("INSERT INTO wan_minute(ts, wan, state, score) VALUES (?, ?, ?, ?)",
                           (decision_ts + 300, wan, state, score))
            db.commit()

        review = json.loads(self.get("/api/decisions?days=7"))
        self.assertEqual(review["total"], 1)
        self.assertEqual(len(review["recommendations"]), 1)
        item = review["recommendations"][0]
        self.assertEqual((item["source"], item["target"], item["kind"]),
                         ("WAN1", "WAN2", "outage failover"))
        self.assertEqual(item["follow_up"][0]["target_minus_source_score"], 57.0)
        self.assertNotIn("message", item)
        self.assertNotIn("192.0.2.77", json.dumps(review))

        with closing(sqlite3.connect(self.s.cfg.db_path)) as db:
            db.executemany(
                "INSERT INTO events(ts, kind, wan, message) VALUES (?, ?, ?, ?)",
                [(decision_ts + offset, "decision", "WAN2",
                  "WOULD SWITCH Example ISP A (WAN1) -> Example ISP B (WAN2): sustained advantage")
                 for offset in range(1, 12)],
            )
            db.commit()
        review = json.loads(self.get("/api/decisions?days=7"))
        self.assertEqual((review["total"], len(review["recommendations"]),
                          review["omitted_recommendations"]), (12, 10, 2))

    def test_router_api_exposes_observed_hardware_and_firmware_versions(self):
        snap = dict(self.s.board.get())
        snap["router"] = {"ok": True, "hardware_version": "ER605 v2.30",
                           "firmware_version": "2.3.3 Build 20251029 Rel.18054"}
        self.s.board.publish(snap)
        data = json.loads(self.get("/api/router"))["router"]
        self.assertEqual(data["hardware_version"], "ER605 v2.30")
        self.assertEqual(data["firmware_version"], "2.3.3 Build 20251029 Rel.18054")

    def test_system_health_api_marks_old_samples_stale(self):
        health = {"checked_at": time.time() - 10, "max_age_seconds": 600,
                  "disk_free_pct": 50.0, "power_check_status": "tool_missing"}
        self.s.board.set_extra("system_health", health)
        fresh = json.loads(self.get("/api/system"))["health"]
        self.assertFalse(fresh["stale"])
        self.assertGreaterEqual(fresh["age_seconds"], 0)
        self.assertEqual(fresh["power_check_status"], "tool_missing")

        health["checked_at"] = time.time() - 1200
        self.s.board.set_extra("system_health", health)
        stale = json.loads(self.get("/api/system"))["health"]
        self.assertTrue(stale["stale"])
        self.assertGreater(stale["age_seconds"], stale["max_age_seconds"])

        health["checked_at"] = time.time() + 3600
        self.s.board.set_extra("system_health", health)
        future = json.loads(self.get("/api/system"))["health"]
        self.assertTrue(future["stale"])
        self.assertIsNone(future["age_seconds"])

    def test_device_api_exposes_only_selected_dhcp_fields(self):
        snap = dict(self.s.board.get())
        snap["router"] = {"checked_at": 1234.0}
        self.s.board.publish(snap)
        self.s.board.set_extra("router_raw", {"clients": [
            {"name": '<img src=x onerror="alert(1)">', "ipaddr": "192.168.0.101",
             "macaddr": "aa-bb-cc-dd-ee-ff", "leasetime": "1:55:00", "bind": "0", "password": "secret"}
        ]})
        data = json.loads(self.get("/api/devices"))
        self.check(data, SCHEMAS["/api/devices"], "devices")
        self.assertTrue(data["inventory_stale"])
        self.assertGreater(data["inventory_age_seconds"], 1200)
        self.assertEqual(data["scan_interval_seconds"], 600)
        self.assertEqual(data["missing_confirmation_scans"], 3)
        self.assertEqual(data["devices"], [{"name": '<img src=x onerror="alert(1)">', "label": "", "ip": "192.168.0.101",
                                             "mac": "AA-BB-CC-DD-EE-FF", "lease": "1:55:00", "listed": True,
                                             "lan_presence": {"state": "unknown", "ip": "192.168.0.101",
                                                              "checked_at": None, "last_reply_at": None, "misses": 0},
                                             "first_seen": None, "last_seen": None,
                                             "reserved": False, "protected": False, "group": "",
                                             "route": "AUTO", "route_expires_at": None,
                                             "np_rule_route": "UNKNOWN", "np_rule_drift": None,
                                             "np_rule_checked_at": None, "np_rule_stale": None}])
        self.assertNotIn(b"secret", self.get("/api/devices"))

    def test_device_api_marks_future_inventory_time_stale_without_negative_age(self):
        snap = dict(self.s.board.get())
        snap["router"] = {"checked_at": time.time() + 3600}
        self.s.board.publish(snap)
        self.s.board.set_extra("router_raw", {"clients": []})
        data = json.loads(self.get("/api/devices"))
        self.assertTrue(data["inventory_stale"])
        self.assertIsNone(data["inventory_age_seconds"])

    def test_device_api_hides_future_device_history_and_route_observation_times(self):
        from netpulse.storage import sqlite
        mac = "AA-BB-CC-DD-EE-11"
        future = int(time.time()) + 3600
        sqlite.observe_devices(self.s.cfg.db_path, [{
            "macaddr": mac, "name": "Tablet", "ipaddr": "192.168.0.121"}], future)
        snap = dict(self.s.board.get())
        snap["router"] = {"checked_at": time.time(), "links_max_age_seconds": 1200}
        self.s.board.publish(snap)
        self.s.board.set_extra("router_raw", {
            "clients": [{"macaddr": mac, "name": "Tablet", "ipaddr": "192.168.0.121"}],
            "policy_routes": [{"name": "NP_R_AABBCCDDEE11", "state": "on", "interfaces": "WAN1"}],
            "policy_routes_checked_at": future,
        })
        device = json.loads(self.get("/api/devices"))["devices"][0]
        self.assertIsNone(device["first_seen"])
        self.assertIsNone(device["last_seen"])
        self.assertTrue(device["np_rule_stale"])
        self.assertIsNone(device["np_rule_checked_at"])

    def test_lan_presence_setting_requires_same_origin_and_persists_owner_choice(self):
        from netpulse.devices.presence import PresenceSettings

        settings = PresenceSettings(self.s.cfg.db_path, available=True)
        self.s.board.set_extra("device_presence_settings", settings)
        self.s.board.set_extra("device_presence_enabled", False)
        self.assertEqual(self.post("/api/devices/presence", {"enabled": True})[0], 403)
        self.assertFalse(settings.enabled)

        host = f"127.0.0.1:{self.server.server_address[1]}"
        status, body = self.post("/api/devices/presence", {"enabled": True}, f"http://{host}")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"enabled": True})
        self.assertTrue(PresenceSettings(self.s.cfg.db_path, available=True).enabled)

    def test_lan_presence_setting_cannot_enable_without_router_monitoring(self):
        from netpulse.devices.presence import PresenceSettings

        settings = PresenceSettings(self.s.cfg.db_path, available=False)
        self.s.board.set_extra("device_presence_settings", settings)
        host = f"127.0.0.1:{self.server.server_address[1]}"
        status, body = self.post("/api/devices/presence", {"enabled": True}, f"http://{host}")
        self.assertEqual(status, 409)
        self.assertIn("Router monitoring is unavailable", json.loads(body)["error"])
        self.assertFalse(settings.enabled)

    def test_router_pause_is_same_origin_fixed_thirty_minutes(self):
        from unittest import mock

        router = mock.Mock()
        router.snapshot.return_value = {"paused_until": 1_800}
        self.s.board.set_extra("router_watch", router)
        self.assertEqual(self.post("/api/router/pause", {"seconds": 1800})[0], 403)

        host = f"127.0.0.1:{self.server.server_address[1]}"
        self.assertEqual(self.post("/api/router/pause", {"seconds": 3600}, f"http://{host}")[0], 400)
        router.pause.assert_not_called()
        status, body = self.post("/api/router/pause", {"seconds": 1800}, f"http://{host}")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"paused_until": 1800, "seconds": 1800})
        router.pause.assert_called_once_with(1800)

    def test_router_pause_requires_router_monitoring(self):
        host = f"127.0.0.1:{self.server.server_address[1]}"
        status, body = self.post("/api/router/pause", {"seconds": 1800}, f"http://{host}")
        self.assertEqual(status, 503)
        self.assertIn("Router monitoring is unavailable", json.loads(body)["error"])

    def test_router_resume_requires_same_origin_and_explicit_confirmation(self):
        from unittest import mock

        router = mock.Mock()
        self.s.board.set_extra("router_watch", router)
        self.assertEqual(self.post("/api/router/resume", {"confirmed": True})[0], 403)

        host = f"127.0.0.1:{self.server.server_address[1]}"
        status, body = self.post("/api/router/resume", {"confirmed": False}, f"http://{host}")
        self.assertEqual(status, 400)
        router.resume.assert_not_called()
        status, body = self.post("/api/router/resume", {"confirmed": True}, f"http://{host}")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"paused_until": 0})
        router.resume.assert_called_once_with()

    def test_router_resume_requires_router_monitoring(self):
        host = f"127.0.0.1:{self.server.server_address[1]}"
        status, body = self.post("/api/router/resume", {"confirmed": True}, f"http://{host}")
        self.assertEqual(status, 503)
        self.assertIn("Router monitoring is unavailable", json.loads(body)["error"])

    def test_firmware_accept_requires_same_origin_and_explicit_review(self):
        from unittest import mock

        control = mock.Mock()
        control.accept_firmware.return_value = {"enabled": True, "firmware_review_required": False}
        self.s.board.set_extra("router_control", control)
        payload = {"confirmed": True, "firmware_version": "2.4.0 Build 20261001"}
        self.assertEqual(self.post("/api/router/firmware/accept", payload)[0], 403)
        host = f"127.0.0.1:{self.server.server_address[1]}"
        status, _ = self.post("/api/router/firmware/accept",
                              {"confirmed": False, "firmware_version": "x"}, f"http://{host}")
        self.assertEqual(status, 400)
        control.accept_firmware.assert_not_called()
        status, body = self.post("/api/router/firmware/accept", payload, f"http://{host}")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"enabled": True, "firmware_review_required": False})
        control.accept_firmware.assert_called_once_with("2.4.0 Build 20261001", True)

    def test_device_api_includes_inactive_reservations_without_router_secrets(self):
        snap = dict(self.s.board.get())
        snap["router"] = {"checked_at": 1234.0}
        self.s.board.publish(snap)
        self.s.board.set_extra("router_raw", {"clients": [], "reservations": [
            {"mac": "aa-bb-cc-dd-ee-01", "ip": "192.168.0.140", "note": "Office printer",
             "enable": "1", "password": "must-not-escape"}
        ]})
        data = json.loads(self.get("/api/devices"))
        self.assertEqual(data["devices"], [{"name": "Office printer", "label": "", "ip": "192.168.0.140",
                                             "mac": "AA-BB-CC-DD-EE-01", "lease": "", "listed": False,
                                             "lan_presence": {"state": "unknown", "ip": "192.168.0.140",
                                                              "checked_at": None, "last_reply_at": None, "misses": 0},
                                             "first_seen": None, "last_seen": None,
                                             "reserved": True, "protected": False, "group": "",
                                             "route": "AUTO", "route_expires_at": None,
                                             "np_rule_route": "UNKNOWN", "np_rule_drift": None,
                                             "np_rule_checked_at": None, "np_rule_stale": None}])
        self.assertNotIn(b"must-not-escape", self.get("/api/devices"))

    def test_device_api_normalizes_colon_macs_across_clients_reservations_labels_and_groups(self):
        from netpulse.storage import sqlite

        mac, other = "AA-BB-CC-DD-EE-21", "AA-BB-CC-DD-EE-22"
        sqlite.set_device_label(self.s.cfg.db_path, mac, "Example work phone")
        sqlite.save_device_group(self.s.cfg.db_path, "Example Work Group", [mac, other], int(time.time()))
        self.s.board.set_extra("router_raw", {
            "clients": [
                {"macaddr": mac.replace("-", ":").lower(), "name": "Example phone",
                 "ipaddr": "192.168.0.121", "leasetime": "1:00"},
                {"macaddr": mac.lower(), "name": "Example phone",
                 "ipaddr": "192.168.0.121", "leasetime": "1:00"},
                {"macaddr": other, "name": "Example phone", "ipaddr": "192.168.0.122",
                 "leasetime": "1:00"},
            ],
            "reservations": [{"mac": mac.lower(), "ip": "192.168.0.121", "note": "Work phone",
                              "enable": "1"}],
        })

        devices = json.loads(self.get("/api/devices"))["devices"]
        by_mac = {device["mac"]: device for device in devices}
        self.assertEqual(set(by_mac), {mac, other})
        self.assertEqual(by_mac[mac]["label"], "Example work phone")
        self.assertEqual(by_mac[mac]["group"], "Example Work Group")
        self.assertTrue(by_mac[mac]["reserved"])
        self.assertEqual(by_mac[other]["name"], "Example phone")
        self.assertEqual(by_mac[other]["group"], "Example Work Group")

    def test_device_api_exposes_only_aggregate_syslog_listener_health(self):
        self.s.board.set_extra("router_syslog", {
            "enabled": True, "listening": True, "accepted_allocations": 7,
            "duplicates_suppressed": 2, "device_events": 3,
            "known_renewals_suppressed": 4, "last_allocation_at": 1234567890.0,
        })
        data = json.loads(self.get("/api/devices"))
        self.assertEqual(data["syslog"], {
            "enabled": True, "listening": True, "accepted_allocations": 7,
            "duplicates_suppressed": 2, "device_events": 3,
            "known_renewals_suppressed": 4, "last_allocation_at": 1234567890.0,
        })
        status = json.dumps(data["syslog"]).lower()
        self.assertNotIn("mac", status)
        self.assertNotIn("ip", status)

    def test_device_api_exposes_stored_first_and_last_seen_times(self):
        from netpulse.storage import sqlite
        mac = "AA-BB-CC-DD-EE-02"
        sqlite.observe_devices(self.s.cfg.db_path, [{"macaddr": mac, "name": "Tablet", "ipaddr": "192.168.0.120"}], 100)
        sqlite.observe_devices(self.s.cfg.db_path, [{"macaddr": mac, "name": "Tablet", "ipaddr": "192.168.0.120"}], 200)
        snap = dict(self.s.board.get())
        snap["router"] = {"checked_at": 200.0}
        self.s.board.publish(snap)
        self.s.board.set_extra("router_raw", {"clients": [
            {"macaddr": mac, "name": "Tablet", "ipaddr": "192.168.0.120", "leasetime": "1:00"}
        ]})
        data = json.loads(self.get("/api/devices"))
        self.assertEqual(data["devices"][0]["first_seen"], 100)
        self.assertEqual(data["devices"][0]["last_seen"], 200)

    def test_device_api_marks_recent_inventory_fresh(self):
        snap = dict(self.s.board.get())
        snap["router"] = {"checked_at": time.time(), "links_max_age_seconds": 1200}
        self.s.board.publish(snap)
        self.s.board.set_extra("router_raw", {"clients": [], "reservations": []})
        data = json.loads(self.get("/api/devices"))
        self.assertFalse(data["inventory_stale"])
        self.assertLessEqual(data["inventory_age_seconds"], 1200)

    def test_device_api_reports_observed_np_rule_and_saved_route_drift(self):
        from netpulse.storage import sqlite
        mac = "AA-BB-CC-DD-EE-03"
        sqlite.set_device_route(self.s.cfg.db_path, mac, "192.168.0.121", "WAN2",
                                200, "owner", "AUTO", "applied")
        snap = dict(self.s.board.get())
        snap["router"] = {"checked_at": 200.0}
        self.s.board.publish(snap)
        self.s.board.set_extra("router_raw", {
            "clients": [{"macaddr": mac, "name": "Tablet", "ipaddr": "192.168.0.121"}],
            "policy_routes": [{"name": "NP_R_AABBCCDDEE03", "state": "on", "interfaces": "WAN1"}],
            "policy_routes_checked_at": 199.0,
        })
        device = json.loads(self.get("/api/devices"))["devices"][0]
        self.assertEqual(device["route"], "WAN2")
        self.assertEqual(device["np_rule_route"], "WAN1")
        self.assertTrue(device["np_rule_drift"])
        self.assertEqual(device["np_rule_checked_at"], 199.0)
        self.assertTrue(device["np_rule_stale"])

    def test_device_api_exposes_ping_evidence_without_calling_it_online(self):
        mac = "AA-BB-CC-DD-EE-04"
        snap = dict(self.s.board.get())
        snap["router"] = {"checked_at": time.time(), "links_max_age_seconds": 1200}
        self.s.board.publish(snap)
        self.s.board.set_extra("router_raw", {"clients": [{
            "macaddr": mac, "name": "Desk lamp", "ipaddr": "192.168.0.122", "leasetime": "1:00:00"
        }]})
        self.s.board.set_extra("device_presence_enabled", True)
        self.s.board.set_extra("device_presence", {mac: {
            "state": "replying", "ip": "192.168.0.122", "checked_at": 100,
            "last_reply_at": 100, "misses": 0,
        }})
        data = json.loads(self.get("/api/devices"))
        self.assertTrue(data["presence_enabled"])
        self.assertEqual(data["presence_probe_cycle_seconds"], 60)
        self.assertTrue(data["presence_inventory_supported"])
        device = data["devices"][0]
        self.assertTrue(device["listed"])
        self.assertEqual(device["lan_presence"]["state"], "replying")
        self.assertNotIn("online", device["lan_presence"])

    def test_device_api_reports_ping_cycle_and_disables_estimate_above_safety_cap(self):
        clients = [{"macaddr": f"02-00-00-{n // 65536:02X}-{(n // 256) % 256:02X}-{n % 256:02X}",
                    "name": "device", "ipaddr": "192.168.0.100"}
                   for n in range(129)]
        self.s.board.set_extra("router_raw", {"clients": clients})
        data = json.loads(self.get("/api/devices"))
        self.assertEqual(data["presence_probe_cycle_seconds"], 120)
        self.assertTrue(data["presence_inventory_supported"])

        from netpulse.probes.presence import MAX_CLIENT_ROWS_TO_SCAN
        clients.extend(clients * 3)
        clients = clients[:MAX_CLIENT_ROWS_TO_SCAN + 1]
        self.s.board.set_extra("router_raw", {"clients": clients})
        data = json.loads(self.get("/api/devices"))
        self.assertIsNone(data["presence_probe_cycle_seconds"])
        self.assertFalse(data["presence_inventory_supported"])

    def test_device_api_preserves_pending_ping_recovery_evidence(self):
        mac = "AA-BB-CC-DD-EE-04"
        self.s.board.set_extra("router_raw", {"clients": [{
            "macaddr": mac, "name": "Desk lamp", "ipaddr": "192.168.0.122"
        }]})
        self.s.board.set_extra("device_presence", {mac: {
            "state": "no_reply", "ip": "192.168.0.122", "checked_at": time.time(),
            "misses": 5, "recovery_replies": 1,
        }})
        device = json.loads(self.get("/api/devices"))["devices"][0]
        self.assertEqual(device["lan_presence"]["state"], "no_reply")
        self.assertEqual(device["lan_presence"]["recovery_replies"], 1)

    def test_device_api_replaces_router_placeholder_name_without_overwriting_owner_label(self):
        from netpulse.storage import sqlite

        mac = "AA-BB-CC-DD-EE-04"
        self.s.board.set_extra("router_raw", {"clients": [{
            "macaddr": mac, "name": "--", "ipaddr": "192.168.0.122"
        }]})
        device = json.loads(self.get("/api/devices"))["devices"][0]
        self.assertEqual(device["name"], "Unnamed device (DD-EE-04)")
        sqlite.set_device_label(self.s.cfg.db_path, mac, "My desk lamp")
        device = json.loads(self.get("/api/devices"))["devices"][0]
        self.assertEqual(device["name"], "Unnamed device (DD-EE-04)")
        self.assertEqual(device["label"], "My desk lamp")

    def test_device_groups_report_wan_control_readiness(self):
        from netpulse.storage import sqlite
        ready, needs_reservation = "AA-BB-CC-DD-EE-10", "AA-BB-CC-DD-EE-11"
        sqlite.save_device_group(self.s.cfg.db_path, "Family", [ready, needs_reservation], 200)
        snap = dict(self.s.board.get())
        snap["router"] = {"checked_at": 200.0}
        snap["updated"] = time.time()
        snap["wans"] = [
            {"name": "WAN1", "state": "HEALTHY", "rtt_ms": 35, "loss_pct": 0},
            {"name": "WAN2", "state": "HEALTHY", "rtt_ms": 12, "loss_pct": 0},
        ]
        self.s.board.publish(snap)
        sqlite.insert_speedtest(self.s.cfg.db_path, {
            "ts": int(time.time()) - 60, "wan": "WAN2", "trigger": "manual",
            "down_mbps": 125, "up_mbps": 18, "idle_ms": 16, "loaded_ms": 87,
            "error": None,
        })
        sqlite.insert_speedtest(self.s.cfg.db_path, {
            "ts": int(time.time()) - 90, "wan": "WAN1", "trigger": "manual",
            "down_mbps": 100, "up_mbps": 22, "idle_ms": 22, "loaded_ms": 120,
            "error": None,
        })
        self.s.board.set_extra("router_raw", {
            "clients": [
                {"macaddr": ready, "name": "Phone", "ipaddr": "192.168.0.120", "leasetime": "1h"},
                {"macaddr": needs_reservation, "name": "TV", "ipaddr": "192.168.0.121", "leasetime": "1h"}],
            "reservations": [{"mac": ready, "ip": "192.168.0.120", "enable": "on"}],
            "policy_routes": [], "policy_routes_checked_at": time.time(),
        })
        data = json.loads(self.get("/api/devices"))
        self.assertEqual(data["groups"][0]["members"], [ready, needs_reservation])
        self.assertIs(data["groups"][0]["smart_routing_enabled"], False)
        self.assertIsNone(data["groups"][0]["smart_enabled_at"])
        self.assertEqual((data["groups"][0]["reserved_count"], data["groups"][0]["blocked_count"]), (1, 1))
        self.assertEqual(data["groups"][0]["suggested_wan"]["wan"], "WAN2")
        self.assertEqual(data["groups"][0]["suggested_wan"]["rtt_ms"], 12.0)
        self.assertEqual(data["groups"][0]["route_readback"], "matches")
        self.assertEqual(data["groups"][0]["observed_route"], "AUTO")
        self.assertEqual(data["recent_speeds"]["WAN2"]["down_mbps"], 125.0)
        self.assertEqual(data["recent_speeds"]["WAN2"]["loaded_ms"], 87.0)
        self.assertEqual(data["recent_speed_comparison"]["download_winner"], "WAN2")
        self.assertEqual(data["recent_speed_comparison"]["upload_winner"], "WAN1")


class DashboardConsistency(unittest.TestCase):
    """Cheap guards that catch the most common ways the single-file dashboard breaks."""

    html = (ROOT / "netpulse" / "web" / "static" / "index.html").read_text(encoding="utf-8")

    def test_every_element_the_script_uses_exists(self):
        ids = set(re.findall(r'\bid="([\w-]+)"', self.html))
        used = set(re.findall(r'\$\("([\w-]+)"\)', self.html))
        self.assertTrue(used)
        self.assertEqual(used - ids, set(), "script refers to element ids that don't exist")

    def test_every_api_the_script_calls_is_served(self):
        calls = set(re.findall(r'["`](/api/[a-z_.-]+)', self.html))
        app_src = (ROOT / "netpulse" / "web" / "app.py").read_text(encoding="utf-8")
        for path in calls:
            self.assertIn(f'"{path}"', app_src, f"dashboard calls {path}, which app.py doesn't serve")

    def test_dashboard_labels_routine_dns_https_diagnostics(self):
        self.assertIn("DNS/HTTPS check (${checkWhen})", self.html)
        self.assertIn("w.connectivity.diagnosis", self.html)

    def test_pi_health_dashboard_marks_low_available_memory(self):
        self.assertIn("h.memory_available_pct", self.html)
        self.assertIn('h.memory_low === true ? " · LOW" : ""', self.html)

    def test_group_cards_offer_reviewed_bulk_dhcp_reservations(self):
        app_src = (ROOT / "netpulse" / "web" / "app.py").read_text(encoding="utf-8")
        self.assertIn("group-reservation-preview", self.html)
        self.assertIn('id="group-reservation-dialog"', self.html)
        self.assertIn("/api/device-groups/reservations/preview", self.html)
        self.assertIn("/api/device-groups/reservations/apply", self.html)
        self.assertIn("preview_group_reservations", app_src)
        self.assertIn("apply_group_reservations", app_src)
        self.assertIn("The router may renew its lease once", self.html)
        self.assertIn("This does not change WAN routes", self.html)

    def test_group_member_summary_keeps_same_model_devices_distinguishable(self):
        self.assertIn('replace(/[^0-9A-F]/g, "").slice(-6)', self.html)
        self.assertIn('"; MAC …" + macTail', self.html)
        self.assertIn('d.label || d.name', self.html)

    def test_group_cards_offer_reviewed_read_only_balanced_wan_recommendation(self):
        self.assertIn("group-suggestion-preview", self.html)
        self.assertIn("Suggested WAN:", self.html)
        self.assertIn("healthy-link probe latency", self.html)
        self.assertIn("Review suggested route", self.html)
        self.assertIn('choice.value = bestButton.dataset.wan', self.html)
        self.assertIn("/api/device-groups/route/preview", self.html)
        self.assertIn("deviceData.recent_speeds", self.html)
        self.assertIn("used only for a close-ping tie", self.html)
        self.assertIn("recent_speed_comparison", self.html)
        self.assertIn("fastest download", self.html)
        self.assertIn("g.route_readback", self.html)
        self.assertIn("g.monitor_advice", self.html)
        self.assertIn("Stable monitor-only candidate", self.html)
        self.assertIn("no route changed", self.html)
        self.assertGreaterEqual(self.html.count('<option value="3600" selected>1 hour</option>'), 2)
        self.assertIn('<option value="0">Until changed</option>', self.html)

    def test_no_external_resources(self):
        # The page must load when the internet is down: nothing from CDNs or font services.
        self.assertIsNone(re.search(r'(src|href)="https?://', self.html))

    def test_status_fields_used_by_script_exist(self):
        fields = set(re.findall(r"\bw\.(\w+)", self.html))
        wan_fields = set(SCHEMAS["wan"]) | {"source_ip", "rtt_ratio"}
        self.assertEqual(fields - wan_fields, set(), "script reads WAN fields the API doesn't send")
        self.assertIn('id="alert-policy"', self.html)
        self.assertIn("Telegram alerts are disabled", self.html)
        self.assertIn("Non-critical alerts, including device notices, are held", self.html)
        self.assertIn("alertPolicy.delivery_since_start", self.html)
        self.assertIn("Telegram API accepted", self.html)
        self.assertIn("delivery.categories.device_notice", self.html)
        self.assertIn("device_notice_suppressed_since_start", self.html)

    def test_device_inventory_labels_stale_router_scans(self):
        app_src = (ROOT / "netpulse" / "web" / "app.py").read_text(encoding="utf-8")
        self.assertIn("inventory_stale", self.html)
        self.assertIn('"inventory_stale": inventory_stale', app_src)
        self.assertIn("Last scan · lease listed · stale", self.html)
        self.assertIn('value="reserved">Reserved devices', self.html)
        self.assertNotIn("ready for WAN steering", self.html)
        self.assertIn('id="device-scan-guidance"', self.html)
        self.assertIn("missing_confirmation_scans", self.html)
        self.assertIn("keep a disconnected device listed until its DHCP lease expires", self.html)
        self.assertIn("device card shows the remaining lease time", self.html)
        self.assertIn("After expiry, allow ${departureTime} for confirmation", self.html)
        self.assertIn("A permanent lease may stay listed indefinitely", self.html)
        self.assertIn("not confirmed device arrival or departure", self.html)
        self.assertIn("DHCP lease time remaining", self.html)
        self.assertIn("Internet pause/resume is not available until ACL enforcement is verified", self.html)
        self.assertIn("ER605 ACL rules do not affect clients on the same LAN", self.html)
        self.assertIn("device may sleep or block ping", self.html)
        self.assertIn('id="presence-toggle"', self.html)
        self.assertIn("vcgencmd not found in the NetPulse service PATH", self.html)
        self.assertIn("/api/devices/presence", self.html)
        self.assertIn("presence_available", self.html)
        self.assertIn("next router check in", self.html)
        self.assertIn("next router check waits for recovery", self.html)
        self.assertIn("missed checks", self.html)
        self.assertIn("presence_probe_cycle_seconds", self.html)
        self.assertIn("each device is checked about every", self.html)
        self.assertIn("exceeds the 512-device safety cap", self.html)
        self.assertIn('e.kind === "connectivity"', self.html)
        self.assertIn('e.kind === "device_presence"', self.html)
        self.assertIn("reply seen ", self.html)
        self.assertIn('e.kind === "router_route"', self.html)
        self.assertIn("Router-reported WAN status; this does not prove physical carrier or end-to-end Internet reachability", self.html)
        self.assertIn('${r.firmware_version ? `<span class="chip">Firmware <b>${esc(r.firmware_version)}</b>', self.html)

    def test_dashboard_surfaces_sanitized_monitor_only_wan_reviews(self):
        app_src = (ROOT / "netpulse" / "web" / "app.py").read_text(encoding="utf-8")
        self.assertIn('id="decision-review"', self.html)
        self.assertIn('id="decision-review-note"', self.html)
        self.assertIn('/api/decisions?days=7', self.html)
        self.assertIn('url.path == "/api/decisions"', app_src)
        self.assertIn("summarize_decision_review(db_path, days, recommendation_limit=10)", app_src)
        self.assertIn("from netpulse.decision.review import summarize as summarize_decision_review", app_src)
        self.assertIn("never changes routes from these recommendations", self.html)

    def test_router_pause_button_calls_same_origin_pause_api(self):
        app_src = (ROOT / "netpulse" / "web" / "app.py").read_text(encoding="utf-8")
        self.assertIn('id="router-pause"', self.html)
        self.assertIn('/api/router/pause', self.html)
        self.assertIn('url.path == "/api/router/pause"', app_src)
        self.assertIn('router_watch.pause(seconds)', app_src)
        self.assertIn("route controls will lock until checks resume", self.html)

    def test_router_resume_button_warns_before_same_origin_resume_api(self):
        app_src = (ROOT / "netpulse" / "web" / "app.py").read_text(encoding="utf-8")
        self.assertIn('id="router-resume"', self.html)
        self.assertIn("window.confirm(", self.html)
        self.assertIn("may end your Omada browser session", self.html)
        self.assertIn('/api/router/resume', self.html)
        self.assertIn('url.path == "/api/router/resume"', app_src)
        self.assertIn('body.get("confirmed") is not True', app_src)
        self.assertIn('router_watch.resume()', app_src)

    def test_firmware_review_button_requires_confirmation(self):
        app_src = (ROOT / "netpulse" / "web" / "app.py").read_text(encoding="utf-8")
        self.assertIn('id="firmware-accept"', self.html)
        self.assertIn("I reviewed the ER605 firmware version", self.html)
        self.assertIn('/api/router/firmware/accept', self.html)
        self.assertIn('url.path == "/api/router/firmware/accept"', app_src)

    def test_group_membership_edits_never_select_an_existing_group_by_name(self):
        self.assertIn("existing.id !== editingGroupId", self.html)
        self.assertIn("Choose Edit members on that group to change its membership", self.html)
        self.assertIn("JSON.stringify({id: editingGroupId, name, members:[...selectedDeviceMacs]})", self.html)

    def test_group_editor_exposes_draft_members_and_explicit_save_state(self):
        self.assertIn('id="group-editor"', self.html)
        self.assertIn('id="group-editor-count"', self.html)
        self.assertIn('`${selectedDeviceMacs.size} selected · changes are a draft`', self.html)
        self.assertIn('"Unavailable in the current router list"', self.html)
        self.assertIn('class="group-member-remove"', self.html)
        self.assertIn('selectedDeviceMacs.delete(button.dataset.mac)', self.html)
        self.assertIn('editingGroupId === null ? "Create device group" : "Save group membership"', self.html)
        self.assertIn('Saving stops Smart WAN for this group until you enable it again; current device routes stay in place.', self.html)

    def test_home_assistant_counts_only_listed_leases_and_optional_ping_responders(self):
        ha = (ROOT / "docs" / "home-assistant.md").read_text(encoding="utf-8")
        self.assertIn("selectattr('listed')", ha)
        self.assertIn("presence_enabled", ha)
        self.assertIn("selectattr('lan_presence.state', 'equalto', 'replying')", ha)
        self.assertIn("not counts of people or proof of Internet access", ha)
        self.assertIn("/api/router", ha)
        self.assertIn("/api/system", ha)
        self.assertIn("NetPulse DHCP allocation records since service start", ha)
        self.assertIn("NetPulse last DHCP allocation age", ha)
        self.assertIn("NetPulse DHCP event listener", ha)
        self.assertIn("value_json.syslog.listening", ha)
        self.assertIn("NetPulse ER605 full check age", ha)
        self.assertIn("NetPulse Pi undervoltage occurred this boot", ha)
        self.assertIn("NetPulse Pi memory low", ha)
        self.assertIn("NetPulse Pi power check", ha)
        self.assertIn("NetPulse Pi CPU throttling now", ha)
        self.assertIn("NetPulse Pi performance limiting occurred this boot", ha)
        self.assertIn("NetPulse Pi SoC temperature", ha)
        self.assertIn("NetPulse Pi one minute load per core", ha)
        self.assertIn("NetPulse Pi memory available", ha)
        self.assertIn("NetPulse Pi health data stale", ha)
        self.assertIn("NetPulse WAN1 outage diagnosis", ha)
        self.assertIn("NetPulse WAN2 outage diagnosis", ha)
        self.assertIn("map(attribute='connectivity')", ha)
        self.assertIn("do not expose controls to Home Assistant", ha)

    def test_device_page_explains_identity_free_fast_dhcp_status(self):
        self.assertIn('id="syslog-status"', self.html)
        self.assertIn("Faster DHCP notices are listening", self.html)
        self.assertIn("last allocation recognized", self.html)
        self.assertIn("since service start", self.html)
        self.assertIn("duplicates suppressed", self.html)
        refresh = self.html.split("async function refreshDevices()", 1)[1].split(
            "function deviceNotice", 1)[0]
        self.assertLess(refresh.index("renderSyslogStatus(d.syslog)"), refresh.index("if (!d.ready)"))

    def test_pi_health_dashboard_labels_performance_limits_separately_from_power(self):
        self.assertIn('id="pi-performance"', self.html)
        self.assertIn('"arm_frequency_capped"', self.html)
        self.assertIn('"throttled"', self.html)
        self.assertIn('"soft_temp_limit"', self.html)
        self.assertIn("reported since reboot", self.html)
        self.assertIn("stale sample", self.html)


class DashboardAuthentication(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = str(Path(self.tmp.name) / "auth.db")
        Storage(self.db).close()
        self.auth_file = Path(self.tmp.name) / "web.auth"
        salt = b"a test salt for dashboard auth"
        digest = hashlib.pbkdf2_hmac("sha256", b"local-test-password", salt, 10_000).hex()
        self.auth_file.write_text(json.dumps({"username": "netpulse", "salt": salt.hex(),
                                              "digest": digest, "iterations": 10_000}), encoding="utf-8")
        self.board = web.StatusBoard()
        self.server = web.start("127.0.0.1", 0, self.board, self.db, str(self.auth_file))
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def request(self, path, credential=None, method="GET", body=None, extra_headers=None):
        c = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=5)
        headers = {"Content-Type": "application/json"} if method == "POST" else {}
        headers.update(extra_headers or {})
        if credential is not None:
            raw = f"{credential[0]}:{credential[1]}".encode()
            headers["Authorization"] = "Basic " + base64.b64encode(raw).decode()
        encoded = json.dumps(body) if body is not None else None
        c.request(method, path, body=encoded, headers=headers)
        r = c.getresponse()
        result = r.status, dict(r.getheaders()), r.read()
        c.close()
        return result

    def test_page_and_api_require_the_configured_password(self):
        status, headers, _ = self.request("/")
        self.assertEqual(status, 401)
        self.assertIn("Basic", headers["WWW-Authenticate"])
        self.assertEqual(self.request("/api/status", ("netpulse", "wrong"))[0], 401)
        status, _, body = self.request("/api/status", ("netpulse", "local-test-password"))
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"wans": [], "updated": None})
        self.assertEqual(self.request("/api/decisions?days=7")[0], 401)
        status, _, body = self.request("/api/decisions?days=7",
                                       ("netpulse", "local-test-password"))
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["total"], 0)

    def test_dashboard_responses_disallow_framing_and_mime_sniffing(self):
        status, headers, _ = self.request("/", ("netpulse", "local-test-password"))
        self.assertEqual(status, 200)
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertEqual(headers["Content-Security-Policy"], "frame-ancestors 'none'")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(headers["Referrer-Policy"], "no-referrer")

    def test_repeated_bad_passwords_are_throttled_per_client(self):
        for _ in range(8):
            self.assertEqual(self.request("/api/status", ("netpulse", "wrong"))[0], 401)
        status, headers, body = self.request("/api/status", ("netpulse", "local-test-password"))
        self.assertEqual(status, 429)
        self.assertGreaterEqual(int(headers["Retry-After"]), 1)
        self.assertEqual(body, b"")

    def test_wildcard_bind_is_rejected_without_authentication(self):
        with self.assertRaisesRegex(RuntimeError, "auth is required"):
            web.start("0.0.0.0", 0, web.StatusBoard(), self.db, None)

    def test_group_write_requires_authentication_and_same_origin(self):
        path = "/api/device-groups/save"
        payload = {"name": "Trusted test group", "members": []}
        self.assertEqual(sqlite.device_groups(self.db), [])

        self.assertEqual(self.request(path, method="POST", body=payload)[0], 401)
        self.assertEqual(sqlite.device_groups(self.db), [])

        credential = ("netpulse", "local-test-password")
        for origin in (None, "https://evil.example", "null"):
            headers = {"Origin": origin} if origin is not None else None
            status, _, _ = self.request(path, credential, "POST", payload, headers)
            self.assertEqual(status, 403, origin)
            self.assertEqual(sqlite.device_groups(self.db), [])

        port = self.server.server_address[1]
        status, _, body = self.request(path, credential, "POST", payload,
                                       {"Origin": f"http://127.0.0.1:{port}"})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["name"], "Trusted test group")
        self.assertEqual([g["name"] for g in sqlite.device_groups(self.db)], ["Trusted test group"])

    def test_group_route_preview_and_apply_require_auth_and_same_origin(self):
        class RecordingControl:
            def __init__(self):
                self.calls = []

            def preview_group(self, *args, **kwargs):
                self.calls.append(("preview", args, kwargs))
                return {"token": "preview-token"}

            def apply_group(self, token):
                self.calls.append(("apply", token))
                return {"applied": True}

            def preview_group_reservations(self, *args, **kwargs):
                self.calls.append(("reservation_preview", args, kwargs))
                return {"token": "reservation-token"}

            def apply_group_reservations(self, token):
                self.calls.append(("reservation_apply", token))
                return {"applied": True}

            def set_group_smart_routing(self, group_id, enabled, actor):
                self.calls.append(("smart_routing", group_id, enabled, actor))
                return {"group": "Work", "enabled": enabled}

        control = RecordingControl()
        self.board.set_extra("router_control", control)
        credential = ("netpulse", "local-test-password")
        port = self.server.server_address[1]
        same_origin = {"Origin": f"http://127.0.0.1:{port}"}
        requests = (
            ("/api/device-groups/route/preview", {"id": 1, "route": "WAN1"}),
            ("/api/device-groups/route/apply", {"token": "preview-token"}),
            ("/api/device-groups/reservations/preview", {"id": 1}),
            ("/api/device-groups/reservations/apply", {"token": "reservation-token"}),
            ("/api/device-groups/smart-routing", {"id": 1, "enabled": True}),
        )
        for path, body in requests:
            self.assertEqual(self.request(path, method="POST", body=body)[0], 401)
            for origin in (None, "https://evil.example", "null"):
                headers = {"Origin": origin} if origin is not None else None
                status, _, _ = self.request(path, credential, "POST", body, headers)
                self.assertEqual(status, 403, (path, origin))
                self.assertEqual(control.calls, [])

        status, _, _ = self.request(requests[0][0], credential, "POST", requests[0][1], same_origin)
        self.assertEqual(status, 200)
        self.assertEqual([call[0] for call in control.calls], ["preview"])
        status, _, _ = self.request(requests[1][0], credential, "POST", requests[1][1], same_origin)
        self.assertEqual(status, 200)
        self.assertEqual([call[0] for call in control.calls], ["preview", "apply"])
        status, _, _ = self.request(requests[2][0], credential, "POST", requests[2][1], same_origin)
        self.assertEqual(status, 200)
        self.assertEqual(control.calls[-1][0], "reservation_preview")
        status, _, _ = self.request(requests[3][0], credential, "POST", requests[3][1], same_origin)
        self.assertEqual(status, 200)
        self.assertEqual(control.calls[-1], ("reservation_apply", "reservation-token"))
        status, _, _ = self.request(requests[4][0], credential, "POST", requests[4][1], same_origin)
        self.assertEqual(status, 200)
        self.assertEqual(control.calls[-1], ("smart_routing", 1, True, "dashboard"))

    def test_setup_generates_verifier_and_reset_rotates_password(self):
        path = Path(self.tmp.name) / "generated.auth"
        first = web_setup.create(path)
        self.assertIsNotNone(first)
        auth = web._read_auth_file(str(path))
        self.assertTrue(web._password_matches("Basic " + base64.b64encode(f"netpulse:{first}".encode()).decode(), auth))
        self.assertIsNone(web_setup.create(path))
        second = web_setup.create(path, reset=True)
        auth = web._read_auth_file(str(path))
        self.assertNotEqual(first, second)
        self.assertFalse(web._password_matches("Basic " + base64.b64encode(f"netpulse:{first}".encode()).decode(), auth))
        self.assertTrue(web._password_matches("Basic " + base64.b64encode(f"netpulse:{second}".encode()).decode(), auth))

    def test_auth_rate_limiter_expires_attempts(self):
        limiter = web._AuthRateLimiter(limit=3, window=10)
        for at in (0.0, 1.0, 2.0):
            limiter.failed("192.0.2.8", at)
        self.assertEqual(limiter.retry_after("192.0.2.8", 2.0), 8)
        self.assertEqual(limiter.retry_after("192.0.2.8", 10.0), 0)


class TelegramOverHttp(unittest.TestCase):
    """The real TelegramBot (threads, JSON, long polling) against a fake Telegram server."""

    OWNER, FRIEND, STRANGER = 42, 77, 99

    def setUp(self):
        self.tg = FakeTelegram()
        self.addCleanup(self.tg.close)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = str(Path(tmp.name) / "t.db")
        Storage(path).close()
        self.bot = TelegramBot("123:test", str(self.OWNER), {"status": lambda: "STATUS", "help": lambda: "HELP"},
                               profile={"description": "d", "short_description": "s"},
                               store=KeyValueFile(path), api_base=self.tg.base)
        self.bot.start()
        self.addCleanup(self.bot.stop)

    def test_profile_is_set_on_start(self):
        calls = self.tg.wait_for(lambda m, b: m == "setMyShortDescription")
        methods = [m for m, _ in calls]
        self.assertIn("setMyCommands", methods)
        self.assertIn("setMyDescription", methods)

    def test_owner_gets_replies_with_buttons_stranger_gets_nothing(self):
        self.tg.message(self.STRANGER, "📶 Status")
        self.tg.message(self.OWNER, "📶 Status")
        calls = self.tg.wait_for(lambda m, b: m == "sendMessage" and b["chat_id"] == str(self.OWNER))
        reply = next(b for m, b in calls if m == "sendMessage" and b["chat_id"] == str(self.OWNER))
        self.assertEqual(reply["text"], "STATUS")
        self.assertIn("keyboard", reply["reply_markup"])
        time.sleep(0.3)
        self.assertEqual(self.tg.sent_to(self.STRANGER), [])

    def test_delivery_stats_count_telegram_api_acceptance_per_recipient(self):
        self.bot._deliver_message("Delivery check", str(self.OWNER), None)
        self.assertIn("Delivery check", self.tg.sent_to(self.OWNER))
        self.assertEqual(self.bot.delivery_stats(), {
            "accepted": 1, "failed": 0, "queue_dropped": 0, "queued": 0,
            "categories": {"device_notice": {"accepted": 0, "failed": 0, "queue_dropped": 0, "queued": 0}},
        })

    def test_device_notice_delivery_is_counted_by_category_without_content(self):
        self.bot.send_categorized("Private camera at 192.0.2.44", DEVICE_NOTICE_CATEGORY)
        item = self.bot._outbox.get_nowait()
        self.assertEqual(len(item), 4)
        self.assertEqual(item[3], DEVICE_NOTICE_CATEGORY)
        self.bot._record_delivery(category=item[3], queued=-1)
        self.bot._deliver_message(*item[:3], category=item[3])
        stats = self.bot.delivery_stats()
        self.assertEqual(stats["categories"][DEVICE_NOTICE_CATEGORY], {
            "accepted": 1, "failed": 0, "queue_dropped": 0, "queued": 0,
        })
        self.assertNotIn("Private camera", json.dumps(stats))

    def test_delivery_stats_count_failed_retries_without_message_content(self):
        bot = TelegramBot("123:test", str(self.OWNER), {"help": lambda: "help"})
        private_text = "Private device 192.0.2.44"
        with mock.patch.object(bot, "_call", return_value=None):
            with mock.patch("netpulse.notifications.telegram.time.sleep"):
                with self.assertLogs("netpulse.notifications.telegram", level="WARNING") as captured:
                    bot._deliver_message(private_text, str(self.OWNER), None)
        output = "\n".join(captured.output)
        self.assertNotIn(private_text, output)
        self.assertEqual(bot.delivery_stats(), {
            "accepted": 0, "failed": 1, "queue_dropped": 0, "queued": 0,
            "categories": {"device_notice": {"accepted": 0, "failed": 0, "queue_dropped": 0, "queued": 0}},
        })

    def test_delivery_stats_count_outbox_overflow(self):
        bot = TelegramBot("123:test", str(self.OWNER), {"help": lambda: "help"})
        for _ in range(bot._outbox.maxsize):
            bot._outbox.put_nowait(("pending", None, None))
        with self.assertLogs("netpulse.notifications.telegram", level="WARNING"):
            bot.send("one more")
        self.assertEqual(bot.delivery_stats(), {
            "accepted": 0, "failed": 0, "queue_dropped": 1, "queued": bot._outbox.maxsize,
            "categories": {"device_notice": {"accepted": 0, "failed": 0, "queue_dropped": 0, "queued": 0}},
        })

    def test_device_notice_queue_drop_is_counted_without_content(self):
        bot = TelegramBot("123:test", str(self.OWNER), {"help": lambda: "help"})
        for _ in range(bot._outbox.maxsize):
            bot._outbox.put_nowait(("pending", None, None))
        with self.assertLogs("netpulse.notifications.telegram", level="WARNING"):
            bot.send_categorized("Private device", DEVICE_NOTICE_CATEGORY)
        stats = bot.delivery_stats()
        self.assertEqual(stats["categories"][DEVICE_NOTICE_CATEGORY]["queue_dropped"], 1)
        self.assertNotIn("Private device", json.dumps(stats))

    def test_invite_approve_and_broadcast(self):
        self.tg.message(self.OWNER, "/invite")
        self.tg.wait_for(lambda m, b: m == "sendMessage" and "Invite open" in b.get("text", ""))
        self.tg.message(self.FRIEND, "hi", first_name="Asha")
        self.tg.wait_for(lambda m, b: m == "sendMessage" and "wants to use NetPulse" in b.get("text", ""))
        self.tg.press(self.OWNER, f"allow:{self.FRIEND}")
        self.tg.wait_for(lambda m, b: m == "sendMessage" and "You're in" in b.get("text", ""))
        self.bot.send("🔴 Example ISP B is DOWN")   # alerts go to everyone allowed
        self.tg.wait_for(lambda m, b: m == "sendMessage" and b["chat_id"] == str(self.FRIEND)
                         and b["text"] == "🔴 Example ISP B is DOWN")
        self.assertIn("🔴 Example ISP B is DOWN", self.tg.sent_to(self.OWNER))


if __name__ == "__main__":
    unittest.main()
