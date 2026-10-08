from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from netpulse.main import Monitor
from netpulse.notifications.telegram import COMMANDS, OWNER_ONLY, TelegramBot
from netpulse.router.control import ControlError
from netpulse.storage import sqlite
from netpulse.storage.sqlite import Storage
from netpulse.web import app as web


class FakePauseControl:
    def __init__(self, enabled=True):
        self.enabled = enabled
        self.calls = []
        self.records_value = []
        self.records_error = None

    def state(self):
        return {"enabled": self.enabled, "reason": "Awaiting Internet pause validation"}

    def records(self):
        if self.records_error:
            raise self.records_error
        return self.records_value

    def preview(self, mac, **kwargs):
        self.calls.append(("preview", mac, kwargs))
        return {"token": "device-token", "action": kwargs["action"], "device": "TV", "mac": mac,
                "ip": "192.0.2.10", "expiry_label": "1 hour", "effect": "IPv4 Internet.", "count": 1}

    def preview_group(self, group_id, **kwargs):
        self.calls.append(("group", group_id, kwargs))
        return {"token": "group-token", "action": kwargs["action"], "group": "Work devices",
                "members": [{"name": "TV", "mac": "AA-BB-CC-DD-EE-01", "ip": "192.0.2.10"}],
                "expiry_label": "1 hour", "effect": "IPv4 Internet.", "count": 1}

    def apply(self, token, actor=None):
        self.calls.append(("apply", token, actor))
        if token == "expired":
            raise ControlError("This preview expired. Review the change again.")
        return {"action": "pause", "count": 1, "detail": "verified"}


class PauseTelegram(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = str(Path(self.tmp.name) / "bot.db")
        Storage(self.db).close()
        self.board = web.StatusBoard()
        self.control = FakePauseControl()
        self.router = SimpleNamespace(snap=SimpleNamespace(raw={
            "clients": [{"macaddr": "AA-BB-CC-DD-EE-01", "name": "TV"}], "reservations": []}))
        cfg = SimpleNamespace(db_path=self.db, router=SimpleNamespace(internet_controls_enabled=True),
                              system_health=SimpleNamespace(enabled=False))
        self.monitor = Monitor.__new__(Monitor)
        self.monitor.cfg = cfg
        self.monitor.board = self.board
        self.monitor.router = self.router
        self.monitor.router_control = None
        self.monitor.pause_control = self.control
        self.handlers = self.monitor.bot_handlers()
        self.bot = TelegramBot("token", "owner", self.handlers)
        self.bot.members = ["member"]

    def test_all_pause_commands_are_registered_owner_only(self):
        for command, handler in (("/pause", "pause"), ("/resume", "resume"), ("/paused", "paused"),
                                 ("/group_pause", "group_pause"), ("/group_resume", "group_resume"),
                                 ("/pause_confirm", "pause_confirm")):
            self.assertEqual(COMMANDS[command], handler)
            self.assertIn(handler, OWNER_ONLY)
            self.assertIn(handler, self.handlers)

    def test_nonowner_cannot_call_handler_or_apply_a_token(self):
        sent = []
        self.bot.send = lambda text, chat=None, markup=None: sent.append((text, chat))
        self.bot._handle({"chat": {"id": "member"}, "text": "/pause_confirm token"})
        self.assertIn("Only the owner", sent[-1][0])
        self.assertEqual(self.control.calls, [])

    def test_device_name_and_group_names_with_spaces_preview_without_writes(self):
        mac = "AA-BB-CC-DD-EE-01"
        sqlite.set_device_label(self.db, mac, "Living Room TV")
        group = sqlite.save_device_group(self.db, "Work devices", [mac], 100)
        self.assertIn("Review Internet pause", self.handlers["pause"]("/pause Living Room TV 15m", "owner"))
        self.assertEqual(self.control.calls[-1][1], mac)
        self.assertEqual(self.control.calls[-1][2]["duration_seconds"], 900)
        self.assertEqual(self.control.calls[-1][2]["actor"], "telegram owner:owner")
        self.assertIn("Work devices", self.handlers["group_pause"]("/group_pause Work devices 6h", "owner"))
        self.assertEqual(self.control.calls[-1][1], group["id"])
        self.assertEqual(self.control.calls[-1][2]["duration_seconds"], 21600)
        self.assertFalse(any(call[0] == "apply" for call in self.control.calls))

    def test_resume_resolves_saved_paused_and_error_labels_when_device_is_offline(self):
        mac = "AA-BB-CC-DD-EE-01"
        self.router.snap.raw = {"clients": [], "reservations": []}
        for state in ("paused", "error"):
            with self.subTest(state=state):
                self.control.calls.clear()
                self.control.records_value = [{"mac": mac, "label": "Offline demo device", "status": state}]
                reply = self.handlers["resume"]("/resume Offline demo device", "owner")
                self.assertIn("Review Internet resume", reply)
                self.assertEqual(self.control.calls[-1][1], mac)
                self.assertEqual(self.control.calls[-1][2]["actor"], "telegram owner:owner")

    def test_resume_rejects_ambiguous_match_between_current_device_and_saved_pause(self):
        current_mac = "AA-BB-CC-DD-EE-02"
        saved_mac = "AA-BB-CC-DD-EE-01"
        self.router.snap.raw = {"clients": [{"macaddr": current_mac, "name": "Offline demo device"}],
                                "reservations": []}
        self.control.records_value = [{"mac": saved_mac, "label": "Offline demo device", "status": "paused"}]
        reply = self.handlers["resume"]("/resume Offline demo device", "owner")
        self.assertIn("matches more than one MAC", reply)
        self.assertEqual(self.control.calls, [])

    def test_resume_rejects_two_saved_pause_labels_that_match(self):
        self.router.snap.raw = {"clients": [], "reservations": []}
        self.control.records_value = [
            {"mac": "AA-BB-CC-DD-EE-01", "label": "Offline demo device", "status": "paused"},
            {"mac": "AA-BB-CC-DD-EE-02", "label": "Offline demo device", "status": "error"},
        ]
        reply = self.handlers["resume"]("/resume Offline demo device", "owner")
        self.assertIn("matches more than one MAC", reply)
        self.assertEqual(self.control.calls, [])

    def test_hostname_resolves_for_current_device_pause(self):
        mac = "AA-BB-CC-DD-EE-03"
        self.router.snap.raw = {"clients": [{"macaddr": mac, "hostname": "Demo host name"}],
                                "reservations": []}
        reply = self.handlers["pause"]("/pause Demo host name 1h", "owner")
        self.assertIn("Review Internet pause", reply)
        self.assertEqual(self.control.calls[-1][1], mac)

    def test_non_resume_resolution_does_not_use_saved_pause_labels(self):
        self.router.snap.raw = {"clients": [], "reservations": []}
        self.control.records_value = [{"mac": "AA-BB-CC-DD-EE-01", "label": "Offline demo device", "status": "paused"}]
        reply = self.handlers["pause"]("/pause Offline demo device", "owner")
        self.assertIn("No router device matches that name", reply)
        self.assertEqual(self.control.calls, [])

        class FakeRouteControl:
            def __init__(self):
                self.calls = []

            def preview(self, *args):
                self.calls.append(args)
                return {}

        route_control = FakeRouteControl()
        self.monitor.router_control = route_control
        reply = self.handlers["route"]("/route Offline demo device WAN1", "owner")
        self.assertIn("No router device matches that name", reply)
        self.assertEqual(route_control.calls, [])

    def test_resume_by_raw_mac_is_unchanged_and_saved_store_errors_fail_closed(self):
        mac = "AA-BB-CC-DD-EE-01"
        self.router.snap.raw = {"clients": [], "reservations": []}
        self.control.records_value = [{"mac": mac, "label": "Offline demo device", "status": "paused"}]
        self.assertIn("Review Internet resume", self.handlers["resume"]("/resume aa:bb:cc:dd:ee:01", "owner"))
        self.assertEqual(self.control.calls[-1][1], mac)

        self.control.calls.clear()
        self.control.records_error = OSError("database unavailable")
        reply = self.handlers["resume"]("/resume Offline demo device", "owner")
        self.assertIn("identities are unavailable", reply)
        self.assertEqual(self.control.calls, [])

        self.control.records_error = None
        self.control.records_value = [{"mac": "invalid", "label": "Offline demo device", "status": "paused"}]
        reply = self.handlers["resume"]("/resume Offline demo device", "owner")
        self.assertIn("identities are invalid", reply)
        self.assertEqual(self.control.calls, [])

    def test_confirmation_is_chat_bound_and_expired_token_is_reported(self):
        self.assertIn("applied", self.handlers["pause_confirm"]("/pause_confirm token", "owner"))
        self.assertEqual(self.control.calls[-1], ("apply", "token", "telegram owner:owner"))
        self.assertIn("expired", self.handlers["pause_confirm"]("/pause_confirm expired", "owner"))

    def test_disabled_pause_reports_validation_reason_without_preview(self):
        self.control.enabled = False
        reply = self.handlers["pause"]("/pause AA-BB-CC-DD-EE-01", "owner")
        self.assertIn("Internet pause has not been enabled", reply)
        self.assertEqual(self.control.calls, [])


if __name__ == "__main__":
    unittest.main()
