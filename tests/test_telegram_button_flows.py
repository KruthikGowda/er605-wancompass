"""Exercise the real bot and monitor adapters using buttons only and fake writes."""
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock

from netpulse.notifications.telegram import TelegramBot
from netpulse.storage import sqlite
from tests.harness import Scenario, local


class ButtonFlows(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.s = Scenario(tmp.name, local(12))
        self.addCleanup(self.s.close)
        self.clients = [{"macaddr": f"02-00-00-00-00-{i:02X}", "name": f"Device {i:02}",
                         "ipaddr": f"192.0.2.{i + 10}"} for i in range(1, 11)]
        self.s.mon.router = SimpleNamespace(snap=SimpleNamespace(
            raw={"clients": self.clients}, checked_at=self.s.clock()))
        self.actions = [{"id": key, "label": label, "enabled": True} for key, label in (
            ("auto", "Auto"), ("prefer_wan1", "Prefer WAN 1"), ("prefer_wan2", "Prefer WAN 2"),
            ("pause", "Pause"), ("resume", "Resume"), ("only_wan1", "Only WAN 1"), ("only_wan2", "Only WAN 2"))]
        self.previews, self.applies, self.tokens = [], [], {}
        self.effect_version = "v1"

        def preview(**payload):
            self.previews.append(payload)
            macs = payload.get("macs")
            if macs is None:
                macs = next(g["members"] for g in sqlite.device_groups(self.s.cfg.db_path)
                            if g["id"] == payload["group_id"])
            token = f"private-token-{len(self.previews)}"
            self.tokens[token] = dict(payload)
            return {"token": token, "action": payload["action"], "reservation_count": 0,
                    "members": [{"mac": mac, "ip": "192.0.2.11", "name": "Synthetic device"}
                                for mac in macs], "effect": payload["action"] + self.effect_version}

        def apply(token, actor):
            self.assertEqual(actor, "telegram:101")
            self.assertEqual(self.tokens[token]["actor"], actor)
            self.applies.append(self.tokens[token])
            return {"count": 1}

        self.s.mon.action_control = SimpleNamespace(
            routes=SimpleNamespace(is_local_device=lambda mac: False),
            state=lambda: {"enabled": True, "actions": self.actions}, preview=preview, apply=apply)
        self.group = sqlite.save_device_group(self.s.cfg.db_path, "Home", [self.clients[0]["macaddr"]],
                                              int(self.s.clock()))
        self.bot = TelegramBot("synthetic", "101", {})
        self.bot.set_handlers(self.s.mon.bot_handlers())  # production late-binding path
        self.bot._call = Mock(return_value={"ok": True})
        self.messages = []
        self.bot.send = lambda text, chat=None, markup=None: self.messages.append((text, markup))
        self.bot._menus.show("home", "101", True)

    def button(self, label):
        return next(b for row in self.messages[-1][1]["inline_keyboard"] for b in row if b["text"] == label)

    def callback(self, data, sender=101, chat=101, kind="private"):
        self.bot._handle_button({"id": "synthetic", "data": data, "from": {"id": sender},
                                 "message": {"chat": {"id": chat, "type": kind}}})

    def tap(self, label):
        self.callback(self.button(label)["callback_data"])

    def select(self, kind="devices"):
        self.bot._menus.show("home", "101", True)
        self.tap("📱 Devices" if kind == "devices" else "👥 Groups")
        first = self.messages[-1][1]["inline_keyboard"][0][0]["text"]
        self.tap(first)
        self.tap("Choose action")

    def test_all_wan_actions_and_pause_durations_for_devices_and_groups_use_only_buttons(self):
        cases = [(key, label, None) for key, label in (
            ("auto", "Auto"), ("prefer_wan1", "Prefer WAN 1"), ("prefer_wan2", "Prefer WAN 2"),
            ("resume", "Resume"), ("only_wan1", "Only WAN 1"), ("only_wan2", "Only WAN 2"))]
        cases += [("pause", "Pause", duration) for duration in (
            ("15 minutes", 900), ("1 hour", 3600), ("6 hours", 21600), ("Until resumed", 0))]
        for kind in ("devices", "groups"):
            for action, label, duration in cases:
                with self.subTest(kind=kind, action=action, duration=duration):
                    before = len(self.applies)
                    self.select(kind)
                    self.tap(label)
                    if duration:
                        self.tap(duration[0])
                    self.assertEqual(len(self.applies), before)
                    self.assertNotIn("private-token", self.messages[-1][0])
                    confirm = self.button("✅ Confirm")["callback_data"]
                    self.tap("✅ Confirm")
                    self.assertEqual(len(self.applies), before + 1)
                    self.assertEqual(self.applies[-1]["action"], action)
                    self.assertEqual(self.applies[-1]["duration_seconds"], duration[1] if duration else 0)
                    if kind == "groups":
                        self.assertEqual(self.applies[-1]["group_id"], self.group["id"])
                    else:
                        self.assertEqual(self.applies[-1]["macs"], [self.clients[0]["macaddr"]])
                    self.callback(confirm)
                    self.assertEqual(len(self.applies), before + 1, "double-tap must not reapply")

    def test_selection_toggle_paging_and_back_preserve_exact_targets(self):
        self.tap("📱 Devices")
        first = self.messages[-1][1]["inline_keyboard"][0][0]["text"]
        self.tap(first)
        self.tap("✓ " + first)
        self.assertNotIn("Choose action", str(self.messages[-1][1]))
        self.tap(first)
        self.tap("More ›")
        ninth = self.messages[-1][1]["inline_keyboard"][0][0]["text"]
        self.tap(ninth)
        self.tap("Choose action")
        self.tap("Pause")
        self.tap("‹ Back")
        self.tap("Prefer WAN 2")
        self.tap("✅ Confirm")
        self.assertEqual(self.applies[-1]["macs"], [self.clients[0]["macaddr"], self.clients[8]["macaddr"]])
        self.assertEqual(self.applies[-1]["duration_seconds"], 0)

    def test_changed_action_indexes_cannot_select_a_different_wan(self):
        self.select()
        old = self.button("Prefer WAN 1")["callback_data"]
        self.actions[1], self.actions[2] = self.actions[2], self.actions[1]
        self.callback(old)
        self.assertIn("action changed", self.messages[-1][0])
        self.assertEqual(self.previews, [])
        self.tap("Prefer WAN 1")
        self.tap("✅ Confirm")
        self.assertEqual(self.applies[-1]["action"], "prefer_wan1")

    def test_cancel_foreign_expired_and_changed_reviews_never_apply(self):
        self.select()
        self.tap("Prefer WAN 1")
        confirm = self.button("✅ Confirm")["callback_data"]
        self.callback(confirm, sender=202)
        self.callback(confirm, chat=202)
        self.callback(confirm, kind="group")
        self.assertEqual(self.applies, [])
        # Foreign callbacks may emit an expiry notice; the owner's real review survives.
        self.effect_version = "v2"
        self.callback(confirm)
        self.assertIn("review changed", self.messages[-1][0])
        self.assertEqual(self.applies, [])
        self.tap("Cancel")
        self.callback(confirm)
        self.assertEqual(self.applies, [])
        self.select()
        self.tap("Resume")
        confirm = self.button("✅ Confirm")["callback_data"]
        self.bot._quick_picker._clock = lambda: 10**20
        self.callback(confirm)
        self.assertIn("expired", self.messages[-1][0])
        self.assertEqual(self.applies, [])

    def test_group_create_rename_and_delete_need_no_typed_name_or_token(self):
        self.tap("👥 Groups")
        self.tap("➕ Create group")
        self.assertNotIn("Home", [b["text"] for row in self.messages[-1][1]["inline_keyboard"] for b in row])
        self.tap("Work")
        self.tap(self.messages[-1][1]["inline_keyboard"][1][0]["text"])
        self.tap("Review changes")
        self.tap("✅ Confirm")
        self.assertIn("Work", [g["name"] for g in sqlite.device_groups(self.s.cfg.db_path)])
        self.bot._menus.show("home", "101", True)
        self.tap("👥 Groups")
        self.tap("Work")
        self.tap("Choose action")
        self.tap("Rename group")
        self.tap("Family")
        self.tap("✅ Confirm")
        self.assertIn("Family", [g["name"] for g in sqlite.device_groups(self.s.cfg.db_path)])
        self.bot._menus.show("home", "101", True)
        self.tap("👥 Groups")
        self.tap("Family")
        self.tap("Choose action")
        self.tap("Delete group")
        self.tap("✅ Confirm")
        self.assertEqual([g["name"] for g in sqlite.device_groups(self.s.cfg.db_path)], ["Home"])
        self.assertEqual(self.applies, [], "group naming must not call router apply")

    def test_main_menu_keyboard_escapes_group_name_prompt_instead_of_creating_a_group(self):
        self.tap("👥 Groups")
        self.tap("➕ Create group")
        self.bot._handle({"chat": {"id": 101, "type": "private"}, "from": {"id": 101},
                          "text": "🏠 Main menu"})
        self.assertIn("WANCompass", self.messages[-1][0])
        self.assertIn("menu:devices", str(self.messages[-1][1]))
        self.assertFalse(self.bot._quick_picker.active("101", "101"))
        self.assertEqual([g["name"] for g in sqlite.device_groups(self.s.cfg.db_path)], ["Home"])
