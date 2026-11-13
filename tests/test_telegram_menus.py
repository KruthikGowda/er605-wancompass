import tempfile
import unittest
from dataclasses import replace
from unittest.mock import Mock

from netpulse.config import TelegramConfig, _validate
from netpulse.notifications.telegram import TelegramBot, KEYBOARD
from netpulse.storage import sqlite
from tests.harness import Scenario, local


class MenuTests(unittest.TestCase):
    def setUp(self):
        self.runs = []
        self.bot = TelegramBot("test", "42", {
            "help": lambda: "help", "status": lambda: "status",
            "speeds": lambda: "saved speeds",
            "speed": lambda: self.runs.append(True) or "started",
            "dashboard_url": lambda: "http://192.0.2.4:8080/",
            "quick_choices": lambda: {"devices": [{"mac": "02-00-00-00-00-01", "name": "Laptop"}], "groups": []},
            "quick_preview": Mock(), "quick_apply": Mock(),
        })
        self.bot._call = Mock(return_value={"ok": True})
        self.bot.members["77"] = "Member"

    def tap(self, action, chat=42, sender=None, kind="private"):
        self.bot._handle_button({"id": "q", "from": {"id": chat if sender is None else sender},
                                 "data": "menu:" + action,
                                 "message": {"chat": {"id": chat, "type": kind}}})

    def out(self):
        return self.bot._outbox.get_nowait()

    @staticmethod
    def action(markup, label):
        return next(b["callback_data"][5:] for row in markup["inline_keyboard"] for b in row
                    if b["text"] == label)

    def test_start_installs_keyboard_and_clickable_dashboard_without_starting_tests(self):
        self.bot._handle({"chat": {"id": 42, "type": "private"}, "from": {"id": 42}, "text": "/start"})
        self.assertEqual(self.out()[2], KEYBOARD)
        _, chat, markup = self.out()
        self.assertEqual(chat, "42")
        self.assertIn({"text": "🌐 Open dashboard", "url": "http://192.0.2.4:8080/"},
                      [b for row in markup["inline_keyboard"] for b in row])
        self.tap("speeds")
        self.assertEqual(self.out()[0], "saved speeds")
        self.assertEqual(self.runs, [])

    def test_private_owner_only_mutations_reject_members_forwarded_and_group_callbacks(self):
        for action in ("test", "mute", "devices", "groups", "paused", "controls", "alerts"):
            self.tap(action, chat=77)
            self.assertEqual(self.out()[0], "Only the owner can do that.")
            self.tap(action, chat=42, sender=77)
            self.tap(action, chat=42, kind="group")
            self.tap(action, chat=999)
            self.assertTrue(self.bot._outbox.empty())
        self.assertEqual(self.runs, [])

    def test_controls_explain_locks_and_help_uses_buttons_instead_of_command_instructions(self):
        self.bot.handlers["quick_control_status"] = lambda: {"actions": [
            {"id": "pause", "label": "Pause", "enabled": False, "reason": "Firmware not validated"}]}
        self.tap("controls")
        text, _, markup = self.out()
        self.assertIn("Pause unavailable: Firmware not validated", text)
        self.assertIn("menu:paused", str(markup))
        self.tap("help")
        text, _, markup = self.out()
        self.assertIn("Button guide", text)
        self.assertNotIn("/pause", text)
        self.assertIn("menu:devices", str(markup))

    def test_every_report_and_alert_button_reaches_its_handler(self):
        called = []
        for action in ("status", "speeds", "pi", "today", "week", "mute", "unmute", "paused"):
            self.bot.handlers[action] = lambda key=action: called.append(key) or key
            self.tap(action)
            self.assertEqual(self.out()[0], action)
        self.assertEqual(called, ["status", "speeds", "pi", "today", "week", "mute", "unmute", "paused"])

    def test_test_confirmation_is_one_use_expiring_and_invalidated_by_navigation(self):
        self.bot._menus.clock = lambda: 100
        self.tap("test")
        text, _, markup = self.out()
        self.assertIn("Pi's Ethernet", text)
        action = self.action(markup, "Run Pi test")
        self.assertEqual(self.runs, [])
        self.tap(action)
        self.assertEqual(self.out()[0], "started")
        self.tap(action)
        self.assertIn("already used", self.out()[0])
        self.assertEqual(len(self.runs), 1)
        self.tap("test")
        action = self.action(self.out()[2], "Run Pi test")
        self.bot._menus.clock = lambda: 221
        self.tap(action)
        self.assertIn("expired", self.out()[0])
        self.tap("test")
        action = self.action(self.out()[2], "Run Pi test")
        self.tap("speeds")
        self.out()
        self.tap(action)
        self.assertIn("expired", self.out()[0])
        self.assertEqual(len(self.runs), 1)

    def test_devices_open_existing_picker_and_menu_navigation_invalidates_it(self):
        self.tap("devices")
        text, _, markup = self.out()
        self.assertIn("Devices", text)
        callback = markup["inline_keyboard"][0][0]["callback_data"]
        self.assertTrue(self.bot._quick_picker.active("42", "42"))
        self.tap("home")
        self.out()
        self.assertFalse(self.bot._quick_picker.active("42", "42"))
        self.bot._handle_button({"id": "q", "data": callback, "from": {"id": 42},
                                 "message": {"chat": {"id": 42, "type": "private"}}})
        self.bot.handlers["quick_apply"].assert_not_called()
        self.bot.handlers["quick_preview"].assert_not_called()

    def test_late_service_handler_binding_initializes_picker_before_polling(self):
        hooks = dict(self.bot.handlers)
        bot = TelegramBot("test", "42", {})
        self.assertIsNone(bot._quick_picker)
        bot.set_handlers(hooks)
        bot._handle({"chat": {"id": 42, "type": "private"}, "from": {"id": 42}, "text": "📱 Devices"})
        text, _, markup = bot._outbox.get_nowait()
        self.assertIn("Devices", text)
        self.assertIn("qp:", str(markup))
        self.assertTrue(bot._quick_picker.active("42", "42"))
        hooks["quick_apply"].assert_not_called()


class SavedSpeedMenuTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.scenario = Scenario(self.tmp.name, local(12))
        self.addCleanup(self.scenario.close)

    def test_sources_are_separate_errors_are_visible_and_report_never_runs_a_test(self):
        scenario = self.scenario
        wan = scenario.cfg.wans[0].name
        for index, (source, speed, error) in enumerate([
            ("manual", 85, None), ("wired_pc", 430, None), ("wired_pc_ookla", 445, None),
            ("manual", None, "synthetic failure"),
        ]):
            sqlite.insert_speedtest(scenario.cfg.db_path, {
                "ts": scenario.clock.t - 100 + index, "wan": wan, "trigger": source,
                "down_mbps": speed, "up_mbps": 100, "error": error,
            })
        scenario.mon.start_speedtest = Mock(side_effect=AssertionError("Read-only report"))
        text = scenario.mon.bot_handlers()["speeds"]()
        self.assertIn("Wired PC · Cloudflare: ↓ 430.0", text)
        self.assertIn("Wired PC · Ookla: ↓ 445.0", text)
        self.assertIn("Pi · Cloudflare (Pi-limited): latest attempt failed", text)
        self.assertNotIn("↓ 85.0", text)
        self.assertIn("No saved measurement", text)

    def test_dashboard_link_rejects_embedded_credentials_and_tokens(self):
        for url in ("https://user:password@example.com/", "https://example.com/?token=secret",
                    "javascript:alert(1)", "http://example.com/#secret", "http://example.com/\n"):
            cfg = replace(self.scenario.cfg, telegram=TelegramConfig(dashboard_url=url))
            with self.subTest(url=url), self.assertRaises(ValueError):
                _validate(cfg)
        _validate(replace(self.scenario.cfg, telegram=TelegramConfig(dashboard_url="http://192.0.2.4:8080/")))
