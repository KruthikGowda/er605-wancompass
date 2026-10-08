import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from netpulse import summary
from netpulse.config import TelegramConfig
from netpulse.notifications.alerts import Alerter, in_quiet_hours
from netpulse.notifications.base import DEVICE_NOTICE_CATEGORY, Notifier
from netpulse.notifications.telegram import TelegramBot, parse_command
from netpulse.storage import sqlite
from netpulse.storage.sqlite import Storage
from tools.telegram_setup import set_keys


class Capture(Notifier):
    def __init__(self):
        self.sent = []

    def send(self, text):
        self.sent.append(text)


def at(hour, minute=0):
    """Epoch for today at local hh:mm."""
    lt = time.localtime()
    return time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday, hour, minute, 0, 0, 0, -1))


class Commands(unittest.TestCase):
    def test_buttons_and_commands(self):
        self.assertEqual(parse_command("📶 Status"), "status")
        self.assertEqual(parse_command("📈 Last 24h"), "today")
        self.assertEqual(parse_command("📊 Last 7d"), "week")
        self.assertEqual(parse_command("/week"), "week")
        self.assertEqual(parse_command("/mute"), "mute")
        self.assertEqual(parse_command("/status@MyNetPulseBot"), "status")
        self.assertEqual(parse_command("/pi"), "pi")
        self.assertEqual(parse_command("/devices"), "devices")
        self.assertEqual(parse_command("/group_suggest"), "group_suggest")
        self.assertEqual(parse_command("🩺 Pi health"), "pi")
        self.assertEqual(parse_command("📦 Device groups"), "groups")
        self.assertEqual(parse_command("🧾 Reserve group"), "group_reserve")
        self.assertEqual(parse_command("🔎 Device details"), "device")
        self.assertEqual(parse_command("/group_route@MyNetPulseBot Work WAN1"), "group_route")
        self.assertEqual(parse_command("/group_reserve@MyNetPulseBot Example Work Group"), "group_reserve")
        self.assertEqual(parse_command("/group_smart@MyNetPulseBot Example Work Group on"), "group_smart")
        self.assertIsNone(parse_command("hello"))

    def test_profile_texts_fit_telegram_limits(self):
        from netpulse.notifications.telegram import KEYBOARD, MENU, profile_texts
        p = profile_texts(["Example ISP A", "Example ISP B"])
        self.assertIn("Example ISP A and Example ISP B", p["description"])
        self.assertLessEqual(len(p["description"]), 512)
        self.assertLessEqual(len(p["short_description"]), 120)
        for c in MENU:
            self.assertRegex(c["command"], r"^[a-z0-9_]{1,32}$")
            self.assertLessEqual(len(c["description"]), 256)
        self.assertLessEqual(len(MENU), 10)
        self.assertIn("help", {c["command"] for c in MENU})
        self.assertLessEqual(len(KEYBOARD["keyboard"]), 4)

    def test_only_configured_chats_are_answered(self):
        bot = TelegramBot("123:abc", "42, 77", {"status": lambda: "ok", "help": lambda: "help"})
        self.assertEqual(bot.chat_ids, ["42", "77"])
        bot._handle({"chat": {"id": 999}, "text": "📶 Status"})
        self.assertTrue(bot._outbox.empty())
        bot._handle({"chat": {"id": 42}, "text": "📶 Status"})
        self.assertEqual(bot._outbox.get_nowait(), ("ok", "42", None))      # reply goes to the asker only
        bot._handle({"chat": {"id": 77}, "text": "what?"})
        self.assertEqual(bot._outbox.get_nowait(), ("help", "77", None))

    def test_group_control_commands_are_owner_only(self):
        bot = TelegramBot("123:abc", "42", {"groups": lambda: "group list",
                          "group_reserve": lambda text, chat: "reservation preview",
                          "group_reserve_confirm": lambda text, chat: "reservations applied",
                          "group_route": lambda text, chat: "route preview",
                          "group_confirm": lambda text, chat: "route applied",
                          "group_smart": lambda text, chat: "smart updated"})
        bot.members["77"] = "Household member"
        for command in ("/groups", "/group_reserve Work", "/group_reserve_confirm token",
                        "/group_suggest Work",
                        "/group_route Work WAN1", "/group_confirm token",
                        "/group_smart Work devices on", "/device Laptop"):
            bot._handle({"chat": {"id": 77}, "text": command})
            self.assertEqual(bot._outbox.get_nowait(), ("Only the owner can do that.", "77", None))
        bot._handle({"chat": {"id": 42}, "text": "/groups"})
        self.assertEqual(bot._outbox.get_nowait(), ("group list", "42", None))

    def test_alerts_go_to_everyone(self):
        bot = TelegramBot("123:abc", "42,77", {"help": lambda: "help"})
        bot.send("🔴 Example ISP A is DOWN")
        self.assertEqual(bot._outbox.get_nowait(), ("🔴 Example ISP A is DOWN", None, None))  # None = all allowed chats


class AlertPolicy(unittest.TestCase):
    def setUp(self):
        self.out = Capture()
        self.a = Alerter(self.out, TelegramConfig(quiet_start="23:00", quiet_end="07:00"))

    def test_quiet_hours_wrap_midnight(self):
        self.assertTrue(in_quiet_hours(23 * 60 + 30, 23 * 60, 7 * 60))
        self.assertTrue(in_quiet_hours(3 * 60, 23 * 60, 7 * 60))
        self.assertFalse(in_quiet_hours(12 * 60, 23 * 60, 7 * 60))

    def test_quiet_hours_hold_non_critical_only(self):
        self.assertFalse(self.a.alert("slow", "WAN1", now=at(2)))
        self.assertTrue(self.a.alert("down", "WAN1", critical=True, now=at(2)))
        self.assertEqual(self.out.sent, ["down"])

    def test_rate_limit_and_mute(self):
        self.assertTrue(self.a.alert("slow", "WAN1", now=at(12)))
        self.assertFalse(self.a.alert("bad", "WAN1", now=at(12, 1)))    # within 5 min
        self.assertTrue(self.a.alert("slow", "WAN2", now=at(12, 1)))    # other WAN
        self.a.mute(3600)
        self.assertFalse(self.a.alert("slow", "WAN1", now=time.time() + 600))
        self.assertTrue(self.a.alert("down", "WAN1", critical=True))
        self.a.unmute()
        self.assertEqual(self.a.muted_until(), 0)

    def test_mute_suppression_log_names_reason_without_alert_content(self):
        self.a.mute(3600)
        private_text = "Private laptop at 192.0.2.8"
        with self.assertLogs("netpulse.notifications.alerts", level="INFO") as captured:
            self.assertFalse(self.a.alert(private_text, "private-device-key"))

        output = "\n".join(captured.output)
        self.assertIn("mute policy", output)
        self.assertNotIn(private_text, output)
        self.assertNotIn("private-device-key", output)

    def test_quiet_suppression_log_names_reason_without_alert_content(self):
        private_text = "Private laptop at 192.0.2.8"
        with mock.patch("netpulse.notifications.alerts.in_quiet_hours", return_value=True):
            with self.assertLogs("netpulse.notifications.alerts", level="INFO") as captured:
                self.assertFalse(self.a.alert(private_text, "private-device-key", now=at(12)))

        output = "\n".join(captured.output)
        self.assertIn("quiet-hours policy", output)
        self.assertNotIn(private_text, output)
        self.assertNotIn("private-device-key", output)

    def test_rate_limit_log_does_not_include_alert_content(self):
        self.assertTrue(self.a.alert("first", "private-device-key", now=at(12)))
        private_text = "Private laptop at 192.0.2.8"
        with self.assertLogs("netpulse.notifications.alerts", level="INFO") as captured:
            self.assertFalse(self.a.alert(private_text, "private-device-key", now=at(12, 1)))

        output = "\n".join(captured.output)
        self.assertIn("alert rate-limited (category=other)", output)
        self.assertNotIn(private_text, output)
        self.assertNotIn("private-device-key", output)

    def test_rate_limit_log_names_fixed_device_category_without_identity(self):
        from netpulse.notifications.base import DEVICE_NOTICE_CATEGORY

        self.assertTrue(self.a.alert("first", "private-device-key", now=at(12),
                                     delivery_category=DEVICE_NOTICE_CATEGORY))
        private_text = "Example phone at 192.168.0.121"
        with self.assertLogs("netpulse.notifications.alerts", level="INFO") as captured:
            self.assertFalse(self.a.alert(private_text, "private-device-key", now=at(12, 1),
                                          delivery_category=DEVICE_NOTICE_CATEGORY))

        output = "\n".join(captured.output)
        self.assertIn("alert rate-limited (category=device_notice)", output)
        self.assertNotIn(private_text, output)
        self.assertNotIn("private-device-key", output)

    def test_suppression_counts_are_reasoned_and_reset_for_a_new_alerter(self):
        self.a.mute(3600)
        self.assertFalse(self.a.alert("private notice", "muted"))
        self.a.unmute()
        with mock.patch("netpulse.notifications.alerts.in_quiet_hours", return_value=True):
            self.assertFalse(self.a.alert("private notice", "quiet", now=at(12)))
        with mock.patch("netpulse.notifications.alerts.in_quiet_hours", return_value=False):
            self.assertTrue(self.a.alert("sent", "limited", now=at(12)))
            self.assertFalse(self.a.alert("private notice", "limited", now=at(12, 1)))

        self.assertEqual(self.a.suppression_counts(),
                         {"mute": 1, "quiet_hours": 1, "rate_limited": 1})
        restarted = Alerter(self.out, TelegramConfig(quiet_start="23:00", quiet_end="07:00"))
        self.assertEqual(restarted.suppression_counts(),
                         {"mute": 0, "quiet_hours": 0, "rate_limited": 0})

    def test_device_notice_suppression_is_counted_without_exposing_the_alert_key(self):
        self.a.mute(3600)
        self.assertFalse(self.a.alert("private device", "device-AA:BB", delivery_category=DEVICE_NOTICE_CATEGORY))
        self.assertEqual(self.a.category_suppression_counts(DEVICE_NOTICE_CATEGORY), {
            "mute": 1, "quiet_hours": 0, "rate_limited": 0,
        })

    def test_device_notice_uses_categorized_notifier_without_changing_message(self):
        class CategorizedCapture(Capture):
            def __init__(self):
                super().__init__()
                self.categories = []

            def send_categorized(self, text, category):
                self.sent.append(text)
                self.categories.append(category)

        out = CategorizedCapture()
        alerter = Alerter(out, TelegramConfig(quiet_start="23:00", quiet_end="07:00"))
        self.assertTrue(alerter.alert("New device notice", "device-private", now=at(12),
                                      delivery_category=DEVICE_NOTICE_CATEGORY))
        self.assertEqual(out.sent, ["New device notice"])
        self.assertEqual(out.categories, [DEVICE_NOTICE_CATEGORY])

    def test_alert_can_request_a_longer_per_key_rate_limit(self):
        self.assertTrue(self.a.alert("first", "device", now=at(12), rate_limit_seconds=1800))
        self.assertFalse(self.a.alert("repeat", "device", now=at(12, 20), rate_limit_seconds=1800))
        self.assertTrue(self.a.alert("after cooldown", "device", now=at(12, 30),
                                     rate_limit_seconds=1800))

    def test_opted_in_rate_limit_survives_a_new_alerter_instance(self):
        class Store:
            values = {}

            def get(self, key):
                return self.values.get(key)

            def set(self, key, value):
                self.values[key] = value

        store = Store()
        first = Alerter(self.out, TelegramConfig(quiet_start="23:00", quiet_end="07:00"), store)
        self.assertTrue(first.alert("first", "presence-AA", now=at(12),
                                    rate_limit_seconds=1800, persist_rate_limit=True))
        restarted = Alerter(self.out, TelegramConfig(quiet_start="23:00", quiet_end="07:00"), store)
        self.assertFalse(restarted.alert("repeat", "presence-AA", now=at(12, 20),
                                         rate_limit_seconds=1800, persist_rate_limit=True))
        self.assertTrue(restarted.alert("after cooldown", "presence-AA", now=at(12, 30),
                                        rate_limit_seconds=1800, persist_rate_limit=True))

    def test_persistent_rate_limit_storage_failure_never_blocks_alert_delivery(self):
        class BrokenStore:
            def get(self, _key):
                raise OSError("database unavailable")

            def set(self, _key, _value):
                raise OSError("database unavailable")

        alert = Alerter(self.out, TelegramConfig(quiet_start="23:00", quiet_end="07:00"),
                        BrokenStore())
        self.assertTrue(alert.alert("first", "presence-AA", now=at(12),
                                    rate_limit_seconds=1800, persist_rate_limit=True))
        self.assertFalse(alert.alert("repeat", "presence-AA", now=at(12, 10),
                                     rate_limit_seconds=1800, persist_rate_limit=True))
        self.assertEqual(self.out.sent, ["first"])


def wan(name, label, state, rtt=20.0):
    return {"name": name, "label": label, "state": state, "rtt_ms": rtt, "loss_pct": 0.0,
            "jitter_ms": 1.0, "score": 99, "reasons": [], "errors": [], "targets": []}


class Headlines(unittest.TestCase):
    def test_status_alert_policy_explains_disabled_muted_quiet_and_active_states(self):
        base = {"alert_policy": {"telegram_enabled": True, "quiet_start": "23:00",
                                 "quiet_end": "07:00"}}
        self.assertIn("quiet hours until 07:00", summary.alert_policy_line(base, at(23, 30)))
        self.assertIn("quiet hours start at 23:00", summary.alert_policy_line(base, at(12)))
        muted = {**base, "muted_until": at(10)}
        self.assertIn("muted until 10:00", summary.alert_policy_line(muted, at(9)))
        disabled = {"alert_policy": {"telegram_enabled": False}}
        self.assertEqual(summary.alert_policy_line(disabled, at(12)), "Telegram alerts are disabled.")

    def test_status_policy_with_equal_quiet_times_reports_quiet_hours_off(self):
        policy = {"alert_policy": {"telegram_enabled": True,
                                    "quiet_start": "00:00", "quiet_end": "00:00"}}
        self.assertIn("quiet hours are off", summary.alert_policy_line(policy, at(12)))

    def test_status_alert_policy_reports_privacy_safe_suppression_counts(self):
        policy = {"alert_policy": {"telegram_enabled": True, "quiet_start": "23:00",
                                   "quiet_end": "07:00",
                                   "suppressed_since_start": {
                                       "mute": 2, "quiet_hours": 3, "rate_limited": 1}}}

        text = summary.alert_policy_line(policy, at(12))

        self.assertIn("Since NetPulse started: 2 held by mute, 3 by quiet hours, 1 rate-limited", text)

    def test_status_alert_policy_reports_telegram_api_delivery_counts(self):
        policy = {"alert_policy": {"telegram_enabled": True, "quiet_start": "23:00",
                                   "quiet_end": "07:00", "delivery_since_start": {
                                       "accepted": 4, "failed": 1, "queue_dropped": 2, "queued": 3}}}
        text = summary.alert_policy_line(policy, at(12))
        self.assertIn("Telegram API accepted 4 recipient message(s)", text)
        self.assertIn("3 queued, 1 failed after retries, 2 dropped before sending", text)

    def test_status_reports_device_notice_delivery_and_policy_outcomes(self):
        policy = {"alert_policy": {
            "telegram_enabled": True, "quiet_start": "23:00", "quiet_end": "07:00",
            "device_notice_suppressed_since_start": {"mute": 1, "quiet_hours": 2, "rate_limited": 3},
            "delivery_since_start": {"accepted": 5, "failed": 0, "queue_dropped": 0, "queued": 0,
                                      "categories": {"device_notice": {
                                          "accepted": 2, "failed": 1, "queue_dropped": 3, "queued": 4}}},
        }}
        text = summary.alert_policy_line(policy, at(12))
        self.assertIn("Device notices: 2 accepted by Telegram, 4 queued, 1 failed after retries, 3 dropped", text)
        self.assertIn("1 muted, 2 held by quiet hours, 3 rate-limited", text)

    def test_all_good(self):
        h = summary.headline({"wans": [wan("WAN1", "Example ISP A", "HEALTHY"), wan("WAN2", "Example ISP B", "HEALTHY")]})
        self.assertEqual(h["level"], "HEALTHY")

    def test_one_slow(self):
        snap = {"wans": [wan("WAN1", "Example ISP A", "DEGRADED"), wan("WAN2", "Example ISP B", "HEALTHY")],
                "decision": {"current": "WAN2"}}
        h = summary.headline(snap)
        self.assertEqual(h["level"], "DEGRADED")
        self.assertIn("Example ISP A is slow", h["text"])
        self.assertIn("Example ISP B is fine", h["text"])
        self.assertIn("Best for critical devices: Example ISP B", h["text"])

    def test_starting_up(self):
        self.assertEqual(summary.headline({"wans": [wan("WAN1", "Example ISP A", "UNKNOWN")]})["level"], "UNKNOWN")

    def test_status_text_is_short_when_healthy(self):
        w = wan("WAN1", "Example ISP A", "HEALTHY")
        w["targets"] = [{"target": "1.1.1.1", "rtt_ms": 29.3}]
        text = summary.status_text({"wans": [w]})
        self.assertIn("Example ISP A: 20 ms · no packet loss", text)
        self.assertNotIn("Cloudflare", text)

    def test_status_text_includes_fresh_dns_https_and_isp_dns_evidence(self):
        w = wan("WAN1", "Example ISP A", "HEALTHY")
        w["connectivity"] = {"checked_at": time.time() - 10, "icmp_state": "HEALTHY",
                             "dns_ok": True, "wan_dns_ok": False, "https_ok": True,
                             "diagnosis": "direct DNS reachable; ISP DNS failed"}

        text = summary.status_text({"wans": [w]})

        self.assertIn("DNS/HTTPS (", text)
        self.assertIn("ICMP healthy at sample", text)
        self.assertIn("direct DNS reachable · ISP DNS failed · HTTPS reachable", text)

    def test_status_text_omits_stale_or_future_dns_https_evidence(self):
        for checked_at in (time.time() - 181, time.time() + 1):
            with self.subTest(checked_at=checked_at):
                w = wan("WAN1", "Example ISP A", "HEALTHY")
                w["connectivity"] = {"checked_at": checked_at, "icmp_state": "HEALTHY",
                                     "dns_ok": True, "https_ok": True}
                self.assertNotIn("DNS/HTTPS", summary.status_text({"wans": [w]}))

    def test_status_text_explains_problems_in_plain_words(self):
        w = wan("WAN1", "Example ISP A", "DEGRADED", rtt=140)
        w["reasons"] = ["loss 7% >= 5%", "RTT 4.4x baseline"]
        w["targets"] = [{"target": "1.1.1.1", "rtt_ms": 151}]
        text = summary.status_text({"wans": [w]})
        self.assertIn("why: 7% of packets lost; 4.4× slower than usual", text)
        self.assertIn("Cloudflare 151", text)


class Digest(unittest.TestCase):
    def test_digest_from_storage(self):
        with tempfile.TemporaryDirectory() as d:
            path = str(Path(d) / "t.db")
            s = Storage(path)
            base = int(time.time()) - 3 * 3600
            rows = []
            for i in range(120):
                ts = base + i * 60
                rows.append((ts, "WAN1", "BAD" if i < 30 else "HEALTHY", 50, 12 if i < 30 else 0, 90, 5, 100))
                rows.append((ts, "WAN2", "HEALTHY", 99, 0, 16, 1, 100))
            s.write_minute(rows, [(base, "state", "WAN1", "Example ISP A (WAN1): HEALTHY -> OFFLINE (x)")], [])
            s.set_value("last_digest_date", "2026-01-01")
            self.assertEqual(s.get_value("last_digest_date"), "2026-01-01")
            s.close()

            p = sqlite.period_summary(path, base - 1, int(time.time()))
            self.assertEqual(p["wans"]["WAN1"]["minutes"], {"BAD": 30, "HEALTHY": 90})
            self.assertEqual(p["wans"]["WAN1"]["outages"], 1)
            text = summary.digest_text(p, {"WAN1": "Example ISP A", "WAN2": "Example ISP B"}, "Daily")
            self.assertIn("Example ISP A (WAN1)", text)
            self.assertIn("bad 30 min", text)
            self.assertIn("went down 1×", text)
            self.assertIn("Example ISP B was the more reliable connection", text)


class SetupConfigEdit(unittest.TestCase):
    def test_set_keys_only_touches_section(self):
        src = '[web]\nport = 8080\n\n[telegram]\nenabled = false\nbot_token = ""\n# note\nquiet_start = "23:00"\n'
        out = set_keys(src, "telegram", {"enabled": "true", "bot_token": '"1:x"', "chat_id": '"42"'})
        self.assertIn("port = 8080", out)
        self.assertIn('enabled = true', out)
        self.assertIn('bot_token = "1:x"', out)
        self.assertIn('chat_id = "42"', out)
        self.assertIn('quiet_start = "23:00"', out)
        self.assertIn("# note", out)


if __name__ == "__main__":
    unittest.main()
