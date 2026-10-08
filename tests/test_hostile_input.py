"""Hostile names: text from outside NetPulse must be shown as text, never run as code.

Outside text includes: device names from the router's DHCP list (any device can name itself
"<script>..."), Telegram display names, ping error messages, and ISP labels in the config.
"""

import csv
import io
import re
import tempfile
import time
import unittest
from pathlib import Path

from netpulse.notifications import telegram as tg_module
from netpulse.notifications.telegram import TelegramBot
from netpulse.storage.sqlite import Storage
from netpulse.web import report

ROOT = Path(__file__).resolve().parent.parent
EVIL = '<img src=x onerror="alert(1)"><script>alert(2)</script>'

# Text fields that arrive from the API and may carry outside text.
TEXT_FIELDS = r"(label|name|ip|mac|lease|message|why|reasons|errors|error|model|text|colo|public_ip|target|emoji)"
# Code that turns a value into safe HTML text (or never produces HTML).
SAFE_WRAPPERS = ("esc(", "labelOf(", "colorOf(", "encodeURIComponent(", "SERVER[")


class DashboardEscaping(unittest.TestCase):
    """Static guard: API text fields must be escaped wherever they're put into HTML."""

    html = (ROOT / "netpulse" / "web" / "static" / "index.html").read_text(encoding="utf-8")
    script = html[html.index("<script>"):]

    @staticmethod
    def unescaped(script: str) -> list[str]:
        problems = []
        for m in re.finditer(r"\$\{", script):
            # Extract the full ${ ... } expression, honouring nested braces.
            depth, i = 1, m.end()
            while depth and i < len(script):
                depth += {"{": 1, "}": -1}.get(script[i], 0)
                i += 1
            expr = script[m.end():i - 1].strip()
            for f in re.finditer(r"\b\w+(?:\[[^\]]*\])?\." + TEXT_FIELDS + r"\b", expr):
                if not any(w in expr[:f.start()] for w in SAFE_WRAPPERS):
                    problems.append(expr[:100])
        return problems

    def test_text_fields_are_escaped_in_html(self):
        self.assertEqual(self.unescaped(self.script), [], "outside text put into HTML without esc()")

    def test_the_checker_catches_a_raw_field(self):
        self.assertEqual(self.unescaped("x.innerHTML = `<b>${w.label}</b>`;"), ["w.label"])
        self.assertEqual(self.unescaped("x.innerHTML = `<b>${esc(w.label)}</b>`;"), [])
        self.assertEqual(self.unescaped("x.innerHTML = `<b>${x.name}</b>`;"), ["x.name"])
        self.assertEqual(self.unescaped("x.innerHTML = `<b>${esc(x.name)}</b>`;"), [])

    def test_esc_covers_the_dangerous_characters(self):
        m = re.search(r"const esc = s => (.+?);\n", self.script)
        self.assertIsNotNone(m)
        for ch in ("&", "<", ">", '"'):
            self.assertIn(ch, m.group(1))


class ReportEscaping(unittest.TestCase):
    def test_hostile_isp_label_is_escaped_in_report(self):
        with tempfile.TemporaryDirectory() as d:
            path = str(Path(d) / "t.db")
            s = Storage(path)
            s.write_minute([(1_790_000_000, "WAN1", "HEALTHY", 99, 0, 7, 1, 100)], [], [])
            s.close()
            html = report.to_html(report.build(path, {"WAN1": EVIL}, {}, 400))
        self.assertNotIn("<script>alert(2)</script>", html)
        self.assertNotIn('<img src=x onerror="alert(1)">', html)
        self.assertIn("&lt;script&gt;", html)

    def test_csv_prefixes_formula_like_isp_labels(self):
        with tempfile.TemporaryDirectory() as d:
            path = str(Path(d) / "t.db")
            s = Storage(path)
            s.write_minute([(int(time.time()) - 120, "WAN1", "HEALTHY", 99, 0, 7, 1, 100)], [], [])
            s.close()
            rep = report.build(path, {"WAN1": "=1+1"}, {}, 1)
            rows = list(csv.DictReader(io.StringIO(report.to_csv(rep, path, {"WAN1": "=1+1"}))))
        self.assertTrue(rows)
        self.assertEqual(rows[0]["isp"], "'=1+1")


class TelegramIsPlainText(unittest.TestCase):
    def test_bot_never_asks_telegram_to_interpret_formatting(self):
        src = Path(tg_module.__file__).read_text(encoding="utf-8")
        self.assertNotIn("parse_mode", src, "HTML/Markdown parsing would let names inject formatting/links")

    def test_hostile_display_name_is_passed_through_literally(self):
        with tempfile.TemporaryDirectory() as d:
            path = str(Path(d) / "t.db")
            Storage(path).close()
            from netpulse.storage.sqlite import KeyValueFile
            bot = TelegramBot("1:x", "42", {"help": lambda: "h"}, store=KeyValueFile(path))
            bot._call = lambda *a, **k: {"ok": True}
            bot._handle({"chat": {"id": 42, "type": "private"}, "text": "/invite"})
            bot._handle({"chat": {"id": 77, "type": "private", "first_name": EVIL, "username": "x_y*z"}, "text": "hi"})
            sent = []
            while not bot._outbox.empty():
                sent.append(bot._outbox.get_nowait())
        ask = next(t for t, chat, _ in sent if chat == "42" and "wants to use NetPulse" in t)
        self.assertIn(EVIL, ask)            # shown literally; Telegram won't interpret it without parse_mode


if __name__ == "__main__":
    unittest.main()
