"""Button-first Telegram navigation; router actions stay in QuickPicker."""
from __future__ import annotations

import secrets
import time


class ControlMenus:
    def __init__(self, bot, clock=time.monotonic):
        self.bot = bot
        self.clock = clock
        self.pending: dict[str, tuple[str, float]] = {}

    def clear(self, chat):
        self.pending.pop(chat, None)

    def show(self, page, chat, owner):
        self.clear(chat)
        rows = []

        def row(*items):
            rows.append([{"text": label, "callback_data": "menu:" + action}
                         for label, action in items])

        if page == "controls" and owner:
            text = ("🎛 Internet controls\n\nChoose Devices or Groups, select the targets, then tap an action.\n"
                    "• Prefer a WAN or return to automatic routing\n"
                    "• Pause Internet with a timer, or resume\n"
                    "• Review reservations and manage groups\n\n"
                    "Every connectivity change needs your review and confirmation. "
                    "Unavailable actions explain what needs setup.")
            row(("📱 Devices", "devices"), ("👥 Groups", "groups"))
        elif page == "alerts" and owner:
            text = ("🔔 Alert controls\n\nMute holds non-critical alerts for one hour. "
                    "WAN down and recovery alerts still come through.")
            row(("🔕 Mute 1 hour", "mute"), ("🔔 Unmute", "unmute"))
        elif page == "reports":
            text = "📈 Reports & diagnostics\nChoose a saved report. These buttons do not run speed tests."
            row(("📊 Speed results", "speeds"), ("🩺 Pi health", "pi"))
            row(("📈 Last 24 hours", "today"), ("📊 Last 7 days", "week"))
            if owner:
                row(("⚡ Run Pi test…", "test"))
        elif page == "test" and owner:
            nonce = secrets.token_urlsafe(9)
            self.pending[chat] = (nonce, self.clock() + 120)
            text = ("⚡ Run a Pi speed test?\n\nTests both WANs using Cloudflare and consumes data. "
                    "The Pi's Ethernet and power limits can reduce the measured speed. "
                    "This does not run a wired-PC or Ookla test. Budget and cooldown checks still apply.")
            row(("Run Pi test", "run:" + nonce), ("Cancel", "home"))
        else:
            text = "🏠 WANCompass\nTap a button below. No commands or device addresses needed."
            row(("📶 Live status", "status"), ("📊 Speed results", "speeds"))
            if owner:
                row(("📱 Devices", "devices"), ("👥 Groups", "groups"))
                row(("🎛 Internet controls", "controls"), ("🔔 Alerts", "alerts"))
            row(("📈 Reports & diagnostics", "reports"))
            row(("❔ Help", "help"))
        url = self.bot.handlers.get("dashboard_url", lambda: "")()
        if url:
            rows.append([{"text": "🌐 Open dashboard", "url": url}])
            text += "\nDashboard access requires your existing login and home network/VPN."
        if page != "home":
            row(("🏠 Main menu", "home"))
        self.bot.send(text, chat=chat, markup={"inline_keyboard": rows})

    def callback(self, cb):
        data = str(cb.get("data", ""))
        if not data.startswith("menu:"):
            return False
        msg = cb.get("message") or {}
        obj = msg.get("chat") or {}
        chat = str(obj.get("id", ""))
        sender = str((cb.get("from") or {}).get("id", ""))
        # A forwarded control panel cannot confer access, even to another owner.
        if obj.get("type") != "private" or sender != chat or not self.bot._is_allowed(chat):
            return True
        owner = chat in self.bot.owners
        action = data[5:]
        if self.bot._quick_picker:
            self.bot._quick_picker.clear(chat, sender)
        if action.startswith("run:"):
            pending = self.pending.pop(chat, None)
            if not owner or not pending or pending[0] != action[4:] or pending[1] <= self.clock():
                self.bot.send("This test confirmation expired or was already used. Open Reports to try again.", chat=chat)
                return True
            self.bot._handle({"chat": obj, "from": cb["from"], "text": "/speed"})
            return True
        self.clear(chat)
        if action in {"home", "controls", "reports", "alerts", "test"}:
            if action in {"controls", "alerts", "test"} and not owner:
                self.bot.send("Only the owner can do that.", chat=chat)
            else:
                self.show(action, chat, owner)
        elif action in {"status", "speeds", "pi", "today", "week", "help", "devices", "groups", "mute", "unmute"}:
            if action in {"devices", "groups", "mute", "unmute"} and not owner:
                self.bot.send("Only the owner can do that.", chat=chat)
            else:
                self.bot._handle({"chat": obj, "from": cb["from"], "text": "/" + action})
        return True
