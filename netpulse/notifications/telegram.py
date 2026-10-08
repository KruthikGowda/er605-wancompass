"""Telegram bot: long polling (no port forwarding, works behind CGNAT), button keyboard.

Runs in two daemon threads (poller + sender) so a slow or unreachable Telegram
never blocks monitoring.

Who may use it:
- **Owners**: the chat IDs in config (`chat_id`, comma-separated). Only owners can invite/remove people.
- **Members**: people an owner approved in Telegram via /invite. Stored in NetPulse's database.
Everyone else is ignored, except while an owner's /invite window is open (2 minutes): then a
newcomer's message makes the bot ask the owners "Allow / Deny?".

Never logs exception text: urllib errors can contain the URL, which holds the token.
"""

from __future__ import annotations

import json
import logging
import queue
import threading
import time
import urllib.error
import urllib.request
from typing import Callable, Protocol

from netpulse.notifications.base import DEVICE_NOTICE_CATEGORY, Notifier

log = logging.getLogger(__name__)

BUTTONS = {
    "📶 Status": "status",
    "🩺 Pi health": "pi",
    "📈 Last 24h": "today",
    "📊 Last 7d": "week",
    "⚡ Speed test": "speed",
    "🔕 Mute 1h": "mute",
    "🔔 Unmute": "unmute",
    "🛠 Using Omada": "omada",
    "🧭 Route a device": "route",
    "➕ Reserve a device": "reserve",
    "🔎 Device details": "device",
    "📦 Device groups": "groups",
    "🧾 Reserve group": "group_reserve",
    "📱 Devices": "devices",
    "👥 Groups": "groups",
    "❔ Help": "help",
}
COMMANDS = {"/start": "start", "/status": "status", "/pi": "pi", "/today": "today", "/week": "week",
            "/speed": "speed", "/mute": "mute",
            "/unmute": "unmute", "/omada": "omada", "/route": "route",
            "/route_confirm": "route_confirm", "/help": "help",
            "/reserve": "reserve", "/reserve_confirm": "reserve_confirm",
            "/device": "device", "/devices": "devices",
            "/groups": "groups", "/group_reserve": "group_reserve",
            "/group_suggest": "group_suggest",
            "/group_reserve_confirm": "group_reserve_confirm",
            "/group_route": "group_route", "/group_confirm": "group_confirm",
            "/group_smart": "group_smart",
            "/pause": "pause", "/resume": "resume", "/paused": "paused",
            "/group_pause": "group_pause", "/group_resume": "group_resume",
            "/pause_confirm": "pause_confirm",
            "/invite": "invite", "/close": "close", "/people": "people"}
OWNER_ONLY = {"invite", "close", "people", "route", "route_confirm", "reserve", "reserve_confirm",
              "groups", "group_reserve", "group_reserve_confirm", "group_suggest",
              "group_route", "group_confirm", "group_smart", "device", "devices"}
OWNER_ONLY.update({"pause", "resume", "paused", "group_pause", "group_resume", "pause_confirm"})
KEYBOARD = {
    "keyboard": [[{"text": "📶 Status"}, {"text": "🩺 Pi health"}],
                 [{"text": "📈 Last 24h"}, {"text": "📊 Last 7d"}],
                 [{"text": "📱 Devices"}, {"text": "👥 Groups"}],
                 [{"text": "🧭 Route a device"}, {"text": "❔ Help"}]],
    "resize_keyboard": True,
    "is_persistent": True,
}
MAX_LEN = 4000  # Telegram limit is 4096
INVITE_SECONDS = 120
MAX_REQUESTS_PER_INVITE = 5
MEMBERS_KEY = "telegram_members"
MENU = [
    {"command": "status", "description": "📶 How both connections are doing now"},
    {"command": "pi", "description": "🩺 Current Pi health"},
    {"command": "today", "description": "📈 Summary of the last 24 hours"},
    {"command": "week", "description": "📊 Summary of the last 7 days"},
    {"command": "speed", "description": "⚡ Speed test both connections now"},
    {"command": "devices", "description": "List current router devices (owner only)"},
    {"command": "groups", "description": "List device groups (owner only)"},
    {"command": "route", "description": "Preview a device WAN route (owner only)"},
    {"command": "help", "description": "All commands and features"},
]


class KeyValue(Protocol):
    def get(self, key: str) -> str | None: ...
    def set(self, key: str, value: str) -> None: ...


def profile_texts(labels: list[str]) -> dict[str, str]:
    """Bot description (shown before Start) and short 'about' text, using the ISP names."""
    isps = " and ".join(labels) if labels else "your internet connections"
    return {
        "description": (
            f"NetPulse watches your home's internet connections ({isps}) around the clock.\n\n"
            "• Alerts when a connection gets slow, bad or goes down, and when it's back\n"
            "• 📶 Status any time and 📈 a summary of the last 24 hours\n"
            "• Daily and weekly reports on demand\n"
            "• Private: only people the owner approves can use it\n\n"
            "Runs on your own Raspberry Pi."
        )[:512],
        "short_description": f"Your home internet at a glance: {isps} health, alerts and daily summaries."[:120],
    }


def parse_command(text: str) -> str | None:
    text = (text or "").strip()
    if text in BUTTONS:
        return BUTTONS[text]
    word = text.split()[0].split("@")[0].lower() if text else ""
    return COMMANDS.get(word)


def parse_chat_ids(value) -> list[str]:
    """chat_id config: one ID, or several separated by commas ("123, 456")."""
    return [c.strip() for c in str(value).split(",") if c.strip()]


def person_name(chat: dict) -> str:
    name = " ".join(filter(None, [chat.get("first_name"), chat.get("last_name")])) or "Someone"
    return f"{name} (@{chat['username']})" if chat.get("username") else name


class TelegramBot(Notifier):
    def __init__(self, token: str, chat_id: str, handlers: dict[str, Callable[[], str]],
                 profile: dict[str, str] | None = None, store: KeyValue | None = None,
                 api_base: str = "https://api.telegram.org"):
        self._base = f"{api_base}/bot{token}/"   # api_base is overridable for the fake server in tests
        self.owners = parse_chat_ids(chat_id)
        self.handlers = handlers
        self.profile = profile
        self.store = store
        self._lock = threading.Lock()
        self.members: dict[str, str] = self._load_members()      # chat id -> display name
        self._invite_until = 0.0
        self._invite_requests = 0
        self._pending: dict[str, str] = {}                        # chat id -> display name
        # (text, chat, markup): chat=None means everyone allowed (alerts, digests).
        self._outbox: queue.Queue[tuple] = queue.Queue(maxsize=100)
        self._delivery_lock = threading.Lock()
        self._delivery_counts = {"accepted": 0, "failed": 0, "queue_dropped": 0}
        self._category_delivery_counts = {
            DEVICE_NOTICE_CATEGORY: {"accepted": 0, "failed": 0, "queue_dropped": 0, "queued": 0}
        }
        self._ignored_chats: set[str] = set()
        self._stop = threading.Event()

    # --- public ---

    @property
    def chat_ids(self) -> list[str]:
        with self._lock:
            return self.owners + [c for c in self.members if c not in self.owners]

    def start(self) -> None:
        threading.Thread(target=self._sender, name="tg-send", daemon=True).start()
        threading.Thread(target=self._poller, name="tg-poll", daemon=True).start()
        log.info("telegram bot started (%d owner(s), %d member(s))", len(self.owners), len(self.members))

    def stop(self) -> None:
        self._stop.set()

    def send(self, text: str, chat: str | None = None, markup: dict | None = None) -> None:
        """Send to one chat, or to every allowed chat when chat is None."""
        self._enqueue(text, chat, markup, None)

    def send_categorized(self, text: str, category: str) -> None:
        """Queue a non-identifying alert category for outcome telemetry."""
        if category not in self._category_delivery_counts:
            raise ValueError("unsupported Telegram delivery category")
        self._enqueue(text, None, None, category)

    def _enqueue(self, text: str, chat: str | None, markup: dict | None,
                 category: str | None) -> None:
        item = (text[:MAX_LEN], chat, markup)
        with self._delivery_lock:
            try:
                self._outbox.put_nowait(item if category is None else (*item, category))
            except queue.Full:
                self._delivery_counts["queue_dropped"] += 1
                if category in self._category_delivery_counts:
                    self._category_delivery_counts[category]["queue_dropped"] += 1
                log.warning("telegram outbox full, dropping message")
            else:
                if category in self._category_delivery_counts:
                    self._category_delivery_counts[category]["queued"] += 1

    def delivery_stats(self) -> dict[str, object]:
        """Privacy-safe process counters; accepted counts Telegram API ok responses per recipient."""
        with self._delivery_lock:
            stats = dict(self._delivery_counts)
        stats["queued"] = self._outbox.qsize()
        with self._delivery_lock:
            stats["categories"] = {
                category: dict(counts)
                for category, counts in self._category_delivery_counts.items()
            }
        return stats

    def _record_delivery(self, category: str | None = None, **increments: int) -> None:
        with self._delivery_lock:
            for key, amount in increments.items():
                if key != "queued":
                    self._delivery_counts[key] += amount
                if category in self._category_delivery_counts:
                    self._category_delivery_counts[category][key] += amount

    # --- members ---

    def _load_members(self) -> dict[str, str]:
        if not self.store:
            return {}
        try:
            return dict(json.loads(self.store.get(MEMBERS_KEY) or "{}"))
        except (ValueError, TypeError):
            log.warning("telegram member list unreadable; starting empty")
            return {}

    def _save_members(self) -> None:
        if self.store:
            with self._lock:
                data = json.dumps(self.members)
            self.store.set(MEMBERS_KEY, data)

    def invite_open(self, now: float | None = None) -> bool:
        return (now or time.time()) < self._invite_until

    # --- transport ---

    def _call(self, method: str, payload: dict, timeout: float = 15) -> dict | None:
        req = urllib.request.Request(
            self._base + method, json.dumps(payload).encode(), {"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.load(resp)
        except urllib.error.HTTPError as e:
            log.warning("telegram %s failed: HTTP %s", method, e.code)
            return None
        except Exception as e:  # noqa: BLE001
            log.warning("telegram %s failed (%s)", method, type(e).__name__)
            return None
        return data if data.get("ok") else None

    def _sender(self) -> None:
        while not self._stop.is_set():
            item = self._outbox.get()
            text, chat, markup = item[:3]
            category = item[3] if len(item) > 3 else None
            if category is not None:
                self._record_delivery(category=category, queued=-1)
            self._deliver_message(text, chat, markup, category)

    def _deliver_message(self, text: str, chat: str | None, markup: dict | None,
                         category: str | None = None) -> None:
        for target in ([chat] if chat else self.chat_ids):
            payload = {"chat_id": target, "text": text, "disable_web_page_preview": True,
                       "reply_markup": markup or (KEYBOARD if self._is_allowed(target) else {"remove_keyboard": True})}
            for attempt in range(4):
                if self._call("sendMessage", payload):
                    self._record_delivery(category=category, accepted=1)
                    break
                time.sleep(5 * 2 ** attempt)  # 5, 10, 20, 40 s
            else:
                self._record_delivery(category=category, failed=1)
                log.warning("telegram message dropped after retries")

    def _apply_profile(self) -> None:
        """Command menu, description and about text. The profile photo can only be set in @BotFather."""
        ok = self._call("setMyCommands", {"commands": MENU}) is not None
        if self.profile:
            ok &= self._call("setMyDescription", {"description": self.profile["description"]}) is not None
            ok &= self._call("setMyShortDescription",
                             {"short_description": self.profile["short_description"]}) is not None
        log.info("telegram bot profile %s", "updated" if ok else "not fully updated (will retry next start)")

    def _poller(self) -> None:
        self._call("deleteWebhook", {})  # getUpdates doesn't work while a webhook is set
        self._apply_profile()
        offset, backoff = 0, 5
        while not self._stop.is_set():
            self._expire_invite()
            # While an invite is open, wake up in time to announce that it closed.
            wait = 50 if not self.invite_open() else max(1, min(50, int(self._invite_until - time.time()) + 1))
            res = self._call("getUpdates", {"offset": offset, "timeout": wait,
                                            "allowed_updates": ["message", "callback_query"]}, timeout=wait + 10)
            if res is None:
                time.sleep(backoff)
                backoff = min(backoff * 2, 120)
                continue
            backoff = 5
            for upd in res.get("result", []):
                offset = upd["update_id"] + 1
                try:
                    if "callback_query" in upd:
                        self._handle_button(upd["callback_query"])
                    else:
                        self._handle(upd.get("message") or {})
                except Exception:  # noqa: BLE001 - one bad message must not kill the bot
                    log.exception("telegram handler failed")

    # --- messages ---

    def _is_allowed(self, chat: str) -> bool:
        with self._lock:
            return chat in self.owners or chat in self.members

    def _handle(self, msg: dict) -> None:
        chat_obj = msg.get("chat") or {}
        chat = str(chat_obj.get("id", ""))
        if not chat:
            return
        if not self._is_allowed(chat):
            self._handle_stranger(chat, chat_obj)
            return
        cmd = parse_command(msg.get("text", "")) or "help"
        if cmd in OWNER_ONLY:
            if chat not in self.owners:
                self.send("Only the owner can do that.", chat=chat)
                return
            if cmd in {"invite", "close", "people"}:
                text, markup = self._owner_command(cmd)
                self.send(text, chat=chat, markup=markup)
            else:
                handler = self.handlers.get(cmd)
                if not handler:
                    self.send("That owner command is not available yet.", chat=chat)
                else:
                    reply = handler(msg.get("text", ""), chat) if getattr(handler, "wants_text", False) else handler()
                    self.send(reply, chat=chat)
            return
        handler = self.handlers.get(cmd) or self.handlers["help"]
        if getattr(handler, "wants_text", False):
            reply = handler(msg.get("text", ""), chat)
        else:
            reply = handler(chat) if getattr(handler, "wants_chat", False) else handler()
        self.send(reply, chat=chat)  # reply only to whoever asked

    def _owner_command(self, cmd: str, now: float | None = None) -> tuple[str, dict | None]:
        now = now or time.time()
        if cmd == "invite":
            log.info("telegram: invite window opened for %d s", INVITE_SECONDS)
            self._invite_until = now + INVITE_SECONDS
            self._invite_requests = 0
            return (f"➕ Invite open for {INVITE_SECONDS // 60} minutes.\n"
                    "Ask the person to open this bot and send \"hi\". You'll get an Allow / Deny question.\n"
                    "Send /close to stop early.", None)
        if cmd == "close":
            was_open = self.invite_open(now)
            self._close_invite()
            return ("🚪 Invite closed. New people can't ask to join." if was_open
                    else "No invite was open.", None)
        # people
        with self._lock:
            members = dict(self.members)
        lines = [f"👑 Owner{'s' if len(self.owners) > 1 else ''}: {len(self.owners)} account(s) from the Pi's config"]
        if not members:
            lines.append("No one else has access. Send /invite to add someone.")
            return ("\n".join(lines), None)
        lines.append("People you approved:")
        lines += [f"• {name}" for name in members.values()]
        buttons = [[{"text": f"🗑 Remove {name}", "callback_data": f"remove:{cid}"}] for cid, name in members.items()]
        return ("\n".join(lines), {"inline_keyboard": buttons})

    def _close_invite(self) -> None:
        self._invite_until = 0.0
        self._pending.clear()

    def _expire_invite(self, now: float | None = None) -> None:
        now = now or time.time()
        if self._invite_until and now >= self._invite_until:
            self._close_invite()
            for owner in self.owners:
                self.send("⏱ Invite closed (2 minutes passed).", chat=owner)

    def _handle_stranger(self, chat: str, chat_obj: dict) -> None:
        if chat_obj.get("type") != "private":
            return
        if not self.invite_open():
            if chat not in self._ignored_chats:
                self._ignored_chats.add(chat)
                log.warning("ignoring telegram messages from an unknown chat (an owner can /invite them)")
            return
        if chat in self._pending:
            return
        if self._invite_requests >= MAX_REQUESTS_PER_INVITE:
            return
        self._invite_requests += 1
        name = person_name(chat_obj)
        self._pending[chat] = name
        self.send("👋 Thanks! The owner has been asked to let you in. Please wait a moment.", chat=chat)
        markup = {"inline_keyboard": [[{"text": "✅ Allow", "callback_data": f"allow:{chat}"},
                                       {"text": "❌ Deny", "callback_data": f"deny:{chat}"}]]}
        for owner in self.owners:
            self.send(f"👤 {name} wants to use NetPulse.\nAllow them to see status and get alerts?",
                      chat=owner, markup=markup)

    def _handle_button(self, cb: dict) -> None:
        who = str((cb.get("from") or {}).get("id", ""))
        msg = cb.get("message") or {}
        self._call("answerCallbackQuery", {"callback_query_id": cb.get("id")})
        if who not in self.owners:
            return
        action, _, target = str(cb.get("data", "")).partition(":")
        if action in ("allow", "deny"):
            name = self._pending.pop(target, None)
            if name is None:
                result = "This request expired. Send /invite and ask them again."
            elif action == "allow":
                with self._lock:
                    self.members[target] = name
                self._save_members()
                log.info("telegram: owner approved a new member (%d member(s) now)", len(self.members))
                result = f"✅ {name} can now use NetPulse."
                self.send("✅ You're in! You'll get NetPulse alerts, and the buttons below work for you now.\n"
                          "Tap 📶 Status to try it.", chat=target)
            else:
                result = f"❌ {name} was not allowed."
                self.send("Sorry, the owner didn't approve this request.", chat=target)
        elif action == "remove":
            with self._lock:
                name = self.members.pop(target, None)
            if name is None:
                result = "They were already removed."
            else:
                self._save_members()
                log.info("telegram: owner removed a member (%d member(s) now)", len(self.members))
                result = f"🗑 {name} no longer has access."
                self.send("Your access to NetPulse was removed by the owner.", chat=target)
        else:
            return
        if msg.get("message_id"):
            self._call("editMessageText", {"chat_id": msg["chat"]["id"], "message_id": msg["message_id"],
                                           "text": result})
