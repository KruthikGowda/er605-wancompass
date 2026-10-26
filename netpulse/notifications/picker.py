"""Private, owner-only Telegram picker for reviewed quick controls.

The application supplies three hooks:

* ``quick_choices()`` returns ``{"devices": [{"mac", "name", "ip", ...}],
  "groups": [{"id", "name", "count", ...}]}``.
* ``quick_choices()`` also returns ``actions`` (each with ``id``, ``label``,
  optional ``enabled`` and ``reason``).
* ``quick_preview(payload, chat)`` returns ``text`` and an opaque
  ``confirm_token``. It may return a stable ``fingerprint`` that excludes the
  token and moving timestamps. ``payload`` has ``kind``, ``items`` and
  ``action``. The hook must preview the complete selected set as one reviewed
  operation.
* ``quick_apply(token, chat)`` applies only the reviewed operation and returns
  either a string or ``{"text": string}``.
* Optional ``quick_group_preview(payload, chat)`` and ``quick_group_apply(token,
  chat)`` provide the same reviewed-token contract for group create, rename,
  delete, and membership edits. Payloads carry ``action`` plus a group ID/name
  and selected MACs as appropriate. Optional ``quick_bandwidth(payload, chat)``
  is read-only and returns explanatory text plus optional text options.

Tokens and identifiers stay in process memory. Telegram callback data contains
only a random session nonce, a revision, an operation name and a display index.
"""

from __future__ import annotations

import re
import secrets
import time
from dataclasses import dataclass, field
from typing import Callable

TTL_SECONDS = 600
PAGE_SIZE = 8
MAX_CHOICES = 512
MAX_SELECTED = 128
MAX_SESSIONS = 32
MAX_TEXT = 3900
_NUMBER_SELECTION = re.compile(r"\s*\d+(?:\s*,\s*\d+)*\s*\Z")


def _single_line(value: object, limit: int = 72) -> str:
    text = " ".join(str(value or "").split())
    # Telegram uses UTF-8 byte limits for callback data; visible labels are
    # bounded by characters here and complete messages are bounded below.
    return text[:limit] or "Unnamed"


def _tail(mac: object) -> str:
    parts = re.findall(r"[0-9A-Fa-f]{2}", str(mac or ""))
    return "-".join(parts[-3:]).upper() if len(parts) == 6 else "MAC unavailable"


def _bounded_text(value: object) -> str:
    text = str(value or "")
    if len(text.encode("utf-8")) <= MAX_TEXT:
        return text
    out: list[str] = []
    size = 0
    for char in text:
        width = len(char.encode("utf-8"))
        if size + width > MAX_TEXT - 3:
            break
        out.append(char)
        size += width
    return "".join(out) + "…"


@dataclass
class _Session:
    chat: str
    sender: str
    kind: str
    nonce: str
    expires: float
    revision: int = 0
    page: int = 0
    choices: list[dict] = field(default_factory=list)
    selected: list[int] = field(default_factory=list)
    phase: str = "list"
    action: str | None = None
    review: dict | None = None
    review_signature: tuple | None = None
    purpose: str = "router"
    group_target: dict | None = None
    group_operation: str | None = None
    source_items: list[dict] = field(default_factory=list)
    group_name: str | None = None
    review_kind: str = "router"
    review_payload: dict | None = None


class QuickPicker:
    """Conversation state and validation for menu-driven router controls."""

    def __init__(self, choices: Callable, preview: Callable, apply: Callable,
                 group_preview: Callable | None = None, group_apply: Callable | None = None,
                 bandwidth: Callable | None = None,
                 clock: Callable[[], float] = time.time):
        self._choices = choices
        self._preview = preview
        self._apply = apply
        self._group_preview = group_preview
        self._group_apply = group_apply
        self._bandwidth = bandwidth
        self._clock = clock
        self._sessions: dict[tuple[str, str], _Session] = {}

    @staticmethod
    def is_selection(text: str) -> bool:
        return bool(_NUMBER_SELECTION.fullmatch(text or ""))

    @staticmethod
    def _key(chat: str, sender: str) -> tuple[str, str]:
        return str(chat), str(sender)

    def clear(self, chat: str, sender: str) -> bool:
        return self._sessions.pop(self._key(chat, sender), None) is not None

    def active(self, chat: str, sender: str) -> bool:
        session = self._sessions.get(self._key(chat, sender))
        if session and session.expires > self._clock():
            return True
        if session:
            self.clear(chat, sender)
        return False

    def begin(self, kind: str, chat: str, sender: str) -> tuple[str, dict | None]:
        choices = self._read_choices(kind)
        now = self._clock()
        for key, current in list(self._sessions.items()):
            if current.expires <= now:
                del self._sessions[key]
        if len(self._sessions) >= MAX_SESSIONS:
            oldest = min(self._sessions, key=lambda key: self._sessions[key].expires)
            del self._sessions[oldest]
        session = _Session(str(chat), str(sender), kind, secrets.token_urlsafe(7),
                           now + TTL_SECONDS, choices=choices)
        self._sessions[self._key(chat, sender)] = session
        if not choices and kind != "groups":
            return ("No devices are available in the latest inventory." if kind == "devices"
                    else "No device groups are available yet."), None
        return self._list_view(session)

    def message(self, text: str, chat: str, sender: str) -> tuple[str, dict | None] | None:
        key = self._key(chat, sender)
        session = self._sessions.get(key)
        if not session:
            return None
        if session.expires <= self._clock():
            self._sessions.pop(key, None)
            return "That picker expired. Open Devices or Groups again.", None
        text = (text or "").strip()
        if text.casefold() in {"cancel", "/cancel", "❌ cancel"}:
            self._sessions.pop(key, None)
            return "Cancelled. Nothing changed.", None
        if session.phase == "await_name":
            if (not text or text.startswith("/") or len(text) > 40 or
                    any(ord(char) < 32 for char in text)):
                return "Send one plain name for the group, 1 to 40 characters, or tap Cancel.", self._cancel_markup(session)
            session.group_name = text
            if session.group_operation == "rename":
                return self._group_review(session, {
                    "action": "rename", "group_id": session.group_target.get("id"), "name": text})
            session.purpose = "create_group"
            session.kind = "devices"
            session.choices = self._read_choices("devices")
            session.selected = []
            session.page = 0
            session.phase = "list"
            session.revision += 1
            return self._list_view(session)
        if session.phase != "list" or not self.is_selection(text):
            return None
        try:
            numbers = [int(part.strip()) for part in text.split(",")]
        except ValueError:
            return "Reply with a displayed number, such as 1 or 1,2.", self._list_markup(session)
        start = session.page * PAGE_SIZE
        end = min(start + PAGE_SIZE, len(session.choices))
        if (len(set(numbers)) != len(numbers) or
                any(number < 1 or number > end - start for number in numbers)):
            return "Choose numbers shown on this page. No change was made.", self._list_markup(session)
        current_page = set(range(start, end))
        updated = (set(session.selected) - current_page) | {start + number - 1 for number in numbers}
        if len(updated) > MAX_SELECTED:
            return f"Choose no more than {MAX_SELECTED} entries at a time.", self._list_markup(session)
        session.selected = sorted(updated)
        session.revision += 1
        return self._after_selection(session)

    def callback(self, cb: dict) -> tuple[str, dict | None] | None:
        data = str(cb.get("data", ""))
        parsed = self._parse_data(data)
        if not parsed:
            return None
        nonce, revision, verb, index = parsed
        who = str((cb.get("from") or {}).get("id", ""))
        msg = cb.get("message") or {}
        origin = msg.get("chat") or {}
        chat = str(origin.get("id", ""))
        if origin.get("type") != "private":
            return None
        session = self._sessions.get(self._key(chat, who))
        if not session or session.expires <= self._clock():
            if session:
                self.clear(chat, who)
            return "This picker expired. Open Devices or Groups again.", None
        if session.nonce != nonce or session.revision != revision:
            return None
        session.revision += 1
        if verb == "cancel":
            self.clear(chat, who)
            return "Cancelled. Nothing changed.", None
        if verb == "create" and session.kind == "groups" and session.purpose == "router":
            if not self._group_preview or not self._group_apply:
                return "Group editing is not available.", self._list_markup(session)
            session.group_operation = "create"
            session.phase = "await_name"
            session.revision += 1
            return "What should the new group be called? Send one plain name (up to 40 characters).", self._cancel_markup(session)
        if session.phase == "list":
            start = session.page * PAGE_SIZE
            end = min(start + PAGE_SIZE, len(session.choices))
            if verb == "item" and 0 <= index < end - start:
                absolute = start + index
                if absolute in session.selected:
                    session.selected.remove(absolute)
                else:
                    if len(session.selected) >= MAX_SELECTED:
                        return f"Choose no more than {MAX_SELECTED} entries at a time.", self._list_markup(session)
                    session.selected.append(absolute)
                session.selected.sort()
                return self._list_view(session)
            if verb == "page" and index in (-1, 1):
                pages = (len(session.choices) + PAGE_SIZE - 1) // PAGE_SIZE
                if 0 <= session.page + index < pages:
                    session.page += index
                    return self._list_view(session)
            if verb == "next" and session.selected:
                return self._after_selection(session)
            return "That picker choice is no longer available.", self._list_markup(session)
        if session.phase == "action":
            actions = self._read_actions(session)
            available = [a for a in actions if a.get("enabled", True)]
            if verb == "action" and 0 <= index < len(available):
                action = available[index]
                if action.get("id") != self._action_id(session, index):
                    return "That action changed. Review the available choices again.", self._actions_markup(session)
                return self._dispatch_action(session, action["id"])
            if verb == "back":
                return self._back_to_list(session)
            return "Choose one of the available actions.", self._actions_markup(session)
        if session.phase == "review" and verb == "confirm":
            return self._confirm(session)
        if session.phase == "review" and verb == "back":
            session.phase = "list" if session.purpose in {"group_members", "create_group", "device_members"} else "action"
            return self._list_view(session) if session.phase == "list" else self._actions_view(session)
        if session.phase == "info" and verb == "back":
            session.phase = "action"
            return self._actions_view(session)
        if session.phase in {"action", "review"} and verb == "back":
            return self._back_to_list(session)
        return None

    @staticmethod
    def _parse_data(data: str) -> tuple[str, int, str, int] | None:
        match = re.fullmatch(r"qp:([A-Za-z0-9_-]{6,16}):(\d+):(item|page|next|action|back|confirm|cancel|create):(\d+|m)", data)
        if not match:
            return None
        nonce, revision, verb, raw_index = match.groups()
        return nonce, int(revision), verb, -1 if raw_index == "m" else int(raw_index)

    def _read_choices(self, kind: str) -> list[dict]:
        try:
            value = self._choices()
            rows = value.get(kind, []) if isinstance(value, dict) else []
            valid = []
            seen = set()
            for row in rows:
                if not isinstance(row, dict):
                    continue
                identity = str(row.get("mac") if kind == "devices" else row.get("id", ""))
                if not identity or identity in seen:
                    continue
                seen.add(identity)
                valid.append(dict(row))
            return valid[:MAX_CHOICES]
        except Exception:
            return []

    def _list_view(self, session: _Session) -> tuple[str, dict]:
        if session.purpose == "group_members" and session.group_target:
            verb = "add to" if session.group_operation == "add" else "remove from"
            title = f"Devices to {verb} {_single_line(session.group_target.get('name'), 32)}"
        elif session.purpose == "create_group":
            title = f"Devices for {_single_line(session.group_name, 36)}"
        elif session.purpose == "device_members":
            title = "Choose one group"
        else:
            title = "Devices" if session.kind == "devices" else "Groups"
        pages = max(1, (len(session.choices) + PAGE_SIZE - 1) // PAGE_SIZE)
        lines = [f"{title} · page {session.page + 1}/{pages}"]
        if not session.choices:
            lines.append("No matching choices are available.")
        else:
            lines.append("Tap to select, or reply with numbers such as 1 or 1,2.")
        if session.selected:
            lines.append("Selected: " + ", ".join(str(i + 1) for i in session.selected))
        for local, choice in enumerate(session.choices[session.page * PAGE_SIZE:(session.page + 1) * PAGE_SIZE], 1):
            absolute = session.page * PAGE_SIZE + local - 1
            marker = "✓ " if absolute in session.selected else ""
            if session.kind == "devices":
                name = _single_line(choice.get("name") or choice.get("friendly_name") or "Device", 42)
                # Duplicate names remain distinguishable even when the labels match.
                label = f"{marker}{local}. {name} · …{_tail(choice.get('mac'))}"
            else:
                name = _single_line(choice.get("name") or "Group", 48)
                count = choice.get("count")
                label = f"{marker}{local}. {name}" + (f" · {count} devices" if isinstance(count, int) else "")
            lines.append(label)
        lines.append("Send /cancel to stop.")
        if len(session.choices) == MAX_CHOICES:
            lines.append("Showing up to 512 entries.")
        return _bounded_text("\n".join(lines)), self._list_markup(session)

    def _list_markup(self, session: _Session) -> dict:
        start = session.page * PAGE_SIZE
        end = min(start + PAGE_SIZE, len(session.choices))
        rows = []
        for absolute in range(start, end):
            choice = session.choices[absolute]
            local = absolute - start
            if session.kind == "devices":
                title = _single_line(choice.get("name") or choice.get("friendly_name") or "Device", 32)
                title += f" · …{_tail(choice.get('mac'))}"
            else:
                title = _single_line(choice.get("name") or "Group", 40)
            if absolute in session.selected:
                title = "✓ " + title
            rows.append([{"text": title[:60], "callback_data": self._data(session, "item", local)}])
        controls = []
        if session.page:
            controls.append({"text": "‹ Back", "callback_data": self._data(session, "page", -1)})
        pages = (len(session.choices) + PAGE_SIZE - 1) // PAGE_SIZE
        if session.page + 1 < pages:
            controls.append({"text": "More ›", "callback_data": self._data(session, "page", 1)})
        if controls:
            rows.append(controls)
        if session.selected:
            label = ("Review changes" if session.purpose in
                     {"group_members", "create_group", "device_members"} else "Choose action")
            rows.append([{"text": label, "callback_data": self._data(session, "next", 0)}])
        if session.kind == "groups" and session.purpose == "router" and self._group_preview and self._group_apply:
            rows.append([{"text": "➕ Create group", "callback_data": self._data(session, "create", 0)}])
        elif session.purpose == "group_members" and session.group_target:
            rows.append([{"text": "‹ Back", "callback_data": self._data(session, "back", 0)}])
        elif session.purpose == "create_group":
            rows.append([{"text": "‹ Back", "callback_data": self._data(session, "back", 0)}])
        elif session.purpose == "device_members":
            rows.append([{"text": "‹ Back", "callback_data": self._data(session, "back", 0)}])
        rows.append([{"text": "Cancel", "callback_data": self._data(session, "cancel", 0)}])
        return {"inline_keyboard": rows}

    def _actions_view(self, session: _Session) -> tuple[str, dict]:
        session.phase = "action"
        session.revision += 1
        actions = self._read_actions(session)
        lines = ["Choose an action:"]
        for action in actions:
            label = _single_line(action.get("label") or action.get("id"), 72)
            if not action.get("enabled", True):
                lines.append(f"• {label} — unavailable: {_single_line(action.get('reason') or 'not ready', 120)}")
            else:
                lines.append(f"• {label}")
        return _bounded_text("\n".join(lines)), self._actions_markup(session, actions)

    def _read_actions(self, session: _Session) -> list[dict]:
        if session.purpose in {"group_members", "create_group", "device_members"}:
            return []
        if session.kind == "groups" and session.purpose == "router":
            if len(session.selected) != 1 or not self._group_preview or not self._group_apply:
                return []
            try:
                value = self._choices()
                actions = value.get("actions", []) if isinstance(value, dict) else []
                actions = [dict(action) for action in actions if isinstance(action, dict)]
            except Exception:
                actions = []
            actions.append({"id": "bandwidth", "label": "Bandwidth and priority"})
            actions.extend([
                {"id": "group_add", "label": "Add devices"},
                {"id": "group_remove", "label": "Remove devices"},
                {"id": "group_rename", "label": "Rename group"},
                {"id": "group_delete", "label": "Delete group"},
            ])
            return actions
        try:
            value = self._choices()
            actions = value.get("actions", []) if isinstance(value, dict) else []
            actions = [dict(a) for a in actions if isinstance(a, dict)]
            if session.kind == "devices" and session.purpose == "router":
                if self._group_preview and self._group_apply:
                    actions.extend([
                        {"id": "add_to_group", "label": "Add to group"},
                        {"id": "remove_from_group", "label": "Remove from group"},
                    ])
                actions.append({"id": "bandwidth", "label": "Bandwidth and priority"})
            return actions
        except Exception:
            return []

    def _action_id(self, session: _Session, index: int) -> str | None:
        actions = [a for a in self._read_actions(session) if a.get("enabled", True)]
        return actions[index].get("id") if 0 <= index < len(actions) else None

    def _actions_markup(self, session: _Session, actions: list[dict] | None = None) -> dict:
        actions = actions if actions is not None else self._read_actions(session)
        rows = []
        enabled_index = 0
        for action in actions:
            if not action.get("enabled", True):
                continue
            rows.append([{"text": _single_line(action.get("label") or action.get("id"), 56),
                          "callback_data": self._data(session, "action", enabled_index)}])
            enabled_index += 1
        rows.append([{"text": "‹ Back", "callback_data": self._data(session, "back", 0)},
                     {"text": "Cancel", "callback_data": self._data(session, "cancel", 0)}])
        return {"inline_keyboard": rows}

    def _after_selection(self, session: _Session) -> tuple[str, dict]:
        if session.kind == "groups" and session.purpose == "router":
            if len(session.selected) != 1:
                return "Choose one group at a time.", self._list_markup(session)
            session.group_target = dict(session.choices[session.selected[0]])
            return self._actions_view(session)
        if session.purpose == "device_members":
            if len(session.selected) != 1:
                return "Choose one group for these devices.", self._list_markup(session)
            session.group_target = dict(session.choices[session.selected[0]])
            macs = [str(item.get("mac", "")) for item in session.source_items]
            return self._group_review(session, {
                "action": session.group_operation,
                "group_id": session.group_target.get("id"),
                "macs": macs,
            })
        if session.purpose == "group_members":
            macs = [str(session.choices[i].get("mac", "")) for i in session.selected]
            return self._group_review(session, {
                "action": session.group_operation,
                "group_id": (session.group_target or {}).get("id"),
                "macs": macs,
            })
        if session.purpose == "create_group":
            macs = [str(session.choices[i].get("mac", "")) for i in session.selected]
            return self._group_review(session, {"action": "create", "name": session.group_name,
                                                "macs": macs})
        return self._actions_view(session)

    def _dispatch_action(self, session: _Session, action: str) -> tuple[str, dict]:
        if action == "bandwidth":
            return self._bandwidth_view(session)
        if action in {"add_to_group", "remove_from_group"}:
            session.source_items = [dict(session.choices[i]) for i in session.selected]
            session.group_operation = "add" if action == "add_to_group" else "remove"
            session.kind = "groups"
            session.purpose = "device_members"
            session.group_target = None
            session.choices = self._read_choices("groups")
            session.selected = []
            session.page = 0
            session.phase = "list"
            session.revision += 1
            if not session.choices:
                return "There are no groups yet. Open Groups and create one first.", self._cancel_markup(session)
            return self._list_view(session)
        if session.kind == "groups" and session.purpose == "router":
            if len(session.selected) != 1:
                return "Choose one group at a time.", self._list_markup(session)
            group = dict(session.choices[session.selected[0]])
            if action == "group_add" or action == "group_remove":
                op = "add" if action == "group_add" else "remove"
                self._choose_group_members(session, group, op)
                return self._list_view(session)
            session.group_target = group
            if action == "group_rename":
                session.group_operation = "rename"
                session.phase = "await_name"
                session.revision += 1
                return ("What should this group be called? Send one plain name (up to 40 characters).",
                        self._cancel_markup(session))
            if action == "group_delete":
                return self._group_review(session, {"action": "delete", "group_id": group.get("id")})
        return self._review_view(session, action)

    def _choose_group_members(self, session: _Session, group: dict, operation: str) -> None:
        devices = self._read_choices("devices")
        by_mac = {str(row.get("mac", "")): row for row in devices}
        members = [str(mac) for mac in group.get("members", []) if isinstance(mac, str)]
        if operation == "add":
            choices = [row for row in devices if str(row.get("mac", "")) not in set(members)]
        else:
            choices = [by_mac.get(mac, {"mac": mac, "name": f"Saved group member ({_tail(mac)})",
                                         "ip": "IP unavailable", "offline": True})
                       for mac in members]
        session.kind = "devices"
        session.purpose = "group_members"
        session.group_target = dict(group)
        session.group_operation = operation
        session.source_items = []
        session.choices = [dict(row) for row in choices]
        session.selected = []
        session.page = 0
        session.phase = "list"
        session.revision += 1

    def _group_review(self, session: _Session, payload: dict) -> tuple[str, dict]:
        if not self._group_preview or not self._group_apply:
            return "Group editing is not available.", self._cancel_markup(session)
        valid, reason = self._validate_group_context(session, payload)
        if not valid:
            session.phase = "list" if session.purpose in {"group_members", "create_group", "device_members"} else "action"
            markup = self._list_markup(session) if session.phase == "list" else self._actions_markup(session)
            return reason, markup
        try:
            review = self._group_preview(payload, session.chat)
        except Exception:
            review = None
        if not isinstance(review, dict) or not review.get("confirm_token"):
            session.phase = "list" if session.purpose in {"group_members", "create_group", "device_members"} else "action"
            text = review.get("text") if isinstance(review, dict) else None
            markup = self._list_markup(session) if session.phase == "list" else self._actions_markup(session)
            return _bounded_text(text or "Could not prepare a fresh group review. Nothing changed."), markup
        session.phase = "review"
        session.review_kind = "group"
        session.review_payload = dict(payload)
        session.review = review
        session.review_signature = self._signature(review)
        text = self._review_text(review, "Confirm to apply, or go back.")
        if payload.get("action") == "delete":
            text = _bounded_text(text + "\n\nSaved WAN routes and Internet pauses remain; Smart WAN for this group stops.")
        return text, self._confirm_markup(session)

    def _validate_group_context(self, session: _Session, payload: dict) -> tuple[bool, str]:
        try:
            value = self._choices()
        except Exception:
            return False, "Current groups or devices are unavailable. Refresh and review again; nothing changed."
        groups = value.get("groups", []) if isinstance(value, dict) else []
        devices = value.get("devices", []) if isinstance(value, dict) else []
        action = payload.get("action")
        if action in {"add", "remove", "rename", "delete"}:
            target = session.group_target or {}
            current = next((group for group in groups
                            if isinstance(group, dict) and group.get("id") == target.get("id")), None)
            if not current or dict(current) != target:
                return False, "The group changed. Refresh Groups and review again; nothing changed."
        if action in {"add", "remove", "create"}:
            by_mac = {str(row.get("mac", "")): row for row in devices if isinstance(row, dict)}
            current_members = {str(mac) for mac in (session.group_target or {}).get("members", [])}
            for item in session.source_items if action in {"add", "remove"} and session.purpose == "device_members" else []:
                if by_mac.get(str(item.get("mac", ""))) != item:
                    return False, "A selected device changed. Refresh Devices and review again; nothing changed."
            selected_items = ([session.choices[i] for i in session.selected]
                              if session.purpose in {"group_members", "create_group"} else session.source_items)
            for item in selected_items:
                mac = str(item.get("mac", ""))
                if action == "remove":
                    if mac not in current_members:
                        return False, "A selected member changed. Refresh the group and review again; nothing changed."
                elif action == "add" and session.purpose == "group_members":
                    if by_mac.get(mac) != item or mac in current_members:
                        return False, "A selected device or group member changed; nothing changed."
                elif action == "create" and by_mac.get(mac) != item:
                    return False, "A selected device changed. Refresh Devices and review again; nothing changed."
        return True, ""

    def _bandwidth_view(self, session: _Session) -> tuple[str, dict]:
        payload = {"items": [session.choices[i] for i in session.selected]}
        if self._bandwidth:
            try:
                result = self._bandwidth(payload, session.chat)
            except Exception:
                result = None
        else:
            result = None
        lines = [str(result.get("text") or "") if isinstance(result, dict) else
                 "Device bandwidth and priority options are unavailable from the verified router controls."]
        options = (result.get("options", result.get("actions", []))
                   if isinstance(result, dict) else [])
        for option in options:
            if isinstance(option, str):
                lines.append(f"• {_single_line(option, 140)}")
            elif isinstance(option, dict):
                label = _single_line(option.get("label") or option.get("id"), 100)
                if not option.get("enabled", True):
                    label += " — unavailable: " + _single_line(option.get("reason") or "not verified", 100)
                lines.append(f"• {label}")
        session.phase = "info"
        session.revision += 1
        return _bounded_text("\n".join(line for line in lines if line)), {
            "inline_keyboard": [[{"text": "‹ Back", "callback_data": self._data(session, "back", 0)},
                                 {"text": "Cancel", "callback_data": self._data(session, "cancel", 0)}]]}

    def _back_to_list(self, session: _Session) -> tuple[str, dict]:
        if session.purpose == "group_members" and session.group_target:
            groups = self._read_choices("groups")
            session.kind = "groups"
            session.purpose = "router"
            session.choices = groups
            session.selected = [i for i, group in enumerate(groups)
                                if group.get("id") == session.group_target.get("id")]
            session.page = session.selected[0] // PAGE_SIZE if session.selected else 0
            return self._actions_view(session) if session.selected else self._list_view(session)
        if session.purpose == "device_members":
            devices = self._read_choices("devices")
            selected_macs = {str(item.get("mac", "")) for item in session.source_items}
            session.kind = "devices"
            session.purpose = "router"
            session.choices = devices
            session.selected = [i for i, item in enumerate(devices)
                                if item.get("mac") in selected_macs]
            session.page = 0
            return self._actions_view(session)
        if session.purpose == "create_group":
            session.kind = "groups"
            session.purpose = "router"
            session.choices = self._read_choices("groups")
            session.selected = []
            session.group_name = None
            session.group_operation = None
            session.page = 0
            session.phase = "list"
            session.revision += 1
            return self._list_view(session)
        session.phase = "list"
        return self._list_view(session)

    def _cancel_markup(self, session: _Session) -> dict:
        return {"inline_keyboard": [[{"text": "Cancel", "callback_data": self._data(session, "cancel", 0)}]]}

    def _confirm_markup(self, session: _Session) -> dict:
        return {"inline_keyboard": [[
            {"text": "✅ Confirm", "callback_data": self._data(session, "confirm", 0)},
            {"text": "‹ Back", "callback_data": self._data(session, "back", 0)},
        ], [{"text": "Cancel", "callback_data": self._data(session, "cancel", 0)}]]}

    def _review_view(self, session: _Session, action: str) -> tuple[str, dict]:
        fresh = self._read_choices(session.kind)
        if not self._same_selection(session, fresh):
            session.choices = fresh
            session.selected = []
            session.phase = "list"
            session.revision += 1
            return "The inventory changed. Choose the devices or groups again.", self._list_markup(session)
        session.phase = "review"
        session.review_kind = "router"
        session.action = action
        payload = self._payload(session, action)
        session.review_payload = payload
        try:
            review = self._preview(payload, session.chat)
        except Exception:
            review = {"text": "Could not prepare a fresh review. Nothing changed."}
        if not isinstance(review, dict) or not review.get("confirm_token"):
            session.review = None
            session.phase = "action"
            return _bounded_text(review.get("text", "This action is unavailable. Nothing changed.") if isinstance(review, dict) else "This action is unavailable. Nothing changed."), self._actions_markup(session)
        session.review = review
        session.review_signature = self._signature(review)
        text = self._review_text(review, "Confirm to apply, or go back.")
        return _bounded_text(text), self._confirm_markup(session)

    def _confirm(self, session: _Session) -> tuple[str, dict]:
        if session.review_kind == "group":
            payload = session.review_payload or {}
            valid, reason = self._validate_group_context(session, payload)
            if not valid:
                self.clear(session.chat, session.sender)
                return reason, None
            try:
                fresh = self._group_preview(payload, session.chat) if self._group_preview else None
            except Exception:
                fresh = None
        else:
            fresh_choices = self._read_choices(session.kind)
            if not self._same_selection(session, fresh_choices):
                session.choices = fresh_choices
                session.selected = []
                session.phase = "list"
                session.revision += 1
                return "The inventory changed since review. Choose again; nothing changed.", self._list_markup(session)
            try:
                fresh = self._preview(self._payload(session, session.action or ""), session.chat)
            except Exception:
                fresh = None
        if (not isinstance(fresh, dict) or not fresh.get("confirm_token") or
                self._signature(fresh) != session.review_signature):
            if isinstance(fresh, dict) and fresh.get("confirm_token"):
                session.review = fresh
                session.review_signature = self._signature(fresh)
                session.revision += 1
                text = self._review_text(fresh, "The review changed. Confirm again to apply.")
                if (session.review_kind == "group" and
                        (session.review_payload or {}).get("action") == "delete"):
                    text = _bounded_text(text + "\n\nSaved WAN routes and Internet pauses remain; Smart WAN for this group stops.")
                return _bounded_text(text), self._confirm_markup(session)
            self.clear(session.chat, session.sender)
            return "The review is no longer available. Nothing changed.", None
        try:
            if session.review_kind == "group":
                result = self._group_apply(fresh["confirm_token"], session.chat)
            else:
                result = self._apply(fresh["confirm_token"], session.chat)
            text = result.get("text", "Done.") if isinstance(result, dict) else result
        except Exception:
            text = "Could not apply this change. Check Status before trying again."
        self.clear(session.chat, session.sender)
        return _bounded_text(text), None

    @staticmethod
    def _signature(review: dict) -> tuple:
        actions = tuple((a.get("id"), a.get("label"), a.get("enabled", True), a.get("reason"))
                        for a in review.get("actions", []) if isinstance(a, dict))
        stable = review.get("fingerprint")
        return (repr(stable) if stable is not None else str(review.get("text") or "")), actions

    @staticmethod
    def _review_text(review: dict, prompt: str) -> str:
        text = str(review.get("text") or "Review this change.")
        token = str(review.get("confirm_token") or "")
        if token:
            text = text.replace(token, "[private confirmation]")
        return _bounded_text(text + "\n\n" + prompt)

    @staticmethod
    def _same_selection(session: _Session, fresh: list[dict]) -> bool:
        identity_key = "mac" if session.kind == "devices" else "id"
        by_id = {str(row.get(identity_key)): row for row in fresh}
        return all(str(session.choices[i].get(identity_key)) in by_id and
                   session.choices[i] == by_id[str(session.choices[i].get(identity_key))]
                   for i in session.selected)

    @staticmethod
    def _payload(session: _Session, action: str) -> dict:
        return {"kind": session.kind,
                "items": [session.choices[i] for i in session.selected],
                "action": action}

    @staticmethod
    def _data(session: _Session, verb: str, index: int) -> str:
        raw_index = "m" if index < 0 else str(index)
        return f"qp:{session.nonce}:{session.revision}:{verb}:{raw_index}"
