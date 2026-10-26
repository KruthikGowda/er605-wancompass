import unittest
from unittest import mock

from netpulse.notifications.picker import QuickPicker
from netpulse.notifications.telegram import KEYBOARD, MORE_KEYBOARD, MENU, TelegramBot, parse_command


OWNER = "42"
MAC1 = "02-00-00-00-00-01"
MAC2 = "02-00-00-00-00-02"


class QuickPickerConversation(unittest.TestCase):
    def setUp(self):
        self.now = 1000.0
        self.rows = {
            "devices": [
                {"mac": MAC1, "name": "Phone", "ip": "192.0.2.11"},
                {"mac": MAC2, "name": "Phone", "ip": "192.0.2.12"},
            ],
            "groups": [{"id": 7, "name": "Home", "count": 2}],
            "actions": [
                {"id": "auto", "label": "Autobalance", "enabled": True},
                {"id": "prefer_wan1", "label": "Prefer WAN1", "enabled": True},
                {"id": "pause", "label": "Pause internet", "enabled": False,
                 "reason": "IPv4-only pause is not verified"},
            ],
        }
        self.previews = []
        self.applied = []
        self.counter = 0

        def preview(payload, chat):
            self.previews.append((payload, chat))
            if payload["action"] == "__availability__":
                return {"actions": self.rows["actions"]}
            self.counter += 1
            return {"text": "Review: " + payload["action"],
                    "confirm_token": f"secret-{self.counter}"}

        self.picker = QuickPicker(lambda: self.rows, preview,
                                  lambda token, chat: self.applied.append((token, chat)) or "Applied",
                                  clock=lambda: self.now)

    @staticmethod
    def _callback(markup, verb, index=0):
        for row in markup["inline_keyboard"]:
            for button in row:
                data = button["callback_data"]
                if f":{verb}:" in data and data.endswith(f":{index}"):
                    return data
        raise AssertionError(f"no {verb} callback in {markup}")

    def _tap(self, data, message_chat=OWNER, sender=OWNER):
        return self.picker.callback({"data": data, "from": {"id": sender},
                                     "message": {"chat": {"id": int(message_chat), "type": "private"}}})

    def test_numbered_duplicate_names_show_safe_mac_tails_and_confirm_once(self):
        text, markup = self.picker.begin("devices", OWNER, OWNER)
        self.assertIn("1. Phone", text)
        self.assertIn("…00-00-01", text)
        self.assertIn("2. Phone", text)
        self.assertNotIn("192.0.2.11", text)
        self.assertIsNone(self.picker.message("AA-BB-CC-DD-EE-FF", OWNER, OWNER))

        text, markup = self.picker.message("1,2", OWNER, OWNER)
        self.assertIn("Autobalance", text)
        self.assertIn("unavailable: IPv4-only pause is not verified", text)
        action = self._callback(markup, "action", 0)
        text, markup = self._tap(action)
        self.assertIn("Review: auto", text)
        self.assertNotIn("secret-", text)
        confirm = self._callback(markup, "confirm")
        text, _ = self._tap(confirm)
        self.assertEqual(text, "Applied")
        self.assertEqual(self.applied, [("secret-2", OWNER)])
        self.assertEqual(self.previews[-1][0]["items"], self.rows["devices"])

    def test_paging_and_stale_revision_buttons(self):
        self.rows["devices"] = [{"mac": f"02-00-00-00-01-{i:02X}", "name": f"D{i}"}
                                 for i in range(10)]
        _, first_markup = self.picker.begin("devices", OWNER, OWNER)
        stale = self._callback(first_markup, "item", 0)
        _, next_markup = self._tap(self._callback(first_markup, "page", 1))
        self.assertIsNone(self._tap(stale))
        text, _ = self._tap(self._callback(next_markup, "item", 0))
        self.assertIn("Selected:", text)
        self.assertIn("page 2/2", text)

    def test_owner_sender_and_private_origin_are_bound_to_session(self):
        _, markup = self.picker.begin("groups", OWNER, OWNER)
        callback = self._callback(markup, "item", 0)
        self._tap(callback, sender="77")
        self._tap(callback, message_chat="77")
        # Neither a different sender nor a different origin chat advances the
        # valid owner's session or reaches a preview/apply hook.
        self.assertTrue(self.picker.active(OWNER, OWNER))
        self.assertEqual(self.applied, [])

    def test_expiry_and_cancel_clear_session(self):
        self.picker.begin("devices", OWNER, OWNER)
        self.now += 601
        result = self.picker.message("1", OWNER, OWNER)
        self.assertIn("expired", result[0])
        self.assertFalse(self.picker.active(OWNER, OWNER))

        self.picker.begin("devices", OWNER, OWNER)
        result = self.picker.message("/cancel", OWNER, OWNER)
        self.assertIn("Cancelled", result[0])
        self.assertFalse(self.picker.active(OWNER, OWNER))

    def test_numeric_input_requires_active_session_and_rejects_bad_indexes(self):
        self.assertIsNone(self.picker.message("1", OWNER, OWNER))
        _, _ = self.picker.begin("devices", OWNER, OWNER)
        text, _ = self.picker.message("8", OWNER, OWNER)
        self.assertIn("Choose numbers shown", text)
        self.assertEqual(self.applied, [])

    def test_confirmation_aborts_when_inventory_changes(self):
        _, _ = self.picker.begin("devices", OWNER, OWNER)
        _, markup = self.picker.message("1", OWNER, OWNER)
        _, markup = self._tap(self._callback(markup, "action", 0))
        confirm = self._callback(markup, "confirm")
        self.rows["devices"][0] = {**self.rows["devices"][0], "name": "Renamed"}
        text, _ = self._tap(confirm)
        self.assertIn("inventory changed", text)
        self.assertEqual(self.applied, [])

    def test_action_rows_pair_related_buttons_and_keep_enabled_callback_indexes(self):
        self.rows["actions"] = [
            {"id": "auto", "label": "Autobalance", "enabled": True},
            {"id": "pause", "label": "Pause internet", "enabled": False,
             "reason": "not configured"},
            {"id": "prefer_wan1", "label": "Prefer WAN1", "enabled": True},
            {"id": "prefer_wan2", "label": "Prefer WAN2", "enabled": True},
            {"id": "pause", "label": "Pause internet", "enabled": True},
            {"id": "resume", "label": "Resume internet", "enabled": True},
            {"id": "only_wan1", "label": "Only WAN1", "enabled": True},
            {"id": "only_wan2", "label": "Only WAN2", "enabled": True},
            {"id": "custom", "label": "A custom action with a label longer than twenty", "enabled": True},
        ]
        _, _ = self.picker.begin("devices", OWNER, OWNER)
        _, markup = self.picker.message("1", OWNER, OWNER)
        keyboard = markup["inline_keyboard"]
        action_rows = [row for row in keyboard if all(button["text"] not in {"‹ Back", "Cancel"}
                                                      for button in row)]
        self.assertEqual([[button["text"] for button in row] for row in action_rows], [
            ["Autobalance"], ["Prefer WAN1", "Prefer WAN2"],
            ["Pause internet", "Resume internet"], ["Only WAN1", "Only WAN2"],
            ["A custom action with a label longer than twenty"], ["Bandwidth and priority"],
        ])
        callback_indexes = {button["text"]: int(button["callback_data"].rsplit(":", 1)[1])
                            for row in action_rows for button in row}
        self.assertEqual(callback_indexes, {
            "Autobalance": 0, "Prefer WAN1": 1, "Prefer WAN2": 2,
            "Pause internet": 3, "Resume internet": 4,
            "Only WAN1": 5, "Only WAN2": 6,
            "A custom action with a label longer than twenty": 7,
            "Bandwidth and priority": 8,
        })
        self.assertEqual(sum(button["text"] == "Pause internet"
                             for row in action_rows for button in row), 1,
                         "disabled actions never get a clickable button")

        self._tap(self._callback(markup, "action", callback_indexes["Prefer WAN2"]))
        self.assertEqual(self.previews[-1][0]["action"], "prefer_wan2")

    def test_bot_keyboard_is_minimal_and_legacy_commands_parse(self):
        self.assertEqual(len(KEYBOARD["keyboard"]), 4)
        self.assertEqual(parse_command("/route@MyNetPulseBot Home WAN1"), "route")
        self.assertEqual(parse_command("🔎 Device details"), "device")
        self.assertEqual(parse_command("❔ Help / More"), "more")


class GroupPickerConversations(unittest.TestCase):
    def setUp(self):
        self.devices = [
            {"mac": MAC1, "name": "Phone", "ip": "192.0.2.11"},
            {"mac": MAC2, "name": "Tablet", "ip": "192.0.2.12"},
        ]
        self.groups = [{"id": 7, "name": "Home", "count": 1, "members": [MAC1],
                        "updated_at": 100}]
        self.actions = [{"id": "auto", "label": "Autobalance", "enabled": True}]
        self.group_previews = []
        self.group_applies = []
        self.bandwidth_calls = []
        self.fingerprint_version = "v1"

        def choices():
            return {"devices": self.devices, "groups": self.groups, "actions": self.actions}

        def group_preview(payload, chat):
            self.group_previews.append((dict(payload), chat))
            stable = repr(sorted(payload.items())) + self.fingerprint_version
            return {"text": f"Review group {payload['action']}",
                    "confirm_token": f"group-secret-{len(self.group_previews)}",
                    "fingerprint": stable}

        def group_apply(token, chat):
            self.group_applies.append((token, chat))
            return "Group updated."

        def bandwidth(payload, chat):
            self.bandwidth_calls.append((payload, chat))
            return {"text": "Bandwidth options are unavailable from verified router controls.",
                    "options": ["No measured speed or QoS support is claimed."]}

        self.picker = QuickPicker(choices, lambda payload, chat: {
            "text": "Route review", "confirm_token": "route-secret", "fingerprint": repr(payload)},
            lambda token, chat: "Routed.", group_preview, group_apply, bandwidth,
            clock=lambda: 1000.0)

    @staticmethod
    def _button(markup, text):
        return next(button["callback_data"] for row in markup["inline_keyboard"] for button in row
                    if text.casefold() in button["text"].casefold())

    def _tap(self, data):
        return self.picker.callback({"data": data, "from": {"id": OWNER},
                                     "message": {"chat": {"id": int(OWNER), "type": "private"}}})

    def test_add_group_members_uses_fresh_review_and_opaque_callbacks(self):
        _, markup = self.picker.begin("groups", OWNER, OWNER)
        _, markup = self.picker.message("1", OWNER, OWNER)
        text, markup = self._tap(self._button(markup, "Add devices"))
        self.assertIn("Devices to add to Home", text)
        self.assertNotIn("…00-00-01", text)
        text, markup = self.picker.message("1", OWNER, OWNER)
        self.assertIn("Review group add", text)
        self.assertNotIn("group-secret", text)
        self.assertEqual(self.group_previews[0][0], {"action": "add", "group_id": 7, "macs": [MAC2]})
        self.assertNotIn(MAC2, str(markup))
        text, _ = self._tap(self._button(markup, "Confirm"))
        self.assertEqual(text, "Group updated.")
        self.assertEqual(self.group_applies, [("group-secret-2", OWNER)])

    def test_group_actions_keep_native_routing_and_bandwidth_with_group_management(self):
        self.actions = [
            {"id": "auto", "label": "Autobalance", "enabled": True},
            {"id": "prefer_wan2", "label": "Prefer WAN 2", "enabled": True},
        ]
        route_previews, route_applies = [], []

        def route_preview(payload, chat):
            route_previews.append((payload, chat))
            return {"text": "Review route change for Home", "confirm_token": "route-secret",
                    "fingerprint": repr(payload)}

        self.picker._preview = route_preview
        self.picker._apply = lambda token, chat: route_applies.append((token, chat)) or "Routed."

        _, markup = self.picker.begin("groups", OWNER, OWNER)
        text, markup = self.picker.message("1", OWNER, OWNER)
        self.assertIn("Autobalance", text)
        self.assertIn("Prefer WAN 2", text)
        self.assertIn("Bandwidth and priority", text)
        self.assertIn("Add devices", text)
        row_labels = [[button["text"] for button in row]
                      for row in markup["inline_keyboard"]
                      if not any(button["text"] in {"‹ Back", "Cancel"} for button in row)]
        self.assertIn(["Add devices", "Remove devices"], row_labels)
        self.assertIn(["Rename group", "Delete group"], row_labels)
        text, markup = self._tap(self._button(markup, "Prefer WAN 2"))
        self.assertIn("Review route change for Home", text)
        self.assertEqual(route_previews[0], ({"kind": "groups", "items": [self.groups[0]],
                                             "action": "prefer_wan2"}, OWNER))
        self.assertNotIn("route-secret", text)
        self.assertEqual(self.group_previews, [])
        text, _ = self._tap(self._button(markup, "Confirm"))
        self.assertEqual(text, "Routed.")
        self.assertEqual(route_applies, [("route-secret", OWNER)])
        self.assertEqual(len(route_previews), 2, "confirmation rechecks the same group route review")

    def test_group_router_actions_require_one_group_selection(self):
        self.groups.append({"id": 8, "name": "Office", "count": 0, "members": [], "updated_at": 100})
        _, markup = self.picker.begin("groups", OWNER, OWNER)
        text, markup = self.picker.message("1,2", OWNER, OWNER)
        self.assertIn("Choose one group at a time", text)
        self.assertNotIn("Choose an action", text)
        self.assertNotIn("Confirm", str(markup))

    def test_remove_list_includes_offline_group_members_and_checks_snapshot(self):
        offline = "02-00-00-00-00-03"
        self.groups[0]["members"] = [MAC1, offline]
        self.groups[0]["count"] = 2
        _, markup = self.picker.begin("groups", OWNER, OWNER)
        _, markup = self.picker.message("1", OWNER, OWNER)
        text, markup = self._tap(self._button(markup, "Remove devices"))
        self.assertIn("Saved group member (00-00-03)", text)
        _, markup = self.picker.message("2", OWNER, OWNER)
        confirm = self._button(markup, "Confirm")
        self.groups[0]["members"] = [MAC1, MAC2]
        text, _ = self._tap(confirm)
        self.assertIn("group changed", text)
        self.assertEqual(self.group_applies, [])

    def test_create_and_rename_names_are_scoped_plain_input(self):
        _, markup = self.picker.begin("groups", OWNER, OWNER)
        _, markup = self._tap(self._button(markup, "Create group"))
        text, markup = self.picker.message("/route Home WAN1", OWNER, OWNER)
        self.assertIn("plain name", text)
        text, markup = self.picker.message("Garden", OWNER, OWNER)
        self.assertIn("Devices for Garden", text)
        _, markup = self.picker.message("1", OWNER, OWNER)
        self.assertEqual(self.group_previews[-1][0], {"action": "create", "name": "Garden",
                                                     "macs": [MAC1]})
        self.assertIn("Confirm", str(markup))

        self.picker.begin("groups", OWNER, OWNER)
        _, markup = self.picker.message("1", OWNER, OWNER)
        _, markup = self._tap(self._button(markup, "Rename group"))
        self.picker.message("Vacation", OWNER, OWNER)
        self.assertEqual(self.group_previews[-1][0], {"action": "rename", "group_id": 7,
                                                      "name": "Vacation"})

    def test_create_name_prompt_and_validation_use_40_character_limit(self):
        _, markup = self.picker.begin("groups", OWNER, OWNER)
        text, markup = self._tap(self._button(markup, "Create group"))
        self.assertIn("up to 40 characters", text)
        text, _ = self.picker.message("G" * 41, OWNER, OWNER)
        self.assertIn("1 to 40 characters", text)
        self.assertEqual(self.group_previews, [])
        text, _ = self.picker.message("G" * 40, OWNER, OWNER)
        self.assertIn("Devices for", text)

    def test_delete_warns_that_routes_and_pauses_remain(self):
        _, markup = self.picker.begin("groups", OWNER, OWNER)
        _, markup = self.picker.message("1", OWNER, OWNER)
        text, _ = self._tap(self._button(markup, "Delete group"))
        self.assertIn("WAN routes and Internet pauses remain", text)
        self.assertIn("Smart WAN for this group stops", text)

    def test_confirmation_requires_a_second_click_if_fresh_group_review_changes(self):
        _, markup = self.picker.begin("groups", OWNER, OWNER)
        _, markup = self.picker.message("1", OWNER, OWNER)
        _, markup = self._tap(self._button(markup, "Rename group"))
        _, markup = self.picker.message("Vacation", OWNER, OWNER)
        confirm = self._button(markup, "Confirm")
        self.fingerprint_version = "v2"
        text, markup = self._tap(confirm)
        self.assertIn("review changed", text)
        self.assertEqual(self.group_applies, [])
        text, _ = self._tap(self._button(markup, "Confirm"))
        self.assertEqual(text, "Group updated.")
        self.assertEqual(self.group_applies, [("group-secret-3", OWNER)])

    def test_device_membership_selects_one_group_and_bandwidth_is_truthful(self):
        _, markup = self.picker.begin("devices", OWNER, OWNER)
        _, markup = self.picker.message("2", OWNER, OWNER)
        text, markup = self._tap(self._button(markup, "Add to group"))
        self.assertIn("Choose one group", text)
        _, markup = self.picker.message("1", OWNER, OWNER)
        self.assertEqual(self.group_previews[-1][0], {"action": "add", "group_id": 7,
                                                      "macs": [MAC2]})

        _, markup = self.picker.begin("devices", OWNER, OWNER)
        _, markup = self.picker.message("1", OWNER, OWNER)
        text, markup = self._tap(self._button(markup, "Bandwidth and priority"))
        self.assertIn("unavailable from verified router controls", text)
        self.assertIn("No measured speed", text)
        self.assertEqual(len(self.bandwidth_calls), 1)


class TelegramMoreMenu(unittest.TestCase):
    def test_more_menu_exposes_reports_and_tools_then_returns_home(self):
        labels = {button["text"] for row in MORE_KEYBOARD["keyboard"] for button in row}
        self.assertTrue({"🩺 Pi health", "📈 Last 24h", "📊 Last 7d", "⚡ Speed test",
                         "🔕 Mute 1h", "🔔 Unmute", "🛠 Using Omada", "🏠 Main menu"} <= labels)
        self.assertTrue(all(parse_command(label) is not None for label in labels))
        self.assertNotIn("/route", {entry["command"] for entry in MENU})
        self.assertEqual(parse_command("/route Home WAN1"), "route")

        bot = TelegramBot("123:abc", OWNER, {"help": lambda: "full advanced help"})
        sent = []
        bot.send = lambda text, chat=None, markup=None: sent.append((text, markup))
        msg = {"chat": {"id": 42, "type": "private"}, "from": {"id": 42}}
        bot._handle({**msg, "text": "❔ Help / More"})
        self.assertIn("Reports, tools", sent[-1][0])
        self.assertEqual(sent[-1][1], MORE_KEYBOARD)
        bot._handle({**msg, "text": "🏠 Main menu"})
        self.assertIn("Choose Status, Devices, Groups", sent[-1][0])
        self.assertEqual(sent[-1][1], KEYBOARD)
        bot._handle({**msg, "text": "/help"})
        self.assertEqual(sent[-1][0], "full advanced help")

    def test_more_menu_is_member_safe_and_invalidates_old_picker_callbacks(self):
        actions = []
        hooks = {
            "help": lambda: "full advanced help",
            "quick_choices": lambda: {"devices": [{"mac": MAC1, "name": "Laptop"}],
                                      "groups": [], "actions": []},
            "quick_preview": lambda payload, chat: {"text": "Review", "confirm_token": "secret"},
            "quick_apply": lambda token, chat: actions.append(token) or "Applied",
        }
        bot = TelegramBot("123:abc", OWNER, hooks)
        bot.members["77"] = "Household member"
        sent = []
        bot.send = lambda text, chat=None, markup=None: sent.append((text, chat, markup))
        owner_msg = {"chat": {"id": 42, "type": "private"}, "from": {"id": 42}}
        bot._handle({**owner_msg, "text": "📱 Devices"})
        stale = sent[-1][2]["inline_keyboard"][0][0]["callback_data"]
        bot._handle({**owner_msg, "text": "❔ Help / More"})
        self.assertFalse(bot._quick_picker.active("42", "42"))
        with mock.patch.object(bot, "_call", return_value={"ok": True}):
            bot._handle_button({"id": "stale", "from": {"id": 42}, "data": stale,
                                "message": {"chat": {"id": 42, "type": "private"}}})
        self.assertEqual(actions, [])

        bot._handle({"chat": {"id": 77, "type": "private"}, "from": {"id": 77},
                     "text": "❔ Help / More"})
        self.assertEqual(sent[-1][2], MORE_KEYBOARD)
        bot._handle({"chat": {"id": 77, "type": "private"}, "from": {"id": 77},
                     "text": "📱 Devices"})
        self.assertEqual(sent[-1][0], "Only the owner can do that.")


class TelegramPickerDispatch(unittest.TestCase):
    def test_only_private_configured_owner_can_open_picker(self):
        hooks = {
            "devices": lambda: "legacy inventory",
            "groups": lambda: "legacy groups",
            "help": lambda: "help",
            "quick_choices": lambda: {"devices": [{"mac": MAC1, "name": "Laptop"}],
                                      "groups": [], "actions": []},
            "quick_preview": lambda payload, chat: {"text": "Review", "confirm_token": "secret"},
            "quick_apply": lambda token, chat: "Applied",
        }
        bot = TelegramBot("123:abc", OWNER, hooks)
        bot.members["77"] = "Household member"
        bot._handle({"chat": {"id": 77, "type": "private"}, "from": {"id": 77}, "text": "📱 Devices"})
        self.assertEqual(bot._outbox.get_nowait()[0], "Only the owner can do that.")
        bot._handle({"chat": {"id": 42, "type": "group"}, "from": {"id": 42}, "text": "📱 Devices"})
        self.assertEqual(bot._outbox.get_nowait()[0], "legacy inventory")
        bot._handle({"chat": {"id": 42, "type": "private"}, "from": {"id": 42}, "text": "📱 Devices"})
        text, chat, markup = bot._outbox.get_nowait()
        self.assertIn("…00-00-01", text)
        self.assertEqual(chat, OWNER)
        self.assertTrue(markup["inline_keyboard"])


if __name__ == "__main__":
    unittest.main()
