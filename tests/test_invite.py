import tempfile
import unittest
from pathlib import Path

from netpulse.notifications import telegram
from netpulse.notifications.telegram import TelegramBot
from netpulse.storage.sqlite import KeyValueFile, Storage

OWNER, FRIEND, STRANGER = "42", "77", "99"


def msg(chat, text="hi", **extra):
    return {"chat": {"id": int(chat), "type": "private", "first_name": extra.get("name", "Friend"),
                     "username": extra.get("username")}, "text": text}


class Invites(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        path = str(Path(self.tmp.name) / "t.db")
        Storage(path).close()  # create schema
        self.store = KeyValueFile(path)
        self.bot = self.new_bot()

    def tearDown(self):
        self.tmp.cleanup()

    def new_bot(self):
        bot = TelegramBot("1:x", OWNER, {"status": lambda: "status!", "help": lambda: "help"}, store=self.store)
        bot._call = lambda method, payload, timeout=15: {"ok": True}   # no network
        return bot

    def drain(self):
        out = []
        while not self.bot._outbox.empty():
            out.append(self.bot._outbox.get_nowait())
        return out

    def press(self, data, who=OWNER):
        self.bot._handle_button({"id": "cb", "from": {"id": int(who)}, "data": data,
                                 "message": {"message_id": 5, "chat": {"id": int(who)}}})

    def test_strangers_ignored_without_invite(self):
        self.bot._handle(msg(STRANGER))
        self.assertEqual(self.drain(), [])

    def test_invite_allow_flow(self):
        self.bot._handle(msg(OWNER, "/invite"))
        self.assertIn("Invite open for 2 minutes", self.drain()[0][0])

        self.bot._handle(msg(FRIEND, "hi", name="Asha", username="asha"))
        out = self.drain()
        self.assertEqual(out[0][1], FRIEND)                                   # "please wait" to them
        text, chat, markup = out[1]
        self.assertEqual(chat, OWNER)
        self.assertIn("Asha (@asha) wants to use NetPulse", text)
        self.assertEqual(markup["inline_keyboard"][0][0]["callback_data"], f"allow:{FRIEND}")

        self.press(f"allow:{FRIEND}")
        self.assertIn(FRIEND, self.bot.chat_ids)
        self.assertIn("You're in", self.drain()[0][0])

        # Member can use normal buttons, gets alerts, but can't invite.
        self.bot._handle(msg(FRIEND, "📶 Status"))
        self.assertEqual(self.drain(), [("status!", FRIEND, None)])
        self.bot._handle(msg(FRIEND, "/invite"))
        self.assertEqual(self.drain()[0][0], "Only the owner can do that.")

        # Survives a restart.
        self.bot = self.new_bot()
        self.assertIn(FRIEND, self.bot.chat_ids)

    def test_deny(self):
        self.bot._handle(msg(OWNER, "/invite"))
        self.bot._handle(msg(FRIEND))
        self.drain()
        self.press(f"deny:{FRIEND}")
        self.assertNotIn(FRIEND, self.bot.chat_ids)
        self.assertIn("didn't approve", self.drain()[0][0])

    def test_only_owner_can_press_allow(self):
        self.bot._handle(msg(OWNER, "/invite"))
        self.bot._handle(msg(FRIEND))
        self.press(f"allow:{FRIEND}", who=STRANGER)
        self.assertNotIn(FRIEND, self.bot.chat_ids)

    def test_close_and_timeout(self):
        self.bot._handle(msg(OWNER, "/invite"))
        self.bot._handle(msg(OWNER, "/close"))
        self.drain()
        self.bot._handle(msg(FRIEND))
        self.assertEqual(self.drain(), [])

        self.bot._handle(msg(OWNER, "/invite"))
        self.bot._expire_invite(now=self.bot._invite_until + 1)
        self.assertIn("Invite closed (2 minutes passed)", self.drain()[-1][0])
        self.bot._handle(msg(FRIEND))
        self.assertEqual(self.drain(), [])

    def test_request_after_close_is_expired(self):
        self.bot._handle(msg(OWNER, "/invite"))
        self.bot._handle(msg(FRIEND))
        self.bot._handle(msg(OWNER, "/close"))
        self.press(f"allow:{FRIEND}")
        self.assertNotIn(FRIEND, self.bot.chat_ids)

    def test_people_and_remove(self):
        self.bot._handle(msg(OWNER, "/invite"))
        self.bot._handle(msg(FRIEND, name="Asha"))
        self.press(f"allow:{FRIEND}")
        self.drain()
        self.bot._handle(msg(OWNER, "/people"))
        text, _, markup = self.drain()[0]
        self.assertIn("• Asha", text)
        self.assertEqual(markup["inline_keyboard"][0][0]["callback_data"], f"remove:{FRIEND}")
        self.press(f"remove:{FRIEND}")
        self.assertNotIn(FRIEND, self.bot.chat_ids)

    def test_request_limit_per_invite(self):
        self.bot._handle(msg(OWNER, "/invite"))
        for i in range(telegram.MAX_REQUESTS_PER_INVITE + 3):
            self.bot._handle(msg(str(1000 + i)))
        self.assertEqual(len(self.bot._pending), telegram.MAX_REQUESTS_PER_INVITE)


if __name__ == "__main__":
    unittest.main()
