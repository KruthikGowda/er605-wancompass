"""Secrets must never reach logs (journald), the dashboard API, or error messages.

Exercises normal use and failure paths, captures every log record (with tracebacks) and fails
if the bot token, router password, router session token (stok) or cookie appears anywhere.
"""

import http.client
import json
import logging
import tempfile
import time
import unittest

from netpulse.notifications.telegram import TelegramBot
from netpulse.router.er605 import ER605Client, RouterAuthError
from netpulse.router.watch import RouterWatch
from netpulse.web import app as web
from tests.fake_er605 import FakeER605
from tests.harness import FakeTelegram, Scenario, local

TOKEN = "987654321:AAsecret-bot-token-DO-NOT-LEAK-1234567"
PASSWORD = "Router-Pa55word-DO-NOT-LEAK"


class CaptureLogs(logging.Handler):
    def __init__(self):
        super().__init__(logging.DEBUG)
        self.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
        self.lines: list[str] = []

    def emit(self, record):
        self.lines.append(self.format(record))   # includes the traceback when there is one


class NoSecrets(unittest.TestCase):
    def setUp(self):
        self.logs = CaptureLogs()
        root = logging.getLogger()
        self.old_level = root.level
        root.setLevel(logging.DEBUG)
        root.addHandler(self.logs)
        self.addCleanup(root.removeHandler, self.logs)
        self.addCleanup(root.setLevel, self.old_level)
        self.secrets = {TOKEN, TOKEN.split(":")[1], PASSWORD}

    def assert_clean(self, text: str, where: str):
        for s in self.secrets:
            self.assertNotIn(s, text, f"secret leaked into {where}")

    def tearDown(self):
        self.assert_clean("\n".join(self.logs.lines), "logs")

    def test_the_checker_itself_catches_a_leak(self):
        with self.assertRaises(AssertionError):
            self.assert_clean(f"GET https://api.telegram.org/bot{TOKEN}/getMe", "self-test")

    def test_telegram_failures_do_not_log_the_token(self):
        tg = FakeTelegram()
        self.addCleanup(tg.close)
        tg.fail_sends = True
        bot = TelegramBot(TOKEN, "42", {"help": lambda: "h"}, api_base=tg.base)
        bot.start()
        self.addCleanup(bot.stop)
        bot.send("hello")
        tg.wait_for(lambda m, b: m == "sendMessage-failed")
        time.sleep(0.2)
        dead = TelegramBot(TOKEN, "42", {"help": lambda: "h"}, api_base="http://127.0.0.1:9")
        self.assertIsNone(dead._call("getMe", {}, timeout=2))       # connection refused path
        self.assertTrue(any("telegram" in line for line in self.logs.lines), "failures should still be logged")

    def test_router_login_success_and_failure_do_not_log_credentials(self):
        router = FakeER605(password=PASSWORD)
        self.addCleanup(router.close)
        good = ER605Client(router.host, "admin", PASSWORD, router.fingerprint(), timeout=5)
        with good.session() as c:
            c.get("online", "online")
            self.secrets |= {router.stok, router.cookie}
        w = RouterWatch(ER605Client(router.host, "admin", "wrong-" + PASSWORD, router.fingerprint(), timeout=5),
                        {"WAN1": "Example ISP A", "WAN2": "Example ISP B"})
        events = w.tick(1000.0)
        for e in events:
            self.assert_clean(f"{e.message} {e.alert}", "router events")
        with self.assertRaises(RouterAuthError) as ctx:
            with ER605Client(router.host, "admin", "nope", router.fingerprint(), timeout=5).session():
                pass
        self.assert_clean(str(ctx.exception), "exception text")
        # Session token/cookie from the successful login must not appear either.
        self.assert_clean(json.dumps(w.snapshot()), "router snapshot")

    def test_dashboard_api_exposes_no_secrets(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        s = Scenario(tmp.name, local(12), {}, {"telegram": {"enabled": True, "bot_token": TOKEN, "chat_id": "42",
                                                            "digest_time": ""}})
        self.addCleanup(s.close)
        s.run(3 * 60)
        server = web.start("127.0.0.1", 0, s.board, s.cfg.db_path)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        for path in ("/api/status", "/api/router?raw=1", "/api/events?limit=50", "/api/speedtests",
                     "/api/history?hours=1", "/report?days=1", "/api/report.csv?days=1", "/"):
            c = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=5)
            c.request("GET", path)
            body = c.getresponse().read().decode(errors="replace")
            c.close()
            self.assert_clean(body, path)


if __name__ == "__main__":
    unittest.main()
