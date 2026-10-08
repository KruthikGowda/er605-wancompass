from __future__ import annotations

import base64
import hashlib
import http.client
import json
import secrets
import tempfile
import unittest
from pathlib import Path

from netpulse.storage.sqlite import Storage
from netpulse.web import app as web


class FakePauseControl:
    def __init__(self):
        self.calls = []
        self.configured = True
        self._records = [{"mac": "AA-BB-CC-DD-EE-01", "label": "Living room", "expires_at": 1234,
                          "status": "paused", "rule": {"name": "NP_PAUSE_SECRET"}}]

    def state(self):
        return {"enabled": self.configured, "configured": self.configured, "cleanup_enabled": False,
                "reason": "Internet pause is disabled in config; staging is not enabled."}

    def records(self):
        return list(self._records)

    def preview(self, mac, **kwargs):
        self.calls.append(("preview", mac, kwargs))
        return {"token": "t-preview", "action": kwargs["action"], "mac": mac}

    def preview_group(self, group_id, **kwargs):
        self.calls.append(("group", group_id, kwargs))
        return {"token": "t-group", "action": kwargs["action"], "group": "Work"}

    def apply(self, token, actor=None):
        self.calls.append(("apply", token, actor))
        return {"action": "pause", "count": 1, "detail": "verified"}


class PauseHttp(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = str(Path(self.tmp.name) / "api.db")
        Storage(self.db).close()
        salt = secrets.token_bytes(16)
        digest = hashlib.pbkdf2_hmac("sha256", b"test-password", salt, 10_000)
        self.auth = Path(self.tmp.name) / "auth.json"
        self.auth.write_text(json.dumps({"username": "owner", "salt": salt.hex(),
                                         "digest": digest.hex(), "iterations": 10_000}), encoding="utf-8")
        self.board = web.StatusBoard()
        self.control = FakePauseControl()
        self.board.set_extra("pause_control", self.control)
        self.server = web.start("127.0.0.1", 0, self.board, self.db, str(self.auth))
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.host, self.port = self.server.server_address

    def request(self, method, path, body=None, *, auth=True, origin=True):
        conn = http.client.HTTPConnection(self.host, self.port, timeout=5)
        headers = {}
        if origin:
            headers["Origin"] = f"http://{self.host}:{self.port}"
        if body is not None:
            headers["Content-Type"] = "application/json"
        if auth:
            raw = base64.b64encode(b"owner:test-password").decode()
            headers["Authorization"] = "Basic " + raw
        conn.request(method, path, body=json.dumps(body) if body is not None else None, headers=headers)
        response = conn.getresponse()
        raw = response.read()
        try:
            parsed = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            parsed = raw.decode(errors="replace")
        result = response.status, parsed
        conn.close()
        return result

    def test_paused_status_requires_auth_and_returns_state_and_records(self):
        self.assertEqual(self.request("GET", "/api/devices/paused", auth=False)[0], 401)
        status, data = self.request("GET", "/api/devices/paused")
        self.assertEqual(status, 200)
        self.assertTrue(data["state"]["enabled"])
        self.assertEqual(data["records"][0]["label"], "Living room")
        self.assertNotIn("rule", data["records"][0], "raw ACL implementation fields stay private")

    def test_disabled_status_uses_plain_language_and_hides_router_details(self):
        self.control.configured = False
        status, data = self.request("GET", "/api/devices/paused")
        self.assertEqual(status, 200)
        self.assertFalse(data["state"]["enabled"])
        self.assertIn("Internet pause has not been enabled", data["state"]["reason"])
        self.assertNotIn("staging", data["state"]["reason"])

    def test_preview_requires_origin_and_passes_management_ip_and_owner_actor(self):
        payload = {"mac": "aa:bb:cc:dd:ee:01", "action": "pause", "duration_seconds": 900}
        self.assertEqual(self.request("POST", "/api/devices/pause/preview", payload, auth=False)[0], 401)
        self.assertEqual(self.request("POST", "/api/devices/pause/preview", payload, origin=False)[0], 403)
        status, preview = self.request("POST", "/api/devices/pause/preview", payload)
        self.assertEqual(status, 200)
        self.assertEqual(preview["token"], "t-preview")
        name, mac, kwargs = self.control.calls[-1]
        self.assertEqual(name, "preview")
        self.assertEqual(mac, "AA-BB-CC-DD-EE-01")
        self.assertEqual(kwargs["actor"], "dashboard owner")
        self.assertEqual(kwargs["duration_seconds"], 900)
        self.assertEqual(kwargs["management_ip"], "127.0.0.1")

    def test_invalid_duration_and_missing_explicit_confirmation_do_not_apply(self):
        for duration in (True, "900", -1, 7200):
            with self.subTest(duration=duration):
                status, _ = self.request("POST", "/api/devices/pause/preview", {
                    "mac": "AA-BB-CC-DD-EE-01", "action": "pause", "duration_seconds": duration})
                self.assertEqual(status, 409)
        self.assertEqual(self.request("POST", "/api/devices/pause/apply", {"token": "t-preview"})[0], 409)
        self.assertFalse(any(call[0] == "apply" for call in self.control.calls))

    def test_group_preview_and_apply_use_the_shared_dashboard_owner(self):
        status, preview = self.request("POST", "/api/device-groups/pause/preview", {
            "id": 12, "action": "resume", "duration_seconds": 0})
        self.assertEqual(status, 200)
        self.assertEqual(preview["token"], "t-group")
        self.assertEqual(self.control.calls[-1][2]["actor"], "dashboard owner")
        status, result = self.request("POST", "/api/devices/pause/apply", {
            "token": "t-group", "confirmed": True})
        self.assertEqual(status, 200)
        self.assertEqual(result["count"], 1)
        self.assertEqual(self.control.calls[-1], ("apply", "t-group", "dashboard owner"))


if __name__ == "__main__":
    unittest.main()
