from __future__ import annotations

import json
import urllib.error
import urllib.request
import unittest
from pathlib import Path
from urllib.parse import urlparse

from tools.dashboard_preview import DEMO_BANNER, INDEX, PreviewServer


class DashboardPreview(unittest.TestCase):
    def test_demo_banner_does_not_cover_dashboard_navigation(self):
        self.assertIn("position:relative", DEMO_BANNER)
        self.assertNotIn("position:sticky", DEMO_BANNER)
        self.assertNotIn("position:fixed", DEMO_BANNER)

    def test_local_server_serves_demo_banner_and_synthetic_dashboard_apis(self):
        production_html = INDEX.read_bytes()
        preview = PreviewServer()
        db_path = preview.db_path
        thread = preview.thread
        self.addCleanup(preview.close)

        parsed = urlparse(preview.url)
        self.assertEqual(parsed.hostname, "127.0.0.1")
        self.assertEqual(preview.server.server_address[0], "127.0.0.1")
        self.assertTrue(db_path.is_file(), "preview owns an ephemeral SQLite file")

        with urllib.request.urlopen(preview.url, timeout=3) as response:
            page = response.read()
            self.assertEqual(response.status, 200)
            self.assertIn(b"DEMO \xc2\xb7 LOCAL PREVIEW", page)
            self.assertIn(b"synthetic data \xc2\xb7 read only", page)
            self.assertIn(b"id=\"devices\"", page)
        self.assertEqual(INDEX.read_bytes(), production_html, "production dashboard source is unchanged")

        with urllib.request.urlopen(preview.url + "api/status", timeout=3) as response:
            status = json.loads(response.read())
        self.assertEqual([wan["state"] for wan in status["wans"]], ["HEALTHY", "OFFLINE"])

        with urllib.request.urlopen(preview.url + "api/devices", timeout=3) as response:
            devices = json.loads(response.read())
        self.assertEqual(len(devices["devices"]), 8)
        self.assertEqual(devices["groups"][0]["name"], "Example Work Group")

        with urllib.request.urlopen(preview.url + "api/devices/paused", timeout=3) as response:
            pauses = json.loads(response.read())
        self.assertEqual({record["status"] for record in pauses["records"]}, {"paused", "error"})
        self.assertTrue(pauses["state"]["enabled"])

        with urllib.request.urlopen(preview.url + "api/actions", timeout=3) as response:
            actions = json.loads(response.read())
        strict = {item["id"]: item for item in actions["actions"] if item["id"].startswith("only_")}
        self.assertTrue(strict["only_wan1"]["enabled"])
        self.assertTrue(strict["only_wan2"]["enabled"])

        with urllib.request.urlopen(
                preview.url + "api/devices/traffic?mac=02-00-00-00-00-01", timeout=3) as response:
            traffic = json.loads(response.read())
        self.assertTrue(traffic["available"])
        self.assertEqual(len(traffic["devices"]), 1)
        self.assertEqual(set(traffic["devices"][0]), {
            "mac", "ip", "available", "stale", "rx_mbps", "tx_mbps", "reason"})
        self.assertEqual(traffic["sample_seconds"], 2.0)

        with urllib.request.urlopen(preview.url + "api/devices/traffic?group_id=1", timeout=3) as response:
            group_traffic = json.loads(response.read())
        self.assertEqual(len(group_traffic["devices"]), 8)
        self.assertTrue(any(row["stale"] for row in group_traffic["devices"]))
        with self.assertRaises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(preview.url + "api/devices/traffic?group_id=999", timeout=3)
        self.assertEqual(caught.exception.code, 400)

    def test_all_http_mutations_are_rejected_and_shutdown_removes_database(self):
        preview = PreviewServer()
        db_path = preview.db_path
        thread = preview.thread
        snapshot = json.dumps(preview.fixture["/api/devices"], sort_keys=True)
        for method, path in (("POST", "api/devices/pause/apply"),
                             ("POST", "api/actions/apply"),
                             ("POST", "api/device-groups/save"),
                             ("PUT", "api/devices/label"),
                             ("PATCH", "api/devices/presence"),
                             ("DELETE", "api/device-groups/delete")):
            request = urllib.request.Request(preview.url + path, data=b"{}", method=method,
                                             headers={"Content-Type": "application/json"})
            with self.subTest(method=method, path=path), self.assertRaises(urllib.error.HTTPError) as caught:
                urllib.request.urlopen(request, timeout=3)
            self.assertEqual(caught.exception.code, 503)
        self.assertEqual(json.dumps(preview.fixture["/api/devices"], sort_keys=True), snapshot)

        preview.close()
        self.assertFalse(thread.is_alive(), "preview server thread has stopped")
        self.assertFalse(db_path.exists(), "ephemeral demo database has been removed")

    def test_combined_action_preview_is_synthetic_and_never_applies(self):
        with PreviewServer() as preview:
            def post(path, payload):
                request = urllib.request.Request(preview.url + path, data=json.dumps(payload).encode(),
                                                 method="POST", headers={"Content-Type": "application/json"})
                try:
                    with urllib.request.urlopen(request, timeout=3) as response:
                        return response.status, json.loads(response.read())
                except urllib.error.HTTPError as error:
                    return error.code, json.loads(error.read())

            before = json.dumps(preview.fixture, sort_keys=True)
            macs = [device["mac"] for device in preview.fixture["/api/devices"]["devices"]]
            one_unreserved = macs[3]
            status, single = post("api/actions/preview", {
                "macs": [one_unreserved], "action": "prefer_wan1", "duration_seconds": 0})
            self.assertEqual(status, 200)
            self.assertEqual(single["target"], "Demo phone")
            self.assertEqual(single["members"][0]["mac"], one_unreserved)
            self.assertTrue(single["members"][0]["reservation_needed"])
            self.assertEqual(single["reservation_count"], 1)
            self.assertEqual(single["token"], "demo-read-only")

            status, group = post("api/actions/preview", {"group_id": 1, "action": "auto", "duration_seconds": 0})
            self.assertEqual(status, 200)
            self.assertEqual(group["group"], "Example Work Group")
            self.assertEqual(group["count"], 8)
            self.assertEqual({member["mac"] for member in group["members"]}, set(macs))
            self.assertTrue(all(member["mac"] in macs for member in group["members"]))

            status, strict = post("api/actions/preview", {
                "macs": [macs[0]], "action": "only_wan1", "duration_seconds": 0})
            self.assertEqual(status, 200)
            self.assertIn("DEMO ONLY", strict["effect"])
            self.assertIn("no WAN fallback", strict["effect"])

            status, pause = post("api/actions/preview", {
                "macs": [macs[0]], "action": "pause", "duration_seconds": 3600})
            self.assertEqual(status, 200)
            self.assertIn("IPv4", pause["effect"])
            self.assertIn("1 hour", pause["effect"])
            self.assertIn("DEMO ONLY", pause["effect"])

            evil = '<script>alert(1)</script>'
            invalid = [
                {"macs": ["02-00-00-00-00-EVIL" + evil], "action": "auto", "duration_seconds": 0},
                {"macs": [macs[0], macs[0]], "action": "auto", "duration_seconds": 0},
                {"macs": [macs[0]], "action": evil, "duration_seconds": 0},
                {"group_id": True, "action": "auto", "duration_seconds": 0},
                {"macs": [macs[0]], "group_id": 1, "action": "auto", "duration_seconds": 0},
                {"macs": [macs[0]], "action": "pause", "duration_seconds": True},
                [macs[0]],
            ]
            for payload in invalid:
                status, error = post("api/actions/preview", payload)
                self.assertEqual(status, 400, payload)
                self.assertNotIn(evil, json.dumps(error))

            request = urllib.request.Request(preview.url + "api/actions/apply",
                                             data=json.dumps({"token": "demo-read-only", "confirmed": True}).encode(),
                                             method="POST", headers={"Content-Type": "application/json"})
            with self.assertRaises(urllib.error.HTTPError) as caught:
                urllib.request.urlopen(request, timeout=3)
            self.assertEqual(caught.exception.code, 503)
            self.assertEqual(json.dumps(preview.fixture, sort_keys=True), before,
                             "catalog and preview endpoints never mutate demo state")

    def test_preview_requests_return_synthetic_review_and_apply_stays_denied(self):
        with PreviewServer() as preview:
            def post(path, payload):
                request = urllib.request.Request(preview.url + path, data=json.dumps(payload).encode(),
                                                 method="POST", headers={"Content-Type": "application/json"})
                try:
                    with urllib.request.urlopen(request, timeout=3) as response:
                        return response.status, json.loads(response.read())
                except urllib.error.HTTPError as error:
                    return error.code, error.read().decode()

            mac = "02-00-00-00-00-01"
            status, single = post("api/devices/pause/preview", {
                "mac": mac, "action": "pause", "duration_seconds": 3600})
            self.assertEqual(status, 200)
            self.assertEqual(single["device"], "Demo Work laptop")
            self.assertEqual(single["effect"], "DEMO ONLY. No router change will occur.")

            status, group = post("api/device-groups/pause/preview", {
                "id": 1, "action": "pause", "duration_seconds": 900})
            self.assertEqual(status, 200)
            self.assertEqual(group["group"], "Example Work Group")
            self.assertEqual(len(group["members"]), 8)
            status, resume = post("api/device-groups/pause/preview", {
                "id": 1, "action": "resume", "duration_seconds": 0})
            self.assertEqual(status, 200)
            self.assertEqual(len(resume["members"]), 2, "resume reviews only saved pause intents")
            status, _ = post("api/device-groups/pause/preview", {
                "id": True, "action": "pause", "duration_seconds": 900})
            self.assertEqual(status, 400)
            status, _ = post("api/devices/pause/apply", {"token": "demo-read-only", "confirmed": True})
            self.assertEqual(status, 503)


if __name__ == "__main__":
    unittest.main()
