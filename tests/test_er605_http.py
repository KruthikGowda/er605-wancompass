"""ER605Client and RouterWatch against a fake ER605 over real HTTPS (see fake_er605.py)."""

import json
import unittest
from urllib.parse import parse_qs

from netpulse.router.er605 import CertificateMismatch, ER605Client, RouterAuthError, RouterError
from netpulse.router.watch import RouterWatch
from tests.fake_er605 import FakeER605, load_fixture


class Base(unittest.TestCase):
    def setUp(self):
        self.router = FakeER605()
        self.addCleanup(self.router.close)

    def client(self, password="correct horse", pin=None):
        return ER605Client(self.router.host, "admin", password, pin or self.router.fingerprint(), timeout=5)


class Login(Base):
    def test_full_session_read_and_logout(self):
        c = self.client()
        with c.session():
            online = c.get("online", "online")
        self.assertEqual([o["interface"] for o in online], ["WAN1", "WAN2"])
        self.assertEqual((self.router.logins, self.router.logouts), (1, 1))
        self.assertIsNone(self.router.stok, "session must be released so the Omada web UI isn't kicked later")

    def test_sends_the_headers_the_router_requires(self):
        with self.client().session() as c:
            c.get("online", "online")
        for r in self.router.requests:
            self.assertEqual(r["headers"]["Origin"], f"https://{self.router.host}")
            self.assertTrue(r["headers"]["Referer"].startswith(f"https://{self.router.host}/webpages/"))
            self.assertEqual(r["headers"]["X-Requested-With"], "XMLHttpRequest")

    def test_password_never_sent_in_clear(self):
        with self.client().session():
            pass
        self.assertFalse(any("correct horse" in r["body"] for r in self.router.requests))
        self.assertFalse(any("correct%20horse" in r["body"] or "correct+horse" in r["body"] for r in self.router.requests))

    def test_public_info_needs_no_login(self):
        info = self.client().public_info()
        self.assertEqual(info["model"], "ER605 v2.30")
        self.assertEqual(self.router.logins, 0)

    def test_wrong_password(self):
        with self.assertRaises(RouterAuthError):
            with self.client(password="nope").session():
                pass
        self.assertEqual(self.router.failed_logins, 1)

    def test_certificate_pin_mismatch_refuses_before_sending_anything(self):
        with self.assertRaises(CertificateMismatch):
            self.client(pin="00" * 32).public_info()
        self.assertEqual(self.router.requests, [])

    def test_second_login_kicks_the_first_session(self):
        a, b = self.client(), self.client()
        a.login()
        b.login()
        with self.assertRaises(RouterError):
            a.get("online", "online")
        self.assertIsInstance(b.get("online", "online"), list)
        b.logout()

    def test_missing_csrf_headers_look_like_404(self):
        import http.client
        import ssl
        ctx = ssl._create_unverified_context()
        conn = http.client.HTTPSConnection(self.router.host, context=ctx, timeout=5)
        conn.request("POST", "/cgi-bin/luci/;stok=/locale?form=lang", "operation=read",
                     {"Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(conn.getresponse().status, 404)


class WritesAgainstFakeRouter(Base):
    """Exercise the production HTTPS client against isolated mutable router forms."""

    def setUp(self):
        super().setUp()
        self.router.fixture.update({
            "ipgroup/ipscope_reservation": [],
            "ipgroup/ipgroup_reservation": [],
            "policy_route/policy_route": [],
        })

    def admin_posts(self, key):
        return [r for r in self.router.requests if f"/admin/{key.split('/', 1)[0]}?form={key.split('/', 1)[1]}" in r["path"]
                and json.loads(parse_qs(r["body"]).get("data", ["{}"])[0]).get("method")
                in {"add", "set", "delete"}]

    @staticmethod
    def payload(request):
        return json.loads(parse_qs(request["body"])["data"][0])

    def test_add_and_delete_allowlisted_np_row_use_firmware_wire_shape(self):
        row = {"name": "NP_I_001122334455", "type": "range", "flag": "user",
               "scope": "192.168.0.150-192.168.0.150", "scope_start": "192.168.0.150",
               "scope_end": "192.168.0.150", "comment": "test"}
        with self.client().session() as c:
            self.assertEqual(c.add_row("ipgroup", "ipscope_reservation", [], row), row)
            self.assertEqual(self.router.fixture["ipgroup/ipscope_reservation"], [row])
            c.delete_row("ipgroup", "ipscope_reservation", row["name"])
        writes = self.admin_posts("ipgroup/ipscope_reservation")
        add, delete = map(self.payload, [writes[0], writes[-1]])
        self.assertEqual(add, {"method": "add", "params": {
            "index": 0, "key": "key-0", "old": "add", "new": row}})
        self.assertEqual(delete["method"], "delete")
        self.assertEqual(delete["params"], {"index": "0", "key": "key-0"})

    def test_set_requires_np_row_and_sends_old_and_new(self):
        old = {"name": "NP_R_001122334455", "state": "off", "comment": "before"}
        new = {**old, "comment": "after"}
        self.router.fixture["policy_route/policy_route"] = [old]
        with self.client().session() as c:
            c.set_row("policy_route", "policy_route", 0, "key-0", old, new)
        request = self.admin_posts("policy_route/policy_route")[0]
        self.assertEqual(self.payload(request), {"method": "set", "params": {
            "index": 0, "key": "key-0", "old": old, "new": new}})
        self.assertEqual(self.router.fixture["policy_route/policy_route"], [new])

    def test_dhcp_reservation_add_and_delete_use_numeric_row_id(self):
        new = {"ip": "192.168.0.150", "mac": "00-11-22-33-44-55",
               "note": "NetPulse: test device", "enable": "on", "bind": "0",
               "interface": "LAN1"}
        with self.client().session() as c:
            row = c.add_dhcp_reservation(self.router.fixture["dhcps/reservation"], new)
            self.assertEqual(row["id"], "5")
            c.delete_dhcp_reservation(row["id"], new["mac"], new["ip"], new["note"])
        writes = self.admin_posts("dhcps/reservation")
        add, delete = map(self.payload, [writes[0], writes[-1]])
        self.assertEqual(add["params"], {"index": 1, "key": "key-1", "old": "add",
            "new": {**new, "ip_bind": "on"}})
        self.assertEqual(delete, {"method": "delete", "params": {"index": "1", "key": "5"}})
        self.assertEqual(len(self.router.fixture["dhcps/reservation"]), 1)

    def test_unallowlisted_forms_and_non_np_rows_are_rejected_before_write(self):
        with self.client().session() as c:
            with self.assertRaises(ValueError):
                c.add_row("firewall", "acl", [], {"name": "NP_test"})
            with self.assertRaises(ValueError):
                c.add_row("ipgroup", "ipscope_reservation", [], {"name": "household"})
            with self.assertRaises(ValueError):
                c.delete_row("ipgroup", "ipgroup_reservation", "household")
        self.assertFalse(any("/admin/firewall?" in r["path"] for r in self.router.requests))
        self.assertFalse(any(r for r in self.admin_posts("ipgroup/ipscope_reservation")
                             if self.payload(r).get("method") in {"add", "delete"}))


class WatchAgainstRouter(Base):
    def watch(self, **kw):
        return RouterWatch(self.client(**kw), {"WAN1": "Example ISP A", "WAN2": "Example ISP B"}, poll_minutes=10)

    def test_snapshot_from_recorded_firmware_responses(self):
        w = self.watch()
        self.assertEqual(w.tick(1000.0), [])
        s = w.snapshot()
        self.assertTrue(s["ok"])
        self.assertEqual(s["model"], "ER605 v2.30")
        self.assertEqual(s["hardware_version"], "ER605 v2.30")
        self.assertEqual(s["firmware_version"], "2.3.3 Build 20251029 Rel.18054")
        self.assertTrue(any(r["path"].split("/admin/", 1)[-1].startswith("firmware?form=upgrade")
                            for r in self.router.requests))
        self.assertEqual((s["cpu_pct"], s["mem_pct"], s["clients"]), (4.8, 30.0, 3))
        self.assertEqual(s["links"]["WAN1"], {"up": True, "interface_up": True,
                                                "ip": "10.0.0.2", "gateway": "203.0.113.198"})
        self.assertEqual(s["links"]["WAN2"]["ip"], "100.64.0.2")
        raw = json.dumps(w.snap.raw)
        for secret_key in ("stok", "password", "sysauth"):
            self.assertNotIn(secret_key, raw)

    def test_firmware_version_read_is_optional_and_safe(self):
        self.router.overrides["firmware/upgrade"] = {
            "id": 1, "error_code": "-1000", "result": {"serial_number": "hidden"}}
        w = self.watch()
        w.tick(1000.0)
        snapshot = w.snapshot()
        self.assertTrue(snapshot["ok"], "missing firmware metadata cannot break normal monitoring")
        self.assertIsNone(snapshot["firmware_version"])
        self.assertIsNone(snapshot["hardware_version"])
        self.assertNotIn("serial_number", json.dumps(w.snap.raw))

    def test_policy_route_read_is_optional_and_timestamped(self):
        self.router.fixture["policy_route/policy_route"] = [
            {"name": "NP_R_AABBCCDDEE01", "state": "on", "interfaces": "WAN2"}]
        w = self.watch()
        w.tick(1000.0)
        self.assertEqual(w.snap.raw["policy_routes"], self.router.fixture["policy_route/policy_route"])
        self.assertEqual(w.snap.raw["policy_routes_checked_at"], 1000.0)

        del self.router.fixture["policy_route/policy_route"]
        w.tick(1600.0)
        self.assertIsNone(w.snap.raw["policy_routes"])
        self.assertIsNone(w.snap.raw["policy_routes_checked_at"])

    def test_wrong_password_backs_off(self):
        w = self.watch(password="nope")
        events = w.tick(1000.0)
        self.assertEqual(len(events), 1)
        for t in range(1060, 1000 + 1800, 60):
            w.tick(float(t))
        self.assertEqual(self.router.failed_logins, 1, "must not hammer the router (lockout risk)")

    def test_router_reboot_detected(self):
        w = self.watch()
        w.tick(1000.0)
        self.router.reboot()
        events = w.tick(1060.0)
        self.assertTrue(any("restarted" in (e.alert or "") for e in events))

    def test_firmware_shape_change_does_not_crash(self):
        # A future firmware renames fields and drops the "normal" wrapper.
        self.router.overrides["interface/status2"] = {
            "id": 1, "error_code": "0",
            "result": [{"name": "WAN1", "wan_ip": "10.0.0.9"}, {"name": "WAN2", "wan_ip": "10.0.0.10"}]}
        self.router.overrides["sys_status/all_usage"] = {"id": 1, "error_code": "0", "result": {"cpu": "12%"}}
        w = self.watch()
        w.tick(1000.0)
        s = w.snapshot()
        self.assertTrue(s["ok"])
        self.assertEqual(s["links"]["WAN1"]["ip"], "10.0.0.9")
        self.assertEqual(s["cpu_pct"], 12.0)
        self.assertIsNone(s["mem_pct"])

    def test_endpoint_error_is_reported_not_raised(self):
        self.router.overrides["online/online"] = {"id": 1, "error_code": "-1000"}
        w = self.watch()
        w.tick(1000.0)
        s = w.snapshot()
        self.assertIn("error -1000", s["error"])
        self.assertEqual(self.router.logouts, 1, "still logs out after a failed read")


class RecordedFixture(unittest.TestCase):
    def test_fixture_has_no_real_identifiers(self):
        text = json.dumps(load_fixture())
        self.assertIn("02-00-00-00-00-01", text)
        self.assertIn("203.0.113.198", text)


if __name__ == "__main__":
    unittest.main()
