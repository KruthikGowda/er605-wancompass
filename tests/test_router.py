import unittest
from contextlib import contextmanager

from netpulse import summary
from netpulse.router.er605 import RouterAuthError, RouterError, normalize_fingerprint, rsa_encrypt, sanitize
from netpulse.router.watch import AUTH_BACKOFF_START, RouterWatch, parse_links


class Crypto(unittest.TestCase):
    def test_zero_padded_raw_rsa(self):
        n = (1 << 1023) + 12345  # any 1024-bit modulus exercises padding + formatting
        e = 0x10001
        out = rsa_encrypt("secret_123", format(n, "x"), format(e, "x"))
        size = 128
        expected = pow(int.from_bytes(b"secret_123" + b"\x00" * (size - 10), "big"), e, n)
        self.assertEqual(out, format(expected, "x").rjust(size * 2, "0"))
        self.assertEqual(len(out), 256)

    def test_fingerprint_normalization(self):
        self.assertEqual(normalize_fingerprint("66:04:af"), "6604AF")


class Sanitize(unittest.TestCase):
    def test_drops_credentials_everywhere(self):
        raw = {"wan": [{"t_name": "WAN1", "ipaddr": "10.0.0.2", "username": "pppoe-user",
                        "password": "x", "psk": "y"}], "stok": "abc", "cpu": 5}
        clean = sanitize(raw)
        self.assertEqual(clean, {"wan": [{"t_name": "WAN1", "ipaddr": "10.0.0.2"}], "cpu": 5})


class Links(unittest.TestCase):
    def test_parse_online_and_status2(self):
        online = [{"state": "up", "t_label": "WAN1", "interface": "WAN1"},
                  {"state": "down", "t_label": "WAN/LAN2", "interface": "WAN2"}]
        status2 = {"normal": [{"t_name": "WAN1", "ipaddr": "10.0.0.2", "gateway": "198.51.100.1"},
                              {"t_name": "WAN2", "ipaddr": "100.64.0.2"}]}
        links = parse_links(online, status2, ["WAN1", "WAN2"])
        self.assertTrue(links["WAN1"].up)
        self.assertEqual(links["WAN1"].ip, "10.0.0.2")
        self.assertEqual(links["WAN1"].gateway, "198.51.100.1")
        self.assertFalse(links["WAN2"].up)

    def test_matches_wan_lan2_label(self):
        links = parse_links([{"state": "up", "t_label": "WAN/LAN2"}], None, ["WAN2"])
        self.assertTrue(links["WAN2"].up)

    def test_interface_flag_is_separate_from_wan_online_state(self):
        online = [{"state": "up", "interface": "WAN1"},
                  {"state": "down", "interface": "WAN2"}]
        status2 = {"normal": [
            {"t_name": "WAN1", "t_isup": "false", "t_proto": "pppoe"},
            {"t_name": "WAN2", "t_isup": True, "t_proto": "pppoe"},
            {"t_name": "LAN", "t_isup": True},
        ]}
        links = parse_links(online, status2, ["WAN1", "WAN2"])
        self.assertTrue(links["WAN1"].up)
        self.assertFalse(links["WAN1"].interface_up)
        self.assertFalse(links["WAN2"].up)
        self.assertTrue(links["WAN2"].interface_up)

    def test_unrecognized_interface_flag_is_unknown(self):
        links = parse_links(None, {"normal": [{"t_name": "WAN1", "t_isup": "maybe"}]}, ["WAN1"])
        self.assertIsNone(links["WAN1"].interface_up)

    def test_wan_dns_servers_are_numeric_unicast_ipv4_only(self):
        links = parse_links(None, {"normal": [{"t_name": "WAN1", "dns1": "1.1.1.1",
                                               "dns2": "8.8.8.8", "dns3": "not-an-ip"},
                                              {"t_name": "WAN2", "dns1": "127.0.0.1",
                                               "dns2": "224.0.0.1"}]}, ["WAN1", "WAN2"])
        self.assertEqual(links["WAN1"].dns_servers, ("1.1.1.1", "8.8.8.8"))
        self.assertEqual(links["WAN2"].dns_servers, ())


class FakeClient:
    def __init__(self):
        self.uptime = 1000
        self.reachable = True
        self.auth_ok = True
        self.logins = 0
        self.online = [{"state": "up", "interface": "WAN1"}, {"state": "up", "interface": "WAN2"}]
        self.status2 = {"normal": [{"t_name": "WAN1", "ipaddr": "10.0.0.1"}, {"t_name": "WAN2", "ipaddr": "100.64.0.1"}]}

    def public_info(self):
        if not self.reachable:
            raise RouterError("cannot connect to router (TimeoutError)")
        return {"uptime": self.uptime, "model": "ER605 v2.30"}

    @contextmanager
    def session(self):
        self.logins += 1
        if not self.auth_ok:
            raise RouterAuthError("login rejected (error_code 700)")
        yield self

    def get(self, module, form, params=None):
        return {"online": self.online, "status2": self.status2,
                "all_usage": {"cpu_usage": ["10", "20"], "mem_usage": "30"},
                "upgrade": {"hardware_version": "ER605 v2.30",
                            "firmware_version": "2.3.3 Build 20251029 Rel.18054"},
                "client": [{}, {}, {}], "reservation": [], "ipscope_list": [], "lan": [],
                "balance_global": [], "balance_basic": []}.get(form, [])


class Watch(unittest.TestCase):
    def setUp(self):
        self.c = FakeClient()
        self.w = RouterWatch(self.c, {"WAN1": "Example ISP A", "WAN2": "Example ISP B"}, poll_minutes=10)

    def test_first_tick_reads_everything(self):
        self.assertEqual(self.w.tick(0), [])
        s = self.w.snapshot()
        self.assertTrue(s["ok"])
        self.assertEqual((s["cpu_pct"], s["mem_pct"], s["clients"]), (15.0, 30.0, 3))
        self.assertTrue(s["links"]["WAN1"]["up"])

    def test_wan_resolver_is_internal_and_not_in_router_api_snapshot(self):
        self.c.status2["normal"][0]["dns1"] = "1.1.1.1"
        self.w.tick(0)
        self.assertEqual(self.w.snap.links["WAN1"].dns_servers, ("1.1.1.1",))
        self.assertNotIn("dns_servers", self.w.snapshot()["links"]["WAN1"])

    def test_full_check_only_every_poll_interval(self):
        self.w.tick(0)
        self.w.tick(60)
        self.w.tick(120)
        self.assertEqual(self.c.logins, 1)
        self.w.tick(600)
        self.assertEqual(self.c.logins, 2)

    def test_full_router_read_runs_under_shared_api_lock(self):
        import threading
        self.w.api_lock = threading.Lock()
        original = self.w._full_check
        entered = []

        def check_under_lock(now, events):
            acquired = self.w.api_lock.acquire(blocking=False)
            if acquired:
                self.w.api_lock.release()
            self.assertFalse(acquired, "full router read must hold the session lock")
            entered.append(True)
            return original(now, events)

        self.w._full_check = check_under_lock
        self.w.tick(0)
        self.assertEqual(entered, [True])

    def test_full_refresh_timestamp_uses_lock_acquisition_time_for_live_clock(self):
        import threading
        import time

        self.w.api_lock.acquire()
        started = time.time()
        worker = threading.Thread(target=self.w.tick, kwargs={
            "now": started, "advance_during_wait": True})
        worker.start()
        try:
            time.sleep(0.08)
            released_at = time.time()
        finally:
            self.w.api_lock.release()
        worker.join(2)

        self.assertFalse(worker.is_alive())
        self.assertGreaterEqual(self.w.snap.checked_at, released_at - 0.01)

    def test_full_refresh_preserves_injected_clock_when_waiting_for_lock(self):
        import threading
        import time

        self.w.api_lock.acquire()
        worker = threading.Thread(target=self.w.tick, args=(1000.0,))
        worker.start()
        try:
            time.sleep(0.08)
        finally:
            self.w.api_lock.release()
        worker.join(2)

        self.assertFalse(worker.is_alive())
        self.assertEqual(self.w.snap.checked_at, 1000.0)

    def test_reboot_detected(self):
        self.w.tick(0)
        self.c.uptime = 1060
        self.assertEqual(self.w.tick(60), [])      # normal: uptime moved with the clock
        self.c.uptime = 30
        events = self.w.tick(120)
        self.assertEqual(len(events), 1)
        self.assertIn("restarted", events[0].alert)
        self.assertTrue(events[0].critical)

    def test_link_down_and_ip_change(self):
        self.w.tick(0)
        self.c.online[0]["state"] = "down"
        self.c.status2["normal"][1]["ipaddr"] = "100.64.9.9"
        events = self.w.tick(600)
        msgs = [e.alert for e in events]
        self.assertTrue(any("Example ISP A WAN status is Offline" in m for m in msgs))
        self.assertTrue(any("Example ISP B reconnected" in m for m in msgs))

    def test_failed_login_backs_off_hard(self):
        self.c.auth_ok = False
        events = self.w.tick(0)
        self.assertEqual(len(events), 1)
        self.assertIn("couldn't log in", events[0].alert)
        self.assertEqual(self.w.snapshot()["next_check"], AUTH_BACKOFF_START)
        # No retries until the backoff has passed, even though polls are due.
        for t in range(600, AUTH_BACKOFF_START, 600):
            self.w.tick(t)
        self.assertEqual(self.c.logins, 1)
        self.w.tick(AUTH_BACKOFF_START + 1)
        self.assertEqual(self.c.logins, 2)

    def test_pause_skips_logins(self):
        self.w.pause(10**9)
        self.w.tick(0)
        self.assertEqual(self.c.logins, 0)
        self.assertTrue(self.w.snapshot()["paused_until"])
        self.w._next_full = 10**9
        self.w.resume()
        self.assertEqual(self.w.snapshot()["paused_until"], 0.0)
        self.assertEqual(self.w._next_full, 0.0)
        self.w.tick(60)
        self.assertEqual(self.c.logins, 1)

    def test_pause_waits_for_active_check_before_returning(self):
        import threading
        import time

        entered = threading.Event()
        finish = threading.Event()
        pause_started = threading.Event()
        paused = threading.Event()
        original = self.w._full_check
        calls = []

        def slow_check(now, events):
            calls.append(True)
            entered.set()
            self.assertTrue(finish.wait(2))
            return original(now, events)

        self.w._full_check = slow_check
        started = time.time()
        tick = threading.Thread(target=self.w.tick, args=(started,))
        tick.start()
        self.assertTrue(entered.wait(2))
        def request_pause():
            pause_started.set()
            self.w.pause(1800)
            paused.set()

        pause = threading.Thread(target=request_pause)
        pause.start()
        self.assertTrue(pause_started.wait(2))
        self.assertFalse(paused.wait(0.05))
        finish.set()
        tick.join(2)
        pause.join(2)
        self.assertFalse(tick.is_alive())
        self.assertFalse(pause.is_alive())
        self.assertTrue(paused.is_set())
        self.assertEqual(calls, [True])

    def test_unreachable_after_three_and_recovery(self):
        self.c.reachable = False
        self.assertEqual(self.w.tick(0), [])
        self.assertEqual(self.w.tick(60), [])
        events = self.w.tick(120)
        self.assertIn("Can't reach", events[0].alert)
        self.assertIsNone(self.w.snapshot()["next_check"])
        self.assertEqual(self.w.tick(180), [])     # reported once
        self.c.reachable = True
        events = self.w.tick(240)
        self.assertIn("reachable again", events[0].alert)

    def test_real_er605_usage_shape(self):
        from netpulse.router.watch import _pct
        usage = {"cpu_usage": {"core1": 3, "core3": 3, "core2": 4, "core4": 9},
                 "mem_usage": {"mem": 30}, "cpu_log": {"core1": [0, 1]}}
        self.assertEqual(_pct(usage, "cpu"), 4.8)
        self.assertEqual(_pct(usage, "mem"), 30.0)

    def test_router_line(self):
        self.w.tick(0)
        line = summary.router_line(self.w.snapshot(), now=0, wan_labels={"WAN1": "Example ISP A", "WAN2": "Example ISP B"})
        self.assertIn("CPU 15%", line)
        self.assertIn("3 devices", line)
        self.assertIn("firmware 2.3.3 Build 20251029 Rel.18054", line)
        self.assertIn("ER605-reported WAN status (last read 0 s ago): Example ISP A Online · Example ISP B Online", line)

    def test_router_line_keeps_interface_flag_distinct(self):
        line = summary.router_line({"ok": True, "checked_at": 100, "links_max_age_seconds": 1200,
                                    "links": {"WAN1": {"up": True, "interface_up": False},
                                              "WAN2": {"up": False, "interface_up": True}}},
                                   now=100, wan_labels={"WAN1": "Example ISP A", "WAN2": "Example ISP B"})
        self.assertIn("ER605 interface flags (not Internet reachability): Example ISP A down · Example ISP B up", line)

    def test_router_line_marks_link_data_stale_without_calling_it_live(self):
        line = summary.router_line({"ok": True, "checked_at": 100, "links_max_age_seconds": 1200,
                                    "links": {"WAN1": {"up": False}, "WAN2": {"up": None}}},
                                   now=2000, wan_labels={"WAN1": "Example ISP A", "WAN2": "Example ISP B"})
        self.assertIn("ER605-reported WAN status (stale · last read 31 min ago)", line)
        self.assertIn("Example ISP A Offline · Example ISP B unknown", line)

    def test_router_line_hides_future_dated_uptime_and_link_status(self):
        line = summary.router_line({"ok": True, "uptime": 100, "uptime_at": 120,
                                    "checked_at": 120, "links_max_age_seconds": 1200,
                                    "links": {"WAN1": {"up": True}}}, now=100)
        self.assertNotIn("up ", line)
        self.assertIn("ER605-reported WAN status (stale", line)
        self.assertIn("read time invalid or in the future", line)

    def test_router_line_reports_device_scan_age_and_auth_retry(self):
        line = summary.router_line({"ok": True, "checked_at": 100, "next_check": 3700,
                                    "links_max_age_seconds": 1200,
                                    "error": "login failed, next try in 60 min", "links": {}}, now=100)
        self.assertIn("Device list: last successful scan 0 s ago; next check in 60 min", line)
        self.assertIn("login failed, next try in 60 min", line)

    def test_router_line_marks_inventory_stale_when_router_is_unreachable(self):
        line = summary.router_line({"ok": False, "checked_at": 100, "next_check": None,
                                    "links_max_age_seconds": 1200,
                                    "error": "cannot connect", "links": {}}, now=3700)
        self.assertIn("Router: not reachable", line)
        self.assertIn("Device list: last successful scan 60 min ago; stale; next scan waits for router recovery", line)

    def test_router_line_reports_firmware_review_lock(self):
        line = summary.router_line({"ok": True, "firmware_version": "2.4.0 Build 20261001",
                                    "control": {"firmware_review_required": True,
                                                "firmware_reason": "ER605 firmware needs review."}}, now=100)
        self.assertIn("firmware 2.4.0 Build 20261001", line)
        self.assertIn("ER605 firmware needs review", line)


if __name__ == "__main__":
    unittest.main()
