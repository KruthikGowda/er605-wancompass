"""Read-only ER605 per-IP byte-counter sampling and identity binding."""
from __future__ import annotations

import threading
import time
import unittest
from contextlib import contextmanager
from types import SimpleNamespace

from netpulse.router.traffic import DeviceTraffic, MAX_ROWS
from netpulse.router.er605 import RouterAuthError


MAC_A, MAC_B = "AA-BB-CC-DD-EE-01", "AA-BB-CC-DD-EE-02"
IP_A, IP_B = "192.168.0.50", "192.168.0.51"


class FakeClock:
    def __init__(self):
        self.wall = 1_800_000_000.0
        self.mono = 100.0

    def time(self):
        return self.wall

    def monotonic(self):
        return self.mono

    def sleep(self, seconds):
        self.wall += seconds
        self.mono += seconds


def client_row(mac, ip):
    return {"macaddr": mac, "ipaddr": ip}


def counter_row(ip, rx, tx):
    return {"addr": ip, "rx_bytes": rx, "tx_bytes": tx,
            "rx_bps": 888888888, "tx_bps": 999999999}


class FakeTrafficClient:
    def __init__(self, *, clients=None, settings=None, stats=None, client_reads=None):
        self.clients = clients or [client_row(MAC_A, IP_A), client_row(MAC_B, IP_B)]
        self.settings = settings if settings is not None else {"ip": "192.168.0.1", "mask": "255.255.255.0", "status": "on"}
        self.stats = list(stats or [])
        self.client_reads = list(client_reads or [])
        self.calls = []
        self.sessions = 0
        self.active = False

    @contextmanager
    def session(self):
        if self.active:
            raise AssertionError("traffic API sessions must be serialized")
        self.active = True
        self.sessions += 1
        try:
            yield self
        finally:
            self.active = False

    def get(self, module, form):
        self.calls.append((module, form, self.active))
        if (module, form) == ("dhcps", "client"):
            return [dict(row) for row in (self.client_reads.pop(0) if self.client_reads else self.clients)]
        if (module, form) == ("ipstats", "setting"):
            return dict(self.settings)
        if (module, form) == ("ipstats", "list"):
            if not self.stats:
                raise AssertionError("unexpected IP stats read")
            value = self.stats.pop(0)
            if isinstance(value, Exception):
                raise value
            return [dict(row) for row in value]
        raise AssertionError((module, form))


class DeviceTrafficTests(unittest.TestCase):
    def make(self, client=None, clock=None, **kwargs):
        clock = clock or FakeClock()
        client = client or FakeTrafficClient()
        watch = SimpleNamespace(client=client, api_lock=threading.RLock(), poll_seconds=60,
                                snap=SimpleNamespace(checked_at=clock.time(), error=None, ok=True),
                                _login_blocked_until=0, _paused_until=0, _unreachable=0)
        return DeviceTraffic(watch, clock=clock.time, sleep=clock.sleep,
                             monotonic=clock.monotonic, **kwargs), client, watch, clock

    def test_derives_rx_tx_rates_from_two_byte_counters_and_returns_only_selected(self):
        stats = [
            [counter_row(IP_A, "100000", 200000), counter_row(IP_B, 1000, 2000)],
            [counter_row(IP_A, 350000, 325000), counter_row(IP_B, 9000, 10000)],
        ]
        traffic, client, _watch, _clock = self.make(FakeTrafficClient(stats=stats))
        result = traffic.read([MAC_A])
        self.assertTrue(result["enabled"])
        self.assertTrue(result["available"])
        self.assertEqual(result["sample_seconds"], 2)
        self.assertEqual(result["devices"], [{"mac": MAC_A, "ip": IP_A, "available": True,
            "rx_mbps": 1.0, "tx_mbps": 0.5, "stale": False, "reason": ""}])
        self.assertIn("router RX/TX", result["source"])
        self.assertEqual([call[:2] for call in client.calls], [
            ("dhcps", "client"), ("ipstats", "setting"), ("ipstats", "list"),
            ("ipstats", "list"), ("dhcps", "client")])
        self.assertTrue(all(call[2] for call in client.calls))

    def test_cache_is_whole_ip_but_identity_is_rechecked_before_and_after_use(self):
        stats = [[counter_row(IP_A, 100, 200), counter_row(IP_B, 300, 400)],
                 [counter_row(IP_A, 200, 400), counter_row(IP_B, 500, 800)]]
        traffic, client, _watch, _clock = self.make(FakeTrafficClient(stats=stats))
        first = traffic.read([MAC_A])
        second = traffic.read([MAC_B])
        self.assertTrue(first["devices"][0]["available"])
        self.assertTrue(second["devices"][0]["available"])
        self.assertEqual(second["devices"][0]["ip"], IP_B)
        self.assertEqual(client.sessions, 2)
        self.assertEqual(sum(call[:2] == ("ipstats", "list") for call in client.calls), 2)

    def test_cache_hit_rechecks_same_selected_identity_in_one_session(self):
        stats = [[counter_row(IP_A, 100, 200)], [counter_row(IP_A, 200, 400)],
                 [counter_row(IP_B, 300, 400)], [counter_row(IP_B, 500, 800)]]
        traffic, client, _watch, _clock = self.make(FakeTrafficClient(stats=stats))
        first = traffic.read([MAC_A])
        second = traffic.read([MAC_A])
        self.assertTrue(first["devices"][0]["available"])
        self.assertTrue(second["devices"][0]["available"])
        self.assertTrue(second["age_seconds"] < 15)
        self.assertEqual(sum(call[:2] == ("ipstats", "list") for call in client.calls), 2)
        client.client_reads = [[client_row(MAC_A, IP_B)], [client_row(MAC_A, IP_B)]]
        changed = traffic.read([MAC_A])
        self.assertEqual(changed["devices"][0]["ip"], IP_B)
        self.assertEqual(changed["devices"][0]["available"], True)
        self.assertEqual(changed["devices"][0]["rx_mbps"], 0.001)

    def test_identity_change_between_before_and_after_reads_aborts_sample(self):
        client = FakeTrafficClient(
            stats=[[counter_row(IP_A, 100, 200)], [counter_row(IP_A, 300, 400)]],
            client_reads=[[client_row(MAC_A, IP_A)], [client_row(MAC_A, IP_B)]])
        traffic, _client, _watch, _clock = self.make(client)
        result = traffic.read([MAC_A])
        self.assertFalse(result["available"])
        self.assertIsNone(result["devices"][0]["rx_mbps"])
        self.assertIn("identity changed", result["reason"])

    def test_duplicate_mac_or_ip_binding_is_unavailable_not_zero(self):
        rows = [client_row(MAC_A, IP_A), client_row(MAC_A, "192.168.0.52"), client_row(MAC_B, IP_B)]
        traffic, client, _watch, _clock = self.make(FakeTrafficClient(clients=rows))
        duplicate_mac = traffic.read([MAC_A])
        self.assertFalse(duplicate_mac["devices"][0]["available"])
        self.assertIsNone(duplicate_mac["devices"][0]["rx_mbps"])
        self.assertEqual(sum(call[:2] == ("ipstats", "list") for call in client.calls), 0)

        rows = [client_row(MAC_A, IP_A), client_row(MAC_B, IP_A)]
        traffic, _client, _watch, _clock = self.make(FakeTrafficClient(clients=rows))
        duplicate_ip = traffic.read([MAC_A])
        self.assertFalse(duplicate_ip["devices"][0]["available"])

    def test_explicit_disabled_or_unknown_status_never_reads_counters(self):
        for status, enabled in (("off", False), ("mystery", None)):
            with self.subTest(status=status):
                client = FakeTrafficClient(settings={"status": status})
                traffic, client, _watch, _clock = self.make(client)
                result = traffic.read([MAC_A])
                self.assertEqual(result["enabled"], enabled)
                self.assertFalse(result["available"])
                self.assertFalse(any(call[:2] == ("ipstats", "list") for call in client.calls))

    def test_malformed_oversized_missing_and_reset_counters_are_unavailable(self):
        cases = (
            [[counter_row(IP_A, -1, 2)], [counter_row(IP_A, 2, 3)]],
            [[counter_row(IP_A, 100, 200)], [counter_row(IP_A, 99, 300)]],
            [[{"addr": "not-an-ip", "rx_bytes": 1, "tx_bytes": 1}], []],
            [[counter_row(IP_A, 1, 1)] * (MAX_ROWS + 1), [counter_row(IP_A, 2, 2)]],
        )
        for stats in cases:
            with self.subTest(case=stats[0][:1]):
                traffic, _client, _watch, _clock = self.make(FakeTrafficClient(stats=stats))
                result = traffic.read([MAC_A])
                self.assertFalse(result["available"])
                self.assertIsNone(result["devices"][0]["rx_mbps"])

    def test_stale_watch_and_auth_backoff_do_not_open_router_session(self):
        clock = FakeClock()
        client = FakeTrafficClient()
        traffic, client, watch, _clock = self.make(client, clock)
        watch.snap.checked_at = clock.time() - 1000
        stale = traffic.read([MAC_A])
        self.assertFalse(stale["available"])
        self.assertEqual(client.sessions, 0)
        watch.snap.checked_at = clock.time()
        watch._login_blocked_until = clock.time() + 300
        backoff = traffic.read([MAC_A])
        self.assertIn("backoff", backoff["reason"])
        self.assertEqual(client.sessions, 0)

    def test_traffic_auth_failure_uses_local_backoff(self):
        client = FakeTrafficClient(stats=[RouterAuthError("private router auth details")])
        traffic, client, _watch, _clock = self.make(client)
        first = traffic.read([MAC_A])
        second = traffic.read([MAC_A])
        self.assertFalse(first["available"])
        self.assertIn("authentication is in backoff", first["reason"])
        self.assertEqual(second["reason"], first["reason"])
        self.assertEqual(client.sessions, 1)

    def test_network_error_returns_sanitized_reason_and_stale_not_available_values(self):
        stats = [[counter_row(IP_A, 100, 200)], [counter_row(IP_A, 200, 400)]]
        traffic, client, _watch, clock = self.make(FakeTrafficClient(stats=stats))
        fresh = traffic.read([MAC_A])
        clock.mono += 16
        clock.wall += 16
        client.stats = [RuntimeError("router request failed for 192.168.0.50 secret")]
        client.client_reads = [[client_row(MAC_A, IP_A)]]
        stale = traffic.read([MAC_A])
        self.assertFalse(stale["available"])
        self.assertTrue(stale["devices"][0]["stale"])
        self.assertEqual(stale["devices"][0]["rx_mbps"], fresh["devices"][0]["rx_mbps"])
        self.assertNotIn(IP_A, stale["reason"])
        self.assertNotIn("secret", stale["reason"])


if __name__ == "__main__":
    unittest.main()
