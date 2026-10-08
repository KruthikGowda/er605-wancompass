"""LAN presence probes are bounded; absent replies never become an offline claim."""

from __future__ import annotations

import asyncio
import unittest
from unittest import mock

from netpulse.devices.presence import PresenceSettings, PresenceTracker
from netpulse.probes import presence


class LanProbeValidation(unittest.TestCase):
    def test_per_device_ping_cadence_accounts_for_rotating_batches_and_safe_cap(self):
        cadence = presence.per_device_scan_interval_seconds
        self.assertEqual(cadence(60, 1), 60)
        self.assertEqual(cadence(60, 128), 60)
        self.assertEqual(cadence(60, 129), 120)
        self.assertEqual(cadence(60, 256), 120)
        self.assertEqual(cadence(60, 512), 240)
        self.assertIsNone(cadence(60, 513))
        self.assertIsNone(cadence(60, 0))
        self.assertIsNone(cadence(0, 1))

    def test_only_private_unicast_ipv4_targets_are_accepted(self):
        for ip in ("192.168.0.10", "10.1.2.3", "172.16.0.9"):
            self.assertTrue(presence.valid_lan_target(ip), ip)
        for ip in ("8.8.8.8", "255.255.255.255", "127.0.0.1", "169.254.1.2",
                   "224.0.0.1", "::1", "not-an-ip"):
            self.assertFalse(presence.valid_lan_target(ip), ip)

    def test_candidate_rows_are_validated_deduplicated_excluded_and_bounded(self):
        clients = [
            {"macaddr": "aa-bb-cc-dd-ee-01", "ipaddr": "192.168.0.10"},
            {"macaddr": "AA-BB-CC-DD-EE-01", "ipaddr": "192.168.0.10"},
            {"macaddr": "AA-BB-CC-DD-EE-02", "ipaddr": "8.8.8.8"},
            {"macaddr": "aa:bb:cc:dd:ee:03", "ipaddr": "192.168.0.11"},
            {"macaddr": "AA-BB-CC-DD-EE-03", "ipaddr": "192.168.0.12"},
            {"macaddr": "malformed", "ipaddr": "192.168.0.12"},
        ]
        self.assertEqual(presence.candidates(clients, exclude_ips=("192.168.0.10",), limit=1), [])
        self.assertEqual(presence.candidates(clients), [
            ("AA-BB-CC-DD-EE-01", "192.168.0.10"),
        ])
        self.assertEqual(presence.candidates(clients, limit=0), [])

    def test_colon_and_hyphen_macs_normalize_but_distinct_phones_remain_distinct(self):
        clients = [
            {"macaddr": "aa:bb:cc:dd:ee:01", "ipaddr": "192.168.0.10", "name": "Example phone"},
            {"macaddr": "AA-BB-CC-DD-EE-02", "ipaddr": "192.168.0.11", "name": "Example phone"},
        ]

        self.assertEqual(presence.candidates(clients), [
            ("AA-BB-CC-DD-EE-01", "192.168.0.10"),
            ("AA-BB-CC-DD-EE-02", "192.168.0.11"),
        ])

    def test_router_list_is_capped_even_when_it_contains_many_valid_clients(self):
        clients = [{"macaddr": f"02-00-00-00-{n // 256:02X}-{n % 256:02X}",
                    "ipaddr": f"192.168.0.{(n % 200) + 10}"} for n in range(200)]
        # The scan remains capped, and each IP is unique in this snapshot.
        self.assertEqual(len(presence.candidates(clients)), presence.MAX_CLIENTS_PER_SCAN)

    def test_clients_beyond_one_scan_batch_rotate_fairly_between_scans(self):
        clients = [{"macaddr": f"02-00-00-00-{n // 256:02X}-{n % 256:02X}",
                    "ipaddr": f"192.168.0.{(n % 200) + 10}"} for n in range(200)]
        first = presence.candidates(clients, offset=0)
        second = presence.candidates(clients, offset=presence.MAX_CLIENTS_PER_SCAN)
        self.assertEqual(len(first), presence.MAX_CLIENTS_PER_SCAN)
        self.assertEqual(len(second), presence.MAX_CLIENTS_PER_SCAN)
        self.assertEqual(len(set(first) | set(second)), 200)
        self.assertEqual(presence.scan_rounds(len(clients)), 2)
        self.assertEqual(presence.scan_rounds(0), 1)
        self.assertEqual(presence.scan_rounds(presence.MAX_CLIENT_ROWS_TO_SCAN + 1), 1)

    def test_every_supported_inventory_size_is_covered_within_its_scan_rounds(self):
        for count in range(presence.MAX_CLIENTS_PER_SCAN + 1,
                           presence.MAX_CLIENT_ROWS_TO_SCAN + 1):
            with self.subTest(count=count):
                clients = [{
                    "macaddr": f"02-00-{n // 65536:02X}-{(n // 256) % 256:02X}-{n % 256:02X}-01",
                    "ipaddr": f"10.0.{n // 254}.{(n % 254) + 1}",
                } for n in range(count)]
                rounds = presence.scan_rounds(count)
                seen = set()
                for batch in range(rounds):
                    rows = presence.candidates(
                        clients, offset=batch * presence.MAX_CLIENTS_PER_SCAN)
                    self.assertLessEqual(len(rows), presence.MAX_CLIENTS_PER_SCAN)
                    seen.update(rows)
                self.assertEqual(len(seen), count)

    def test_oversized_router_snapshot_is_rejected_instead_of_partially_attributed(self):
        clients = [{"macaddr": f"02-00-00-{n // 65536:02X}-{(n // 256) % 256:02X}-{n % 256:02X}",
                    "ipaddr": f"192.168.0.{(n % 200) + 10}"}
                   for n in range(presence.MAX_CLIENT_ROWS_TO_SCAN + 1)]
        self.assertEqual(presence.candidates(clients), [])

    def test_conflicting_mac_ip_mappings_are_excluded(self):
        clients = [
            {"macaddr": "AA-BB-CC-DD-EE-01", "ipaddr": "192.168.0.10"},
            {"macaddr": "AA-BB-CC-DD-EE-02", "ipaddr": "192.168.0.10"},
            {"macaddr": "AA-BB-CC-DD-EE-03", "ipaddr": "192.168.0.11"},
            {"macaddr": "AA-BB-CC-DD-EE-03", "ipaddr": "192.168.0.12"},
            {"macaddr": "AA-BB-CC-DD-EE-04", "ipaddr": "192.168.0.13"},
        ]
        self.assertEqual(presence.candidates(clients), [
            ("AA-BB-CC-DD-EE-04", "192.168.0.13"),
        ])


class PresenceSettingsTests(unittest.TestCase):
    def test_dashboard_choice_persists_and_defaults_to_config_value(self):
        import tempfile
        from pathlib import Path
        from netpulse.storage.sqlite import Storage

        with tempfile.TemporaryDirectory() as temp:
            db = str(Path(temp) / "presence.sqlite3")
            Storage(db).close()
            settings = PresenceSettings(db, available=True)
            self.assertFalse(settings.enabled)
            self.assertTrue(settings.set_enabled(True))
            self.assertTrue(PresenceSettings(db, available=True).enabled)
            self.assertFalse(PresenceSettings(db, available=True).set_enabled(False))
            self.assertFalse(PresenceSettings(db, available=True).enabled)

    def test_unavailable_router_cannot_enable_lan_probes(self):
        import tempfile
        from pathlib import Path
        from netpulse.storage.sqlite import Storage

        with tempfile.TemporaryDirectory() as temp:
            db = str(Path(temp) / "presence.sqlite3")
            Storage(db).close()
            settings = PresenceSettings(db, available=False)
            with self.assertRaisesRegex(ValueError, "Router monitoring is unavailable"):
                settings.set_enabled(True)


class LanProbeExecution(unittest.IsolatedAsyncioTestCase):
    async def test_scan_uses_bounded_concurrency_and_returns_unknown_on_probe_error(self):
        rows = [{"macaddr": f"AA-BB-CC-DD-{n // 256:02X}-{n % 256:02X}",
                 "ipaddr": f"192.168.0.{n + 10}"} for n in range(20)]
        active = 0
        maximum = 0

        async def fake_ping(ip, timeout):
            nonlocal active, maximum
            active += 1
            maximum = max(maximum, active)
            await asyncio.sleep(0)
            active -= 1
            if ip.endswith(".10"):
                raise OSError("simulated probe error")
            return True

        results = await presence.scan(rows, now=123, ping=fake_ping)
        self.assertEqual(len(results), len(rows))
        self.assertLessEqual(maximum, presence.MAX_CONCURRENT_PINGS)
        first = results["AA-BB-CC-DD-00-00"]
        self.assertIsNone(first["response"])
        self.assertEqual(first["checked_at"], 123)
        self.assertTrue(results["AA-BB-CC-DD-00-01"]["response"])

    async def test_scan_offset_selects_a_rotating_batch_without_exceeding_the_cap(self):
        rows = [{"macaddr": f"02-00-00-00-{n // 256:02X}-{n % 256:02X}",
                 "ipaddr": f"192.168.0.{(n % 200) + 10}"} for n in range(200)]
        first = await presence.scan(rows, ping=mock.AsyncMock(return_value=True), offset=0)
        second = await presence.scan(rows, ping=mock.AsyncMock(return_value=True), offset=128)
        self.assertEqual(len(first), presence.MAX_CLIENTS_PER_SCAN)
        self.assertEqual(len(second), presence.MAX_CLIENTS_PER_SCAN)
        self.assertEqual(len(set(first) | set(second)), 200)

    async def test_ping_exit_codes_distinguish_no_reply_from_probe_error(self):
        class Process:
            def __init__(self, code):
                self.returncode = code

            async def wait(self):
                return self.returncode

        for code, expected in ((0, True), (1, False), (2, None)):
            with mock.patch.object(presence.asyncio, "create_subprocess_exec",
                                   new=mock.AsyncMock(return_value=Process(code))) as run:
                self.assertEqual(await presence._ping("192.168.0.10", 1), expected)
                self.assertIn("192.168.0.10", run.await_args.args)


class PresenceSemantics(unittest.TestCase):
    def test_only_previous_ping_responder_can_transition_to_no_reply(self):
        tracker = PresenceTracker(confirm_misses=3)
        def result(response, ip="192.168.0.10", at=100):
            return {"AA-BB-CC-DD-EE-01": {"ip": ip, "response": response, "checked_at": at}}

        self.assertEqual(tracker.observe(result(False)), [])
        self.assertEqual(tracker.snapshot()["AA-BB-CC-DD-EE-01"]["state"], "unknown")
        self.assertEqual(tracker.observe(result(True, at=110)), [])
        self.assertEqual(tracker.observe(result(False, at=120)), [])
        self.assertEqual(tracker.observe({"AA-BB-CC-DD-EE-01": {"ip": "192.168.0.10",
                                                                  "response": None, "checked_at": 125}}), [])
        self.assertEqual(tracker.observe(result(False, at=130)), [])
        self.assertEqual(tracker.observe(result(False, at=140)),
                         [("AA-BB-CC-DD-EE-01", "no_reply", "192.168.0.10")])
        self.assertEqual(tracker.snapshot()["AA-BB-CC-DD-EE-01"]["state"], "no_reply")

    def test_recovery_and_ip_change_do_not_create_false_departures(self):
        tracker = PresenceTracker(confirm_misses=2)
        mac = "AA-BB-CC-DD-EE-01"
        tracker.observe({mac: {"ip": "192.168.0.10", "response": True, "checked_at": 1}})
        tracker.observe({mac: {"ip": "192.168.0.10", "response": False, "checked_at": 2}})
        transitions = tracker.observe({mac: {"ip": "192.168.0.10", "response": False, "checked_at": 3}})
        self.assertEqual(transitions[0][1], "no_reply")
        self.assertEqual(tracker.observe({mac: {"ip": "192.168.0.10", "response": True, "checked_at": 4}}), [])
        self.assertEqual(tracker.snapshot()[mac]["state"], "no_reply")
        self.assertEqual(tracker.snapshot()[mac]["recovery_replies"], 1)
        self.assertEqual(tracker.observe({mac: {"ip": "192.168.0.10", "response": True, "checked_at": 5}}),
                         [(mac, "reply_restored", "192.168.0.10")])
        self.assertEqual(tracker.snapshot()[mac]["state"], "replying")
        self.assertEqual(tracker.observe({mac: {"ip": "192.168.0.11", "response": False, "checked_at": 6}}), [])
        self.assertEqual(tracker.snapshot()[mac]["state"], "unknown")

    def test_a_miss_cancels_a_pending_recovery_confirmation(self):
        tracker = PresenceTracker(confirm_misses=2, confirm_replies=2)
        mac = "AA-BB-CC-DD-EE-01"
        sample = lambda response, at: {mac: {"ip": "192.168.0.10", "response": response,
                                            "checked_at": at}}
        tracker.observe(sample(True, 1))
        tracker.observe(sample(False, 2))
        tracker.observe(sample(False, 3))
        tracker.observe(sample(True, 4))
        self.assertEqual(tracker.snapshot()[mac]["recovery_replies"], 1)
        self.assertEqual(tracker.observe(sample(False, 5)), [])
        self.assertEqual(tracker.snapshot()[mac]["recovery_replies"], 0)
        self.assertEqual(tracker.snapshot()[mac]["state"], "no_reply")

    def test_probe_error_or_long_gap_breaks_consecutive_recovery_replies(self):
        tracker = PresenceTracker(confirm_misses=2, confirm_replies=2,
                                  probe_interval_seconds=60)
        mac = "AA-BB-CC-DD-EE-01"
        def sample(response, at):
            return {mac: {"ip": "192.168.0.10", "response": response, "checked_at": at}}

        tracker.observe(sample(True, 0))
        tracker.observe(sample(False, 60))
        tracker.observe(sample(False, 120))
        tracker.observe(sample(True, 180))
        tracker.observe(sample(None, 240))
        self.assertEqual(tracker.snapshot()[mac]["recovery_replies"], 0)
        tracker.observe(sample(True, 300))
        tracker.observe(sample(True, 481))  # More than 2.5 configured probe intervals.
        self.assertEqual(tracker.snapshot()[mac]["state"], "no_reply")
        self.assertEqual(tracker.snapshot()[mac]["recovery_replies"], 1)

    def test_rotated_large_inventory_allows_recovery_across_longer_scan_rounds(self):
        tracker = PresenceTracker(confirm_misses=3, confirm_replies=2,
                                  probe_interval_seconds=60)
        mac = "AA-BB-CC-DD-EE-01"
        def sample(response, at):
            return {mac: {"ip": "192.168.0.10", "response": response, "checked_at": at}}

        tracker.observe(sample(True, 0), scan_rounds=4)
        tracker.observe(sample(False, 240), scan_rounds=4)
        tracker.observe(sample(False, 480), scan_rounds=4)
        tracker.observe(sample(False, 720), scan_rounds=4)
        self.assertEqual(tracker.snapshot()[mac]["state"], "no_reply")
        self.assertEqual(tracker.observe(sample(True, 960), scan_rounds=4), [])
        self.assertEqual(tracker.snapshot()[mac]["recovery_replies"], 1)
        self.assertEqual(tracker.observe(sample(True, 1200), scan_rounds=4),
                         [(mac, "reply_restored", "192.168.0.10")])

    def test_oldest_inactive_device_is_evicted_at_tracker_limit(self):
        from netpulse.devices.presence import MAX_TRACKED_DEVICES

        tracker = PresenceTracker()
        for n in range(MAX_TRACKED_DEVICES + 1):
            mac = f"02-00-00-{n // 65536:02X}-{(n // 256) % 256:02X}-{n % 256:02X}"
            tracker.observe({mac: {"ip": f"192.168.0.{(n % 200) + 10}",
                                  "response": True, "checked_at": n + 1}})

        states = tracker.snapshot()
        oldest = "02-00-00-00-00-00"
        newest = "02-00-00-00-02-00"
        self.assertEqual(len(states), MAX_TRACKED_DEVICES)
        self.assertNotIn(oldest, states)
        self.assertIn(newest, states)


if __name__ == "__main__":
    unittest.main()
