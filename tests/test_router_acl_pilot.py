"""Preflight and short-lived phone-probe tests for the isolated ACL pilot."""

from __future__ import annotations

import json
import os
import stat
import tempfile
import urllib.error
import urllib.request
import unittest
from unittest.mock import MagicMock, patch
from types import SimpleNamespace

from netpulse.router.er605 import ER605Client, RouterError
from tools import router_acl_pilot as pilot


MAC = "02-11-22-33-44-55"
IP = "10.23.45.67"
NAME = "Synthetic test phone"
SUFFIX = MAC.replace("-", "")


def facts():
    return {
        "selector": MAC,
        "expected_mac": MAC,
        "expected_ip": IP,
        "clients": [{"name": NAME, "macaddr": MAC, "ipaddr": IP}],
        "reservations": [{"mac": MAC, "ip": IP, "enable": "on"}],
        "ip_entries": [{"name": f"NP_I_{SUFFIX}", "scope": f"{IP}-{IP}"}],
        "ip_groups": [{"name": f"NP_G_{SUFFIX}", "rule_scope": [f"NP_I_{SUFFIX}"]}],
        "policy_routes": [{"name": f"NP_R_{SUFFIX}", "state": "on", "interfaces": "WAN1",
                           "mode": "Priority", "src_ipgroup": f"NP_G_{SUFFIX}",
                           "dst_ipgroup": "IPGROUP_ANY"}],
        "acl_response": {"error_code": "0", "result": {}, "others": {"max_rules": 128}},
        "controls_enabled": True,
        "kill_switch_active": False,
        "firmware_version": "2.3.3 Build 20251029 Rel.18054",
        "accepted_firmware": "2.3.3 Build 20251029 Rel.18054",
        "pending_firmware": None,
        "status_checked_at": 1000.0,
        "uptime": 10000,
        "uptime_at": 1000.0,
        "now": 1001.0,
        "pi_addresses": ["192.168.0.142"],
    }


class PilotPreflightTests(unittest.TestCase):
    def test_pilot_cli_requires_explicit_device(self):
        with self.assertRaises(SystemExit):
            pilot.main([])

    def test_exact_candidate_preflight_returns_only_aggregate_identity(self):
        result = pilot.validate_preflight(**facts())
        self.assertEqual(result["mac_suffix"], MAC[-8:])
        self.assertEqual(result["ip_last_octet"], "67")
        self.assertEqual(result["route"], "WAN1")
        self.assertNotIn(MAC, repr(result))
        self.assertNotIn(IP, repr(result))

    def test_preflight_fails_closed_on_changed_candidate_or_duplicate_lease(self):
        sample = facts()
        sample["clients"].append(dict(sample["clients"][0]))
        with self.assertRaisesRegex(pilot.PilotError, "exactly one"):
            pilot.validate_preflight(**sample)

        sample = facts()
        sample["expected_ip"] = "192.168.0.155"
        with self.assertRaisesRegex(pilot.PilotError, "does not match"):
            pilot.validate_preflight(**sample)

    def test_preflight_refuses_stale_firmware_and_kill_switch(self):
        for update in (
            {"kill_switch_active": True},
            {"pending_firmware": "review"},
            {"accepted_firmware": "older"},
            {"accepted_firmware": "2.3.4 Build 20260101"},
            {"status_checked_at": 600.0},
            {"uptime": 100},
        ):
            sample = facts()
            sample.update(update)
            with self.subTest(update=update), self.assertRaises(pilot.PilotError):
                pilot.validate_preflight(**sample)

    def test_preflight_refuses_nonpriority_route_nonempty_acl_and_pi_ip(self):
        sample = facts()
        sample["policy_routes"][0]["mode"] = "Only"
        with self.assertRaisesRegex(pilot.PilotError, "WAN1 Priority"):
            pilot.validate_preflight(**sample)

        sample = facts()
        sample["acl_response"] = {"error_code": "0", "result": {"rules": [{
            "policy": "DROP", "zone": "LAN", "iptype": "ipv4", "src": "NP_G_X",
            "dest": "IPGROUP_ANY", "service": "ALL"}]}}
        with self.assertRaisesRegex(pilot.PilotError, "existing rules"):
            pilot.validate_preflight(**sample)

        sample = facts()
        sample["pi_addresses"] = [IP]
        with self.assertRaisesRegex(pilot.PilotError, "belongs to the Pi"):
            pilot.validate_preflight(**sample)

        sample = facts()
        sample["reservations"][0].pop("enable")
        with self.assertRaisesRegex(pilot.PilotError, "enabled DHCP reservation"):
            pilot.validate_preflight(**sample)

    def test_acl_row_uses_authenticated_firmware_state_array(self):
        row = pilot.build_acl_row(MAC, pilot.new_rule_name())
        self.assertEqual(row["states"], ["new", "established", "related", "invalid"])
        self.assertEqual(row["dest"], "IPGROUP_ANY")
        self.assertEqual(row["iptype"], "ipv4")

    @patch.object(pilot, "_validate_root_private_metadata")
    def test_private_review_file_requires_explicit_canonical_private_pairs(self, _validate_private):
        with tempfile.TemporaryDirectory() as directory:
            path = pilot.Path(directory) / "approved.json"
            path.write_text(json.dumps({MAC: IP}))
            path.chmod(0o600)
            self.assertEqual(pilot.load_reviewed_devices(path), {MAC: IP})
            self.assertIsNone(pilot.load_reviewed_devices(path).get("02-11-22-33-44-56"))

            for text in ('{"02-11-22-33-44-55":"203.0.113.7"}',
                         '{"02-11-22-33-44-55":"10.23.45.67","02-11-22-33-44-55":"10.23.45.68"}',
                         '{"02:11:22:33:44:55":"10.23.45.67"}', '[]', '{broken'):
                path.write_text(text)
                with self.subTest(text=text), self.assertRaises(pilot.PilotError):
                    pilot.load_reviewed_devices(path)
            path.unlink()
            with self.assertRaisesRegex(pilot.PilotError, "missing or invalid"):
                pilot.load_reviewed_devices(path)

    def test_endpoint_probe_serves_only_temporary_phone_report(self):
        probe = pilot.EndpointProbe("127.0.0.1", "127.0.0.1", ttl_seconds=60)
        self.addCleanup(probe.close)
        url = probe.url
        with urllib.request.urlopen(url, timeout=2) as response:
            page = response.read().decode()
        self.assertIn(pilot.IPIFY_IPV4, page)
        self.assertIn('mode:"cors"', page)
        self.assertIn("expectedGeneration", page)
        self.assertIn("response.ok", page)
        self.assertIn("Number(x)<=255", page)
        self.assertIn("report(false,expectedPhase,expectedGeneration)", page)
        self.assertNotIn("netpulseIPv4", repr(probe.reports))

        state_url = url.replace(pilot.PROBE_PATH + "?t=", "/state?t=")
        with urllib.request.urlopen(state_url, timeout=2) as response:
            self.assertEqual(json.load(response)["phase"], "baseline")

        report_url = url.replace(pilot.PROBE_PATH + "?t=", "/report?t=")
        request = urllib.request.Request(
            report_url,
            data=json.dumps({"phase": "baseline", "internet_ipv4_ok": True,
                             "lan_ok": True}).encode(),
            headers={"Content-Type": "application/json", "Origin": f"http://{probe.server.server_address[0]}:{probe.server.server_address[1]}"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=2) as response:
            self.assertEqual(response.status, 204)
        self.assertEqual(probe.wait_report("baseline", 0),
                         {"internet_ipv4_ok": True, "lan_ok": True})

        with self.assertRaises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(url.replace(probe.token, "wrong-token"), timeout=2)
        self.assertEqual(caught.exception.code, 404)

        probe.set_phase("blocked")
        malformed = urllib.request.Request(
            report_url,
            data=json.dumps([]).encode(),
            headers={"Content-Type": "application/json", "Origin": f"http://{probe.server.server_address[0]}:{probe.server.server_address[1]}"},
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(malformed, timeout=2)
        self.assertEqual(caught.exception.code, 400)


class TransactionTests(unittest.TestCase):
    class FakeClient:
        def __init__(self):
            self.rows = []
            self.calls = []

        def read_acl_pilot_rows(self):
            return list(self.rows)

        def add_acl_pilot_rule(self, rows, row):
            self.calls.append("add")
            self.rows.append(dict(row))
            return self.rows[0]

        def delete_acl_pilot_rule(self, name, expected):
            self.calls.append("delete")
            if self.rows != [expected] or expected.get("name") != name:
                raise RuntimeError("unexpected cleanup target")
            self.rows.clear()

    class FakeProbe:
        def __init__(self, reports):
            self.reports = iter(reports)
            self.phases = []

        def wait_report(self, phase, _timeout):
            return next(self.reports)

        def set_phase(self, phase):
            self.phases.append(phase)

    def test_successful_transaction_observes_block_and_recovery(self):
        client, probe = self.FakeClient(), self.FakeProbe([
            {"internet_ipv4_ok": True, "lan_ok": True},
            {"internet_ipv4_ok": False, "lan_ok": True},
            {"internet_ipv4_ok": True, "lan_ok": True},
        ])
        row = pilot.build_acl_row(MAC, pilot.new_rule_name())
        result = pilot.run_callback_transaction(client, facts()["acl_response"], row, probe, 15)
        self.assertEqual(client.calls, ["add", "delete"])
        self.assertEqual(client.rows, [])
        self.assertTrue(result["recovered_ipv4"])

    def test_failed_block_still_removes_exact_temporary_row(self):
        client, probe = self.FakeClient(), self.FakeProbe([
            {"internet_ipv4_ok": True, "lan_ok": True},
            {"internet_ipv4_ok": True, "lan_ok": True},
            {"internet_ipv4_ok": True, "lan_ok": True},
        ])
        row = pilot.build_acl_row(MAC, pilot.new_rule_name())
        with self.assertRaisesRegex(pilot.PilotError, "did not show IPv4 Internet blocked"):
            pilot.run_callback_transaction(client, facts()["acl_response"], row, probe, 15)
        self.assertEqual(client.calls, ["add", "delete"])
        self.assertEqual(client.rows, [])


class ER605AclMethodTests(unittest.TestCase):
    def _boot_record(self, directory, *, restart=True):
        row = pilot.build_acl_row(MAC, pilot.new_rule_name())
        record = pilot.Path(directory) / "watchdog.json"
        pilot._write_cleanup_record(record, "/etc/netpulse/config.toml", row, 90, restart)
        return record, row

    @unittest.skipIf(os.name == "posix" and os.geteuid() != 0,
                     "root-private watchdog fixture requires root on POSIX")
    def test_boot_recovery_missing_record_never_loads_config_or_logs_in(self):
        with tempfile.TemporaryDirectory() as directory:
            record = pilot.Path(directory) / "watchdog.json"
            factory = MagicMock()
            with patch.object(pilot, "load") as load:
                self.assertEqual(pilot.recover_acl_on_boot(record, client_factory=factory), 0)
            load.assert_not_called()
            factory.assert_not_called()
            self.assertFalse(record.with_suffix(".failed").exists())

    @unittest.skipIf(os.name == "posix" and os.geteuid() != 0,
                     "root-private watchdog fixture requires root on POSIX")
    def test_boot_recovery_refuses_symlink_record_before_login(self):
        with tempfile.TemporaryDirectory() as directory:
            record, _ = self._boot_record(directory)
            target = pilot.Path(directory) / "target"
            target.write_text(record.read_text())
            record.unlink()
            record.symlink_to(target)
            factory = MagicMock()
            with patch.object(pilot, "load") as load:
                self.assertEqual(pilot.recover_acl_on_boot(record, client_factory=factory), 2)
            load.assert_not_called()
            factory.assert_not_called()

    def test_watchdog_metadata_rejects_wrong_owner_and_permissions(self):
        regular = stat.S_IFREG | 0o600
        with patch.object(pilot.os, "name", "posix"):
            with self.assertRaisesRegex(pilot.PilotError, "root-owned"):
                pilot._validate_root_private_metadata(
                    SimpleNamespace(st_uid=1000, st_mode=regular), 0o600, "Watchdog record")
            with self.assertRaisesRegex(pilot.PilotError, "root-owned"):
                pilot._validate_root_private_metadata(
                    SimpleNamespace(st_uid=0, st_mode=stat.S_IFREG | 0o640), 0o600,
                    "Watchdog record")

    @unittest.skipIf(os.name == "posix" and os.geteuid() != 0,
                     "root-private watchdog fixture requires root on POSIX")
    def test_boot_recovery_oversized_record_refuses_before_login(self):
        with tempfile.TemporaryDirectory() as directory:
            record, _ = self._boot_record(directory)
            record.write_bytes(b"x" * (pilot.MAX_WATCHDOG_RECORD_BYTES + 1))
            factory = MagicMock()
            with patch.object(pilot, "load") as load:
                self.assertEqual(pilot.recover_acl_on_boot(record, client_factory=factory), 2)
            load.assert_not_called()
            factory.assert_not_called()

    @unittest.skipIf(os.name == "posix" and os.geteuid() != 0,
                     "root-private watchdog fixture requires root on POSIX")
    def test_boot_recovery_ignores_pid_and_future_deadline_after_clock_rollback(self):
        with tempfile.TemporaryDirectory() as directory:
            record, _ = self._boot_record(directory)
            payload = json.loads(record.read_text())
            payload["deadline"] += 10**9
            record.write_text(json.dumps(payload))
            client = MagicMock()
            client.session.return_value.__enter__.return_value = client
            client.read_acl_pilot_rows.return_value = []
            factory = MagicMock(return_value=client)
            forbidden = MagicMock(side_effect=AssertionError("boot recovery must not wait"))
            with patch.object(pilot, "load", return_value=SimpleNamespace(
                    router=SimpleNamespace(credentials_file="protected", host="router"))), \
                 patch.object(pilot, "load_router_credentials", return_value=SimpleNamespace(
                     username="admin", password="private", cert_sha256="00" * 32)), \
                 patch.object(pilot, "_start_service") as start:
                result = pilot.recover_acl_on_boot(
                    record, pid_alive_fn=forbidden, sleep_fn=forbidden, client_factory=factory)
            self.assertEqual(result, 0)
            forbidden.assert_not_called()
            start.assert_not_called()
            self.assertFalse(record.exists())
            client.read_acl_pilot_rows.assert_called_once_with()

    @unittest.skipIf(os.name == "posix" and os.geteuid() != 0,
                     "root-private watchdog fixture requires root on POSIX")
    def test_boot_recovery_matches_normalized_row_and_preserves_other_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            record, row = self._boot_record(directory)
            observed = {**row, "zone": ["LAN"], "states": list(reversed(row["states"]))}
            unrelated = {"name": "owner rule", "policy": "ACCEPT"}
            client = MagicMock()
            client.session.return_value.__enter__.return_value = client
            client.read_acl_pilot_rows.return_value = [unrelated, observed]
            with patch.object(pilot, "load", return_value=SimpleNamespace(
                    router=SimpleNamespace(credentials_file="protected", host="router"))), \
                 patch.object(pilot, "load_router_credentials", return_value=SimpleNamespace(
                     username="admin", password="private", cert_sha256="00" * 32)), \
                 patch.object(pilot, "_start_service") as start:
                result = pilot.recover_acl_on_boot(record, client_factory=MagicMock(return_value=client))
            self.assertEqual(result, 0)
            client.delete_acl_pilot_rule.assert_called_once_with(row["name"], observed)
            start.assert_not_called()
            self.assertFalse(record.exists())
            self.assertEqual(client.read_acl_pilot_rows.return_value[0], unrelated)

    @unittest.skipIf(os.name == "posix" and os.geteuid() != 0,
                     "root-private watchdog fixture requires root on POSIX")
    def test_boot_recovery_keeps_changed_row_and_writes_failure_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            record, row = self._boot_record(directory)
            changed = {**row, "src": "owner_changed_source"}
            client = MagicMock()
            client.session.return_value.__enter__.return_value = client
            client.read_acl_pilot_rows.return_value = [changed]
            with patch.object(pilot, "load", return_value=SimpleNamespace(
                    router=SimpleNamespace(credentials_file="protected", host="router"))), \
                 patch.object(pilot, "load_router_credentials", return_value=SimpleNamespace(
                     username="admin", password="private", cert_sha256="00" * 32)), \
                 patch.object(pilot, "_start_service") as start:
                result = pilot.recover_acl_on_boot(record, client_factory=MagicMock(return_value=client))
            self.assertEqual(result, 2)
            client.delete_acl_pilot_rule.assert_not_called()
            start.assert_not_called()
            self.assertTrue(record.exists())
            self.assertTrue(record.with_suffix(".failed").exists())

    @unittest.skipIf(os.name == "posix" and os.geteuid() != 0,
                     "root-private watchdog fixture requires root on POSIX")
    def test_boot_recovery_unsafe_parent_refuses_without_api_or_marker_outside(self):
        with tempfile.TemporaryDirectory() as directory:
            record, _ = self._boot_record(directory)
            real_lstat = pilot.Path.lstat

            def unsafe_parent(path):
                if path == record.parent:
                    return SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=0,
                                           st_size=0, st_ino=1, st_dev=1)
                return real_lstat(path)

            factory = MagicMock()
            with patch.object(pilot.Path, "lstat", unsafe_parent), \
                 patch.object(pilot, "load") as load:
                self.assertEqual(pilot.recover_acl_on_boot(record, client_factory=factory), 2)
            load.assert_not_called()
            factory.assert_not_called()
            self.assertFalse(record.with_suffix(".failed").exists())

    def test_watchdog_recovery_requires_canonical_owned_row_not_a_fixed_mac_list(self):
        name = pilot.new_rule_name()
        self.assertTrue(pilot._reviewed_row(pilot.build_acl_row(MAC, name)))
        other_mac = "02-AA-BB-CC-DD-EE"
        self.assertTrue(pilot._reviewed_row(pilot.build_acl_row(other_mac, name)))
        self.assertFalse(pilot._reviewed_row({**pilot.build_acl_row(MAC, name), "src": "NP_G_ANY"}))
        self.assertFalse(pilot._reviewed_row({**pilot.build_acl_row(MAC, name), "policy": "ACCEPT"}))
        self.assertFalse(pilot._reviewed_row({**pilot.build_acl_row(MAC, name), "name": "owner-rule"}))
        self.assertFalse(pilot._reviewed_row({"name": name}))

    @unittest.skipIf(os.name == "posix" and os.geteuid() != 0,
                     "Root-owned watchdog records require a root test process")
    def test_watchdog_cleans_reordered_states_and_restores_service(self):
        for changed, absent in ((False, False), (True, False), (False, True)):
            with self.subTest(changed=changed, absent=absent), tempfile.TemporaryDirectory() as directory:
                row = pilot.build_acl_row(MAC, pilot.new_rule_name())
                record = pilot.Path(directory) / "watchdog.json"
                pilot._write_cleanup_record(record, "/etc/netpulse/config.toml", row, 90, True)
                observed = {**row, "states": list(reversed(row["states"]))}
                if changed:
                    observed["src"] = "owner_changed_source"
                client = MagicMock()
                client.session.return_value.__enter__.return_value = client
                client.read_acl_pilot_rows.return_value = [] if absent else [observed]
                cfg = SimpleNamespace(router=SimpleNamespace(credentials_file="protected", host="router"))
                credentials = SimpleNamespace(username="admin", password="private", cert_sha256="00" * 32)
                with patch.object(pilot, "_pid_alive", return_value=False), \
                     patch.object(pilot, "load", return_value=cfg), \
                     patch.object(pilot, "load_router_credentials", return_value=credentials), \
                     patch.object(pilot, "ER605Client", return_value=client), \
                     patch.object(pilot, "_start_service") as restart:
                    result = pilot._watchdog(record)
                restart.assert_called_once_with()
                if changed:
                    self.assertEqual(result, 2)
                    self.assertTrue(record.exists())
                    self.assertTrue(record.with_suffix(".failed").exists())
                    client.delete_acl_pilot_rule.assert_not_called()
                else:
                    self.assertEqual(result, 0)
                    self.assertFalse(record.exists())
                    if absent:
                        client.delete_acl_pilot_rule.assert_not_called()
                    else:
                        client.delete_acl_pilot_rule.assert_called_once_with(row["name"], observed)

    def test_acl_add_uses_verified_add_key_and_reads_back_metadata(self):
        client = ER605Client("router", "admin", "secret", "00" * 32)
        client._stok = "fake-stok"
        row = pilot.build_acl_row(MAC, pilot.new_rule_name())
        observed = {**row, "states": list(reversed(row["states"])),
                    "t_label": "All the time", "dotname": "Any", "position": "1", "zone": ["LAN"]}
        with patch.object(client, "read_acl_pilot_rows", return_value=[observed]), \
             patch.object(client, "_post", return_value={"error_code": "0"}) as post:
            result = client.add_acl_pilot_rule([], row)
        self.assertEqual(result, observed)
        payload = json.loads(post.call_args.args[1]["data"])
        self.assertEqual(payload["params"]["key"], "add")
        self.assertEqual(payload["params"]["old"], "add")
        self.assertEqual(payload["params"]["new"]["position"], "")
        self.assertEqual(payload["params"]["new"]["states"], list(pilot.ACL_STATE_VALUES))

    def test_acl_delete_requires_exact_unique_temporary_row_and_absence_readback(self):
        client = ER605Client("router", "admin", "secret", "00" * 32)
        client._stok = "fake-stok"
        row = pilot.build_acl_row(MAC, pilot.new_rule_name())
        other = {"name": "owner rule", "policy": "ACCEPT", "zone": "LAN"}
        observed = {**row, "states": list(reversed(row["states"])), "t_label": "All the time"}
        with patch.object(client, "read_acl_pilot_rows", side_effect=[[other, observed], [other]]), \
             patch.object(client, "_post", return_value={"error_code": "0"}) as post:
            client.delete_acl_pilot_rule(row["name"], row)
        payload = json.loads(post.call_args.args[1]["data"])
        self.assertEqual(payload["method"], "delete")
        self.assertEqual(payload["params"], {"index": "1", "key": "key-1"})
        with patch.object(client, "read_acl_pilot_rows", return_value=[other, {**observed, "policy": "ACCEPT"}]), \
             patch.object(client, "_post") as post:
            with self.assertRaisesRegex(RouterError, "changed"):
                client.delete_acl_pilot_rule(row["name"], observed)
            post.assert_not_called()

    @unittest.skipIf(os.name == "posix" and os.geteuid() != 0,
                     "Production watchdog records require root-owned fixtures")
    def test_watchdog_record_contains_only_exact_temporary_rule_and_is_private(self):
        row = pilot.build_acl_row(MAC, pilot.new_rule_name())
        with tempfile.TemporaryDirectory() as directory:
            path = pilot.Path(directory) / "watchdog.json"
            pilot._write_cleanup_record(path, "/etc/netpulse/config.toml", row, 90)
            record = json.loads(path.read_text())
            self.assertEqual(record["row"], row)
            self.assertNotIn("password", path.read_text().lower())
            if os.name == "posix":
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(pilot.PilotError):
                pilot._write_cleanup_record(path, "/etc/netpulse/config.toml",
                                            {**row, "policy": "ACCEPT"}, 90)


if __name__ == "__main__":
    unittest.main()
