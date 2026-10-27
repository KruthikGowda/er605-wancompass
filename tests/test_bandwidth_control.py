"""Synthetic, local tests for durable owner-reviewed bandwidth configuration."""
import copy
import json
import tempfile
import threading
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import netpulse.router.bandwidth as bandwidth_module
from netpulse.router.bandwidth import BandwidthControl, BandwidthControlError
from netpulse.router.control import STRICT_WAN_FIRMWARE
from netpulse.storage.bandwidth import BandwidthStoreError


MAC_A, MAC_B = "AA-BB-CC-DD-EE-01", "AA-BB-CC-DD-EE-02"
IP_A, IP_B = "192.0.2.51", "192.0.2.52"


def global_result(enabled="on", threshold="off", counter="0"):
    return {".name": "qos_global", ".type": "qos", "qos_threshold": "0",
            "threshold_enable": threshold, "bandwidth": 100000, ".anonymous": False,
            "qos_enable": enabled, "interface": [], "qos_setting_number": counter}


def global_response(enabled="on", threshold="off", counter="0"):
    return {"id": 1, "result": global_result(enabled, threshold, counter), "error_code": "0"}


def rule(name, group, *, position=1, rate_up=1000, rate_down=1000, setting_index="0"):
    return {".name": name, ".type": "rule", ".anonymous": False,
            "setting_index": str(setting_index), "t_ping_label": "LAN", "t_pong_label": "WAN/LAN2",
            "position": position, "name": name, "if_ping": "LAN", "if_pong": "WAN2",
            "source_type": "ip_group", "ip_group": group, "rate_max": rate_up,
            "rate_max_mate": rate_down, "mode": "priv", "time": "Any",
            "comment": "NetPulse validation", "enable": "on", "ip_type": "src"}


def row_for(mac, *, position=1, down=1000, up=1000):
    hexmac = mac.replace("-", "")
    return rule(f"NP_Q_{hexmac}", f"NP_G_{hexmac}", position=position,
                rate_up=up, rate_down=down, setting_index=str(position - 1))


def collection_response(rows, max_rules=64):
    return {"id": 2, "others": {"max_rules": max_rules},
            "result": copy.deepcopy(rows) if rows else {}, "error_code": "0"}


def target(mac, ip, *, reservation_needed=False):
    return {"mac": mac, "ip": ip, "name": "Device " + mac[-2:],
            "reservation_needed": reservation_needed, "current": "AUTO"}


class FakeClient:
    _stok = "synthetic-session"

    def __init__(self, engine="off", rules=None, target_rows=None):
        self.engine = engine
        self.threshold = "off"
        self.qos_setting_number = "0"
        self.rules = copy.deepcopy(rules or [])
        self.target_rows = target_rows or {
            MAC_A: (IP_A, "Device 01"), MAC_B: (IP_B, "Device 02")}
        self.active_rows = copy.deepcopy(self.target_rows)
        self.host = "192.0.2.1"
        self.active_sessions = 0
        self.posts = []
        self.write_count = 0
        self.fail_after_write_number = None
        self.external_rule_after_write = None
        self.on_post = None
        self.max_rules = 64
        self._setting_counter = 0

    @contextmanager
    def session(self):
        self.active_sessions += 1
        try:
            yield self
        finally:
            self.active_sessions -= 1

    def get_response(self, module, form):
        if (module, form) == ("qos", "global"):
            return global_response(self.engine, self.threshold, self.qos_setting_number)
        if (module, form) == ("qos", "rule"):
            return collection_response(self.rules, self.max_rules)
        if (module, form) == ("qos_ctl", "class"):
            return {"id": 3, "others": {"max_rules": 64}, "result": {}, "error_code": "0"}
        raise AssertionError((module, form))

    def get(self, module, form, params=None):
        if (module, form) == ("dhcps", "client"):
            return [{"macaddr": mac, "ipaddr": ip, "name": name}
                    for mac, (ip, name) in self.active_rows.items()]
        if (module, form) == ("dhcps", "reservation"):
            return [{"mac": mac, "ip": ip, "enable": "on", "note": name}
                    for mac, (ip, name) in self.target_rows.items()]
        if (module, form) == ("ipgroup", "ipscope_reservation"):
            return [{".name": "NP_I_" + mac.replace("-", "") + "_ipscope",
                     ".type": "rule_ipscope", "name": "NP_I_" + mac.replace("-", ""),
                     "flag": "user", "scope": f"{ip}-{ip}", "comment": "NetPulse",
                     ".anonymous": False, "type": "range"}
                    for mac, (ip, _name) in self.target_rows.items()]
        if (module, form) == ("ipgroup", "ipgroup_reservation"):
            return [{".name": "NP_G_" + mac.replace("-", "") + "_ipgroup",
                     ".type": "rule_ipgroup", ".anonymous": False, "flag": "user",
                     "name": "NP_G_" + mac.replace("-", ""),
                     "rule_scope": ["NP_I_" + mac.replace("-", "")], "ref": "1", "comment": ""}
                    for mac in self.target_rows]
        raise AssertionError((module, form))

    def _post(self, url, payload):
        call = (url, copy.deepcopy(payload))
        self.posts.append(call)
        doc = json.loads(payload["data"])
        if self.on_post:
            self.on_post(doc)
        if url.endswith("form=global"):
            if doc["method"] != "set" or set(doc["params"]) != {
                    "qos_enable", "threshold_enable", "qos_threshold"}:
                raise AssertionError("unexpected global QoS write contract")
            if not isinstance(doc["params"]["qos_threshold"], str):
                raise AssertionError("QoS threshold must use the observed string field")
            self.engine = doc["params"]["qos_enable"]
            self.threshold = doc["params"]["threshold_enable"]
        elif url.endswith("form=rule"):
            params = doc["params"]
            if doc["method"] == "delete":
                self.rules.pop(int(params["index"]))
                for index, row in enumerate(self.rules, 1):
                    row["position"] = index
            elif doc["method"] == "add":
                new = params["new"]
                self._setting_counter += 1
                self.rules.append(rule(new["name"], new["ip_group"], position=len(self.rules) + 1,
                                       rate_up=int(new["rate_max"]), rate_down=int(new["rate_max_mate"]),
                                       setting_index=str(self._setting_counter)))
                if self.external_rule_after_write is not None:
                    self.rules.append(copy.deepcopy(self.external_rule_after_write))
                    self.external_rule_after_write = None
        else:
            raise AssertionError(url)
        self.write_count += 1
        if (self.fail_after_write_number == self.write_count):
            self.fail_after_write_number = None
            raise TimeoutError("synthetic lost router response")
        return {"error_code": "0"}


class FakeRoutes:
    def __init__(self, client, *, enabled=True):
        self.client = client
        self.enabled = enabled
        self._router_write_lock = threading.RLock()
        self.kill_switch = "/path/that/does/not/exist"
        self.router = SimpleNamespace(_paused_until=0, _login_blocked_until=0, _unreachable=0,
                                      snap=SimpleNamespace(ok=True))

    def state(self):
        return {"enabled": self.enabled, "configured": self.enabled, "kill_switch": False,
                "firmware_version": STRICT_WAN_FIRMWARE, "firmware_review_required": False,
                "load_balancing": True, "router_age_seconds": 1,
                "router_uptime_seconds": 1000, "router_uptime_age_seconds": 1}

    @staticmethod
    def is_local_device(mac):
        return False

    @staticmethod
    def _assert_not_paused(mac):
        return None


class BandwidthControlTests(unittest.TestCase):
    def setUp(self):
        gate = patch.object(bandwidth_module, "BANDWIDTH_TRANSACTIONS_VERIFIED", True)
        gate.start()
        self.addCleanup(gate.stop)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.now = 1800000000.0
        self.client = FakeClient()
        self.routes = FakeRoutes(self.client)
        self.sleeps = []

        def sleep(seconds):
            self.assertEqual(self.client.active_sessions, 0, "settling must not hold a router login")
            self.assertTrue(self.control.owns_current_thread)
            self.sleeps.append(seconds)

        self.control = BandwidthControl(self.routes, Path(self.temp.name) / "app.db", enabled=True,
                                        sleep=sleep, clock=lambda: self.now)

    def _review(self, targets=None, **kwargs):
        return self.control.preview(targets or [target(MAC_A, IP_A), target(MAC_B, IP_B)],
                                    "owner", down_kbps=2000, up_kbps=1000, **kwargs)

    def test_two_device_batch_and_first_row_delete_preserve_other_rule(self):
        review = self._review()
        self.assertTrue(review["global_setup"])
        self.assertIn("across the router", review["effect"])
        self.assertIn("Allow up to 20 seconds", review["effect"])
        self.assertEqual(review["global_setup_fields"], {"qos_enable": "on", "threshold_enable": "off",
                                                         "qos_threshold": 0})
        self.assertTrue(self.control.check_review(review["token"], "owner")["valid"])
        self.assertEqual(self.client.posts, [], "preview and review validation are read-only")
        observed_phases = []
        self.client.on_post = lambda _doc: observed_phases.append(
            self.control.store.pending()[0]["record"]["phase"])
        applied = self.control.apply(review["token"], "owner")
        self.client.on_post = None
        self.assertTrue(observed_phases)
        self.assertEqual(set(observed_phases), {"applying"})
        global_payload = json.loads(self.client.posts[0][1]["data"])
        self.assertEqual(global_payload["method"], "set")
        self.assertEqual(global_payload["params"], {
            "qos_enable": "on", "threshold_enable": "off", "qos_threshold": "0"})
        self.assertTrue(applied["applied"])
        self.assertEqual(len(self.client.rules), 2)
        self.assertEqual([row["name"] for row in self.client.rules],
                         ["NP_Q_AABBCCDDEE01", "NP_Q_AABBCCDDEE02"])
        self.assertEqual([(row["rate_max_mate"], row["rate_max"]) for row in self.client.rules],
                         [(2000, 1000), (2000, 1000)])
        self.assertEqual(set(self.control.store.caps()), {MAC_A, MAC_B})
        self.assertEqual(self.sleeps, [20])
        self.assertFalse(self.control.state()["enforcement_verified"])

        removal = self.control.preview([target(MAC_A, IP_A)], "owner", remove=True)
        self.control.apply(removal["token"], "owner")
        self.assertEqual([row["name"] for row in self.client.rules], ["NP_Q_AABBCCDDEE02"])
        self.assertNotIn(MAC_A, self.control.store.caps())
        self.assertIn(MAC_B, self.control.store.caps())
        self.assertEqual(self.sleeps, [20, 20])

    def test_actor_binding_failed_first_add_rolls_back_durably_and_settles_once(self):
        review = self._review([target(MAC_A, IP_A)])
        with self.assertRaises(BandwidthControlError):
            self.control.apply(review["token"], "other")
        self.assertTrue(self.control.check_review(review["token"], "owner")["valid"])
        self.client.fail_after_write_number = 2  # global setup is the first write; first cap add is second.
        with self.assertRaises(BandwidthControlError) as recovered_error:
            self.control.apply(review["token"], "owner")
        self.assertIn("previous router state was restored and verified", str(recovered_error.exception))
        self.assertEqual(self.client.rules, [])
        self.assertEqual(self.client.engine, "off")
        self.assertEqual(self.control.pending_count, 0)
        self.assertEqual(self.control.store.caps(), {})
        self.assertEqual(self.sleeps, [20])
        self.assertEqual(self.client.active_sessions, 0)

    def test_unknown_external_rule_keeps_pending_lock_and_reports_unresolved_recovery(self):
        review = self._review([target(MAC_A, IP_A)])
        self.client.fail_after_write_number = 2  # Cap add reached the router; response was lost.
        self.client.external_rule_after_write = row_for("00-11-22-33-44-55", position=2)
        with self.assertRaises(BandwidthControlError) as unresolved_error:
            self.control.apply(review["token"], "owner")
        self.assertIn("Recovery is unresolved", str(unresolved_error.exception))
        self.assertIn("durable operation remains pending", str(unresolved_error.exception))
        self.assertIn("controls are locked", str(unresolved_error.exception))
        self.assertEqual(self.control.pending_count, 1)
        self.assertTrue(self.control.state()["recovery_pending"])
        self.assertEqual([row["name"] for row in self.client.rules],
                         ["NP_Q_AABBCCDDEE01", "NP_Q_001122334455"])

    def test_engine_off_with_existing_rules_is_never_enabled_implicitly(self):
        self.client.rules = [row_for(MAC_B)]
        with self.assertRaises(BandwidthControlError):
            self._review([target(MAC_A, IP_A)])
        self.assertEqual(self.client.posts, [])
        self.assertEqual(self.client.engine, "off")

    def test_qos_setting_counter_does_not_invalidate_review(self):
        review = self._review([target(MAC_A, IP_A)])
        self.client.qos_setting_number = "9"
        self.assertTrue(self.control.check_review(review["token"], "owner")["valid"])

    def test_live_scope_projection_is_accepted_but_unknown_scope_selector_is_rejected(self):
        # FakeClient returns the observed ER605 shape without scope_start/end.
        review = self._review([target(MAC_A, IP_A)])
        self.assertTrue(self.control.check_review(review["token"], "owner")["valid"])
        original_get = self.client.get

        def unknown_scope(module, form, params=None):
            rows = original_get(module, form, params)
            if (module, form) == ("ipgroup", "ipscope_reservation"):
                rows[0]["scope_mask"] = "255.255.255.255"
            return rows

        self.client.get = unknown_scope
        with self.assertRaises(BandwidthControlError):
            self._review([target(MAC_A, IP_A)])
        self.assertEqual(self.client.posts, [])

    def test_active_ip_conflicts_and_changed_target_lease_refuse_before_write(self):
        self.client.active_rows[MAC_B] = (IP_A, "Other device")
        with self.assertRaises(BandwidthControlError):
            self._review([target(MAC_A, IP_A)])
        self.assertEqual(self.client.posts, [])

        self.client.active_rows[MAC_B] = (IP_B, "Device 02")
        self.client.active_rows[MAC_A] = (IP_B, "Device 01")
        with self.assertRaises(BandwidthControlError):
            self._review([target(MAC_A, IP_A)])
        self.assertEqual(self.client.posts, [])

    def test_offline_saved_cap_can_be_removed_when_reserved_identity_is_unchanged(self):
        review = self._review([target(MAC_A, IP_A)])
        self.control.apply(review["token"], "owner")
        self.client.active_rows.pop(MAC_A)
        removal = self.control.preview([target(MAC_A, IP_A)], "owner", remove=True)
        result = self.control.apply(removal["token"], "owner")
        self.assertTrue(result["applied"])
        self.assertEqual(self.client.rules, [])
        self.assertNotIn(MAC_A, self.control.store.caps())

    def test_candidate_transactions_stay_hard_gated_until_verified(self):
        with patch.object(bandwidth_module, "BANDWIDTH_TRANSACTIONS_VERIFIED", False):
            self.assertFalse(self.control.state()["enabled"])
            with self.assertRaises(BandwidthControlError):
                self._review([target(MAC_A, IP_A)])
            self.assertEqual(self.client.posts, [])

    def test_saved_cap_cleanup_stays_available_when_add_config_is_disabled(self):
        review = self._review([target(MAC_A, IP_A)])
        self.control.apply(review["token"], "owner")
        locked_routes = FakeRoutes(self.client, enabled=False)
        cleanup = BandwidthControl(locked_routes, self.control.db_path, enabled=False,
                                   sleep=lambda seconds: self.sleeps.append(seconds), clock=lambda: self.now)
        self.assertFalse(cleanup.state()["enabled"])
        self.assertTrue(cleanup.state()["cleanup_enabled"])
        review_remove = cleanup.preview([target(MAC_A, IP_A)], "owner", remove=True)
        cleanup.apply(review_remove["token"], "owner")
        self.assertEqual(self.client.rules, [])
        self.assertEqual(cleanup.store.caps(), {})

    def test_missing_identity_and_reviewed_missing_reservation_flow(self):
        self.client.target_rows.pop(MAC_A)
        with self.assertRaises(BandwidthControlError):
            self._review([target(MAC_A, IP_A, reservation_needed=False)])
        # Standalone preview may review one fresh DHCP client; apply requires the
        # parent route preflight to create its reservation and NP_G -> NP_I objects.
        self.client.target_rows[MAC_A] = (IP_A, "Device 01")
        original_get = self.client.get

        def missing_objects(module, form, params=None):
            if (module, form) == ("dhcps", "reservation"):
                return []
            if (module, form) in {("ipgroup", "ipscope_reservation"), ("ipgroup", "ipgroup_reservation")}:
                return []
            return original_get(module, form, params)

        self.client.get = missing_objects
        review = self._review([target(MAC_A, IP_A, reservation_needed=True)])
        self.assertEqual(self.client.posts, [])
        self.client.get = original_get  # Parent preflight creates the reviewed reservation and address objects.
        self.assertTrue(self.control.check_review(review["token"], "owner")["valid"])
        result = self.control.apply(review["token"], "owner")
        self.assertTrue(result["applied"])

    def test_group_cas_is_checked_again_at_each_http_write(self):
        group = {"id": 8, "members": [MAC_A]}
        review = self._review([target(MAC_A, IP_A)], group_snapshot=group)
        calls = []

        def changed():
            calls.append(1)
            return len(calls) < 4

        with self.assertRaises(BandwidthControlError):
            self.control.apply(review["token"], "owner", check_unchanged=changed)
        self.assertEqual(len(self.client.rules), 0)
        self.assertEqual(self.control.pending_count, 0)
        self.assertGreaterEqual(len(calls), 4)

    def test_unknown_router_row_during_recovery_retains_pending_gate(self):
        review = self._review([target(MAC_A, IP_A)])
        preview = self.control._tokens[review["token"]]
        with self.client.session() as client:
            snapshot = self.control._snapshot(client)
        record = self.control._intent_record(preview, snapshot)
        ident = self.control.store.prepare(record)
        record["phase"] = "recovering"
        self.control.store.replace(ident, 1, record)
        self.client.rules = [row_for("00-11-22-33-44-55")]
        recovery = self.control.recover_pending()
        self.assertFalse(recovery["recovered"])
        self.assertEqual(self.control.pending_count, 1)
        self.assertFalse(self.control.state()["enabled"])
        self.assertTrue(self.control.state()["recovery_pending"])
        self.assertEqual(len(self.client.rules), 1)


if __name__ == "__main__":
    unittest.main()
