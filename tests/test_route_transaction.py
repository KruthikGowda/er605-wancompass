"""Offline tests for delayed strict-route intent, settling, and recovery."""
import copy
import tempfile
import threading
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

from netpulse.router.route_transaction import (
    STRICT_WAN_FIRMWARE, RouteTransaction, RouteTransactionError,
)
from netpulse.storage import sqlite
from netpulse.storage.route_intents import RouteIntentStore
from netpulse.storage.sqlite import Storage


MAC_A, IP_A = "AA-BB-CC-DD-EE-01", "192.0.2.51"
MAC_B, IP_B = "AA-BB-CC-DD-EE-02", "192.0.2.52"
ACTOR = "route-transaction-test"


def managed(mac=MAC_A, *, interface="WAN1", mode="Priority", state="on", index=2):
    suffix = mac.replace("-", "")
    return {"name": "NP_R_" + suffix, "service_type": "ALL",
            "src_ipgroup": "NP_G_" + suffix, "dst_ipgroup": "IPGROUP_ANY",
            "interfaces": interface, "timeobj": "Any", "mode": mode,
            "comment": "NetPulse", "state": state, "index": index,
            "src": "ipgroup", "dst": "ipgroup", "t_label": "LAN"}


def pi_policy(name, index):
    return {"name": name, "service_type": "ALL", "src_ipgroup": "IPGROUP_LAN",
            "dst_ipgroup": "IPGROUP_ANY", "interfaces": "WAN1", "timeobj": "Any",
            "mode": "Priority", "comment": "Pi policy", "state": "on",
            "index": index, "src": "ipgroup", "dst": "ipgroup", "t_label": "LAN"}


class FakeClient:
    def __init__(self, policies, clients, reservations):
        self.policies = copy.deepcopy(policies)
        self.clients = copy.deepcopy(clients)
        self.reservations = copy.deepcopy(reservations)
        self.active_sessions = 0
        self.writes = []

    @contextmanager
    def session(self):
        self.active_sessions += 1
        try:
            yield self
        finally:
            self.active_sessions -= 1

    def get(self, module, form):
        if (module, form) == ("dhcps", "client"):
            return copy.deepcopy(self.clients)
        if (module, form) == ("dhcps", "reservation"):
            return copy.deepcopy(self.reservations)
        if (module, form) == ("policy_route", "policy_route"):
            return copy.deepcopy(self.policies)
        raise AssertionError((module, form))

    @staticmethod
    def _effective(row):
        return {k: v for k, v in row.items() if v is not None}

    def set_row(self, module, form, index, key, old, new):
        assert self.active_sessions
        row = self.policies[index]
        if row.get("name") != old.get("name") or key != f"key-{index}":
            raise RuntimeError("stale row identity")
        if any(row.get(field) != value for field, value in old.items()):
            raise RuntimeError("old row changed")
        self.writes.append(("set", row["name"], index))
        row.update(copy.deepcopy(new))

    def delete_row(self, module, form, name):
        assert self.active_sessions
        found = [(i, row) for i, row in enumerate(self.policies) if row.get("name") == name]
        if len(found) != 1:
            raise RuntimeError("ambiguous delete")
        index, _row = found[0]
        self.writes.append(("delete", name, index))
        self.policies.pop(index)

    def add_row(self, module, form, rows, new):
        assert self.active_sessions
        if rows != self.policies:
            raise RuntimeError("stale add collection")
        self.policies.append(copy.deepcopy(new))
        return copy.deepcopy(new)


class FakeRoutes:
    def __init__(self, db_path, client):
        self.db_path = str(db_path)
        self.client = client
        self._router_write_lock = threading.RLock()
        self.router = SimpleNamespace(snap=SimpleNamespace(firmware_version=STRICT_WAN_FIRMWARE))
        self.readiness = {"enabled": True, "firmware_version": STRICT_WAN_FIRMWARE,
                          "accepted_firmware_version": STRICT_WAN_FIRMWARE,
                          "firmware_review_required": False}

    def state(self):
        return dict(self.readiness)

    @staticmethod
    def _client_mac(row):
        from netpulse.devices.identity import normalize_mac
        return normalize_mac(row.get("macaddr", row.get("mac", "")))

    @staticmethod
    def _client_ip(row):
        return str(row.get("ipaddr", row.get("ip", "")))

    def _reservation(self, leases, reservations, mac):
        from netpulse.devices.identity import normalize_mac
        match = [row for row in reservations if normalize_mac(row.get("mac", row.get("macaddr", ""))) == mac]
        if len(match) != 1:
            raise ValueError("reservation mismatch")
        ip = str(match[0].get("ip"))
        if sum(str(row.get("ip")) == ip for row in reservations) != 1:
            raise ValueError("duplicate reservation IP")
        return match[0], ip

    def route_state(self):
        return sqlite.device_routes(self.db_path)


class RouteTransactionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db_path = Path(self.tmp.name) / "app.db"
        self.storage = Storage(str(self.db_path))
        self.addCleanup(self.storage.db.close)
        self.client = FakeClient(
            [pi_policy("pi-route-a", 1), managed(MAC_A, index=2),
             pi_policy("pi-route-b", 3), managed(MAC_B, index=4)],
            [{"macaddr": MAC_A, "ipaddr": IP_A}, {"macaddr": MAC_B, "ipaddr": IP_B}],
            [{"mac": MAC_A, "ip": IP_A, "enable": "on"},
             {"mac": MAC_B, "ip": IP_B, "enable": "on"}],
        )
        self.routes = FakeRoutes(self.db_path, self.client)
        self.store = RouteIntentStore(self.db_path)
        sqlite.set_device_route(str(self.db_path), MAC_A, IP_A, "WAN1", 100, "owner", "AUTO",
                                "applied", expires_at=500, expires_monotonic=300.0, boot_id="boot-a")
        sqlite.set_device_route(str(self.db_path), MAC_B, IP_B, "WAN2", 101, "owner", "AUTO",
                                "applied", expires_at=600, expires_monotonic=400.0, boot_id="boot-a")
        self.sleep_calls = []

    def make_transaction(self, sleep=None):
        if sleep is None:
            def sleep(seconds):
                self.assertEqual(self.client.active_sessions, 0, "no router session may span settling")
                self.sleep_calls.append(seconds)
        return RouteTransaction(self.routes, self.store, sleep=sleep, clock=lambda: 200,
                                settle_seconds=30)

    def apply_callback(self, tx, macs=(MAC_A, MAC_B), route="WAN2_ONLY", actor=ACTOR):
        def apply():
            self.assertTrue(tx.owns_current_thread)
            pending = self.store.pending()
            self.assertEqual(len(pending), 1)
            self.assertEqual(pending[0]["record"]["phase"], "applying")
            with self.client.session() as api:
                for mac in macs:
                    name = "NP_R_" + mac.replace("-", "")
                    target = next((row for row in api.policies if row["name"] == name), None)
                    if route == "AUTO":
                        patch = {"state": "off"}
                    else:
                        patch = {"interfaces": route.removesuffix("_ONLY"),
                                 "mode": "Only" if route.endswith("_ONLY") else "Priority",
                                 "state": "on"}
                    if target:
                        target.update(patch)
                    elif route != "AUTO":
                        target = {**managed(mac, interface=patch["interfaces"], mode="Only"), **patch}
                        target["index"] = max((row.get("index", -1) for row in api.policies), default=-1) + 1
                        api.policies.append(target)
            for ix, mac in enumerate(macs):
                saved = self.routes.route_state().get(mac)
                sqlite.set_device_route(str(self.db_path), mac, IP_A if mac == MAC_A else IP_B,
                                        route, 300 + ix, actor, saved["route"] if saved else "AUTO",
                                        "applied")
            return "applied"
        return apply

    def _seed_recovery_intent(self, mac=MAC_A, *, new=False):
        tx = self.make_transaction()
        targets, _before_rows = tx._capture_targets([mac], "WAN1_ONLY")
        if new:
            target = targets[0]
            target["before_row"] = None
        saved = self.routes.route_state().get(mac)
        target = targets[0]
        target["before_saved"] = copy.deepcopy(saved)
        record = {"actor": ACTOR, "created_at": 200, "firmware": STRICT_WAN_FIRMWARE,
                  "targets": targets, "phase": "applying"}
        intent_id = self.store.prepare(record)
        name = "NP_R_" + mac.replace("-", "")
        if new:
            with self.client.session() as api:
                created = {"name": name, "service_type": "ALL", "src_ipgroup": "NP_G_" + mac.replace("-", ""),
                           "dst_ipgroup": "IPGROUP_ANY", "interfaces": "WAN1", "timeobj": "Any",
                           "mode": "Only", "comment": "NetPulse", "state": "on", "index": 5,
                           "src": "ipgroup", "dst": "ipgroup", "t_label": "LAN"}
                api.policies.append(created)
            sqlite.set_device_route(str(self.db_path), mac, IP_A if mac == MAC_A else IP_B,
                                    "WAN1_ONLY", 201, ACTOR, saved["route"] if saved else "AUTO", "applied")
        else:
            with self.client.session() as api:
                row = next(row for row in api.policies if row["name"] == name)
                row.update(interfaces="WAN1", mode="Only", state="on")
            sqlite.set_device_route(str(self.db_path), mac, IP_A if mac == MAC_A else IP_B,
                                    "WAN1_ONLY", 201, ACTOR, saved["route"], "applied")
        return intent_id, target

    def _set_strict_before(self, mac=MAC_A):
        name = "NP_R_" + mac.replace("-", "")
        row = next(row for row in self.client.policies if row["name"] == name)
        row.update(mode="Only", interfaces="WAN1", state="on")
        ip = IP_A if mac == MAC_A else IP_B
        sqlite.set_device_route(str(self.db_path), mac, ip, "WAN1_ONLY", 100,
                                "owner", "AUTO", "applied", expires_at=500,
                                expires_monotonic=300.0, boot_id="boot-a")

    def test_normal_batch_prepares_before_callback_settles_once_and_finishes(self):
        tx = self.make_transaction()
        result = tx.run([MAC_A, MAC_B], "WAN2_ONLY", ACTOR,
                        self.apply_callback(tx))
        self.assertEqual(result, "applied")
        self.assertEqual(self.sleep_calls, [30])
        self.assertEqual(self.store.pending(), [])
        self.assertEqual([r["name"] for r in self.client.policies],
                         ["pi-route-a", "NP_R_" + MAC_A.replace("-", ""),
                          "pi-route-b", "NP_R_" + MAC_B.replace("-", "")])
        self.assertTrue(all(row["mode"] == "Only" and row["interfaces"] == "WAN2"
                            for row in self.client.policies if row["name"].startswith("NP_R_")))

    def test_nested_same_coordinator_call_runs_callback_without_second_intent(self):
        tx = self.make_transaction()
        nested_calls = []

        def outer():
            nested = tx.run([MAC_A], "WAN2_ONLY", ACTOR,
                            lambda: nested_calls.append("nested") or "nested result")
            self.apply_callback(tx)()
            return nested

        self.assertEqual(tx.run([MAC_A, MAC_B], "WAN2_ONLY", ACTOR, outer), "nested result")
        self.assertEqual(nested_calls, ["nested"])
        self.assertEqual(len(self.sleep_calls), 1)
        self.assertEqual(self.store.pending(), [])

    def test_non_strict_route_runs_without_intent_or_settling_delay(self):
        tx = self.make_transaction()
        self.assertEqual(tx.run([MAC_A], "WAN2", ACTOR, lambda: "ordinary"), "ordinary")
        self.assertEqual(self.store.pending(), [])
        self.assertEqual(self.sleep_calls, [])

    def test_strict_to_prefer_is_journaled_and_settled(self):
        self._set_strict_before()
        tx = self.make_transaction()
        self.assertEqual(tx.run([MAC_A], "WAN2", ACTOR,
                                self.apply_callback(tx, (MAC_A,), "WAN2")), "applied")
        self.assertEqual(self.client.policies[1]["mode"], "Priority")
        self.assertEqual(self.client.policies[1]["interfaces"], "WAN2")
        self.assertEqual(self.routes.route_state()[MAC_A]["route"], "WAN2")
        self.assertEqual(self.sleep_calls, [30])
        self.assertEqual(self.store.pending(), [])

    def test_strict_to_auto_disables_existing_row_and_settles(self):
        self._set_strict_before()
        self.client.policies = [row for row in self.client.policies
                                if row["name"] != "NP_R_" + MAC_B.replace("-", "")]
        tx = self.make_transaction()
        self.assertEqual(tx.run([MAC_A, MAC_B], "AUTO", ACTOR,
                                self.apply_callback(tx, (MAC_A, MAC_B), "AUTO")), "applied")
        self.assertEqual(self.client.policies[1]["mode"], "Only")
        self.assertEqual(self.client.policies[1]["interfaces"], "WAN1")
        self.assertEqual(self.client.policies[1]["state"], "off")
        self.assertFalse(any(row["name"] == "NP_R_" + MAC_B.replace("-", "")
                             for row in self.client.policies))
        self.assertEqual(self.routes.route_state()[MAC_A]["route"], "AUTO")
        self.assertEqual(self.routes.route_state()[MAC_B]["route"], "AUTO")
        self.assertEqual(self.sleep_calls, [30])
        self.assertEqual(self.store.pending(), [])

    def test_failed_strict_to_prefer_recovers_exact_route_and_expiry_metadata(self):
        self._set_strict_before()
        original_row = copy.deepcopy(self.client.policies[1])
        original_saved = copy.deepcopy(self.routes.route_state()[MAC_A])
        tx = RouteTransaction(self.routes, self.store,
                              sleep=lambda _seconds: (_ for _ in ()).throw(TimeoutError()),
                              clock=lambda: 200, settle_seconds=30)
        with self.assertRaisesRegex(RouteTransactionError, "unresolved intent remains locked"):
            tx.run([MAC_A], "WAN2", ACTOR, self.apply_callback(tx, (MAC_A,), "WAN2"))
        recovery = self.make_transaction()
        self.assertEqual(recovery.recover_pending(), 1)
        self.assertEqual(self.client.policies[1], original_row)
        self.assertEqual(self.routes.route_state()[MAC_A], original_saved)
        self.assertEqual(self.store.pending(), [])

    def test_failed_strict_to_auto_recovers_exact_route_and_expiry_metadata(self):
        self._set_strict_before()
        original_row = copy.deepcopy(self.client.policies[1])
        original_saved = copy.deepcopy(self.routes.route_state()[MAC_A])
        tx = RouteTransaction(self.routes, self.store,
                              sleep=lambda _seconds: (_ for _ in ()).throw(TimeoutError()),
                              clock=lambda: 200, settle_seconds=30)
        with self.assertRaisesRegex(RouteTransactionError, "unresolved intent remains locked"):
            tx.run([MAC_A], "AUTO", ACTOR, self.apply_callback(tx, (MAC_A,), "AUTO"))
        recovery = self.make_transaction()
        self.assertEqual(recovery.recover_pending(), 1)
        self.assertEqual(self.client.policies[1], original_row)
        self.assertEqual(self.routes.route_state()[MAC_A], original_saved)
        self.assertEqual(self.store.pending(), [])

    def test_pending_intent_blocks_even_non_strict_route_callback(self):
        self._seed_recovery_intent()
        calls = []
        tx = self.make_transaction()
        with self.assertRaisesRegex(RouteTransactionError, "unresolved route intent"):
            tx.run([MAC_B], "WAN1", ACTOR, lambda: calls.append("called"))
        self.assertEqual(calls, [])

    def test_prepared_new_target_recovery_finishes_without_router_writes(self):
        self.client.policies = [row for row in self.client.policies
                                if row["name"] != "NP_R_" + MAC_B.replace("-", "")]
        tx = self.make_transaction()
        targets, _rows = tx._capture_targets([MAC_B], "WAN2_ONLY")
        intent_id = self.store.prepare({"actor": ACTOR, "created_at": 200,
                                        "firmware": STRICT_WAN_FIRMWARE,
                                        "targets": targets, "phase": "prepared"})
        self.assertTrue(intent_id)
        self.assertEqual(tx.recover_pending(), 1)
        self.assertEqual(self.client.writes, [])
        self.assertEqual(self.sleep_calls, [30])
        self.assertEqual(self.store.pending(), [])

    def test_nested_recorded_before_route_is_allowed_but_arbitrary_route_is_not(self):
        tx = self.make_transaction()
        nested_calls = []

        def outer():
            result = tx.run([MAC_A], "WAN1", ACTOR,
                            lambda: nested_calls.append("rollback-scope") or "allowed")
            with self.assertRaisesRegex(RouteTransactionError, "active intent scope"):
                tx.run([MAC_A], "WAN2", ACTOR, lambda: self.fail("arbitrary nested route"))
            self.apply_callback(tx, (MAC_A,), "WAN2_ONLY")()
            return result

        self.assertEqual(tx.run([MAC_A], "WAN2_ONLY", ACTOR, outer), "allowed")
        self.assertEqual(nested_calls, ["rollback-scope"])
        self.assertEqual(self.store.pending(), [])

    def test_reopened_coordinator_recovers_after_write_and_restores_expiry_metadata(self):
        original = self.routes.route_state()[MAC_A]
        _intent_id, _target = self._seed_recovery_intent()
        reopened_store = RouteIntentStore(self.db_path)
        reopened = RouteTransaction(self.routes, reopened_store, sleep=lambda seconds: self.sleep_calls.append(seconds),
                                     clock=lambda: 201, settle_seconds=30)
        self.assertEqual(reopened.recover_pending(), 1)
        restored = self.routes.route_state()[MAC_A]
        self.assertEqual(restored, original)
        self.assertEqual(self.store.pending(), [])
        self.assertEqual([row["name"] for row in self.client.policies],
                         ["pi-route-a", "NP_R_" + MAC_A.replace("-", ""),
                          "pi-route-b", "NP_R_" + MAC_B.replace("-", "")])
        self.assertEqual(self.client.policies[1]["mode"], "Priority")
        self.assertEqual(self.client.policies[0], pi_policy("pi-route-a", 1))
        self.assertEqual(self.client.policies[2], pi_policy("pi-route-b", 3))
        self.assertEqual(self.sleep_calls, [30])

    def test_recovery_refreshes_uptime_with_owner_context_before_readiness(self):
        self._seed_recovery_intent()
        tx = self.make_transaction()
        calls = []

        def refresh():
            self.assertTrue(tx.owns_current_thread)
            calls.append("refresh")

        self.routes._refresh_transaction_uptime = refresh
        self.assertEqual(tx.recover_pending(), 1)
        self.assertEqual(calls, ["refresh", "refresh"])
        self.assertEqual(self.store.pending(), [])

    def test_uptime_refresh_failure_keeps_intent_and_performs_no_router_writes(self):
        intent_id, _target = self._seed_recovery_intent()
        tx = self.make_transaction()

        def refresh():
            self.assertTrue(tx.owns_current_thread)
            raise RuntimeError("private refresh detail")

        self.routes._refresh_transaction_uptime = refresh
        with self.assertRaisesRegex(RouteTransactionError, "intent remains locked"):
            tx.recover_pending()
        self.assertEqual(self.client.writes, [])
        self.assertEqual(self.store.get(intent_id)["record"]["phase"], "error")

    def test_recovery_of_new_target_deletes_only_exact_appended_route(self):
        self.client.policies = [row for row in self.client.policies
                                if row["name"] != "NP_R_" + MAC_B.replace("-", "")]
        _intent_id, _target = self._seed_recovery_intent(MAC_B, new=True)
        tx = self.make_transaction()
        self.assertEqual(tx.recover_pending(), 1)
        self.assertFalse(any(row["name"] == "NP_R_" + MAC_B.replace("-", "")
                             for row in self.client.policies))
        self.assertEqual([row["name"] for row in self.client.policies],
                         ["pi-route-a", "NP_R_" + MAC_A.replace("-", ""), "pi-route-b"])
        self.assertEqual(self.client.writes[-1][0], "delete")
        self.assertEqual(self.store.pending(), [])

    def test_unknown_target_state_retains_error_intent_without_restore_writes(self):
        intent_id, _target = self._seed_recovery_intent()
        self.client.policies[1]["src_ipgroup"] = "NP_G_WRONG"
        tx = self.make_transaction()
        with self.assertRaisesRegex(RouteTransactionError, "intent remains locked"):
            tx.recover_pending()
        self.assertEqual(self.client.writes, [])
        pending = self.store.get(intent_id)
        self.assertEqual(pending["record"]["phase"], "error")

    def test_late_drift_retains_intent_without_guessing_a_restore(self):
        def drift(seconds):
            self.assertEqual(self.client.active_sessions, 0)
            self.client.policies[1]["mode"] = "Priority"

        tx = RouteTransaction(self.routes, self.store, sleep=drift, clock=lambda: 200, settle_seconds=30)
        with self.assertRaises(RouteTransactionError):
            tx.run([MAC_A], "WAN2_ONLY", ACTOR,
                   self.apply_callback(tx, (MAC_A,), "WAN2_ONLY", ACTOR))
        pending = self.store.pending()
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["record"]["phase"], "error")
        self.assertEqual(self.client.writes, [])

    def test_settling_failure_keeps_intent_until_a_later_recovery(self):
        tx = RouteTransaction(self.routes, self.store,
                              sleep=lambda _seconds: (_ for _ in ()).throw(TimeoutError()),
                              clock=lambda: 200, settle_seconds=30)
        with self.assertRaises(RouteTransactionError):
            tx.run([MAC_A], "WAN2_ONLY", ACTOR, self.apply_callback(tx, (MAC_A,)))
        self.assertEqual(len(self.store.pending()), 1)
        self.assertEqual(self.store.pending()[0]["record"]["phase"], "error")
        self.assertEqual(self.client.policies[1]["mode"], "Priority")
        recovery = RouteTransaction(self.routes, self.store, sleep=lambda _seconds: None,
                                    clock=lambda: 201, settle_seconds=30)
        self.assertEqual(recovery.recover_pending(), 1)
        self.assertEqual(self.store.pending(), [])
        self.assertEqual(self.routes.route_state()[MAC_A]["route"], "WAN1")

    def test_transaction_rejects_unknown_raw_route_metadata_before_intent(self):
        self.client.policies[0]["mystery"] = "unsafe"
        tx = self.make_transaction()
        with self.assertRaisesRegex(RouteTransactionError, "unknown fields"):
            tx.run([MAC_A], "WAN2_ONLY", ACTOR, lambda: self.fail("must not call"))
        self.assertEqual(self.store.pending(), [])
        self.assertEqual(self.client.writes, [])

    def test_duplicate_active_ip_lease_is_rejected_before_callback(self):
        self.client.clients.append({"macaddr": MAC_B, "ipaddr": IP_A})
        calls = []
        tx = self.make_transaction()
        with self.assertRaisesRegex(RouteTransactionError, "share one active IP"):
            tx.run([MAC_A], "WAN2", ACTOR, lambda: calls.append("called"))
        self.assertEqual(calls, [])
        self.assertEqual(self.store.pending(), [])

    def test_constructor_rejects_nonfinite_settling_delays(self):
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(value=value), self.assertRaises(ValueError):
                RouteTransaction(self.routes, self.store, settle_seconds=value)


if __name__ == "__main__":
    unittest.main()
