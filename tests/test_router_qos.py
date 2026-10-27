import threading
import unittest
from contextlib import contextmanager
from types import SimpleNamespace

from netpulse.router.er605 import RouterAuthError
from netpulse.router.qos import (
    MAX_QOS_ROWS, QoSError, QoSInventory, _response_result, _unique_rows,
    canonical_classification_row, canonical_qos_global, canonical_rate_rule_row,
)


def rate_row(**changes):
    row = {
        ".name": "NP_Q_020000000010", ".type": "rule", ".anonymous": False,
        "setting_index": "0", "t_ping_label": "LAN", "t_pong_label": "WAN/LAN2",
        "position": 1, "name": "NP_Q_020000000010", "if_ping": "LAN", "if_pong": "WAN2",
        "source_type": "ip_group", "ip_group": "NP_G_020000000010",
        "rate_max": "1000", "rate_max_mate": "1000", "mode": "priv",
        "time": "Any", "comment": "NetPulse validation", "enable": "on", "ip_type": "src",
    }
    row.update(changes)
    return row


def class_row(**changes):
    row = {
        ".name": "qos_rule_1", ".type": "rule", ".anonymous": False,
        "dscp": "any", "class": "class2", "ip": "ipv4", "service": "ALL",
        "id": "1", "src_ip": "NP_G_TESTA", "status": "disable",
        "dst_ip": "IPGROUP_ANY", "rule": "1", "ipt_idx": "1",
    }
    row.update(changes)
    return row


def global_result(**changes):
    result = {
        ".name": "qos_global", ".type": "qos", "qos_threshold": "0",
        "threshold_enable": "off", "bandwidth": 1000, ".anonymous": False,
        "qos_enable": "off", "interface": [], "qos_setting_number": "3",
    }
    result.update(changes)
    return result


def empty_rows_response(max_rules=128):
    return {"id": 1, "others": {"max_rules": max_rules}, "result": {}, "error_code": "0"}


def populated_rows_response(row=None, max_rules=128):
    return {"id": 2, "others": {"max_rules": max_rules},
            "result": [class_row() if row is None else row], "error_code": "0"}


class QoSCanonicalizationTests(unittest.TestCase):
    def test_firmware_global_schema_and_threshold_bounds(self):
        live_off = canonical_qos_global(global_result())
        self.assertEqual((live_off["qos_enable"], live_off["threshold_enable"]), ("off", "off"))
        self.assertEqual(live_off["qos_setting_number"], "3")
        for count in ("0", "1", "3"):
            self.assertEqual(canonical_qos_global(global_result(qos_setting_number=count))[
                "qos_setting_number"], count)
        without_counter = global_result()
        del without_counter["qos_setting_number"]
        self.assertNotIn("qos_setting_number", canonical_qos_global(without_counter))
        observed = global_result(qos_enable="on", threshold_enable="on", qos_threshold="100",
                                 interface=["WAN1"])
        canonical = canonical_qos_global(observed)
        self.assertEqual(canonical["qos_threshold"], 100)
        self.assertEqual(canonical["interface"], ["WAN1"])
        # Preserve a disabled threshold value; its meaning with QoS off is unverified.
        self.assertEqual(canonical_qos_global(global_result(qos_threshold="25"))["qos_threshold"], 25)
        for bad in (
            global_result(qos_threshold="101"), global_result(qos_enable=True),
            global_result(qos_enable="0"), global_result(threshold_enable="maybe"),
            global_result(bandwidth=True), global_result(**{".anonymous": True}),
            global_result(qos_setting_number=3),
            global_result(qos_setting_number="12345678901"),
            global_result(interface=["WAN1", "WAN1"]), global_result(extra="x"),
        ):
            with self.subTest(bad=bad):
                self.assertIsNone(canonical_qos_global(bad))

    def test_firmware_rate_row_normalizes_numeric_fields_and_rejects_unknown_fields(self):
        row = canonical_rate_rule_row(rate_row())
        self.assertEqual(row["rate_max"], 1000)
        self.assertEqual(row["rate_max_mate"], 1000)
        self.assertEqual(row["position"], 1)
        self.assertEqual(row["enable"], "on")
        self.assertIsNone(canonical_rate_rule_row(rate_row(rate_max=99)))
        self.assertIsNone(canonical_rate_rule_row(rate_row(rate_max=1_000_001)))
        self.assertIsNone(canonical_rate_rule_row(rate_row(position="129")))
        self.assertIsNone(canonical_rate_rule_row(rate_row(comment="x" * 51)))
        self.assertIsNone(canonical_rate_rule_row(rate_row(network="")))
        self.assertIsNone(canonical_rate_rule_row(rate_row(source_type="network")))
        self.assertIsNone(canonical_rate_rule_row(rate_row(**{".name": "other"})))

    def test_rate_rows_reject_duplicate_names_and_unknown_states_or_fields(self):
        self.assertIsNone(canonical_rate_rule_row(rate_row(mode="burst")))
        self.assertIsNone(canonical_rate_rule_row(rate_row(source_type="host")))
        self.assertIsNone(canonical_rate_rule_row(rate_row(enable="1")))
        self.assertEqual(canonical_rate_rule_row(rate_row(enable="off"))["enable"], "off")
        self.assertIsNone(canonical_rate_rule_row(rate_row(enable=True)))
        self.assertIsNone(canonical_rate_rule_row(rate_row(extra="future-field")))
        with self.assertRaises(QoSError):
            _unique_rows([rate_row(), rate_row()], canonical_rate_rule_row, "name")

    def test_class_rows_match_verified_firmware_shape_and_keep_opaque_metadata(self):
        observed = class_row()
        canonical = canonical_classification_row(observed)
        self.assertEqual(canonical[".name"], "qos_rule_1")
        self.assertEqual(canonical["id"], "1")
        self.assertEqual(canonical["rule"], "1")
        self.assertEqual(canonical["ipt_idx"], "1")
        self.assertEqual(canonical["status"], "disable")
        self.assertNotIn("ipt_order", canonical)

    def test_class_rows_reject_unknown_state_malformed_types_and_duplicates(self):
        for bad in (class_row(**{"class": "class4"}), class_row(status="enabled"),
                    class_row(ip="any"), class_row(id=7), class_row(**{".anonymous": 0}),
                    class_row(**{".type": "future"}), class_row(ipt_idx=True),
                    class_row(ipt_order="1"),
                    class_row(extra="unknown")):
            with self.subTest(bad=bad):
                self.assertIsNone(canonical_classification_row(bad))
        with self.assertRaises(QoSError):
            _unique_rows([class_row(), class_row()], canonical_classification_row, "id")

    def test_response_envelope_must_be_exact_and_collection_is_bounded(self):
        self.assertEqual(_response_result({"id": 1, "result": global_result(),
                                           "error_code": "0"}, dict), global_result())
        for response in ({"id": True, "result": global_result(), "error_code": "0"},
                         {"id": 1, "result": global_result(), "error_code": "0", "others": {}}):
            with self.subTest(response=response), self.assertRaises(QoSError):
                _response_result(response, dict)
        self.assertEqual(_response_result(empty_rows_response(4096), list), [])
        self.assertEqual(_response_result(populated_rows_response(), list, allow_nonempty=True),
                         [class_row()])
        rate_collection = {"id": 1, "others": {"max_rules": 128},
                           "result": [rate_row()], "error_code": "0"}
        self.assertEqual(_response_result(rate_collection, list, allow_nonempty=True), [rate_row()])
        self.assertEqual(_response_result(populated_rows_response(max_rules=1), list,
                                           allow_nonempty=True), [class_row()])
        for response in (empty_rows_response(0), empty_rows_response(4097),
                         {"id": 1, "others": {}, "result": {}, "error_code": "0"},
                         {"id": 1, "others": {"max_rules": True}, "result": {}, "error_code": "0"},
                         rate_collection,
                         {"id": 1, "others": {"max_rules": 10}, "result": {}, "error_code": "1"},
                         {"id": 1, "result": {}, "error_code": "0"},
                         populated_rows_response(max_rules=0),
                         {"id": 2, "others": {"max_rules": 0},
                          "result": [class_row()], "error_code": "0"}):
            with self.subTest(response=response), self.assertRaises(QoSError):
                _response_result(response, list)
        with self.assertRaises(QoSError):
            _unique_rows([rate_row()] * (MAX_QOS_ROWS + 1), canonical_rate_rule_row, "name")


class InventoryTests(unittest.TestCase):
    def test_reads_all_forms_in_session_under_shared_lock(self):
        lock = threading.RLock()
        calls = []
        responses = {
            ("qos", "global"): {"id": 1, "result": global_result(), "error_code": "0"},
            ("qos", "rule"): {"id": 1, "others": {"max_rules": 128},
                                "result": [rate_row()], "error_code": "0"},
            ("qos_ctl", "class"): populated_rows_response(),
        }

        class Client:
            @contextmanager
            def session(self):
                self.active = True
                try:
                    yield self
                finally:
                    self.active = False

            def get_response(self, module, form):
                self.lock_held = lock.acquire(blocking=False)
                if self.lock_held:
                    lock.release()
                self_in_session = getattr(self, "active", False)
                calls.append((module, form, self.lock_held, self_in_session))
                return responses[(module, form)]

        client = Client()
        watch = SimpleNamespace(client=client, api_lock=lock, poll_seconds=60,
                                snap=SimpleNamespace(ok=True, checked_at=1000, error=""))
        inventory = QoSInventory(watch, clock=lambda: 1000).read()
        self.assertTrue(inventory["available"])
        self.assertEqual(inventory["rate_rules"], [canonical_rate_rule_row(rate_row())])
        self.assertEqual(inventory["class_rules"], [canonical_classification_row(class_row())])
        self.assertEqual([item[:2] for item in calls],
                         [("qos", "global"), ("qos", "rule"), ("qos_ctl", "class")])
        self.assertTrue(all(held and active for _, _, held, active in calls))

    def test_ambiguous_snapshot_is_unavailable(self):
        class Client:
            @contextmanager
            def session(self):
                yield self

            def get_response(self, module, form):
                return {"id": 1, "result": global_result(), "error_code": "0"} if form == "global" else {
                    "id": 1, "others": {}, "result": {}, "error_code": "0"}

        watch = SimpleNamespace(client=Client(), api_lock=threading.RLock(), poll_seconds=60,
                                snap=SimpleNamespace(ok=True, checked_at=1000, error=""))
        result = QoSInventory(watch, clock=lambda: 1000).read()
        self.assertFalse(result["available"])
        self.assertIsNone(result["global"])
        self.assertEqual(result["rate_rules"], [])

    def test_watch_guards_prevent_login_during_backoff_pause_or_stale_status(self):
        class Client:
            def __init__(self):
                self.sessions = 0

            @contextmanager
            def session(self):
                self.sessions += 1
                yield self

        cases = ({"_login_blocked_until": 1200}, {"_paused_until": 1200},
                 {"_unreachable": 1})
        for fields in cases:
            client = Client()
            watch = SimpleNamespace(client=client, api_lock=threading.RLock(), poll_seconds=60,
                                    snap=SimpleNamespace(ok=True, checked_at=1000, error=""), **fields)
            result = QoSInventory(watch, clock=lambda: 1000).read()
            with self.subTest(fields=fields):
                self.assertFalse(result["available"])
                self.assertEqual(client.sessions, 0)
        client = Client()
        watch = SimpleNamespace(client=client, api_lock=threading.RLock(), poll_seconds=60,
                                snap=SimpleNamespace(ok=True, checked_at=700, error=""))
        result = QoSInventory(watch, clock=lambda: 1000).read()
        self.assertFalse(result["available"])
        self.assertEqual(client.sessions, 0)

    def test_auth_and_generic_failures_back_off_before_another_login(self):
        class Clock:
            now = 1000

            def __call__(self):
                return self.now

        class Client:
            def __init__(self, failure):
                self.failure = failure
                self.sessions = 0

            @contextmanager
            def session(self):
                self.sessions += 1
                if self.failure is not None:
                    error, self.failure = self.failure, None
                    raise error
                yield self

            def get_response(self, module, form):
                if form == "global":
                    return {"id": 1, "result": global_result(), "error_code": "0"}
                return empty_rows_response()

        for failure, backoff in ((RouterAuthError("synthetic auth failure"), 1800),
                                 (RuntimeError("synthetic read failure"), 15)):
            clock = Clock()
            client = Client(failure)
            watch = SimpleNamespace(client=client, api_lock=threading.RLock(), poll_seconds=60,
                                    snap=SimpleNamespace(ok=True, checked_at=1000, error=""))
            inventory = QoSInventory(watch, clock=clock)
            self.assertFalse(inventory.read()["available"])
            self.assertFalse(inventory.read()["available"])
            self.assertEqual(client.sessions, 1)
            clock.now += backoff
            watch.snap.checked_at = clock.now
            self.assertTrue(inventory.read()["available"])
            self.assertEqual(client.sessions, 2)

    def test_watch_guard_is_rechecked_after_shared_lock_acquisition(self):
        class Client:
            def __init__(self):
                self.sessions = 0

            @contextmanager
            def session(self):
                self.sessions += 1
                yield self

        client = Client()
        watch = SimpleNamespace(client=client, poll_seconds=60,
                                snap=SimpleNamespace(ok=True, checked_at=1000, error=""))

        class LockThatPausesWatch:
            def __enter__(self):
                watch._paused_until = 1200
                return self

            def __exit__(self, *_):
                return False

        watch.api_lock = LockThatPausesWatch()
        result = QoSInventory(watch, clock=lambda: 1000).read()
        self.assertFalse(result["available"])
        self.assertEqual(client.sessions, 0)


if __name__ == "__main__":
    unittest.main()
