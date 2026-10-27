import math
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from netpulse.storage.route_intents import (
    RouteIntentConflict, RouteIntentError, RouteIntentStorageError, RouteIntentStore,
)


MAC = "AA-BB-CC-DD-EE-01"
IP = "192.0.2.50"


def route_row(mac=MAC, *, interface="WAN2", mode="Only", state="on"):
    hexmac = mac.replace("-", "")
    return {
        ".name": None, "name": f"NP_R_{hexmac}",
        "service_type": "ALL", "src_ipgroup": f"NP_G_{hexmac}",
        "dst_ipgroup": "IPGROUP_ANY", "interfaces": interface, "timeobj": "Any",
        "mode": mode, "comment": "NetPulse", "state": state, "index": 2,
        "src": "ipgroup", "dst": "ipgroup", "dst_country_group": None,
        "dst_domain": None, "flag": None,
    }


def target(mac=MAC, ip=IP):
    return {
        "mac": mac,
        "ip": ip,
        "before_saved": {
            "ip": ip, "route": "WAN1", "updated_at": 1800000000, "actor": "owner",
            "expires_at": 1800003600, "expires_monotonic": 1200.0, "boot_id": "boot-test",
        },
        "before_row": route_row(mac, interface="WAN1", mode="Priority"),
        "after_row": route_row(mac),
    }


def record(**overrides):
    value = {"actor": "owner", "created_at": 1800000000,
             "firmware": "2.3.3 Build 20251029 Rel.18054",
             "targets": [target()], "phase": "prepared"}
    value.update(overrides)
    return value


class RouteIntentStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "app.db"

    def test_restart_persistence_and_return_values_are_deepcopies(self):
        store = RouteIntentStore(self.path)
        original = record()
        intent_id = store.prepare(original)
        self.assertRegex(intent_id, r"^[A-Za-z0-9_-]{24,40}$")
        original["targets"][0]["after_row"]["interfaces"] = "WAN1"

        reopened = RouteIntentStore(self.path)
        entry = reopened.get(intent_id)
        self.assertEqual(entry["revision"], 1)
        self.assertEqual(entry["record"]["targets"][0]["after_row"]["interfaces"], "WAN2")
        entry["record"]["targets"].clear()
        pending = reopened.pending()
        self.assertEqual(len(pending), 1)
        self.assertEqual(len(pending[0]["record"]["targets"]), 1)

    def test_prepare_is_globally_single_pending_and_replace_uses_cas_revision(self):
        store = RouteIntentStore(self.path)
        intent_id = store.prepare(record())
        with self.assertRaises(RouteIntentConflict):
            store.prepare(record(phase="applying"))

        changed = record(phase="applying")
        self.assertEqual(store.replace(intent_id, 1, changed), 2)
        self.assertEqual(store.get(intent_id)["record"]["phase"], "applying")
        with self.assertRaises(RouteIntentConflict):
            store.replace(intent_id, 1, record(phase="settling"))
        with self.assertRaises(RouteIntentConflict):
            store.finish(intent_id, 1)
        self.assertEqual(store.pending()[0]["revision"], 2)

        store.finish(intent_id, 2)
        self.assertEqual(store.pending(), [])
        self.assertIsNone(store.get(intent_id))

    def test_existing_application_tables_are_preserved(self):
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("CREATE TABLE app_state (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            db.execute("INSERT INTO app_state VALUES ('kept', 'yes')")
        RouteIntentStore(self.path).prepare(record())
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("SELECT value FROM app_state WHERE key='kept'").fetchone(), ("yes",))
            self.assertTrue(db.execute("SELECT 1 FROM sqlite_master WHERE name='router_route_intents'").fetchone())

    def _create_device_routes(self):
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("""CREATE TABLE device_routes (
              mac TEXT PRIMARY KEY, ip TEXT NOT NULL, route TEXT NOT NULL,
              updated_at INTEGER NOT NULL, actor TEXT NOT NULL, expires_at INTEGER,
              expires_monotonic REAL, boot_id TEXT)""")

    def test_restore_saved_restores_exact_rows_in_recovery_and_keeps_intent_pending(self):
        self._create_device_routes()
        mac2, ip2 = "AA-BB-CC-DD-EE-02", "192.0.2.51"
        prior = target()
        prior["before_saved"].update({"mac": MAC})
        prior2 = target(mac2, ip2)
        prior2["before_saved"] = None
        store = RouteIntentStore(self.path)
        intent_id = store.prepare(record(phase="recovering", targets=[prior, prior2]))
        changed_at = 1800000050
        with closing(sqlite3.connect(self.path)) as db, db:
            db.executemany("""INSERT INTO device_routes
              (mac,ip,route,updated_at,actor,expires_at,expires_monotonic,boot_id)
              VALUES(?,?,?,?,?,?,?,?)""", [
                (MAC, IP, "WAN2_ONLY", changed_at, "owner", 1800000600, 1800.0, "boot-test"),
                (mac2, ip2, "AUTO", changed_at, "owner", None, None, None),
            ])

        store.restore_saved(intent_id, 1)
        with closing(sqlite3.connect(self.path)) as db:
            restored = db.execute("SELECT ip,route,updated_at,actor,expires_at,expires_monotonic,boot_id "
                                  "FROM device_routes WHERE mac=?", (MAC,)).fetchone()
            missing = db.execute("SELECT 1 FROM device_routes WHERE mac=?", (mac2,)).fetchone()
        self.assertEqual(restored, (IP, "WAN1", 1800000000, "owner", 1800003600, 1200.0, "boot-test"))
        self.assertIsNone(missing)
        self.assertEqual(store.pending()[0]["revision"], 1)
        store.restore_saved(intent_id, 1)  # A retry after successful local restoration is harmless.

    def test_restore_saved_refuses_external_route_change_without_partial_restore(self):
        self._create_device_routes()
        mac2, ip2 = "AA-BB-CC-DD-EE-02", "192.0.2.51"
        store = RouteIntentStore(self.path)
        intent_id = store.prepare(record(phase="error", targets=[target(), target(mac2, ip2)]))
        with closing(sqlite3.connect(self.path)) as db, db:
            db.executemany("""INSERT INTO device_routes
              (mac,ip,route,updated_at,actor,expires_at,expires_monotonic,boot_id)
              VALUES(?,?,?,?,?,?,?,?)""", [
                (MAC, IP, "WAN2_ONLY", 1800000050, "owner", None, None, None),
                (mac2, ip2, "WAN1", 1800000050, "another operator", None, None, None),
            ])
        with self.assertRaises(RouteIntentConflict):
            store.restore_saved(intent_id, 1)
        with closing(sqlite3.connect(self.path)) as db:
            first = db.execute("SELECT route,updated_at FROM device_routes WHERE mac=?", (MAC,)).fetchone()
        self.assertEqual(first, ("WAN2_ONLY", 1800000050))

    def test_restore_saved_sql_failure_rolls_back_every_target(self):
        self._create_device_routes()
        mac2, ip2 = "AA-BB-CC-DD-EE-02", "192.0.2.51"
        store = RouteIntentStore(self.path)
        intent_id = store.prepare(record(phase="recovering", targets=[target(), target(mac2, ip2)]))
        with closing(sqlite3.connect(self.path)) as db, db:
            db.executemany("""INSERT INTO device_routes
              (mac,ip,route,updated_at,actor,expires_at,expires_monotonic,boot_id)
              VALUES(?,?,?,?,?,?,?,?)""", [
                (MAC, IP, "WAN2_ONLY", 1800000050, "owner", None, None, None),
                (mac2, ip2, "WAN1", 1800000050, "owner", None, None, None),
            ])
            db.execute(f"""CREATE TRIGGER reject_second_restore BEFORE INSERT ON device_routes
                         WHEN NEW.mac='{mac2}' BEGIN SELECT RAISE(ABORT, 'injected failure'); END""")
        with self.assertRaises(RouteIntentStorageError):
            store.restore_saved(intent_id, 1)
        with closing(sqlite3.connect(self.path)) as db:
            routes = dict(db.execute("SELECT mac,route FROM device_routes"))
        self.assertEqual(routes, {MAC: "WAN2_ONLY", mac2: "WAN1"})

    def test_restore_saved_requires_recovery_phase_and_revision(self):
        self._create_device_routes()
        store = RouteIntentStore(self.path)
        intent_id = store.prepare(record())
        with self.assertRaises(RouteIntentError):
            store.restore_saved(intent_id, 1)
        with self.assertRaises(RouteIntentConflict):
            store.restore_saved(intent_id, 2)

    def test_invalid_identity_timestamps_fields_and_policy_rows_are_rejected(self):
        store = RouteIntentStore(self.path)
        invalid = [
            record(targets=[target(), target()]),
            record(targets=[target(), target("00-11-22-33-44-55", IP)]),
            record(targets=[target(ip="192.0.2.50/32")]),
            record(created_at=float("nan")),
            record(created_at=math.inf),
            record(extra="unknown"),
            record(targets=[{**target(), "name": "wrong"}]),
            record(targets=[{**target(), "after_row": {**route_row(), "src_ipgroup": "NP_G_001122334455"}}]),
            record(targets=[{**target(), "after_row": {**route_row(), "password": "secret"}}]),
            record(targets=[{**target(), "before_saved": {**target()["before_saved"], "route": "WAN3"}}]),
        ]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(RouteIntentError):
                store.prepare(value)
        self.assertEqual(store.pending(), [])

    def test_database_insert_failure_rolls_back_without_half_intent(self):
        store = RouteIntentStore(self.path)
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("""CREATE TRIGGER reject_route_intent BEFORE INSERT ON router_route_intents
                         BEGIN SELECT RAISE(ABORT, 'injected failure'); END""")
        with self.assertRaises(RouteIntentStorageError):
            store.prepare(record())
        with closing(sqlite3.connect(self.path)) as db:
            count = db.execute("SELECT COUNT(*) FROM router_route_intents").fetchone()[0]
        self.assertEqual(count, 0)

    def test_unknown_phase_bad_target_bounds_and_unsafe_metadata_fail_closed(self):
        store = RouteIntentStore(self.path)
        invalid = [
            record(phase="complete"),
            record(targets=[]),
            record(targets=[target()] * 129),
            record(firmware="fw\nprivate"),
            record(targets=[{**target(), "after_row": {**route_row(), "password": "secret"}}]),
            record(targets=[{**target(), "before_row": {**route_row(), ".name": "OTHER"}}]),
        ]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(RouteIntentError):
                store.prepare(value)
        self.assertEqual(store.pending(), [])


if __name__ == "__main__":
    unittest.main()
