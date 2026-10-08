import sqlite3
from contextlib import closing
import tempfile
import unittest
from pathlib import Path

from netpulse.storage.pauses import PauseStore, blocked_macs


def rule(mac="AABBCCDDEEFF", suffix="A"):
    return {"name": "NP_PAUSE_" + suffix * 32, "policy": "DROP", "service": "ALL", "iptype": "ipv4",
            "zone": "LAN", "is_src": "ipgroup", "src": "NP_G_" + mac, "is_dst": "ipgroup",
            "dest": "IPGROUP_ANY", "time": "Any", "states": ["new", "established", "related", "invalid"],
            "position": "", "flag": "1", "user": "1"}


def record(**overrides):
    r = {"mac": "AA-BB-CC-DD-EE-FF", "ip": "192.168.0.22", "name": rule()["name"], "label": "Tablet",
         "actor": "admin", "created_at": 1800000000, "expires_at": 1800003600,
         "expires_monotonic": 43200.25, "boot_id": "boot-x", "status": "applying",
         "rule": rule(), "group_id": None}
    r.update(overrides)
    return r


class PauseStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_existing_database_migration_and_restart_roundtrip(self):
        path = self.root / "existing.db"
        db = sqlite3.connect(path)
        db.execute("CREATE TABLE kv(key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        db.execute("INSERT INTO kv VALUES('keep','yes')")
        db.commit(); db.close()
        store = PauseStore(path)
        store.put(record())
        self.assertEqual(PauseStore(path).get(record()["mac"]), record())
        db = sqlite3.connect(path)
        self.assertEqual(db.execute("SELECT value FROM kv WHERE key='keep'").fetchone(), ("yes",))
        db.close()

    def test_consistent_backup_preserves_pause_intent_and_audit(self):
        from netpulse.storage import backup
        from netpulse.storage.sqlite import Storage
        path = self.root / "live.db"
        Storage(str(path)).close()
        store = PauseStore(path)
        saved = record(status="error")
        store.put(saved)
        store.audit(1800000000, "owner", "pause", saved["mac"], "failed", "needs repair")
        snapshot = backup.create(str(path), str(self.root / "backups"))
        self.assertEqual(backup.rehearse_restore(snapshot)["integrity"], "ok")
        restored = PauseStore(snapshot)
        self.assertEqual(restored.get(saved["mac"]), saved)
        self.assertEqual(restored.audit_tail()[0]["detail"], "needs repair")

    def test_blocked_macs_includes_every_status_and_absent_file_stays_absent(self):
        missing = self.root / "missing.db"
        self.assertEqual(blocked_macs(missing), set())
        self.assertFalse(missing.exists())
        store = PauseStore(self.root / "p.db")
        store.put(record(status="paused"))
        store.put(record(mac="00-11-22-33-44-55", name="NP_PAUSE_" + "B" * 32,
                         rule=rule("001122334455", "B"), status="error"))
        self.assertEqual(blocked_macs(store.path), {"AA-BB-CC-DD-EE-FF", "00-11-22-33-44-55"})

    def test_malformed_identity_rule_and_expiry_fields_rejected(self):
        store = PauseStore(self.root / "p.db")
        changes = [
            {"mac": "aa-bb-cc-dd-ee-ff"}, {"ip": "8.8.8.8"}, {"ip": "127.0.0.1"},
            {"ip": "192.168.1.2/24"}, {"expires_monotonic": float("inf")},
            {"expires_monotonic": -1}, {"created_at": -1}, {"expires_at": 1700000000},
            {"boot_id": None}, {"status": "active"}, {"name": "bad"}, {"rule": {"password": "x"}},
            {"rule": rule("112233445566")},
            {"expires_at": None}, {"status": []},
        ]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                store.put(record(**change))

    def test_audit_redaction_bounded_and_tail(self):
        store = PauseStore(self.root / "p.db")
        for i in range(4):
            store.audit(1800000000 + i, "admin", "pause", "AA-BB-CC-DD-EE-FF", "ok", "token=secret " + "x" * 1100)
        tail = store.audit_tail(2)
        self.assertEqual(len(tail), 2)
        self.assertEqual(tail[0]["ts"], 1800000003)
        self.assertNotIn("secret", tail[0]["detail"])
        self.assertLessEqual(len(tail[0]["detail"]), 1000)

    def test_corrupt_saved_state_stays_blocked_and_cannot_be_claimed_as_verified(self):
        store = PauseStore(self.root / "p.db")
        store.put(record())
        with closing(sqlite3.connect(store.path)) as db, db:
            db.execute("UPDATE device_pauses SET status='unknown'")
        self.assertEqual(blocked_macs(store.path), {record()["mac"]})
        with self.assertRaises(ValueError):
            store.get(record()["mac"])
        with self.assertRaises(ValueError):
            store.list()

    def test_corrupt_saved_identity_fails_closed_for_route_controls(self):
        store = PauseStore(self.root / "p.db")
        store.put(record())
        with closing(sqlite3.connect(store.path)) as db, db:
            db.execute("UPDATE device_pauses SET mac='malformed'")
        with self.assertRaises(ValueError):
            blocked_macs(store.path)


if __name__ == "__main__":
    unittest.main()
