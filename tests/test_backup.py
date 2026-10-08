import sqlite3
import hashlib
import io
import os
import tempfile
import time
import unittest
from contextlib import closing, redirect_stdout
from pathlib import Path
from unittest import mock

from netpulse.storage import backup, sqlite
from netpulse.storage.sqlite import Storage


class DatabaseBackup(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.source = Path(self.tmp.name) / "netpulse.db"
        self.destination = Path(self.tmp.name) / "backups"
        self.storage = Storage(str(self.source))
        self.addCleanup(self.storage.close)
        sqlite.set_device_label(str(self.source), "AA-BB-CC-DD-EE-01", "Example NAS")
        self.storage.write_minute([(60, "WAN1", "HEALTHY", 99, 0, 7, 1, 100)], [], [])

    def test_snapshot_is_readable_rotated_and_contains_current_state(self):
        first = backup.create(str(self.source), str(self.destination), keep=2, now=1)
        backup.create(str(self.source), str(self.destination), keep=2, now=2)
        third = backup.create(str(self.source), str(self.destination), keep=2, now=3)
        files = sorted(self.destination.glob("netpulse-db-*.sqlite3"))
        self.assertEqual(len(files), 2)
        self.assertNotIn(Path(first), files)
        self.assertIn(Path(third), files)
        with closing(sqlite3.connect(third)) as db:
            self.assertEqual(db.execute("PRAGMA integrity_check").fetchone()[0], "ok")
            self.assertEqual(db.execute("SELECT state FROM wan_minute").fetchone()[0], "HEALTHY")
            self.assertEqual(db.execute("SELECT label FROM device_labels").fetchone()[0], "Example NAS")

        before = hashlib.sha256(Path(third).read_bytes()).digest()
        report = backup.rehearse_restore(third)
        self.assertEqual(report["integrity"], "ok")
        self.assertEqual(report["tables"]["wan_minute"], 1)
        self.assertEqual(report["tables"]["device_labels"], 1)
        self.assertEqual(hashlib.sha256(Path(third).read_bytes()).digest(), before)

    def test_restore_rehearsal_rejects_non_backup_names_and_incomplete_databases(self):
        arbitrary = Path(self.tmp.name) / "not-a-backup.sqlite3"
        arbitrary.write_bytes(b"not a database")
        with self.assertRaisesRegex(ValueError, "choose a NetPulse SQLite backup"):
            backup.rehearse_restore(str(arbitrary))

        incomplete = self.destination / f"{backup.PREFIX}incomplete.sqlite3"
        self.destination.mkdir()
        with closing(sqlite3.connect(incomplete)) as db:
            with db:
                db.execute("CREATE TABLE unrelated (value TEXT)")
        with self.assertRaisesRegex(sqlite3.DatabaseError, "missing required NetPulse tables"):
            backup.rehearse_restore(str(incomplete))

    def test_restore_rehearsal_cli_prints_only_aggregate_counts(self):
        from tools.backup_restore_rehearsal import main

        snapshot = backup.create(str(self.source), str(self.destination))
        output = io.StringIO()
        with redirect_stdout(output):
            status = main([snapshot])
        self.assertEqual(status, 0)
        self.assertIn("Restore rehearsal succeeded on a temporary copy", output.getvalue())
        self.assertIn("device_labels=1", output.getvalue())
        self.assertNotIn("AA-BB-CC-DD-EE-01", output.getvalue())

    def test_nas_mount_must_be_present_before_creating_a_backup(self):
        with mock.patch.object(backup.os.path, "ismount", return_value=False):
            with self.assertRaisesRegex(OSError, "mount is not available"):
                backup.create(str(self.source), str(self.destination), mount_path="/mnt/nas")
        self.assertFalse(self.destination.exists())

    def test_future_dated_snapshot_is_stale_not_healthy(self):
        path = Path(backup.create(str(self.source), str(self.destination)))
        future = time.time() + 3600
        os.utime(path, (future, future))
        result = backup.status(str(self.destination), 7)
        self.assertEqual(result["status"], "stale")
        self.assertIsNone(result["age_seconds"])
        self.assertEqual(result["latest_at"], future)


if __name__ == "__main__":
    unittest.main()
