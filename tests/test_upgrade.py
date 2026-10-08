"""Upgrade compatibility: new code must start on configs and databases written by older versions.

The Pi keeps /etc/netpulse/config.toml and /var/lib/netpulse/netpulse.db across upgrades, and
install.sh never overwrites the config. So every new setting needs a safe default, and every
schema change must work on an existing database without losing history.
"""

import sqlite3
import hashlib
import shutil
import tempfile
import time
import tomllib
import unittest
from pathlib import Path

from netpulse import config
from netpulse.storage import backup
from netpulse.storage import sqlite
from netpulse.storage.sqlite import Storage

FIXTURES = Path(__file__).resolve().parent / "fixtures"

# The database schema of the first release (before target_minute, kv and speedtests existed).
SCHEMA_V01 = """
CREATE TABLE wan_minute (ts INTEGER NOT NULL, wan TEXT NOT NULL, state TEXT NOT NULL, score REAL,
    loss_pct REAL, rtt_ms REAL, jitter_ms REAL, availability_pct REAL, PRIMARY KEY (ts, wan));
CREATE TABLE events (id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, kind TEXT NOT NULL, wan TEXT, message TEXT NOT NULL);
CREATE INDEX events_ts ON events (ts);
CREATE TABLE baselines (wan TEXT NOT NULL, target TEXT NOT NULL, value REAL NOT NULL, samples INTEGER NOT NULL,
    PRIMARY KEY (wan, target));
"""


class OldConfig(unittest.TestCase):
    def test_first_install_config_still_loads_with_safe_defaults(self):
        cfg = config.load(FIXTURES / "config_v0.1_first_install.toml")
        self.assertEqual([w.label for w in cfg.wans], ["Example ISP A", "Example ISP B"])
        self.assertEqual([w.plan_mbps for w in cfg.wans], [0, 0])           # unknown plan: no plan line
        self.assertFalse(cfg.speedtest.schedule_enabled)                     # never auto-enable speed tests
        self.assertEqual(cfg.telegram.quiet_start, "23:00")
        self.assertEqual(cfg.telegram.digest_time, "")
        self.assertEqual(cfg.telegram.weekly_report_time, "")
        self.assertEqual(cfg.router.poll_minutes, 10)
        self.assertEqual(cfg.router.credentials_file, "/etc/netpulse/router.toml")

    def test_unknown_or_removed_keys_warn_instead_of_crashing(self):
        raw = tomllib.loads((FIXTURES / "config_v0.1_first_install.toml").read_text(encoding="utf-8"))
        raw["general"]["old_setting"] = 1
        raw["telegram"]["retired_option"] = "x"
        raw["wan"][0]["typo_lable"] = "Example ISP A"
        cfg = config.parse(raw)
        self.assertEqual(sorted(cfg.warnings), [
            "unknown setting general.old_setting (ignored)",
            "unknown setting telegram.retired_option (ignored)",
            "unknown setting wan[1].typo_lable (ignored)",
        ])

    def test_example_config_has_no_warnings(self):
        cfg = config.load(Path(__file__).resolve().parent.parent / "config.example.toml")
        self.assertEqual(cfg.warnings, ())


class OldDatabase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.tmp.name) / "old.db")
        db = sqlite3.connect(self.path)
        db.executescript(SCHEMA_V01)
        now = int(time.time()) // 60 * 60
        db.executemany("INSERT INTO wan_minute VALUES (?,?,?,?,?,?,?,?)",
                       [(now - 60 * i, w, "HEALTHY", 99, 0, 7, 1, 100) for i in range(1, 121) for w in ("WAN1", "WAN2")])
        db.execute("INSERT INTO events (ts, kind, wan, message) VALUES (?,?,?,?)",
                   (now - 3600, "state", "WAN1", "WAN1: UNKNOWN -> HEALTHY (7ms 0% loss)"))
        db.execute("INSERT INTO baselines VALUES ('WAN1', '1.1.1.1', 29.4, 500)")
        db.commit()
        db.close()

    def tearDown(self):
        self.tmp.cleanup()

    def test_new_code_upgrades_schema_and_keeps_history(self):
        s = Storage(self.path)
        tables = {r[0] for r in s.db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertTrue({"wan_minute", "events", "baselines", "target_minute", "kv", "speedtests"} <= tables)
        self.assertEqual(s.load_baselines()[("WAN1", "1.1.1.1")].value, 29.4)
        s.set_value("x", "1")
        s.close()
        self.assertEqual(len(sqlite.history(self.path, 0, 60)), 240)
        self.assertEqual(sqlite.recent_events(self.path, 5)[0]["message"], "WAN1: UNKNOWN -> HEALTHY (7ms 0% loss)")
        self.assertEqual(sqlite.speedtests(self.path, 0), [])
        # Per-server history is simply empty for the old period (nothing to crash on).
        self.assertEqual(sqlite.target_history(self.path, 0, 60, "1.1.1.1"), [])
        summ = sqlite.period_summary(self.path, 0, 2**62)
        self.assertEqual(summ["wans"]["WAN1"]["minutes"], {"HEALTHY": 120})

    def test_opening_twice_is_harmless(self):
        Storage(self.path).close()
        Storage(self.path).close()
        self.assertEqual(len(sqlite.history(self.path, 0, 60)), 240)

    def test_restore_rehearsal_migrates_first_release_backup_without_changing_it(self):
        legacy = Path(self.tmp.name) / f"{backup.PREFIX}v01.sqlite3"
        shutil.copyfile(self.path, legacy)
        original_hash = hashlib.sha256(legacy.read_bytes()).digest()

        report = backup.rehearse_restore(str(legacy))

        self.assertEqual(report["integrity"], "ok")
        self.assertEqual(report["tables"]["wan_minute"], 240)
        self.assertEqual(report["tables"]["events"], 1)
        self.assertEqual(report["tables"]["baselines"], 1)
        self.assertEqual(report["tables"]["kv"], 0)
        self.assertEqual(hashlib.sha256(legacy.read_bytes()).digest(), original_hash)

    def test_old_route_expiry_rows_migrate_to_monotonic_metadata(self):
        path = str(Path(self.tmp.name) / "route-expiry-v1.db")
        db = sqlite3.connect(path)
        db.execute("CREATE TABLE device_routes (mac TEXT PRIMARY KEY, ip TEXT NOT NULL, route TEXT NOT NULL, "
                   "updated_at INTEGER NOT NULL, actor TEXT NOT NULL, expires_at INTEGER)")
        db.execute("INSERT INTO device_routes VALUES (?,?,?,?,?,?)",
                   ("AA-BB-CC-DD-EE-01", "192.0.2.10", "WAN1", 100, "owner", 3700))
        db.commit()
        db.close()

        upgraded = Storage(path)
        columns = {row[1] for row in upgraded.db.execute("PRAGMA table_info(device_routes)")}
        upgraded.close()
        self.assertTrue({"expires_at", "expires_monotonic", "boot_id"} <= columns)
        saved = sqlite.device_routes(path)["AA-BB-CC-DD-EE-01"]
        self.assertEqual((saved["route"], saved["expires_at"]), ("WAN1", 3700))
        self.assertIsNone(saved["expires_monotonic"])
        self.assertIsNone(saved["boot_id"])


if __name__ == "__main__":
    unittest.main()
