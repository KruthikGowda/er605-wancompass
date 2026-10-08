"""The installer must surface timed route changes before it mutates or restarts the service."""

import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools.route_expiry_preflight import imminent_route_expiry_count


class RouteExpiryPreflightTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.tmp.name) / "netpulse.db")
        db = sqlite3.connect(self.db_path)
        db.execute("CREATE TABLE device_routes (mac TEXT PRIMARY KEY, ip TEXT NOT NULL, route TEXT NOT NULL, "
                   "updated_at INTEGER NOT NULL, actor TEXT NOT NULL, expires_at INTEGER, "
                   "expires_monotonic REAL, boot_id TEXT)")
        db.executemany("INSERT INTO device_routes VALUES (?,?,?,?,?,?,?,?)", [
            ("AA-BB-CC-DD-EE-01", "192.0.2.1", "WAN1", 1, "owner", 2000, 2000.0, "boot-a"),
            ("AA-BB-CC-DD-EE-02", "192.0.2.2", "WAN2", 1, "owner", 5000, 5000.0, "boot-a"),
            ("AA-BB-CC-DD-EE-03", "192.0.2.3", "WAN1", 1, "owner", None, None, None),
            ("AA-BB-CC-DD-EE-04", "192.0.2.4", "AUTO", 1, "owner", 1100, 1100.0, "boot-a"),
        ])
        db.commit()
        db.close()

    def tearDown(self):
        self.tmp.cleanup()

    def test_counts_due_and_nearby_same_boot_routes_using_monotonic_time(self):
        # Wall clock has jumped backwards; the monotonic expiry remains authoritative.
        self.assertEqual(imminent_route_expiry_count(
            self.db_path, now=1000, monotonic_now=1900.0, boot_id="boot-a", window_seconds=200), 1)

    def test_previous_boot_uses_wall_clock_fallback(self):
        # The current boot has no matching monotonic epoch, so wall-clock expiry must be used.
        self.assertEqual(imminent_route_expiry_count(
            self.db_path, now=1900, monotonic_now=10.0, boot_id="boot-b", window_seconds=200), 1)

    def test_counts_already_due_routes_and_ignores_permanent_or_auto_routes(self):
        self.assertEqual(imminent_route_expiry_count(
            self.db_path, now=2100, monotonic_now=2100.0, boot_id="boot-a", window_seconds=0), 1)

    def test_old_database_without_route_table_is_safe(self):
        path = str(Path(self.tmp.name) / "old.db")
        sqlite3.connect(path).close()
        self.assertEqual(imminent_route_expiry_count(path, now=1000, monotonic_now=1000, boot_id="boot-a"), 0)

    def test_missing_database_on_first_install_is_safe(self):
        path = str(Path(self.tmp.name) / "not-created.db")
        self.assertEqual(imminent_route_expiry_count(path, now=1000, monotonic_now=1000, boot_id="boot-a"), 0)
        self.assertFalse(Path(path).exists())

    def test_installer_checks_before_apt_copy_or_restart_and_requires_tty_confirmation(self):
        root = Path(__file__).resolve().parents[1]
        script = (root / "scripts" / "install.sh").read_text(encoding="utf-8")
        check_at = script.index("route_expiry_preflight.py")
        apt_at = script.index('apt-get install')
        copy_at = script.index('cp -r "$REPO/netpulse"')
        restart_at = script.index("systemctl restart netpulse.service")
        active_check_at = script.index("systemctl is-active --quiet netpulse.service")
        dashboard_at = script.index('echo "Dashboard: http://${IP}:8080/')
        self.assertLess(check_at, apt_at)
        self.assertLess(check_at, copy_at)
        self.assertLess(check_at, restart_at)
        self.assertLess(restart_at, active_check_at)
        self.assertLess(active_check_at, dashboard_at)
        self.assertIn("NetPulse did not remain active after restart; installation is incomplete.", script)
        self.assertIn("journalctl -u netpulse.service --no-pager --lines=40 >&2 || true", script)
        self.assertIn('if [[ ! -t 0 ]]', script)
        self.assertIn('Continue with the install and service restart?', script)
        self.assertIn('Install cancelled before changing installed files or restarting NetPulse.', script)


if __name__ == "__main__":
    unittest.main()
