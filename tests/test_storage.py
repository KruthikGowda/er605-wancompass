import tempfile
import unittest
import sqlite3 as stdlib_sqlite3
from pathlib import Path

from netpulse.storage import sqlite
from netpulse.storage.sqlite import Storage


class StorageRoundTrip(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.tmp.name) / "t.db")
        self.s = Storage(self.path)

    def tearDown(self):
        self.s.close()
        self.tmp.cleanup()

    def test_wan_and_target_history(self):
        self.s.write_minute(
            rows=[(600, "WAN1", "HEALTHY", 99, 0, 7, 1, 100), (660, "WAN1", "DEGRADED", 70, 8, 90, 20, 100)],
            events=[(600, "state", "WAN1", "Example ISP A (WAN1): UNKNOWN -> HEALTHY")],
            baselines=[],
            target_rows=[(600, "WAN1", "1.1.1.1", 0, 29, 1), (600, "WAN1", "8.8.8.8", 0, 7, 1)],
        )
        pts = sqlite.history(self.path, since=0, bucket=60)
        self.assertEqual([p["rtt_ms"] for p in pts], [7, 90])

        cf = sqlite.target_history(self.path, since=0, bucket=60, target="1.1.1.1")
        self.assertEqual([(p["wan"], p["rtt_ms"]) for p in cf], [("WAN1", 29)])

        self.assertEqual(sqlite.state_minutes(self.path, 0), {"WAN1": {"HEALTHY": 1, "DEGRADED": 1}})
        self.assertEqual(sqlite.recent_events(self.path, 5)[0]["message"], "Example ISP A (WAN1): UNKNOWN -> HEALTHY")

    def test_first_device_scan_is_quiet_then_new_devices_are_reported_once(self):
        existing = [{"name": "NAS", "macaddr": "aa-bb-cc-dd-ee-01", "ipaddr": "192.168.0.107"}]
        self.assertEqual(sqlite.observe_devices(self.path, [], 50), [])
        self.assertEqual(sqlite.observe_devices(self.path, existing, 100), [])
        self.assertEqual(sqlite.observe_devices(self.path, existing, 200), [])
        joined = {"name": "ESP <script>", "macaddr": "aa-bb-cc-dd-ee-02", "ipaddr": "192.168.0.125"}
        self.assertEqual(sqlite.observe_devices(self.path, existing + [joined], 300),
                         [{"mac": "AA-BB-CC-DD-EE-02", "name": "ESP <script>", "ip": "192.168.0.125"}])
        self.assertEqual(sqlite.observe_devices(self.path, existing + [joined], 400), [])

    def test_device_missing_requires_three_valid_scans_and_is_reported_on_return(self):
        nas = {"name": "NAS", "macaddr": "aa-bb-cc-dd-ee-01", "ipaddr": "192.168.0.107"}
        laptop = {"name": "Laptop", "macaddr": "aa-bb-cc-dd-ee-02", "ipaddr": "192.168.0.108"}
        sqlite.observe_device_listing(self.path, [nas, laptop], 100)

        self.assertEqual(sqlite.observe_device_listing(self.path, [nas], 200)["missing"], [])
        self.assertEqual(sqlite.observe_device_listing(self.path, [], 300)["missing"], [])
        self.assertEqual(sqlite.observe_device_listing(self.path, [nas], 400)["missing"], [])
        missing = sqlite.observe_device_listing(self.path, [nas], 500)
        self.assertEqual(missing["missing"], [{"mac": "AA-BB-CC-DD-EE-02", "name": "Laptop", "ip": "192.168.0.108"}])
        self.assertEqual(sqlite.observe_device_listing(self.path, [nas], 600)["missing"], [])
        returned = sqlite.observe_device_listing(self.path, [nas, laptop], 700)
        self.assertEqual(returned["returned"], [{"mac": "AA-BB-CC-DD-EE-02", "name": "Laptop", "ip": "192.168.0.108"}])

    def test_colon_mac_scan_preserves_existing_device_history_and_label(self):
        nas = {"name": "NAS", "macaddr": "AA-BB-CC-DD-EE-01", "ipaddr": "192.168.0.107"}
        laptop = {"name": "Laptop", "macaddr": "AA-BB-CC-DD-EE-02", "ipaddr": "192.168.0.108"}
        sqlite.observe_device_listing(self.path, [nas, laptop], 100)
        sqlite.set_device_label(self.path, "aa:bb:cc:dd:ee:01", "Office NAS")
        colon_nas = {**nas, "macaddr": "aa:bb:cc:dd:ee:01"}

        for timestamp in (200, 300, 400):
            with self.subTest(timestamp=timestamp):
                changes = sqlite.observe_device_listing(self.path, [colon_nas, laptop], timestamp)
                self.assertEqual(changes, {"new": [], "missing": [], "returned": []})

        self.assertEqual(sqlite.device_labels(self.path), {"AA-BB-CC-DD-EE-01": "Office NAS"})
        self.assertEqual(sqlite.known_device(self.path, "aa:bb:cc:dd:ee:01"), {
            "name": "NAS", "ip": "192.168.0.107", "listed": True,
        })

    def test_existing_device_schema_migrates_for_listing_tracking(self):
        self.s.close()
        import sqlite3
        db = sqlite3.connect(self.path)
        db.execute("DROP TABLE known_devices")
        db.execute("CREATE TABLE known_devices (mac TEXT PRIMARY KEY, name TEXT NOT NULL, ip TEXT NOT NULL, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL)")
        db.execute("INSERT INTO known_devices VALUES ('AA-BB-CC-DD-EE-01','NAS','192.168.0.107',10,20)")
        db.commit()
        db.close()
        self.s = Storage(self.path)
        rows = self.s.db.execute("SELECT listed, missing_scans FROM known_devices").fetchall()
        self.assertEqual(rows, [(1, 0)])

    def test_device_groups_round_trip_and_cascade_members(self):
        group = sqlite.save_device_group(self.path, "Work", ["AA-BB-CC-DD-EE-01", "AA-BB-CC-DD-EE-02"], 100)
        self.assertEqual(group["members"], ["AA-BB-CC-DD-EE-01", "AA-BB-CC-DD-EE-02"])
        self.assertFalse(group["smart_routing_enabled"])
        changed = sqlite.save_device_group(self.path, "Work gear", ["AA-BB-CC-DD-EE-02"], 200, group["id"])
        self.assertEqual(changed["name"], "Work gear")
        self.assertEqual(changed["members"], ["AA-BB-CC-DD-EE-02"])
        self.assertTrue(sqlite.delete_device_group(self.path, group["id"]))
        self.assertEqual(sqlite.device_groups(self.path), [])

    def test_group_smart_routing_is_explicit_and_manual_member_routes_disable_it(self):
        group = sqlite.save_device_group(self.path, "Work", ["AA-BB-CC-DD-EE-01"], 100)
        self.assertTrue(sqlite.set_group_smart_routing(self.path, group["id"], True, now=120))
        self.assertTrue(sqlite.record_group_smart_action(self.path, group["id"], 456))
        saved = sqlite.device_groups(self.path)[0]
        self.assertTrue(saved["smart_routing_enabled"])
        self.assertEqual(saved["smart_enabled_at"], 120)
        self.assertEqual(saved["smart_last_action_at"], 456)

        sqlite.disable_group_smart_routing_for_member(self.path, "aa:bb:cc:dd:ee:01")

        saved = sqlite.device_groups(self.path)[0]
        self.assertFalse(saved["smart_routing_enabled"])
        self.assertIsNone(saved["smart_enabled_at"])

    def test_group_membership_change_requires_new_smart_routing_opt_in(self):
        group = sqlite.save_device_group(self.path, "Work", ["AA-BB-CC-DD-EE-01"], 100)
        sqlite.set_group_smart_routing(self.path, group["id"], True, now=120)
        updated = sqlite.save_device_group(self.path, "Work", ["AA-BB-CC-DD-EE-02"], 200, group["id"])
        self.assertFalse(updated["smart_routing_enabled"])
        self.assertIsNone(updated["smart_enabled_at"])

    def test_device_can_belong_to_only_one_group(self):
        sqlite.save_device_group(self.path, "Work", ["AA-BB-CC-DD-EE-01"], 100)
        with self.assertRaises(Exception):
            sqlite.save_device_group(self.path, "Media", ["AA-BB-CC-DD-EE-01"], 101)
        self.assertEqual(len(sqlite.device_groups(self.path)), 1)

    def test_existing_group_schema_migrates_smart_routing_to_disabled_by_default(self):
        legacy = str(Path(self.tmp.name) / "legacy-groups.db")
        db = stdlib_sqlite3.connect(legacy)
        db.execute("CREATE TABLE device_groups (id INTEGER PRIMARY KEY, name TEXT UNIQUE, "
                   "created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)")
        db.execute("INSERT INTO device_groups VALUES (1, 'Example Work Group', 10, 20)")
        db.commit()
        db.close()

        migrated = Storage(legacy)
        migrated.close()

        group = sqlite.device_groups(legacy)[0]
        self.assertEqual((group["name"], group["created_at"], group["updated_at"]),
                         ("Example Work Group", 10, 20))
        self.assertFalse(group["smart_routing_enabled"])
        self.assertIsNone(group["smart_enabled_at"])
        self.assertIsNone(group["smart_last_action_at"])


if __name__ == "__main__":
    unittest.main()
