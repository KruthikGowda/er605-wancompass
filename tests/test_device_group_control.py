"""Reviewed group membership operations avoid router side effects."""
from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path

from netpulse.devices.group_control import GroupControl, MAX_PENDING, TOKEN_SECONDS
from netpulse.router.control import ControlError
from netpulse.storage import sqlite
from netpulse.storage.sqlite import Storage


MAC_A = "AA-BB-CC-DD-EE-01"
MAC_B = "AA-BB-CC-DD-EE-02"
IP_A = "192.168.0.50"
IP_B = "192.168.0.51"


class DeviceGroupMembershipControl(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.db = str(Path(temp.name) / "groups.db")
        Storage(self.db).close()
        self.devices = [
            {"mac": MAC_A, "ip": IP_A, "name": "Laptop", "protected": False},
            {"mac": MAC_B, "ip": IP_B, "name": "Tablet", "protected": False},
        ]
        self.control = GroupControl(self.db, lambda: {"devices": list(self.devices)})

    def test_create_and_add_preview_readonly_then_apply(self):
        created = self.control.preview(action="create", actor="owner", name="Family",
                                       macs=[MAC_A])
        self.assertEqual(created["after_members"], [{"mac": MAC_A, "name": "Laptop", "ip": IP_A}])
        self.assertIn("does not change WAN routes or pause/resume state", created["effect"])
        self.assertEqual(sqlite.device_groups(self.db), [])
        group_result = self.control.apply(created["token"], "owner")
        group = sqlite.device_groups(self.db)[0]
        self.assertEqual((group_result["action"], group["name"], group["members"]),
                         ("create", "Family", [MAC_A]))

        sqlite.set_group_smart_routing(self.db, group["id"], True, now=123)
        add = self.control.preview(action="add", actor="owner", group_id=group["id"], macs=[MAC_B])
        self.assertEqual([m["mac"] for m in add["after_members"]], [MAC_A, MAC_B])
        self.assertIn("turn Smart WAN off", add["effect"])
        applied = self.control.apply(add["token"], "owner")
        saved = sqlite.device_groups(self.db)[0]
        self.assertEqual(applied["members"], [MAC_A, MAC_B])
        self.assertFalse(saved["smart_routing_enabled"])

    def test_foreign_actor_consumes_token_and_reuse_is_rejected(self):
        preview = self.control.preview(action="create", actor="owner", name="Family", macs=[MAC_A])
        with self.assertRaisesRegex(ControlError, "actor differs"):
            self.control.apply(preview["token"], "different owner")
        with self.assertRaisesRegex(ControlError, "expired or was already used"):
            self.control.apply(preview["token"], "owner")
        self.assertEqual(sqlite.device_groups(self.db), [])

    def test_preview_ttl_and_pending_queue_are_bounded(self):
        preview = self.control.preview(action="create", actor="owner", name="Family", macs=[MAC_A])
        self.assertEqual(preview["expires_in"], TOKEN_SECONDS)
        self.control._pending[preview["token"]]["expires"] = 0
        with self.assertRaisesRegex(ControlError, "expired or was already used"):
            self.control.apply(preview["token"], "owner")
        expires = time.time() + TOKEN_SECONDS
        self.control._pending = {f"pending-{index}": {"expires": expires}
                                 for index in range(MAX_PENDING)}
        with self.assertRaisesRegex(ControlError, "Too many pending group reviews"):
            self.control.preview(action="create", actor="owner", name="Family", macs=[MAC_A])
        self.assertEqual(sqlite.device_groups(self.db), [])

    def test_create_rejects_existing_case_insensitive_name(self):
        sqlite.save_device_group(self.db, "Family", [MAC_A], 100)
        with self.assertRaisesRegex(ControlError, "name already exists"):
            self.control.preview(action="create", actor="owner", name="family", macs=[MAC_B])
        self.assertEqual([g["name"] for g in sqlite.device_groups(self.db)], ["Family"])

    def test_rename_keeps_members_routes_and_smart_routing(self):
        group = sqlite.save_device_group(self.db, "Family", [MAC_A], 100)
        sqlite.set_group_smart_routing(self.db, group["id"], True, now=123)
        sqlite.set_device_route(self.db, MAC_A, IP_A, "WAN1", 101, "owner", "AUTO", "applied", "route")
        preview = self.control.preview(action="rename", actor="owner", group_id=group["id"], name="Household")
        self.assertEqual(preview["before_members"], preview["after_members"])
        self.assertIn("Smart WAN remains enabled", preview["effect"])
        result = self.control.apply(preview["token"], "owner")
        saved = sqlite.device_groups(self.db)[0]
        self.assertEqual((result["group"], saved["members"], saved["smart_routing_enabled"]),
                         ("Household", [MAC_A], True))
        self.assertEqual(sqlite.device_routes(self.db)[MAC_A]["route"], "WAN1")

    def test_rename_name_collision_at_apply_keeps_original_group(self):
        group = sqlite.save_device_group(self.db, "Family", [MAC_A], 100)
        preview = self.control.preview(action="rename", actor="owner", group_id=group["id"], name="Work")
        sqlite.save_device_group(self.db, "Work", [MAC_B], 101)
        with self.assertRaisesRegex(ControlError, "conflicts with another group"):
            self.control.apply(preview["token"], "owner")
        saved = {item["name"]: item["members"] for item in sqlite.device_groups(self.db)}
        self.assertEqual(saved, {"Family": [MAC_A], "Work": [MAC_B]})

    def test_group_snapshot_cas_rejects_membership_and_smart_flag_drift(self):
        group = sqlite.save_device_group(self.db, "Family", [MAC_A], 100)
        sqlite.set_group_smart_routing(self.db, group["id"], True, now=123)
        preview = self.control.preview(action="add", actor="owner", group_id=group["id"], macs=[MAC_B])
        sqlite.set_group_smart_routing(self.db, group["id"], False, now=124)
        with self.assertRaisesRegex(ControlError, "changed after review"):
            self.control.apply(preview["token"], "owner")
        saved = sqlite.device_groups(self.db)[0]
        self.assertEqual(saved["members"], [MAC_A])
        self.assertFalse(saved["smart_routing_enabled"])

    def test_fingerprint_is_stable_and_changes_with_group_version_or_name(self):
        group = sqlite.save_device_group(self.db, "Family", [MAC_A], 100)
        first = self.control.preview(action="add", actor="owner", group_id=group["id"], macs=[MAC_B])
        repeated = self.control.preview(action="add", actor="owner", group_id=group["id"], macs=[MAC_B])
        self.assertNotEqual(first["token"], repeated["token"])
        self.assertEqual(first["fingerprint"], repeated["fingerprint"])

        sqlite.save_device_group(self.db, "Household", [MAC_A], 101, group["id"])
        renamed = self.control.preview(action="add", actor="owner", group_id=group["id"], macs=[MAC_B])
        self.assertNotEqual(first["fingerprint"], renamed["fingerprint"])
        sqlite.set_group_smart_routing(self.db, group["id"], True, now=123)
        smart_flag_changed = self.control.preview(action="add", actor="owner",
                                                  group_id=group["id"], macs=[MAC_B])
        self.assertNotEqual(renamed["fingerprint"], smart_flag_changed["fingerprint"])

    def test_protected_status_change_after_review_blocks_addition(self):
        group = sqlite.save_device_group(self.db, "Family", [MAC_A], 100)
        preview = self.control.preview(action="add", actor="owner", group_id=group["id"], macs=[MAC_B])
        self.devices[1]["protected"] = True
        with self.assertRaisesRegex(ControlError, "no longer eligible"):
            self.control.apply(preview["token"], "owner")
        self.assertEqual(sqlite.device_groups(self.db)[0]["members"], [MAC_A])

    def test_delete_compares_group_version_before_cascade(self):
        group = sqlite.save_device_group(self.db, "Family", [MAC_A], 100)
        preview = self.control.preview(action="delete", actor="owner", group_id=group["id"])
        sqlite.save_device_group(self.db, "Family", [MAC_A], 101, group["id"])
        with self.assertRaisesRegex(ControlError, "changed after review"):
            self.control.apply(preview["token"], "owner")
        self.assertEqual(sqlite.device_groups(self.db)[0]["members"], [MAC_A])

    def test_remove_offline_member_and_delete_preserve_route_state(self):
        group = sqlite.save_device_group(self.db, "Family", [MAC_A], 100)
        self.devices = []
        sqlite.set_device_route(self.db, MAC_A, IP_A, "WAN2_ONLY", 101, "owner", "AUTO", "applied", "strict route")
        remove = self.control.preview(action="remove", actor="owner", group_id=group["id"], macs=[MAC_A])
        self.assertEqual(remove["removed"], [{"mac": MAC_A, "name": "Home device", "ip": ""}])
        self.control.apply(remove["token"], "owner")
        self.assertEqual(sqlite.device_groups(self.db)[0]["members"], [])
        self.assertEqual(sqlite.device_routes(self.db)[MAC_A]["route"], "WAN2_ONLY")

        delete = self.control.preview(action="delete", actor="owner", group_id=group["id"])
        self.assertIn("only the group and its membership are removed", delete["effect"])
        self.control.apply(delete["token"], "owner")
        self.assertEqual(sqlite.device_groups(self.db), [])
        self.assertEqual(sqlite.device_routes(self.db)[MAC_A]["route"], "WAN2_ONLY")

    def test_protected_or_ambiguous_inventory_cannot_be_added(self):
        group = sqlite.save_device_group(self.db, "Family", [MAC_A], 100)
        self.devices[1]["protected"] = True
        with self.assertRaisesRegex(ControlError, "no longer eligible"):
            self.control.preview(action="add", actor="owner", group_id=group["id"], macs=[MAC_B])
        self.devices[1]["protected"] = False
        self.devices.append(dict(self.devices[1]))
        with self.assertRaisesRegex(ControlError, "ambiguous"):
            self.control.preview(action="add", actor="owner", group_id=group["id"], macs=[MAC_B])
        self.assertEqual(sqlite.device_groups(self.db)[0]["members"], [MAC_A])

    def test_atomic_constraint_failure_keeps_original_membership(self):
        group = sqlite.save_device_group(self.db, "Family", [MAC_A], 100)
        preview = self.control.preview(action="add", actor="owner", group_id=group["id"], macs=[MAC_B])
        real_owners = self.control._other_group_owners

        def insert_competing_owner(macs, group_id=None):
            owners = real_owners(macs, group_id)
            sqlite.save_device_group(self.db, "Other", [MAC_B], 101)
            return owners

        self.control._other_group_owners = insert_competing_owner
        with self.assertRaisesRegex(ControlError, "conflicts with another group"):
            self.control.apply(preview["token"], "owner")
        groups = {item["name"]: item["members"] for item in sqlite.device_groups(self.db)}
        self.assertEqual(groups, {"Family": [MAC_A], "Other": [MAC_B]})

    def test_create_name_collision_at_apply_does_not_replace_existing_group(self):
        preview = self.control.preview(action="create", actor="owner", name="Family", macs=[MAC_A])
        sqlite.save_device_group(self.db, "Family", [MAC_B], 101)
        with self.assertRaisesRegex(ControlError, "conflicts with another group"):
            self.control.apply(preview["token"], "owner")
        self.assertEqual([(g["name"], g["members"]) for g in sqlite.device_groups(self.db)],
                         [("Family", [MAC_B])])


if __name__ == "__main__":
    unittest.main()
