"""A durable Internet pause takes precedence over route and reservation controls."""
import unittest

from netpulse.router.control import ControlError
from netpulse.storage.pauses import PauseStore
from tests import test_router_control as fixtures

MAC, IP = fixtures.MAC, fixtures.IP


def pause_record(status="paused"):
    rule = {"name": "NP_PAUSE_" + "A" * 32, "policy": "DROP", "service": "ALL",
            "iptype": "ipv4", "zone": "LAN", "is_src": "ipgroup",
            "src": "NP_G_" + MAC.replace("-", ""), "is_dst": "ipgroup",
            "dest": "IPGROUP_ANY", "time": "Any",
            "states": ["new", "established", "related", "invalid"],
            "position": "", "flag": "1", "user": "1"}
    return {"mac": MAC, "ip": IP, "name": rule["name"], "label": "Phone",
            "actor": "owner", "created_at": 100, "expires_at": None,
            "expires_monotonic": None, "boot_id": None, "status": status,
            "rule": rule, "group_id": None}


class PauseRoutePrecedence(unittest.TestCase):
    def setUp(self):
        fixtures.RouteControlApply.setUp(self)
        self.pauses = PauseStore(self.db)

    def test_all_durable_pause_states_prevent_new_route_previews(self):
        for status in ("applying", "paused", "resuming", "error"):
            with self.subTest(status=status):
                self.pauses.put(pause_record(status))
                with self.assertRaisesRegex(ControlError, "Internet pause"):
                    self.control.preview(MAC, "WAN2", "owner")
        self.assertEqual(self.client.writes, [])

    def test_pause_after_route_preview_prevents_confirmation_write(self):
        preview = self.control.preview(MAC, "WAN2", "owner")
        self.pauses.put(pause_record())
        with self.assertRaisesRegex(ControlError, "Internet pause"):
            self.control.apply(preview["token"])
        self.assertEqual(self.client.writes, [])

    def test_pause_prevents_reservation_candidate_changes(self):
        self.pauses.put(pause_record())
        with self.assertRaisesRegex(ControlError, "Internet pause"):
            self.control._reservation_candidate([], [], [], {}, MAC)
        self.assertEqual(self.client.writes, [])

    def test_verified_pause_removal_releases_route_preview(self):
        self.pauses.put(pause_record())
        self.pauses.delete(MAC)
        preview = self.control.preview(MAC, "WAN2", "owner")
        self.assertEqual(preview["route"], "WAN2")
        self.assertEqual(self.client.writes, [])


class PauseTimedRoutePrecedence(unittest.TestCase):
    def setUp(self):
        fixtures.TimedRouteExpiry.setUp(self)

    def test_timed_route_expiry_waits_for_verified_pause_removal(self):
        PauseStore(self.db).put(pause_record())
        self.assertEqual(self.control.expire_due_routes(1001), 0)
        self.assertEqual(self.client.writes, [])
        self.assertEqual(self.control.route_state()[MAC]["route"], "WAN1")
