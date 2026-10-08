import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from netpulse.storage import sqlite
from tests.harness import Scenario, local


class TelegramRouteListing(unittest.TestCase):
    def test_route_list_distinguishes_saved_preferences_from_live_tracking(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        scenario = Scenario(tmp.name, local(12))
        self.addCleanup(scenario.close)
        mac1 = "AA-BB-CC-DD-EE-01"
        mac2 = "AA-BB-CC-DD-EE-02"
        sqlite.set_device_label(scenario.cfg.db_path, mac1, "Office laptop")
        scenario.mon.router = SimpleNamespace(snap=SimpleNamespace(raw={
            "reservations": [
                {"mac": mac1, "ip": "192.168.0.50", "enable": "on"},
                {"mac": mac2, "ip": "192.168.0.51", "enable": "on", "note": "TV"},
            ],
            "clients": [],
        }))
        scenario.mon.router_control = SimpleNamespace(
            route_state=lambda: {
                mac1: {"route": "WAN2", "expires_at": local(14)},
            },
            is_local_device=lambda _mac: False,
            state=lambda: {"enabled": True},
        )

        text = scenario.mon.bot_handlers()["route"]("/route")

        self.assertIn("saved NetPulse settings, not live flow tracking", text)
        self.assertIn("Office laptop: " + mac1, text)
        self.assertIn("Prefer WAN2 until ", text)
        self.assertIn("TV: " + mac2, text)
        self.assertIn("Auto", text)

    def test_route_command_defaults_to_one_hour_but_forever_is_explicit(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        scenario = Scenario(tmp.name, local(12))
        self.addCleanup(scenario.close)
        mac = "AA-BB-CC-DD-EE-01"
        control = SimpleNamespace(preview=mock.Mock(return_value={
            "device": "Phone", "mac": mac, "ip": "192.168.0.50", "current": "AUTO",
            "route": "WAN1", "expiry_label": "1 hour", "effect": "Reviewed route", "token": "tok",
        }))
        scenario.mon.router_control = control
        handlers = scenario.mon.bot_handlers()

        handlers["route"](f"/route {mac} WAN1")
        control.preview.assert_called_once_with(mac, "WAN1", "telegram owner", 3600)
        handlers["route"](f"/route {mac} WAN1 forever")
        control.preview.assert_called_with(mac, "WAN1", "telegram owner", 0)


if __name__ == "__main__":
    unittest.main()
