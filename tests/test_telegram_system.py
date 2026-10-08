import tempfile
import unittest

from tests.harness import Scenario, local


class TelegramPiHealthTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.scenario = Scenario(self.tmp.name, local(12))
        self.addCleanup(self.scenario.close)

    def test_pi_health_command_reports_fresh_metrics_and_missing_power_tool(self):
        now = self.scenario.clock.t
        self.scenario.mon.board.set_extra("system_health", {
            "checked_at": now, "disk_free_pct": 76.2, "temperature_c": 47.8,
            "load_per_core": 0.12, "memory_available_pct": 63.5,
            "memory_available_mb": 754.0, "power_check_status": "tool_missing",
            "backup": {"enabled": True, "status": "ok", "age_seconds": 3600, "count": 3},
            "undervoltage": None, "undervoltage_occurred": None,
            "arm_frequency_capped": False, "arm_frequency_capped_occurred": False,
            "throttled": False, "throttled_occurred": False,
            "soft_temp_limit": False, "soft_temp_limit_occurred": False,
        })
        text = self.scenario.mon.bot_handlers()["pi"]()
        self.assertIn("Sample under 1 min ago · current", text)
        self.assertIn("Storage: 76.2% free", text)
        self.assertIn("Temperature: 47.8 °C", text)
        self.assertIn("Memory available: 63.5% (754.0 MB)", text)
        self.assertIn("Database backups: current; last 1 h 0 min ago; 3 kept", text)
        self.assertIn("vcgencmd not found in service PATH", text)
        self.assertIn("Performance limits: no active limits reported", text)

    def test_stale_pi_health_reading_is_explicit(self):
        now = self.scenario.clock.t
        self.scenario.mon.board.set_extra("system_health", {
            "checked_at": now - 601, "disk_free_pct": 50,
            "power_check_status": "command_failed",
        })
        text = self.scenario.mon.bot_handlers()["pi"]()
        self.assertIn("STALE; readings may be out of date", text)
        self.assertIn("vcgencmd could not read power status", text)

    def test_pi_health_command_marks_low_available_memory(self):
        now = self.scenario.clock.t
        self.scenario.mon.board.set_extra("system_health", {
            "checked_at": now, "memory_available_pct": 8.0, "memory_available_mb": 80.0,
            "memory_low": True,
        })
        text = self.scenario.mon.bot_handlers()["pi"]()
        self.assertIn("Memory available: LOW · 8.0% (80.0 MB)", text)

    def test_pi_health_command_explains_backup_states_without_exposing_destination(self):
        now = self.scenario.clock.t
        cases = (
            ({"enabled": False}, "Database backups: disabled"),
            ({"enabled": True, "status": "stale"}, "Database backups: STALE; create a fresh backup"),
            ({"enabled": True, "status": "missing"}, "Database backups: no snapshot found"),
            ({"enabled": True, "status": "unavailable"}, "Database backups: destination unavailable"),
        )
        for backup, expected in cases:
            with self.subTest(expected=expected):
                self.scenario.mon.board.set_extra("system_health", {
                    "checked_at": now, "backup": backup,
                })
                text = self.scenario.mon.bot_handlers()["pi"]()
                self.assertIn(expected, text)
                self.assertNotIn("/var/lib/netpulse/backups", text)

    def test_no_sample_and_disabled_monitor_have_clear_messages(self):
        self.assertEqual(self.scenario.mon.bot_handlers()["pi"](),
                         "No Pi health sample is available yet.")
        from dataclasses import replace
        self.scenario.mon.cfg = replace(
            self.scenario.cfg,
            system_health=replace(self.scenario.cfg.system_health, enabled=False),
        )
        self.assertEqual(self.scenario.mon.bot_handlers()["pi"](),
                         "Pi health checks are disabled in NetPulse configuration.")
