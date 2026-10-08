import tomllib
import unittest
from pathlib import Path

from netpulse import config

EXAMPLE = Path(__file__).resolve().parent.parent / "config.example.toml"


class LoadConfig(unittest.TestCase):
    def test_example_config_is_valid(self):
        cfg = config.load(EXAMPLE)
        self.assertEqual([w.name for w in cfg.wans], ["WAN1", "WAN2"])
        self.assertEqual(cfg.preferred_wan, "WAN2")
        self.assertEqual(len(cfg.probe.targets), 3)

    def test_rejects_unknown_preferred_wan(self):
        raw = tomllib.loads(EXAMPLE.read_text())
        raw["general"]["preferred_wan"] = "WAN9"
        with self.assertRaises(ValueError):
            config.parse(raw)

    def test_rejects_single_target(self):
        raw = tomllib.loads(EXAMPLE.read_text())
        raw["probe"]["targets"] = ["1.1.1.1"]
        with self.assertRaises(ValueError):
            config.parse(raw)

    def test_expected_asns_normalize_and_validate(self):
        raw = tomllib.loads(EXAMPLE.read_text())
        raw["wan"][0]["expected_asns"] = ["as64500", "64501"]
        self.assertEqual(config.parse(raw).wans[0].expected_asns, ("AS64500", "AS64501"))
        raw["wan"][0]["expected_asns"] = ["provider"]
        with self.assertRaisesRegex(ValueError, "expected_asns"):
            config.parse(raw)

    def test_rejects_too_frequent_or_unreasonable_system_health_checks(self):
        raw = tomllib.loads(EXAMPLE.read_text())
        raw["system_health"]["interval_seconds"] = 5
        with self.assertRaisesRegex(ValueError, "interval_seconds"):
            config.parse(raw)
        raw["system_health"]["interval_seconds"] = 300
        raw["system_health"]["low_disk_pct"] = 90
        with self.assertRaisesRegex(ValueError, "low_disk_pct"):
            config.parse(raw)
        raw = tomllib.loads(EXAMPLE.read_text())
        raw["system_health"]["low_memory_pct"] = 51
        with self.assertRaisesRegex(ValueError, "low_memory_pct"):
            config.parse(raw)
        raw["system_health"]["low_memory_pct"] = 20
        raw["system_health"]["memory_recovery_pct"] = 20
        with self.assertRaisesRegex(ValueError, "memory_recovery_pct"):
            config.parse(raw)

    def test_weekly_report_time_is_optional_but_must_be_hhmm_when_set(self):
        raw = tomllib.loads(EXAMPLE.read_text())
        self.assertEqual(config.parse(raw).telegram.digest_time, "")
        self.assertEqual(config.parse(raw).telegram.weekly_report_time, "")
        raw["telegram"]["weekly_report_time"] = "9am"
        with self.assertRaisesRegex(ValueError, "weekly_report_time"):
            config.parse(raw)

    def test_device_activity_notifications_default_off_and_can_be_enabled(self):
        raw = tomllib.loads(EXAMPLE.read_text(encoding="utf-8"))
        self.assertFalse(config.parse(raw).telegram.device_activity_notifications)
        raw["telegram"]["device_activity_notifications"] = True
        self.assertTrue(config.parse(raw).telegram.device_activity_notifications)

    def test_backup_rotation_settings_are_bounded(self):
        raw = tomllib.loads(EXAMPLE.read_text())
        raw["backup"]["keep"] = 1000
        with self.assertRaisesRegex(ValueError, "backup.keep"):
            config.parse(raw)

    def test_optional_device_presence_probe_defaults_off_and_has_bounded_settings(self):
        raw = tomllib.loads(EXAMPLE.read_text(encoding="utf-8"))
        cfg = config.parse(raw)
        self.assertFalse(cfg.router.presence_probes_enabled)
        self.assertEqual(cfg.router.presence_probe_interval_seconds, 60)
        self.assertEqual(cfg.router.presence_confirm_misses, 3)
        raw["router"]["presence_probe_interval_seconds"] = 5
        with self.assertRaisesRegex(ValueError, "presence_probe_interval_seconds"):
            config.parse(raw)
        raw["router"]["presence_probe_interval_seconds"] = 60
        raw["router"]["presence_confirm_misses"] = 1
        with self.assertRaisesRegex(ValueError, "presence_confirm_misses"):
            config.parse(raw)

    def test_optional_router_syslog_defaults_off_and_requires_valid_bind_settings(self):
        raw = tomllib.loads(EXAMPLE.read_text(encoding="utf-8"))
        cfg = config.parse(raw)
        self.assertFalse(cfg.router.syslog_enabled)
        self.assertEqual(cfg.router.syslog_port, 514)
        raw["router"]["syslog_port"] = 0
        with self.assertRaisesRegex(ValueError, "syslog_port"):
            config.parse(raw)
        raw["router"]["syslog_port"] = 514
        raw["router"]["syslog_enabled"] = True
        raw["router"]["host"] = "router.local"
        with self.assertRaisesRegex(ValueError, "router.host"):
            config.parse(raw)


if __name__ == "__main__":
    unittest.main()
