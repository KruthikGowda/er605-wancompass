import tomllib
import unittest
from pathlib import Path

from netpulse import config


class PauseConfig(unittest.TestCase):
    def setUp(self):
        path = Path(__file__).resolve().parents[1] / "config.example.toml"
        self.raw = tomllib.loads(path.read_text(encoding="utf-8"))

    def test_pause_controls_default_off_and_protected_macs_normalize(self):
        self.assertFalse(config.parse(self.raw).router.internet_controls_enabled)
        raw = {**self.raw, "router": {**self.raw["router"], "protected_macs": ["aa:bb:cc:dd:ee:ff"]}}
        cfg = config.parse(raw)
        self.assertEqual(cfg.router.protected_macs, ("AA-BB-CC-DD-EE-FF",))

    def test_rejects_bad_pause_flag_and_invalid_or_duplicate_protected_macs(self):
        raw = {**self.raw, "router": {**self.raw["router"], "internet_controls_enabled": "false"}}
        with self.assertRaisesRegex(ValueError, "internet_controls_enabled"):
            config.parse(raw)
        for macs in (["bad"], ["AA:BB:CC:DD:EE:FF", "aa-bb-cc-dd-ee-ff"], "AA-BB-CC-DD-EE-FF"):
            raw = {**self.raw, "router": {**self.raw["router"], "protected_macs": macs}}
            with self.subTest(macs=macs), self.assertRaisesRegex(ValueError, "protected_macs"):
                config.parse(raw)
