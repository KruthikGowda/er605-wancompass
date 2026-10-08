import tomllib
import unittest
import subprocess
import sys
from pathlib import Path

from tools.telegram_quiet_setup import quiet_config


class QuietSetup(unittest.TestCase):
    def test_quiets_activity_and_scheduled_reports_without_touching_credentials(self):
        source = Path("config.example.toml").read_text(encoding="utf-8")
        source = source.replace('enabled = false\nbot_token = ""\nchat_id = ""',
                                'enabled = true\nbot_token = "keep-this-token"\nchat_id = "42, 77"')
        source = source.replace('device_activity_notifications = false',
                                'device_activity_notifications = true')
        source = source.replace('digest_time = ""', 'digest_time = "09:00"')
        source = source.replace('weekly_report_time = ""', 'weekly_report_time = "09:00"')
        updated = quiet_config(source)
        self.assertEqual(quiet_config(updated), updated)
        saved = tomllib.loads(updated)
        self.assertTrue(saved["telegram"]["enabled"])
        self.assertEqual(saved["telegram"]["bot_token"], "keep-this-token")
        self.assertEqual(saved["telegram"]["chat_id"], "42, 77")
        self.assertFalse(saved["telegram"]["device_activity_notifications"])
        self.assertEqual(saved["telegram"]["digest_time"], "")
        self.assertEqual(saved["telegram"]["weekly_report_time"], "")
        self.assertFalse(saved["router"]["enabled"])

    def test_direct_path_invocation_bootstraps_repository_imports(self):
        script = Path(__file__).resolve().parents[1] / "tools" / "telegram_quiet_setup.py"
        result = subprocess.run(
            [sys.executable, "-c", "import runpy, sys; runpy.run_path(sys.argv[1], run_name='import_check')",
             str(script)], cwd=script.parent.parent.parent, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
