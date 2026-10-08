import subprocess
import tempfile
import unittest
from unittest import mock

from netpulse import system_health
from tests.harness import Scenario, local


class Samples(unittest.TestCase):
    def test_disk_usage_error_does_not_discard_other_pi_health_metrics(self):
        outputs = [
            subprocess.CompletedProcess([], 0, "throttled=0x0\n", ""),
            subprocess.CompletedProcess([], 0, "temp=48.5'C\n", ""),
        ]
        with mock.patch.object(system_health.shutil, "disk_usage", side_effect=OSError("mount missing")), \
             mock.patch.object(system_health.shutil, "which", return_value="/usr/bin/vcgencmd"), \
             mock.patch.object(system_health.subprocess, "run", side_effect=outputs):
            sample = system_health.sample("/tmp/db")
        self.assertIsNone(sample["disk_free_pct"])
        self.assertEqual(sample["disk_check_status"], "unavailable")
        self.assertEqual(sample["temperature_c"], 48.5)
        self.assertEqual(sample["power_check_status"], "available")

    def test_linux_load_and_available_memory_are_normalized_read_only_metrics(self):
        from pathlib import Path

        def read_text(path, *args, **kwargs):
            values = {
                "/proc/loadavg": "1.00 0.80 0.50 1/200 1234\n",
                "/proc/meminfo": "MemTotal: 1000000 kB\nMemAvailable: 500000 kB\n",
            }
            normalized = str(path).replace("\\", "/")
            if normalized in values:
                return values[normalized]
            raise OSError("not present in test")

        with mock.patch.object(system_health.shutil, "disk_usage", return_value=mock.Mock(total=100, free=50)), \
             mock.patch.object(system_health.shutil, "which", return_value=None), \
             mock.patch.object(system_health.os, "cpu_count", return_value=4), \
             mock.patch.object(Path, "read_text", read_text):
            sample = system_health.sample("/tmp/db")
        self.assertEqual(sample["load_per_core"], 0.25)
        self.assertEqual(sample["memory_available_pct"], 50.0)
        self.assertEqual(sample["memory_available_mb"], 488.3)
        self.assertNotIn("cpu_usage_pct", sample)

    def test_soc_temperature_is_parsed_as_a_measurement(self):
        outputs = [
            subprocess.CompletedProcess([], 0, "throttled=0x0\n", ""),
            subprocess.CompletedProcess([], 0, "temp=48.5'C\n", ""),
        ]
        with mock.patch.object(system_health.shutil, "disk_usage", return_value=mock.Mock(total=100, free=50)), \
             mock.patch.object(system_health.shutil, "which", return_value="/usr/bin/vcgencmd"), \
             mock.patch.object(system_health.subprocess, "run", side_effect=outputs) as run:
            sample = system_health.sample("/tmp/db")
        self.assertEqual(sample["temperature_c"], 48.5)
        self.assertEqual(sample["power_check_status"], "available")
        self.assertEqual(run.call_count, 2)

    def test_disk_space_and_throttled_bits_are_parsed(self):
        usage = mock.Mock(total=1000, used=700, free=300)
        completed = subprocess.CompletedProcess([], 0, "throttled=0xf000f\n", "")
        with mock.patch.object(system_health.shutil, "disk_usage", return_value=usage), \
             mock.patch.object(system_health.shutil, "which", return_value="/usr/bin/vcgencmd"), \
             mock.patch.object(system_health.subprocess, "run", return_value=completed):
            sample = system_health.sample("/var/lib/netpulse/netpulse.db")
        self.assertEqual(sample["disk_free_pct"], 30.0)
        self.assertEqual(sample["disk_free_bytes"], 300)
        self.assertTrue(sample["undervoltage"])
        self.assertTrue(sample["undervoltage_occurred"])
        self.assertTrue(sample["arm_frequency_capped"])
        self.assertTrue(sample["arm_frequency_capped_occurred"])
        self.assertTrue(sample["throttled"])
        self.assertTrue(sample["throttled_occurred"])
        self.assertTrue(sample["soft_temp_limit"])
        self.assertTrue(sample["soft_temp_limit_occurred"])
        self.assertEqual(sample["power_check_status"], "available")

    def test_unknown_power_flag_when_vcgencmd_is_missing(self):
        with mock.patch.object(system_health.shutil, "disk_usage", return_value=mock.Mock(total=100, free=25)), \
             mock.patch.object(system_health.shutil, "which", return_value=None):
            sample = system_health.sample("/tmp/db")
        self.assertEqual(sample["disk_free_pct"], 25.0)
        self.assertIsNone(sample["undervoltage"])
        self.assertIsNone(sample["throttled"])
        self.assertEqual(sample["power_check_status"], "tool_missing")

    def test_power_check_distinguishes_command_failure_and_bad_output(self):
        with mock.patch.object(system_health.shutil, "disk_usage", return_value=mock.Mock(total=100, free=25)), \
             mock.patch.object(system_health.shutil, "which", return_value="/usr/bin/vcgencmd"), \
             mock.patch.object(system_health.subprocess, "run", side_effect=subprocess.TimeoutExpired("vcgencmd", 2)):
            failed = system_health.sample("/tmp/db")
        self.assertEqual(failed["power_check_status"], "command_failed")
        self.assertIsNone(failed["undervoltage"])

        outputs = [
            subprocess.CompletedProcess([], 0, "unsupported output\n", ""),
            subprocess.CompletedProcess([], 0, "temp=48.5'C\n", ""),
        ]
        with mock.patch.object(system_health.shutil, "disk_usage", return_value=mock.Mock(total=100, free=25)), \
             mock.patch.object(system_health.shutil, "which", return_value="/usr/bin/vcgencmd"), \
             mock.patch.object(system_health.subprocess, "run", side_effect=outputs):
            malformed = system_health.sample("/tmp/db")
        self.assertEqual(malformed["power_check_status"], "unexpected_response")
        self.assertIsNone(malformed["undervoltage"])


class Alerts(unittest.TestCase):
    def test_disk_check_failure_does_not_look_like_disk_recovery(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        start = local(12)
        s = Scenario(tmp.name, start)
        self.addCleanup(s.close)

        low = {"disk_free_pct": 5.0, "disk_free_bytes": 100, "disk_total_bytes": 2000}
        s.mon.on_system_health(start, low)
        unavailable = {"disk_free_pct": None, "disk_check_status": "unavailable"}
        s.mon.on_system_health(start + 10, unavailable)
        self.assertEqual(sum("disk space is back to normal" in text for text in s.outbox.texts()), 0)

        recovered = {"disk_free_pct": 30.0, "disk_free_bytes": 600, "disk_total_bytes": 2000}
        s.mon.on_system_health(start + 20, recovered)
        self.assertEqual(sum("disk space is back to normal" in text for text in s.outbox.texts()), 1)

    def test_stale_sampler_alerts_once_and_reports_recovery_once(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        start = local(12)
        s = Scenario(tmp.name, start)
        self.addCleanup(s.close)

        s.mon.on_system_health_stale(start, False)
        s.mon.on_system_health_stale(start + 1, False)
        self.assertEqual(s.outbox.texts(), [])
        s.mon.on_system_health_stale(start + 2, True)
        s.mon.on_system_health_stale(start + 3, True)
        s.mon.on_system_health_stale(start + 4, False)
        s.mon.on_system_health_stale(start + 5, False)

        self.assertEqual(len([text for text in s.outbox.texts() if "health sampling is stale" in text]), 1)
        self.assertEqual(len([text for text in s.outbox.texts() if "health sampling has resumed" in text]), 1)

    def test_warns_once_on_low_disk_and_sends_clear_when_recovered(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        start = local(12)
        s = Scenario(tmp.name, start)
        self.addCleanup(s.close)
        low = {"disk_free_pct": 5.0, "disk_free_bytes": 100, "disk_total_bytes": 2000,
               "undervoltage": True, "undervoltage_occurred": True}
        s.mon.on_system_health(start, low)
        s.mon.on_system_health(start + 10, low)
        self.assertEqual(len([t for t in s.outbox.texts() if "disk is nearly full" in t]), 1)
        self.assertEqual(len([t for t in s.outbox.texts() if "undervoltage" in t.lower()]), 1)
        recovered = {**low, "disk_free_pct": 30.0, "undervoltage": False}
        s.mon.on_system_health(start + 20, recovered)
        self.assertTrue(any("disk space is back to normal" in t for t in s.outbox.texts()))
        self.assertTrue(any("power is back in range" in t for t in s.outbox.texts()))
        self.assertTrue(s.board.get_extra("system_health")["checked_at"] == start + 20)

    def test_low_memory_alert_uses_recovery_hysteresis_and_ignores_missing_samples(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        start = local(12)
        s = Scenario(tmp.name, start)
        self.addCleanup(s.close)
        healthy = {"memory_available_pct": 20.0, "memory_available_mb": 200.0}
        low = {"memory_available_pct": 8.0, "memory_available_mb": 80.0}
        s.mon.on_system_health(start, healthy)
        s.mon.on_system_health(start + 10, low)
        s.mon.on_system_health(start + 20, low)
        self.assertEqual(sum("available memory is low" in text for text in s.outbox.texts()), 1)
        self.assertTrue(s.board.get_extra("system_health")["memory_low"])

        s.mon.on_system_health(start + 30, {"memory_available_pct": None})
        s.mon.on_system_health(start + 40, {"memory_available_pct": 12.0})
        self.assertFalse(any("memory has recovered" in text for text in s.outbox.texts()))
        s.mon.on_system_health(start + 50, {"memory_available_pct": 15.0})
        self.assertEqual(sum("memory has recovered" in text for text in s.outbox.texts()), 1)
        s.mon.on_system_health(start + 60, healthy)
        self.assertEqual(sum("memory has recovered" in text for text in s.outbox.texts()), 1)

    def test_performance_limits_alert_on_activation_clear_and_new_boot_history_once(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        start = local(12)
        s = Scenario(tmp.name, start)
        self.addCleanup(s.close)
        base = {
            "boot_id": "boot-test", "disk_free_pct": 60.0, "disk_free_bytes": 600,
            "disk_total_bytes": 1000, "undervoltage": False, "undervoltage_occurred": False,
            "arm_frequency_capped": False, "arm_frequency_capped_occurred": False,
            "throttled": False, "throttled_occurred": False,
            "soft_temp_limit": False, "soft_temp_limit_occurred": False,
        }
        s.mon.on_system_health(start, dict(base))
        active = {**base, "throttled": True, "throttled_occurred": True}
        s.mon.on_system_health(start + 10, dict(active))
        s.mon.on_system_health(start + 20, dict(active))
        self.assertEqual(sum("CPU is being throttled" in text for text in s.outbox.texts()), 1)
        cleared = {**base, "throttled_occurred": True}
        s.mon.on_system_health(start + 30, dict(cleared))
        self.assertEqual(sum("performance limit cleared" in text for text in s.outbox.texts()), 1)

        later = {**cleared, "arm_frequency_capped_occurred": True}
        s.mon.on_system_health(start + 40, dict(later))
        s.mon.on_system_health(start + 50, dict(later))
        self.assertEqual(sum("ARM frequency is capped" in text for text in s.outbox.texts()), 1)


if __name__ == "__main__":
    unittest.main()
