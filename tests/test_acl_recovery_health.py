"""Read-only visibility and transition alerts for interrupted ACL-test cleanup."""

from __future__ import annotations

import asyncio
from dataclasses import replace
import subprocess
import tempfile
import threading
import unittest
from unittest import mock

from netpulse import main, system_health
from tests.harness import Scenario, local


def systemctl_output(*, load="loaded", result="success", status="0", active="inactive"):
    return "\n".join((f"LoadState={load}", f"Result={result}",
                       f"ExecMainStatus={status}", f"ActiveState={active}")) + "\n"


class RecoverySamplerTests(unittest.TestCase):
    def run_sample(self, output=None, returncode=0, error=None):
        if error:
            run_mock = mock.patch.object(system_health, "_SYSTEMCTL_RUN", side_effect=error)
        else:
            completed = subprocess.CompletedProcess([], returncode, output or "", "")
            run_mock = mock.patch.object(system_health, "_SYSTEMCTL_RUN", return_value=completed)
        with mock.patch.object(system_health, "_has_systemd_runtime", return_value=True), \
             run_mock as run:
            status = system_health.sample_acl_recovery()
        run.assert_called_once()
        call = run.call_args
        self.assertEqual(call.args[0], [
            "systemctl", "show", "netpulse-acl-recovery.service", "--property=LoadState",
            "--property=Result", "--property=ExecMainStatus", "--property=ActiveState",
        ])
        self.assertEqual(call.kwargs["timeout"], 2)
        self.assertEqual(call.kwargs["encoding"], "utf-8")
        self.assertTrue(call.kwargs["capture_output"])
        return status

    def test_successful_inactive_oneshot_is_ok(self):
        self.assertEqual(self.run_sample(systemctl_output()), {"status": "ok"})

    def test_transitional_unit_is_pending_even_with_nonzero_last_result(self):
        self.assertEqual(self.run_sample(systemctl_output(result="exit-code", status="1",
                                                          active="activating")),
                         {"status": "pending"})

    def test_loaded_terminal_failures_are_reported(self):
        self.assertEqual(self.run_sample(systemctl_output(result="exit-code", status="1")),
                         {"status": "failed"})
        self.assertEqual(self.run_sample(systemctl_output(active="failed")), {"status": "failed"})

    def test_missing_malformed_unknown_and_timeout_are_unavailable(self):
        for kwargs in (
            {"output": systemctl_output(load="not-found")},
            {"output": "LoadState=loaded\nResult=success\n"},
            {"output": systemctl_output() + "Result=success\n"},
            {"output": systemctl_output(result="mystery")},
            {"output": systemctl_output(result="skipped")},
            {"output": systemctl_output(status="-1")},
            {"output": "x" * 8193},
            {"error": subprocess.TimeoutExpired("systemctl", 2)},
            {"error": FileNotFoundError("systemctl")},
            {"output": systemctl_output(), "returncode": 1},
        ):
            with self.subTest(kwargs=kwargs):
                self.assertEqual(self.run_sample(**kwargs), {"status": "unavailable"})


class RecoveryAlertTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.start = local(12)
        self.scenario = Scenario(self.tmp.name, self.start)
        self.addCleanup(self.scenario.close)

    @staticmethod
    def health(status):
        return {"acl_recovery": {"status": status}}

    def run_startup(self, sample_outcome, initial_marker=None):
        s = self.scenario
        s.cfg = replace(
            s.cfg,
            system_health=replace(s.cfg.system_health, enabled=False),
            telegram=replace(s.cfg.telegram, enabled=True, bot_token="123:test", chat_id="42"),
        )
        if initial_marker is not None:
            s.storage.set_value("pi_acl_recovery_failed", initial_marker)
        events = []
        web_marker = []
        sample_thread = []

        class StoppedEvent:
            def is_set(self):
                return True

        def sample_recovery():
            sample_thread.append(threading.get_ident())
            events.append("sample")
            if isinstance(sample_outcome, Exception):
                raise sample_outcome
            return {"status": sample_outcome}

        def start_web(*_args):
            events.append("web")
            web_marker.append(s.storage.get_value("pi_acl_recovery_failed"))

        bot = mock.Mock()
        bot.start = mock.Mock(side_effect=lambda: events.append("bot"))
        sample = mock.Mock(side_effect=sample_recovery)
        web_start = mock.Mock(side_effect=start_web)
        with mock.patch.object(main.system_health, "sample_acl_recovery", sample), \
             mock.patch.object(main.web, "start", web_start), \
             mock.patch.object(main, "TelegramBot", return_value=bot), \
             mock.patch.object(main.asyncio, "Event", StoppedEvent):
            asyncio.run(main.run_async(s.cfg))
        self.assertEqual(events, ["sample", "web", "bot"])
        sample.assert_called_once_with()
        web_start.assert_called_once()
        bot.start.assert_called_once()
        self.assertNotEqual(sample_thread[0], threading.get_ident())
        return web_marker[0], s.storage.get_value("pi_acl_recovery_failed")

    def test_failed_alert_dedupes_and_recovery_persists_across_monitor_restart(self):
        s = self.scenario
        s.mon.on_system_health(self.start, self.health("failed"))
        s.mon.on_system_health(self.start + 1, self.health("failed"))
        s.mon.on_system_health(self.start + 2, self.health("unavailable"))
        s.mon.on_system_health(self.start + 3, self.health("pending"))
        self.assertEqual(sum("interrupted temporary router test" in x for x in s.outbox.texts()), 1)
        self.assertEqual(s.storage.get_value("pi_acl_recovery_failed"), "1")

        restarted = main.Monitor(s.cfg, s.storage, main.Alerter(s.outbox, s.cfg.telegram),
                                 s.board, clock=s.clock)
        restarted.on_system_health(self.start + 4, self.health("failed"))
        self.assertEqual(sum("interrupted temporary router test" in x for x in s.outbox.texts()), 1)
        restarted.on_system_health(self.start + 5, self.health("ok"))
        restarted.on_system_health(self.start + 6, self.health("ok"))
        self.assertEqual(s.storage.get_value("pi_acl_recovery_failed"), "0")
        self.assertEqual(sum("ACL recovery completed" in x for x in s.outbox.texts()), 1)

    def test_pi_health_reports_all_recovery_states_without_claiming_cleanup(self):
        s = self.scenario
        handler = s.mon.bot_handlers()["pi"]
        for status, expected in (
            ("failed", "Temporary router-test recovery: Recovery status: FAILED"),
            ("pending", "Temporary router-test recovery: Recovery status: cleanup is running"),
            ("unavailable", "Temporary router-test recovery: Recovery status: unavailable"),
            ("ok", "Temporary router-test recovery: Recovery status: last check passed"),
        ):
            s.board.set_extra("system_health", {"checked_at": self.start,
                                                  "acl_recovery": {"status": status}})
            self.assertIn(expected, handler())

    def test_startup_check_runs_before_web_and_bot_when_optional_health_is_disabled(self):
        s = self.scenario
        web_marker, stored_marker = self.run_startup("failed")
        self.assertEqual(web_marker, "1")
        self.assertEqual(stored_marker, "1")
        self.assertEqual(s.storage.get_value("pi_acl_recovery_failed"), "1")

    def test_startup_unavailable_and_pending_preserve_failure_while_interfaces_start(self):
        for status in ("unavailable", "pending"):
            with self.subTest(status=status):
                web_marker, stored_marker = self.run_startup(status, initial_marker="1")
                self.assertEqual(web_marker, "1")
                self.assertEqual(stored_marker, "1")

    def test_startup_sampler_exception_preserves_failure_while_interfaces_start(self):
        web_marker, stored_marker = self.run_startup(RuntimeError("sampler failed"), initial_marker="1")
        self.assertEqual(web_marker, "1")
        self.assertEqual(stored_marker, "1")

    def test_startup_success_clears_failure_before_web_starts(self):
        web_marker, stored_marker = self.run_startup("ok", initial_marker="1")
        self.assertEqual(web_marker, "0")
        self.assertEqual(stored_marker, "0")


if __name__ == "__main__":
    unittest.main()
