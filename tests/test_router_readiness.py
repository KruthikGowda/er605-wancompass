"""Read-only router readiness summaries expose counts, not device identities."""

import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from netpulse.storage import sqlite
from tools import router_control_readiness
from tools.router_control_readiness import (overdue_route_expiry_count, summarize_group_reservations,
                                            summarize_netpulse_routes,
                                            assess_native_fallback_prerequisites)


class RouterReadinessSummary(unittest.TestCase):
    def test_group_reservation_summary_counts_only_unique_enabled_private_ipv4_reservations(self):
        macs = [f"AA-BB-CC-DD-EE-{n:02X}" for n in range(1, 5)]
        groups = [{"name": "Example Work Group", "members": macs}]
        reservations = [
            {"mac": macs[0], "ip": "192.168.0.107", "enable": "on"},
            {"mac": macs[1], "ip": "192.168.0.118", "enable": "on"},
            {"mac": macs[2], "ip": "192.168.0.118", "enable": "on"},
            {"mac": macs[3], "ip": "192.168.0.123", "enable": "off"},
        ]

        self.assertEqual(summarize_group_reservations(groups, reservations), [{
            "name": "Example Work Group", "members": 4, "reserved": 1, "needs_reservation": 3,
        }])

    def test_group_reservation_summary_handles_missing_and_invalid_inputs(self):
        self.assertEqual(summarize_group_reservations(None, []), [])
        self.assertEqual(summarize_group_reservations(
            [{"name": "Empty", "members": []}, {"name": "Bad", "members": "not a list"}], []),
            [{"name": "Empty", "members": 0, "reserved": 0, "needs_reservation": 0}])

    def test_saved_expiry_summary_prints_before_router_credentials_are_loaded(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = str(Path(directory) / "netpulse.db")
            storage = sqlite.Storage(db_path)
            storage.close()
            cfg = SimpleNamespace(
                db_path=db_path,
                router=SimpleNamespace(enabled=True, controls_enabled=False,
                                       kill_switch=str(Path(directory) / "disabled"),
                                       credentials_file="unused"),
            )
            output = io.StringIO()

            def fail_if_router_auth_is_attempted(*_args):
                self.assertIn("Timed WAN preferences currently overdue: 0", output.getvalue())
                raise RuntimeError("router login unavailable")

            with mock.patch.object(router_control_readiness.os, "geteuid", return_value=0, create=True), \
                    mock.patch.object(router_control_readiness, "load", return_value=cfg), \
                    mock.patch.object(router_control_readiness, "load_router_credentials",
                                      side_effect=fail_if_router_auth_is_attempted), \
                    redirect_stdout(output), self.assertRaisesRegex(RuntimeError, "router login"):
                router_control_readiness.main()

    def test_expiry_preflight_returns_only_the_number_of_overdue_routes(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = str(Path(directory) / "netpulse.db")
            storage = sqlite.Storage(db_path)
            try:
                sqlite.set_device_route(db_path, "AA-BB-CC-DD-EE-01", "192.0.2.10", "WAN1",
                                        100, "owner", "AUTO", "applied", "timed",
                                        expires_at=900, expires_monotonic=900.0, boot_id="boot")
                sqlite.set_device_route(db_path, "AA-BB-CC-DD-EE-02", "192.0.2.11", "WAN2",
                                        100, "owner", "AUTO", "applied", "timed",
                                        expires_at=1100, expires_monotonic=1100.0, boot_id="boot")
            finally:
                storage.close()

            self.assertEqual(overdue_route_expiry_count(
                db_path, now=1000, monotonic_now=1000.0, boot_id="boot"), 1)

    def test_live_owned_rules_are_compared_with_saved_preferences(self):
        saved = {
            "AA-BB-CC-DD-EE-01": {"route": "WAN2"},
            "AA-BB-CC-DD-EE-02": {"route": "WAN1"},
            "AA-BB-CC-DD-EE-03": {"route": "AUTO"},
        }
        rows = [
            {"name": "NP_R_AABBCCDDEE01", "state": "on", "interfaces": "WAN2", "mode": "Priority"},
            {"name": "NP_R_AABBCCDDEE02", "state": "on", "interfaces": "WAN2", "mode": "Only"},
            {"name": "NP_R_AABBCCDDEE03", "state": "off", "interfaces": "WAN1", "mode": "Only"},
            {"name": "NP_R_AABBCCDDEE04", "state": "on", "interfaces": "WAN1"},
            {"name": "untrusted-device-name", "state": "on", "interfaces": "WAN1"},
            {"name": "NP_I_AABBCCDDEE05", "state": "on", "interfaces": "WAN1"},
        ]

        self.assertEqual(summarize_netpulse_routes(rows, saved), {
            "rules": 4,
            "enabled": 3,
            "disabled": 1,
            "priority_enabled": 1,
            "only_enabled": 1,
            "unknown_mode_enabled": 1,
            "priority_target_unknown": 0,
            "unknown_state": 0,
            "saved_match": 2,
            "saved_drift": 1,
            "saved_unknown": 0,
            "untracked_rules": 1,
        })

    def test_pi_offline_prerequisites_pass_for_balanced_priority_rules(self):
        summary = summarize_netpulse_routes([
            {"name": "NP_R_AABBCCDDEE01", "state": "on", "interfaces": "WAN2", "mode": "Priority"},
        ], {"AA-BB-CC-DD-EE-01": {"route": "WAN2"}})
        result = assess_native_fallback_prerequisites(True, summary)
        self.assertEqual(result, {"status": "prerequisites_pass", "blockers": []})

    def test_pi_offline_prerequisites_fail_closed_for_unsafe_or_unknown_rows(self):
        cases = [
            ([{"name": "NP_R_AABBCCDDEE01", "state": "on", "interfaces": "WAN2", "mode": "Only"}],
             {"AA-BB-CC-DD-EE-01": {"route": "WAN2"}}),
            ([{"name": "NP_R_AABBCCDDEE01", "state": "on", "interfaces": "LAN", "mode": "Priority"}],
             {"AA-BB-CC-DD-EE-01": {"route": "WAN2"}}),
            ([{"name": "NP_R_AABBCCDDEE01", "state": "mystery", "interfaces": "WAN2", "mode": "Priority"}],
             {"AA-BB-CC-DD-EE-01": {"route": "AUTO"}}),
        ]
        for rows, saved in cases:
            with self.subTest(rows=rows):
                summary = summarize_netpulse_routes(rows, saved)
                self.assertEqual(assess_native_fallback_prerequisites(True, summary)["status"],
                                 "needs_review")
        self.assertEqual(assess_native_fallback_prerequisites(None, None)["status"], "unavailable")

    def test_duplicate_or_malformed_route_state_is_unknown(self):
        saved = {"AA-BB-CC-DD-EE-01": {"route": "WAN1"}}
        rows = [
            {"name": "NP_R_AABBCCDDEE01", "state": "on", "interfaces": "WAN1"},
            {"name": "NP_R_AABBCCDDEE01", "state": "on", "interfaces": "WAN1"},
        ]
        summary = summarize_netpulse_routes(rows, saved)
        self.assertEqual(summary["saved_unknown"], 1)
        self.assertEqual(summary["saved_match"], 0)

    def test_unavailable_or_wrapped_result_is_not_called_empty(self):
        self.assertIsNone(summarize_netpulse_routes(None, {}))
        self.assertIsNone(summarize_netpulse_routes({"data": []}, {}))


if __name__ == "__main__":
    unittest.main()
