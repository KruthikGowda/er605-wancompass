"""The root recovery helper must be installed before service start, without a cycle."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class RecoveryInstallContract(unittest.TestCase):
    def test_recovery_precedes_app_but_failure_does_not_require_app_to_stop(self):
        app = (ROOT / "systemd/netpulse.service").read_text()
        recovery = (ROOT / "systemd/netpulse-acl-recovery.service").read_text()
        self.assertIn("Wants=network-online.target netpulse-acl-recovery.service", app)
        self.assertIn("After=network-online.target netpulse-acl-recovery.service", app)
        self.assertNotIn("Requires=netpulse-acl-recovery.service", app)
        self.assertIn("Before=netpulse.service", recovery)
        self.assertNotIn("After=netpulse.service", recovery)
        self.assertIn("User=root", recovery)
        self.assertIn("SupplementaryGroups=netpulse", recovery)
        self.assertIn("CapabilityBoundingSet=", recovery)
        self.assertIn("--recover-on-boot", recovery)
        self.assertIn("TimeoutStartSec=60", recovery)
        self.assertIn("ReadWritePaths=-/var/lib/netpulse", recovery)

    def test_installer_copies_runtime_helpers_and_units_before_restart(self):
        script = (ROOT / "scripts/install.sh").read_text()
        restart = script.index("systemctl restart netpulse.service")
        for required in ("$REPO/tools/router_acl_pilot.py", "$REPO/tools/router_firewall_discover.py",
                         "$REPO/systemd/netpulse-acl-recovery.service"):
            self.assertLess(script.index(required), restart)
        self.assertLess(script.index("systemctl daemon-reload"), restart)


if __name__ == "__main__":
    unittest.main()
