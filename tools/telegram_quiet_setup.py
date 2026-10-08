"""Quiet Telegram home-device activity notifications on an existing installation.

Run on the Pi with sudo: python3 tools/telegram_quiet_setup.py
The saved bot token and chat IDs are preserved and never displayed.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tomllib
from pathlib import Path

# Direct invocation by file path starts with tools/ on sys.path, not the repository root.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from netpulse import config as netpulse_config
from tools.telegram_setup import CONFIG, set_keys, write_preserving


def quiet_config(text: str) -> str:
    """Disable automatic device notices and scheduled reports while keeping config intact."""
    updated = set_keys(text, "telegram", {
        "device_activity_notifications": "false",
        "digest_time": '""',
        "weekly_report_time": '""',
    })
    netpulse_config.parse(tomllib.loads(updated))  # validate before replacing the user's config
    return updated


def main() -> None:
    if os.geteuid() != 0:
        sys.exit("Run with sudo: sudo python3 tools/telegram_quiet_setup.py")
    if not os.path.exists(CONFIG):
        sys.exit(f"{CONFIG} not found: install NetPulse first (sudo ./scripts/install.sh)")
    with open(CONFIG, encoding="utf-8") as f:
        updated = quiet_config(f.read())
    write_preserving(CONFIG, updated)
    restart = subprocess.run(["systemctl", "restart", "netpulse"], check=False)
    if restart.returncode != 0:
        sys.exit("Settings were saved, but NetPulse did not restart. Check: systemctl status netpulse")
    active = subprocess.run(["systemctl", "is-active", "netpulse"], capture_output=True,
                            text=True, check=False)
    if active.returncode != 0 or active.stdout.strip() != "active":
        sys.exit("Settings were saved, but NetPulse is not active. Check: systemctl status netpulse")
    print("NetPulse Telegram device notices and scheduled reports are disabled. Service: active")


if __name__ == "__main__":
    main()
