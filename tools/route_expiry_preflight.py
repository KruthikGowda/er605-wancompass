#!/usr/bin/env python3
"""Read-only, identity-free check for timed WAN routes near expiry.

The installer runs this before copying files or restarting the service. A due or imminent
temporary route can return to Auto when NetPulse starts; the script reports only an aggregate
count and does not contact the ER605 or modify the database.
"""

from __future__ import annotations

import argparse
import sqlite3
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from netpulse.config import load  # noqa: E402
from netpulse.router.control import _system_boot_id  # noqa: E402
from netpulse.storage import sqlite  # noqa: E402

DEFAULT_CONFIG = "/etc/netpulse/config.toml"
DEFAULT_WINDOW_SECONDS = 15 * 60


def imminent_route_expiry_count(db_path: str, now: int | None = None,
                                monotonic_now: float | None = None,
                                boot_id: str | None = None,
                                window_seconds: int = DEFAULT_WINDOW_SECONDS) -> int:
    """Count timed WAN pins due now or within the window, without returning identities."""
    if isinstance(window_seconds, bool) or not isinstance(window_seconds, int) or window_seconds < 0:
        raise ValueError("window_seconds must be a non-negative integer")
    now = int(time.time()) if now is None else int(now)
    monotonic_now = time.monotonic() if monotonic_now is None else float(monotonic_now)
    boot_id = _system_boot_id() if boot_id is None else boot_id
    if not Path(db_path).exists():
        return 0
    try:
        routes = sqlite.device_routes(db_path)
    except sqlite3.OperationalError as exc:
        # A pre-controls database has no route table and cannot trigger route expiry at startup.
        if "no such table: device_routes" in str(exc).lower():
            return 0
        raise

    count = 0
    for route in routes.values():
        if not isinstance(route, dict) or route.get("route") not in ("WAN1", "WAN2"):
            continue
        if route.get("expires_at") is None:
            continue
        same_boot = bool(boot_id and route.get("boot_id") == boot_id
                         and route.get("expires_monotonic") is not None)
        remaining = (float(route["expires_monotonic"]) - monotonic_now if same_boot
                     else int(route["expires_at"]) - now)
        if remaining <= window_seconds:
            count += 1
    return count


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=DEFAULT_CONFIG,
                        help=f"NetPulse config file (default: {DEFAULT_CONFIG})")
    parser.add_argument("--window-seconds", type=int, default=DEFAULT_WINDOW_SECONDS)
    parser.add_argument("--count-only", action="store_true",
                        help="print only the aggregate count for installer use")
    args = parser.parse_args(argv)
    if args.window_seconds < 0:
        parser.error("--window-seconds must be non-negative")
    try:
        cfg = load(args.config)
        count = imminent_route_expiry_count(cfg.db_path, window_seconds=args.window_seconds)
    except (OSError, ValueError, sqlite3.Error) as exc:
        parser.error(f"cannot read timed route state: {type(exc).__name__}")
    if args.count_only:
        print(count)
    else:
        print(f"Timed WAN preferences due or expiring within {args.window_seconds} seconds: {count}")
        if count:
            print("A NetPulse service start may return these preferences to Auto after fresh router checks.")
        print("No device identities were read out, no router was contacted, and no state was changed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
