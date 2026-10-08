"""Create/reset the local dashboard password file.

Run as root on the Pi: sudo python3 tools/web_setup.py
The generated password is printed once; store it in a password manager.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
from pathlib import Path

DEFAULT_PATH = Path("/etc/netpulse/web.auth")
ITERATIONS = 180_000


def create(path: Path, reset: bool = False) -> str | None:
    password = secrets.token_urlsafe(24)
    salt = secrets.token_bytes(16)
    data = {
        "username": "netpulse",
        "salt": salt.hex(),
        "digest": hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS).hex(),
        "iterations": ITERATIONS,
    }
    path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    if not reset and path.exists():
        return None
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        os.chmod(path, 0o640)
        if os.name == "posix" and os.geteuid() == 0:
            import grp
            try:
                os.chown(path, 0, grp.getgrnam("netpulse").gr_gid)
            except KeyError:
                pass
    finally:
        if tmp.exists():
            tmp.unlink()
    return password


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--path", type=Path, default=DEFAULT_PATH)
    parser.add_argument("--reset", action="store_true", help="replace an existing password")
    args = parser.parse_args()
    password = create(args.path, args.reset)
    if password is None:
        print(f"Dashboard password file already exists: {args.path}")
        print("To reset: sudo python3 tools/web_setup.py --reset")
    else:
        print("Dashboard login created")
        print("Username: netpulse")
        print(f"Password: {password}")
        print("Save this password now; only its salted verifier is stored.")


if __name__ == "__main__":
    main()
