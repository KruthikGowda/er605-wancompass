"""Connect NetPulse to the ER605 (read-only). Run on the Pi from the repo folder:

    sudo python3 tools/router_setup.py

- Pins the router's HTTPS certificate (you confirm its fingerprint).
- Asks for the admin username and password (hidden, never printed or logged).
- Tests one login/logout. Note: this logs you out of the Omada web page if you're in it.
- Saves /etc/netpulse/router.toml (root:netpulse, mode 640), enables [router], restarts NetPulse.
"""

from __future__ import annotations

import getpass
import grp
import json
import os
import socket
import ssl
import subprocess
import sys
import time
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from netpulse.router.er605 import (ER605Client, RouterAuthError, RouterError,  # noqa: E402
                                   fingerprint)
from netpulse.router.watch import parse_links  # noqa: E402
from tools.telegram_setup import set_keys, write_preserving  # noqa: E402

CONFIG = "/etc/netpulse/config.toml"


def fetch_fingerprint(host: str) -> str:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, 443), timeout=10) as raw:
        with ctx.wrap_socket(raw) as s:
            return fingerprint(s.getpeercert(binary_form=True))


def pretty(fp: str) -> str:
    return ":".join(fp[i:i + 2] for i in range(0, len(fp), 2))


def main() -> None:
    if os.geteuid() != 0:
        sys.exit("Run with sudo: sudo python3 tools/router_setup.py")
    with open(CONFIG, "rb") as f:
        cfg = tomllib.load(f)
    router_cfg = cfg.get("router", {})
    host = router_cfg.get("host", "192.168.0.1")
    creds_path = router_cfg.get("credentials_file", "/etc/netpulse/router.toml")

    print(f"NetPulse router setup (ER605 at {host})\n")
    try:
        fp = fetch_fingerprint(host)
    except OSError as e:
        sys.exit(f"Can't reach https://{host} ({type(e).__name__}).")
    print("Router certificate fingerprint (SHA-256):")
    print(f"  {pretty(fp)}")
    print("NetPulse will refuse to talk to anything presenting a different certificate.")
    if input("Trust this certificate? [y/N] ").strip().lower() != "y":
        sys.exit("Cancelled. Nothing was changed.")

    username = input("\nER605 admin username [admin]: ").strip() or "admin"
    password = getpass.getpass("ER605 admin password (hidden): ")
    if not password:
        sys.exit("No password entered. Nothing was changed.")

    print("\nTesting login (this logs you out of the Omada web page if it's open)...")
    client = ER605Client(host, username, password, fp)
    try:
        with client.session() as c:
            online = c.get("online", "online")
            status2 = c.get("interface", "status2")
    except RouterAuthError:
        sys.exit("❌ The router rejected that username/password.\n"
                 "Wait a minute before trying again: repeated failures can lock the login.")
    except RouterError as e:
        sys.exit(f"❌ Couldn't complete the test: {e}")

    wans = [w["name"] for w in cfg.get("wan", [])] or ["WAN1", "WAN2"]
    labels = {w["name"]: w.get("label") or w["name"] for w in cfg.get("wan", [])}
    print("✅ Login works. The router reports:")
    for wan, link in parse_links(online, status2, wans).items():
        state = "up" if link.up else "DOWN" if link.up is False else "unknown"
        print(f"   {labels.get(wan, wan)} ({wan}): link {state}{f', IP {link.ip}' if link.ip else ''}")

    # Credentials file: root:netpulse, 640. json.dumps output is a valid TOML basic string.
    content = (f"username = {json.dumps(username)}\n"
               f"password = {json.dumps(password)}\n"
               f"cert_sha256 = {json.dumps(fp)}\n")
    gid = grp.getgrnam("netpulse").gr_gid
    tmp = creds_path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
    with os.fdopen(fd, "w") as f:
        f.write(content)
    os.chown(tmp, 0, gid)
    os.chmod(tmp, 0o640)
    os.replace(tmp, creds_path)
    print(f"\n✅ Saved credentials to {creds_path} (readable only by root and NetPulse)")

    with open(CONFIG) as f:
        text = f.read()
    write_preserving(CONFIG, set_keys(text, "router", {"enabled": "true"}))
    print(f"✅ Enabled router checks in {CONFIG}")

    subprocess.run(["systemctl", "restart", "netpulse"], check=False)
    time.sleep(3)
    state = subprocess.run(["systemctl", "is-active", "netpulse"], capture_output=True, text=True).stdout.strip()
    print(f"NetPulse restarted: {state}")
    print("Tip: tap 🛠 Using Omada in Telegram before editing the router, so NetPulse doesn't log you out.")


if __name__ == "__main__":
    main()
