"""Verify ER605 DHCP reservation add/read/delete with one temporary dummy MAC.

Run on the Pi: sudo python3 tools/router_reservation_probe.py --run
Uses only 192.168.0.250, after confirming it is inside the LAN, outside the
configured DHCP pool, and absent from current leases and reservations. No client
uses the dummy MAC; IP-MAC binding is explicitly disabled.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from netpulse.config import load, load_router_credentials  # noqa: E402
from netpulse.router.er605 import ER605Client, RouterError  # noqa: E402

CONFIG = "/etc/netpulse/config.toml"
TEST_IP = "192.168.0.250"
TEST_MAC = "02-50-55-4E-50-01"
NOTE = "NetPulse temporary API verification"


def rows(client, module, form):
    value = client.get(module, form) or []
    return [x for x in value if isinstance(x, dict)] if isinstance(value, list) else []


def matches(items):
    return [x for x in items if str(x.get("mac", x.get("macaddr", ""))).upper() == TEST_MAC
            or str(x.get("note", "")) == NOTE]


def delete_exact(client):
    items = rows(client, "dhcps", "reservation")
    found = matches(items)
    if not found:
        return
    if len(found) != 1 or str(found[0].get("ip", "")) != TEST_IP:
        raise RouterError("temporary reservation became ambiguous; refusing deletion")
    index = items.index(found[0])
    path = f"/cgi-bin/luci/;stok={client._stok}/admin/dhcps?form=reservation"
    # DHCP reservation rows expose a stable numeric id; this form's UI key is
    # keyed to that id (unlike the IP-group forms, where the list position was
    # the key). Keep index as the just-read position and derive key from id.
    row_id = str(found[0].get("id", ""))
    if not row_id.isdigit():
        raise RouterError("temporary reservation has no numeric UI row id; refusing deletion")
    result = client._post(path, {"data": json.dumps({"method": "delete", "params": {
        "index": str(index), "key": row_id}})})
    if str(result.get("error_code")) != "0":
        raise RouterError(f"reservation delete error {result.get('error_code')}")
    if matches(rows(client, "dhcps", "reservation")):
        raise RouterError("temporary reservation remained after deletion")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", help="create, verify, and delete the temporary reservation")
    parser.add_argument("--cleanup-known-test", action="store_true",
                        help="remove only the exact disabled NetPulse placeholder previously found at .250")
    args = parser.parse_args()
    if args.cleanup_known_test:
        if os.geteuid() != 0:
            raise SystemExit("Run with sudo.")
        cfg = load(CONFIG)
        creds = load_router_credentials(cfg.router.credentials_file)
        client = ER605Client(cfg.router.host, creds.username, creds.password, creds.cert_sha256)
        with client.session() as c:
            found = matches(rows(c, "dhcps", "reservation"))
            if (len(found) != 1 or str(found[0].get("ip")) != TEST_IP
                    or str(found[0].get("enable", "")).lower() not in ("0", "off", "false")):
                raise SystemExit("Refusing: the exact disabled temporary row was not found uniquely.")
            delete_exact(c)
        print("PASS: disabled temporary reservation removed and read-back verified.")
        return
    if not args.run:
        parser.error("pass --run to perform this bounded router API verification")
    if os.geteuid() != 0:
        raise SystemExit("Run with sudo.")
    cfg = load(CONFIG)
    creds = load_router_credentials(cfg.router.credentials_file)
    client = ER605Client(cfg.router.host, creds.username, creds.password, creds.cert_sha256)
    success = False
    add_started = False
    cleanup_error = None
    try:
        with client.session() as c:
            current = rows(c, "dhcps", "reservation")
            leases = rows(c, "dhcps", "client")
            lan_rows = rows(c, "ipgroup", "ipscope_list")
            lan_scope = next((r.get("scope") for r in lan_rows if r.get("name") == "IP_LAN"), None)
            pool = c.get("dhcps", "lan")
            if isinstance(pool, list):
                pool = pool[0] if len(pool) == 1 else None
            if not isinstance(pool, dict):
                raise RouterError("cannot read DHCP server settings; no write attempted")
            try:
                address = ipaddress.ip_address(TEST_IP)
                network = ipaddress.ip_network(str(lan_scope), strict=False)
                start, end = ipaddress.ip_address(pool["ipaddr_start"]), ipaddress.ip_address(pool["ipaddr_end"])
            except (KeyError, ValueError, TypeError):
                raise RouterError("cannot validate LAN and DHCP pool; no write attempted") from None
            if address not in network or address in (network.network_address, network.broadcast_address):
                raise RouterError(f"{TEST_IP} is not a usable address in {network}")
            if start <= address <= end:
                raise RouterError(f"{TEST_IP} is inside DHCP pool {start}–{end}; no write attempted")
            conflicts = [r for r in current + leases if str(r.get("ip", r.get("ipaddr", ""))) == TEST_IP
                         or str(r.get("mac", r.get("macaddr", ""))).upper() == TEST_MAC
                         or str(r.get("note", "")) == NOTE]
            if conflicts:
                print("Reservation list with positions (read-only): " + json.dumps(
                    [{"position": i, "row": row} for i, row in enumerate(current)], sort_keys=True))
                print("Conflicting reservation/lease rows (read-only): " + json.dumps(conflicts, sort_keys=True))
                raise RouterError("dummy MAC or test IP is already present; no write attempted")
            print(f"Verified test IP {TEST_IP} is in {network}, outside DHCP pool {start}–{end}, and unused.")
            index = len(current)
            path = f"/cgi-bin/luci/;stok={c._stok}/admin/dhcps?form=reservation"
            payload = {"method": "add", "params": {"index": index, "key": f"key-{index}", "old": "add",
                "new": {"ip": TEST_IP, "mac": TEST_MAC, "note": NOTE, "enable": "on",
                        "bind": "0", "ip_bind": "on", "interface": "LAN1"}}}
            add_started = True
            result = c._post(path, {"data": json.dumps(payload)})
            if str(result.get("error_code")) != "0":
                raise RouterError(f"reservation add error {result.get('error_code')}")
            readback = matches(rows(c, "dhcps", "reservation"))
            if len(readback) != 1:
                raise RouterError("reservation add did not produce exactly one identifiable read-back")
            row = readback[0]
            if (str(row.get("ip")) != TEST_IP or str(row.get("mac", "")).upper() != TEST_MAC
                    or str(row.get("enable", "1")).lower() not in ("1", "true", "on")
                    or str(row.get("bind", "0")).lower() not in ("0", "false", "off", "")):
                print("Reservation read-back: " + json.dumps(row, sort_keys=True))
                raise RouterError("reservation read-back differs from request or binding is enabled")
            print("Read-back verified: enabled DHCP reservation; IP-MAC binding remains off.")
            success = True
    except Exception as exc:  # noqa: BLE001
        print(f"Probe error: {type(exc).__name__}: {exc}")
    finally:
        if add_started:
            try:
                with client.session() as c:
                    delete_exact(c)
            except Exception as exc:  # noqa: BLE001
                cleanup_error = f"{type(exc).__name__}: {exc}"
    if cleanup_error:
        raise SystemExit("CRITICAL: temporary reservation cleanup failed; inspect router DHCP reservations for "
                         f"MAC {TEST_MAC}, IP {TEST_IP}. Detail: {cleanup_error}")
    if not success:
        raise SystemExit("Probe failed; cleanup verified.")
    print("PASS: temporary reservation was removed and removal read-back was verified.")


if __name__ == "__main__":
    main()
