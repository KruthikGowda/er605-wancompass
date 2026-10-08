"""Verify the exact manual-route object chain without steering a real device.

Run on the Pi after install:
    sudo python3 tools/router_control_probe.py --run

The probe creates a test address/group and a policy route whose source is an
unused LAN IP and whose state is off. It reads each object back, then deletes
them in reverse order. It refuses to run if the test names/address are in use.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from netpulse.config import load, load_router_credentials  # noqa: E402
from netpulse.router.er605 import ER605Client, RouterError  # noqa: E402

CONFIG = "/etc/netpulse/config.toml"
TEST_IP = "192.168.0.250"  # previously used as an isolated API-test address; outside this router's DHCP pool
IP_NAME = "NP_VERIFY_I"
GROUP_NAME = "NP_VERIFY_G"
ROUTE_NAME = "NP_VERIFY_R"
OBJECTS = (("policy_route", "policy_route", ROUTE_NAME),
           ("ipgroup", "ipgroup_reservation", GROUP_NAME),
           ("ipgroup", "ipscope_reservation", IP_NAME))


def _rows(client: ER605Client, module: str, form: str) -> list[dict]:
    value = client.get(module, form) or []
    return [row for row in value if isinstance(row, dict)] if isinstance(value, list) else []


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", help="perform the temporary disabled-rule probe")
    args = parser.parse_args()
    if not args.run:
        parser.error("This router-writing check is opt-in; pass --run to create and remove temporary NP_VERIFY objects.")
    if os.geteuid() != 0:
        raise SystemExit("Run with sudo: sudo python3 tools/router_control_probe.py --run")

    cfg = load(CONFIG)
    creds = load_router_credentials(cfg.router.credentials_file)
    client = ER605Client(cfg.router.host, creds.username, creds.password, creds.cert_sha256)
    present: set[tuple[str, str, str]] = set()
    problems: list[str] = []
    success = False
    try:
        with client.session() as c:
            all_rows = {("ipgroup", "ipscope_reservation"): _rows(c, "ipgroup", "ipscope_reservation"),
                        ("ipgroup", "ipgroup_reservation"): _rows(c, "ipgroup", "ipgroup_reservation"),
                        ("policy_route", "policy_route"): _rows(c, "policy_route", "policy_route")}
            for module, form, name in OBJECTS:
                if any(row.get("name") == name for row in all_rows[(module, form)]):
                    raise SystemExit(f"Refusing probe: temporary object {name} already exists; inspect it first.")

            address = ipaddress.ip_address(TEST_IP)
            reservations = c.get("dhcps", "reservation") or []
            clients = c.get("dhcps", "client") or []
            if any(str(row.get("ip", row.get("ipaddr", ""))) == TEST_IP
                   for row in list(reservations) + list(clients) if isinstance(row, dict)):
                raise SystemExit(f"Refusing probe: {TEST_IP} is currently reserved or leased.")
            scopes = c.get("ipgroup", "ipscope_list") or []
            lan_scope = next((row.get("scope") for row in scopes if isinstance(row, dict)
                              and row.get("name") == "IP_LAN"), None)
            try:
                lan = ipaddress.ip_network(str(lan_scope), strict=False)
            except ValueError:
                raise SystemExit("Refusing probe: could not determine the ER605 LAN subnet.") from None
            if address not in lan or address in (lan.network_address, lan.broadcast_address):
                raise SystemExit(f"Refusing probe: test address {TEST_IP} is not a usable address in {lan}.")
            for row in all_rows[("ipgroup", "ipscope_reservation")]:
                scope = str(row.get("scope", ""))
                try:
                    start, end = (ipaddress.ip_address(part) for part in scope.split("-", 1))
                except ValueError:
                    continue
                if start <= address <= end:
                    raise SystemExit(f"Refusing probe: {TEST_IP} is already covered by router object {row.get('name')}.")

            ip_rows = all_rows[("ipgroup", "ipscope_reservation")]
            present.add(OBJECTS[2])  # an add may succeed even if its read-back then fails
            c.add_row("ipgroup", "ipscope_reservation", ip_rows, {
                "name": IP_NAME, "type": "range", "flag": "user", "scope": f"{TEST_IP}-{TEST_IP}",
                "scope_start": TEST_IP, "scope_end": TEST_IP, "comment": "NetPulse temporary verification",
            })
            group_rows = _rows(c, "ipgroup", "ipgroup_reservation")
            present.add(OBJECTS[1])
            c.add_row("ipgroup", "ipgroup_reservation", group_rows, {
                "name": GROUP_NAME, "rule_scope": [IP_NAME], "comment": "NetPulse temporary verification",
                "flag": "user",
            })
            groups = _rows(c, "ipgroup", "ipgroup_reservation")
            group = next((row for row in groups if row.get("name") == GROUP_NAME), None)
            if not group or group.get("rule_scope") != [IP_NAME]:
                raise RouterError("populated test-group read-back did not match the address entry")

            routes = _rows(c, "policy_route", "policy_route")
            indices = [int(row["index"]) for row in routes if str(row.get("index", "")).isdigit()]
            route_index = max(indices, default=0) + 1
            if route_index > 64:
                raise RouterError("policy-route table has no available rule index for the disabled test")
            present.add(OBJECTS[0])
            c.add_row("policy_route", "policy_route", routes, {
                "name": ROUTE_NAME, "service_type": "ALL", "src_ipgroup": GROUP_NAME,
                "dst_ipgroup": "IPGROUP_ANY", "interfaces": "WAN1", "timeobj": "Any",
                "mode": "Priority", "comment": "NetPulse temporary verification", "state": "off",
                "index": route_index, "src": "ipgroup", "dst": "ipgroup",
            })
            route_rows = _rows(c, "policy_route", "policy_route")
            route = next((row for row in route_rows if row.get("name") == ROUTE_NAME), None)
            if (not route or route.get("src_ipgroup") != GROUP_NAME or route.get("dst_ipgroup") != "IPGROUP_ANY"
                    or route.get("interfaces") != "WAN1" or route.get("mode") != "Priority"
                    or route.get("state") != "off"):
                raise RouterError("disabled test-route read-back did not match the requested fields")
            success = True
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001
        problems.append(type(exc).__name__ + ": " + str(exc))
    finally:
        if present:
            try:
                with client.session() as c:
                    for module, form, name in OBJECTS:
                        try:
                            if any(row.get("name") == name for row in _rows(c, module, form)):
                                c.delete_row(module, form, name)
                        except Exception as exc:  # noqa: BLE001
                            problems.append(f"cleanup {name}: {type(exc).__name__}")
                            # Preserve dependencies if a route or group could not be removed.
                            break
            except Exception as exc:  # noqa: BLE001
                problems.append(f"cleanup session: {type(exc).__name__}")

    if problems:
        raise SystemExit("Probe did not finish cleanly:\n  " + "\n  ".join(problems)
                         + "\nInspect only the NP_VERIFY_* objects before another attempt.")
    if success:
        print("PASS: populated IP group and disabled Priority route read back exactly; all NP_VERIFY_* objects were removed.")
    else:
        raise SystemExit("Probe failed; no success was reported.")


if __name__ == "__main__":
    main()
