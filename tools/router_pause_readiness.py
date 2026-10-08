#!/usr/bin/env python3
"""Read-only endpoint and ACL-order precheck for a proposed ER605 ACL test.

Run on the Pi with sudo after connecting the expendable endpoint to the LAN and reserving its
lease:
    sudo python3 tools/router_pause_readiness.py "Test device name or MAC"

Prints pass/fail checks only. It never prints the supplied address, device identity, or router data,
and never changes the ER605. A pass confirms one matching reserved lease, a valid LAN scope, that
the candidate is not a Pi/router address, and a readable empty ACL snapshot. It does not prove
packet enforcement, both WAN paths, or IPv6 behavior.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from netpulse.config import load, load_router_credentials  # noqa: E402
from netpulse.router.er605 import ER605Client, RouterError  # noqa: E402
from tools.router_firewall_discover import summarize_acl_order  # noqa: E402

CONFIG = "/etc/netpulse/config.toml"
MAC_RE = re.compile(r"[0-9A-F]{2}(?:[:-][0-9A-F]{2}){5}\Z")
PRIVATE_IPV4_NETWORKS = tuple(ipaddress.ip_network(value) for value in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
))


def valid_candidate_ipv4(address: ipaddress.IPv4Address) -> bool:
    """Accept only ordinary RFC1918 unicast client addresses."""
    return (isinstance(address, ipaddress.IPv4Address)
            and any(address in network for network in PRIVATE_IPV4_NETWORKS)
            and not (address.is_loopback or address.is_link_local or address.is_multicast
                     or address.is_reserved or address.is_unspecified))


def pi_ipv4_addresses(ip_output: str) -> list[ipaddress.IPv4Address]:
    """Parse exact local global IPv4 addresses from `ip -j -4 address show`."""
    parsed = json.loads(ip_output)
    if not isinstance(parsed, list):
        raise ValueError("invalid ip address response")
    addresses = set()
    for interface in parsed:
        if not isinstance(interface, dict) or interface.get("ifname") == "lo":
            continue
        for address in interface.get("addr_info", []):
            if not isinstance(address, dict) or address.get("family") != "inet":
                continue
            if address.get("scope") != "global":
                continue
            try:
                ip = ipaddress.ip_address(address.get("local"))
                prefix = address.get("prefixlen")
                if isinstance(ip, ipaddress.IPv4Address) and isinstance(prefix, int):
                    addresses.add(ip)
            except (ValueError, TypeError):
                continue
    return sorted(addresses, key=int)


def pi_ipv4_networks(ip_output: str) -> list[ipaddress.IPv4Network]:
    """Compatibility helper returning global Pi prefixes."""
    parsed = json.loads(ip_output)
    if not isinstance(parsed, list):
        raise ValueError("invalid ip address response")
    networks = set()
    for interface in parsed:
        if not isinstance(interface, dict) or interface.get("ifname") == "lo":
            continue
        for item in interface.get("addr_info", []):
            if isinstance(item, dict) and item.get("family") == "inet" and item.get("scope") == "global":
                try:
                    ip, prefix = ipaddress.ip_address(item.get("local")), item.get("prefixlen")
                    if isinstance(ip, ipaddress.IPv4Address) and isinstance(prefix, int):
                        networks.add(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))
                except (TypeError, ValueError):
                    pass
    return sorted(networks, key=lambda network: (int(network.network_address), network.prefixlen))


def resolve_candidate_ip(selector: str, clients) -> str:
    """Resolve one exact leased IP, MAC, or client name without returning device details."""
    selector = str(selector or "").strip()
    if not selector:
        raise ValueError("candidate selector is empty")
    try:
        candidate = ipaddress.ip_address(selector)
    except ValueError:
        candidate = None
    if candidate is not None:
        if not isinstance(candidate, ipaddress.IPv4Address):
            raise ValueError("candidate must be a private unicast IPv4 address")
        if not valid_candidate_ipv4(candidate):
            raise ValueError("candidate must be a private unicast IPv4 address")
        return str(candidate)

    normalized_mac = selector.upper().replace(":", "-")
    if MAC_RE.fullmatch(selector.upper()):
        matches = [row for row in clients if isinstance(row, dict)
                   and str(row.get("macaddr", row.get("mac", ""))).upper().replace(":", "-")
                   == normalized_mac] if isinstance(clients, list) else []
    else:
        normalized_name = selector.casefold()
        matches = [row for row in clients if isinstance(row, dict)
                   and any(str(row.get(field, "")).strip().casefold() == normalized_name
                           for field in ("name", "hostname"))] if isinstance(clients, list) else []
    if len(matches) != 1:
        raise ValueError("candidate must match exactly one current ER605 lease")
    raw_ip = matches[0].get("ipaddr", matches[0].get("ip", ""))
    try:
        address = ipaddress.ip_address(str(raw_ip))
    except ValueError as exc:
        raise ValueError("candidate lease has no valid IPv4 address") from exc
    if not isinstance(address, ipaddress.IPv4Address) or not valid_candidate_ipv4(address):
        raise ValueError("candidate must be a private unicast IPv4 address")
    return str(address)


def evaluate_candidate(candidate_ip: str, lan_scopes, clients, reservations,
                       pi_networks=None, acl_snapshot=None, *, pi_addresses=None,
                       router_address=None) -> dict:
    """Evaluate lease, reservation, local-address, LAN-scope and ACL facts only."""
    candidate = ipaddress.ip_address(candidate_ip)
    if not isinstance(candidate, ipaddress.IPv4Address):
        raise ValueError("candidate must be an IPv4 address")
    if not valid_candidate_ipv4(candidate):
        raise ValueError("candidate must be a private unicast IPv4 address")

    lan_rows = [item for item in lan_scopes if isinstance(item, dict) and item.get("name") == "IP_LAN"] \
        if isinstance(lan_scopes, list) else []
    lan_network = None
    if len(lan_rows) == 1:
        try:
            net = ipaddress.ip_network(str(lan_rows[0].get("scope")), strict=False)
            if (isinstance(net, ipaddress.IPv4Network) and net.prefixlen <= 30
                    and any(net.subnet_of(private) for private in PRIVATE_IPV4_NETWORKS)):
                lan_network = net
        except (TypeError, ValueError):
            pass

    client_rows = [row for row in clients if isinstance(row, dict)
                   and str(row.get("ipaddr", row.get("ip", ""))) == str(candidate)] \
        if isinstance(clients, list) else []
    lease_confirmed = len(client_rows) == 1
    mac = ""
    if lease_confirmed:
        raw_mac = str(client_rows[0].get("macaddr", client_rows[0].get("mac", ""))).upper().replace(":", "-")
        mac = raw_mac if MAC_RE.fullmatch(raw_mac) else ""
        lease_confirmed = bool(mac)

    all_client_rows = clients if isinstance(clients, list) else []
    same_mac_clients = [row for row in all_client_rows if isinstance(row, dict)
                        and str(row.get("macaddr", row.get("mac", ""))).upper().replace(":", "-") == mac]
    lease_confirmed = lease_confirmed and len(same_mac_clients) == 1
    reservation_rows = [row for row in reservations if isinstance(row, dict)
                        and str(row.get("ip", row.get("ipaddr", ""))) == str(candidate)
                        and str(row.get("mac", row.get("macaddr", ""))).upper().replace(":", "-") == mac
                        and str(row.get("enable", "1")).strip().lower() not in ("0", "false", "off")] \
        if isinstance(reservations, list) and mac else []
    same_ip_reservations = [row for row in reservations if isinstance(row, dict)
                            and str(row.get("ip", row.get("ipaddr", ""))) == str(candidate)] \
        if isinstance(reservations, list) else []
    same_mac_reservations = [row for row in reservations if isinstance(row, dict)
                             and str(row.get("mac", row.get("macaddr", ""))).upper().replace(":", "-") == mac
                             and str(row.get("enable", "1")).strip().lower() not in ("0", "false", "off")] \
        if isinstance(reservations, list) and mac else []

    # `pi_addresses` is exact-address evidence from `ip -j`; a subnet list is not
    # sufficient to exclude a candidate because same-LAN endpoints are expected.
    if pi_addresses is None:
        pi_addresses = []
    exact_pi_evidence = False
    exact_pi = set()
    for address in pi_addresses:
        try:
            parsed = ipaddress.ip_address(address)
            if isinstance(parsed, ipaddress.IPv4Address):
                exact_pi.add(parsed)
                exact_pi_evidence = True
        except (TypeError, ValueError):
            continue
    try:
        router_ip = ipaddress.ip_address(router_address) if router_address is not None else None
    except ValueError:
        router_ip = None
    router_valid = isinstance(router_ip, ipaddress.IPv4Address)
    acl = summarize_acl_order(acl_snapshot)
    acl_empty = bool(acl.get("readable") and acl.get("count") == 0)
    acl_rules = acl.get("rules", []) if acl.get("readable") else []
    address_valid = bool(lan_network is not None and candidate in lan_network
                         and candidate not in (lan_network.network_address, lan_network.broadcast_address)
                         and candidate not in exact_pi and exact_pi_evidence
                         and router_valid and candidate != router_ip)
    reservation_confirmed = (len(reservation_rows) == 1 and len(same_ip_reservations) == 1
                             and len(same_mac_reservations) == 1)
    subnet_precheck = bool(lease_confirmed and reservation_confirmed and address_valid)
    return {
        "lease_confirmed": lease_confirmed,
        "reservation_confirmed": reservation_confirmed,
        "within_er605_lan": None if lan_network is None else candidate in lan_network,
        "not_pi_address": None if not exact_pi_evidence else candidate not in exact_pi,
        "not_router_address": None if not router_valid else candidate != router_ip,
        "subnet_precheck": subnet_precheck,
        "acl_readable": bool(acl.get("readable")),
        "acl_rule_count": acl.get("count") if acl.get("readable") else None,
        "acl_rules": acl_rules,
        "acl_precheck": acl_empty,
        "control_precheck": bool(subnet_precheck and acl_empty),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("device", help="exact ER605 client name or MAC, or its current IPv4 address (never printed)")
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("Run with sudo on the Pi so NetPulse can read its protected router configuration.")
    try:
        pi_output = subprocess.run(["ip", "-j", "-4", "address", "show"], check=True,
                                   capture_output=True, text=True, timeout=5).stdout
        pi_addresses = pi_ipv4_addresses(pi_output)
        if not pi_addresses:
            raise ValueError("no global Pi IPv4 addresses found")
        cfg = load(CONFIG)
        if not cfg.router.enabled:
            raise ValueError("ER605 monitoring is disabled in NetPulse configuration")
        credentials = load_router_credentials(cfg.router.credentials_file)
        client = ER605Client(cfg.router.host, credentials.username, credentials.password,
                             credentials.cert_sha256)
        with client.session() as router:
            lan_scopes = router.get("ipgroup", "ipscope_list")
            clients = router.get("dhcps", "client")
            reservations = router.get("dhcps", "reservation")
            acl_snapshot = router.get_response("access_ctl", "acl_inner")
        candidate_ip = resolve_candidate_ip(args.device, clients)
        result = evaluate_candidate(candidate_ip, lan_scopes, clients, reservations,
                                    acl_snapshot=acl_snapshot, pi_addresses=pi_addresses,
                                    router_address=cfg.router.host)
    except (OSError, ValueError, RouterError, subprocess.SubprocessError) as exc:
        print(f"Precheck unavailable ({type(exc).__name__}); no router settings were changed.", file=sys.stderr)
        return 2

    print(f"Candidate appears exactly once in the ER605 lease list: {'yes' if result['lease_confirmed'] else 'no'}")
    print(f"Matching enabled DHCP reservation: {'yes' if result['reservation_confirmed'] else 'no'}")
    print(f"Within ER605 primary LAN subnet: {result['within_er605_lan'] if result['within_er605_lan'] is not None else 'unknown'}")
    print(f"Not a Pi IPv4 address: {result['not_pi_address'] if result['not_pi_address'] is not None else 'unknown'}")
    print(f"Not the router management address: {result['not_router_address'] if result['not_router_address'] is not None else 'unknown'}")
    print(f"LAN candidate precheck: {'PASS' if result['subnet_precheck'] else 'NOT READY'}")
    if result["acl_precheck"]:
        acl_status = "PASS (readable and empty at the time of this check)"
    elif result["acl_readable"]:
        acl_status = (f"NOT READY ({result['acl_rule_count']} existing rule(s); review order and effects)")
    else:
        acl_status = "NOT READY (current ACL list could not be safely interpreted)"
    print(f"Current ACL order precheck: {acl_status}")
    for rule in result["acl_rules"]:
        print(f"  ACL row {rule['order']}: {rule['policy']} | {rule['direction']} | "
              f"{rule['ip_version']} | {rule['service']} | {rule['source']} to "
              f"{rule['destination']} | {rule['state']}")
    if result["control_precheck"]:
        print("Read-only candidate/ACL precheck: PASS (packet enforcement UNVERIFIED)")
    else:
        print("Read-only candidate/ACL precheck: NOT READY")
    print("PASS confirms one matching reserved lease on the valid primary LAN scope, exact Pi/router "
          "address checks, and a readable empty ACL snapshot. It does not prove packet enforcement, "
          "both WAN paths, or IPv6 behavior. No router settings were changed.")
    return 0 if result["control_precheck"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
