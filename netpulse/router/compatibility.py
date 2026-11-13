"""Exact-build trial eligibility, distinct from production feature acceptance.

2.4.10 is a candidate for isolated operator trials, not an enforcement guarantee.
Do not extend ACL normalization without authenticated evidence from that build.
"""
from __future__ import annotations

from copy import deepcopy
import ipaddress
import re

from netpulse.router.control import ROUTE_FIELDS
from netpulse.router.er605 import ACL_PILOT_NAME_RE, ACL_PILOT_STATES

LEGACY_FIRMWARE = "2.3.3 Build 20251029 Rel.18054"
CANDIDATE_FIRMWARE = "2.4.10 Build 20260916 Rel.63334"


class CompatibilityError(ValueError):
    pass


def capabilities(firmware: str) -> dict:
    """No caller can turn trial eligibility into production acceptance."""
    return {"pause": firmware == LEGACY_FIRMWARE, "only_wan": False,
            "group_trial": False, "candidate_trial": firmware == CANDIDATE_FIRMWARE}


def route_shape(row):
    if (not isinstance(row, dict) or set(row) - set(ROUTE_FIELDS)
            or row.get("mode") not in {"Priority", "Only"}
            or row.get("interfaces") not in {"WAN1", "WAN2"}
            or row.get("state") != "on" or row.get("service_type") != "ALL"
            or row.get("timeobj") != "Any" or row.get("dst_ipgroup") != "IPGROUP_ANY"):
        raise CompatibilityError("Unreviewed policy-route shape; no trial write is allowed.")
    return {k: deepcopy(v) for k, v in row.items() if k != "index"}


def build_plan(snapshot: dict, approval: dict, *, acl_name: str | None = None) -> dict:
    """Prepare one approved endpoint operation without mutating any router state.

    Snapshot includes only the endpoint-relevant lists plus complete ACL/routes.
    Model/hardware strings are intentionally narrow; unexpected formats need review.
    Existing prerequisite objects are required; the trial creates none implicitly.
    """
    if not isinstance(approval, dict) or set(approval) != {"confirmed", "mac", "ip", "action", "wan"}:
        raise CompatibilityError("An exact reviewed one-device approval is required.")
    if approval["confirmed"] is not True:
        raise CompatibilityError("Explicit owner approval is required.")
    mac, ip = approval["mac"], approval["ip"]
    if not isinstance(mac, str) or not re.fullmatch(r"[0-9A-F]{2}(?:-[0-9A-F]{2}){5}", mac):
        raise CompatibilityError("Invalid approved device identity.")
    try:
        address = ipaddress.IPv4Address(ip)
        if not address.is_private or address.is_loopback or address.is_link_local or str(address) != ip:
            raise ValueError
    except (ValueError, TypeError):
        raise CompatibilityError("An exact private IPv4 endpoint is required.") from None
    if approval["action"] not in {"pause", "only_wan"} or approval["wan"] not in {"WAN1", "WAN2"}:
        raise CompatibilityError("Only one reviewed pause or Only-WAN trial is supported.")
    if (snapshot.get("model") != "ER605" or snapshot.get("hardware_version") not in {"2.30", "v2.30", "ER605 v2.30"}
            or snapshot.get("firmware_version") != CANDIDATE_FIRMWARE
            or type(snapshot.get("uptime")) is not int or snapshot["uptime"] < 300
            or snapshot.get("ready") is not True or ip in snapshot.get("protected_ips", [])
            or mac in snapshot.get("protected_macs", [])):
        raise CompatibilityError("Exact hardware/build, settled readiness and an unprotected endpoint are required.")
    if (not isinstance(snapshot.get('router_host'), str) or not snapshot['router_host']
            or not re.fullmatch(r'[A-Fa-f0-9]{64}', str(snapshot.get('cert_sha256', '')))):
        raise CompatibilityError("Exact router host and TLS pin are required for recovery identity.")
    required = ("clients", "reservations", "ipscopes", "ipgroups", "routes", "acls")
    if any(not isinstance(snapshot.get(k), list) or len(snapshot[k]) > 512
           or any(not isinstance(row, dict) for row in snapshot[k]) for k in required):
        raise CompatibilityError("Complete bounded router collections are required.")
    if snapshot["acls"]:
        raise CompatibilityError("The initial compatibility trial requires an empty ACL.")
    clients = [r for r in snapshot["clients"] if r.get("macaddr") == mac or r.get("ipaddr") == ip]
    leases = [r for r in snapshot["reservations"] if r.get("mac") == mac or r.get("ip") == ip]
    if (len(clients) != 1 or clients[0].get("macaddr") != mac or clients[0].get("ipaddr") != ip
            or len(leases) != 1 or leases[0].get("mac") != mac or leases[0].get("ip") != ip
            or leases[0].get("enable") != "on"):
        raise CompatibilityError("Unique matching current lease and enabled reservation are required.")
    if any('oneplus' in str(clients[0].get(k, '')).casefold() for k in ('name', 'hostname', 'manufacturer')):
        raise CompatibilityError("This endpoint is excluded from compatibility trials.")
    suffix = mac.replace("-", "")
    def named(key, name):
        found = [r for r in snapshot[key] if r.get("name") == name]
        if len(found) != 1:
            raise CompatibilityError("A prerequisite object is missing or ambiguous.")
        return found[0]
    scope = named("ipscopes", "NP_I_" + suffix)
    group = named("ipgroups", "NP_G_" + suffix)
    route = named("routes", "NP_R_" + suffix)
    if scope.get("scope") != f"{ip}-{ip}" or group.get("rule_scope") != [scope["name"]]:
        raise CompatibilityError("Prerequisite objects do not match the approved endpoint.")
    if route.get("src_ipgroup") != group["name"]:
        raise CompatibilityError("The route does not select the approved endpoint group.")
    # Any other policy referring to this group creates ambiguous precedence.
    if len([r for r in snapshot["routes"] if r.get("src_ipgroup") == group["name"]]) != 1:
        raise CompatibilityError("Competing source routes require review.")
    route_shape(route)
    if approval["action"] == "pause":
        if route["interfaces"] != approval["wan"]:
            raise CompatibilityError("Pause trial WAN must match the existing endpoint route.")
        if not isinstance(acl_name, str) or not ACL_PILOT_NAME_RE.fullmatch(acl_name):
            raise CompatibilityError("A unique temporary ACL identity is required.")
        change = {"name": acl_name, "policy": "DROP", "service": "ALL", "iptype": "ipv4",
                  "zone": "LAN", "is_src": "ipgroup", "src": group["name"], "is_dst": "ipgroup",
                  "dest": "IPGROUP_ANY", "time": "Any", "states": list(ACL_PILOT_STATES),
                  "position": "", "flag": "1", "user": "1"}
    else:
        change = deepcopy(route)
        change.update(mode="Only", interfaces=approval["wan"])
        if route_shape(change) == route_shape(route):
            raise CompatibilityError("Choose a transition rather than an unchanged route.")
    return {"approval": deepcopy(approval), "before": deepcopy(snapshot), "change": change}


def validate_plan(plan):
    if not isinstance(plan, dict) or set(plan) != {"approval", "before", "change"}:
        raise CompatibilityError("Invalid trial plan.")
    expected = build_plan(plan["before"], plan["approval"], acl_name=plan["change"].get("name"))
    if plan != expected:
        raise CompatibilityError("Trial plan differs from its reviewed operation.")
    return plan
