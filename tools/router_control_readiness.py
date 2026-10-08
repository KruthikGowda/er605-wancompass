"""Read-only preflight for the manual ER605 route-control pilot.

Run on the Pi with sudo after deploying NetPulse:
    sudo python3 tools/router_control_readiness.py

Prints router model, load-balancing state, and aggregate reservation/route counts only. It
never changes router settings or prints device identities or protected router credentials.
"""

from __future__ import annotations

import ipaddress
import os
import re
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from netpulse.config import load, load_router_credentials  # noqa: E402
from netpulse.router.control import (MAC_RE, ROUTER_SETTLE_SECONDS, _balance_enabled,
                                     _system_boot_id, observed_netpulse_route)  # noqa: E402
from netpulse.router.er605 import ER605Client, RouterError  # noqa: E402
from netpulse.storage import sqlite  # noqa: E402

CONFIG = "/etc/netpulse/config.toml"
NETPULSE_ROUTE = re.compile(r"NP_R_([0-9A-F]{12})\Z")


def _first(row: dict, *keys: str) -> str:
    for key in keys:
        value = row.get(key)
        if value not in (None, ""):
            return str(value)
    return ""


def summarize_netpulse_routes(rows, saved_routes: dict[str, dict]) -> dict | None:
    """Compare only aggregate status; never print device identities or IP addresses."""
    if not isinstance(rows, list):
        return None
    owned_rows = []
    router_macs = set()
    enabled = disabled = priority_enabled = only_enabled = unknown_mode_enabled = 0
    priority_target_unknown = unknown_state = 0
    for row in rows:
        if not isinstance(row, dict):
            continue
        match = NETPULSE_ROUTE.fullmatch(str(row.get("name", "")).upper())
        if not match:
            continue
        owned_rows.append(row)
        compact = match.group(1)
        router_macs.add("-".join(compact[i:i + 2] for i in range(0, 12, 2)))
        state = str(row.get("state", "")).lower()
        if state in ("on", "1", "true", "enabled"):
            enabled += 1
            mode = str(row.get("mode", "")).strip().lower()
            if mode == "priority":
                priority_enabled += 1
                if str(row.get("interfaces", "")).upper() not in ("WAN1", "WAN2"):
                    priority_target_unknown += 1
            elif mode == "only":
                only_enabled += 1
            else:
                unknown_mode_enabled += 1
        elif state in ("off", "0", "false", "disabled"):
            disabled += 1
        else:
            unknown_state += 1

    matched = drift = unknown = 0
    for mac, preference in saved_routes.items():
        normalized = str(mac).upper().replace(":", "-")
        if not MAC_RE.fullmatch(normalized):
            continue
        observed = observed_netpulse_route({"policy_routes": owned_rows}, normalized)["route"]
        expected = preference.get("route", "AUTO") if isinstance(preference, dict) else "AUTO"
        if observed is None:
            unknown += 1
        elif observed == expected:
            matched += 1
        else:
            drift += 1
    saved_macs = {str(mac).upper().replace(":", "-") for mac in saved_routes
                  if MAC_RE.fullmatch(str(mac).upper().replace(":", "-"))}
    return {
        "rules": len(owned_rows), "enabled": enabled, "disabled": disabled,
        "priority_enabled": priority_enabled, "only_enabled": only_enabled,
        "unknown_mode_enabled": unknown_mode_enabled,
        "priority_target_unknown": priority_target_unknown,
        "unknown_state": unknown_state,
        "saved_match": matched, "saved_drift": drift, "saved_unknown": unknown,
        "untracked_rules": len(router_macs - saved_macs),
    }


def assess_native_fallback_prerequisites(balance_enabled: bool,
                                         route_summary: dict | None) -> dict:
    """Check configuration prerequisites only; never claim an end-to-end failover proof."""
    if route_summary is None or balance_enabled is None:
        return {"status": "unavailable", "blockers": ["router state unavailable"]}
    blockers = []
    if balance_enabled is not True:
        blockers.append("load balancing is not confirmed enabled")
    if route_summary["only_enabled"]:
        blockers.append("enabled Only-mode policy rows ignore WAN online detection")
    if route_summary["unknown_mode_enabled"]:
        blockers.append("enabled policy rows have an unknown mode")
    if route_summary["priority_target_unknown"]:
        blockers.append("enabled Priority rows have an unknown WAN target")
    if route_summary["unknown_state"]:
        blockers.append("policy rows have an unknown enabled state")
    if route_summary["saved_drift"] or route_summary["saved_unknown"]:
        blockers.append("saved NetPulse preferences do not all match observed rules")
    if route_summary["untracked_rules"]:
        blockers.append("NetPulse policy rules exist without saved preferences")
    return {"status": "prerequisites_pass" if not blockers else "needs_review",
            "blockers": blockers}


def overdue_route_expiry_count(db_path: str, now: int | None = None,
                               monotonic_now: float | None = None,
                               boot_id: str | None = None) -> int:
    """Return an aggregate only; never expose the affected device identities."""
    return len(sqlite.due_device_routes(db_path, now, monotonic_now, boot_id))


def summarize_group_reservations(groups, reservations) -> list[dict[str, int | str]]:
    """Count group members with exactly one enabled reservation and a unique IPv4 address."""
    if not isinstance(groups, list) or not isinstance(reservations, list):
        return []
    by_mac: dict[str, list[dict]] = {}
    enabled_ips: list[str] = []
    for row in reservations:
        if not isinstance(row, dict):
            continue
        mac = str(row.get("mac", row.get("macaddr", ""))).upper().replace(":", "-")
        if not MAC_RE.fullmatch(mac):
            continue
        by_mac.setdefault(mac, []).append(row)
        if str(row.get("enable", "1")).lower() not in ("0", "false", "off"):
            enabled_ips.append(str(row.get("ip", row.get("ipaddr", "")) or ""))

    result = []
    for group in groups:
        if not isinstance(group, dict):
            continue
        members = group.get("members")
        if not isinstance(members, list):
            continue
        ready = 0
        for value in members:
            mac = str(value).upper().replace(":", "-")
            matches = [row for row in by_mac.get(mac, [])
                       if str(row.get("enable", "1")).lower() not in ("0", "false", "off")]
            if len(matches) != 1:
                continue
            ip = str(matches[0].get("ip", matches[0].get("ipaddr", "")) or "")
            try:
                address = ipaddress.IPv4Address(ip)
            except ipaddress.AddressValueError:
                continue
            if enabled_ips.count(ip) == 1 and address.is_private:
                ready += 1
        result.append({"name": str(group.get("name", "Device group"))[:40],
                       "members": len(members), "reserved": ready,
                       "needs_reservation": len(members) - ready})
    return result


def main() -> None:
    if os.geteuid() != 0:
        raise SystemExit("Run with sudo: sudo python3 tools/router_control_readiness.py")
    cfg = load(CONFIG)
    route_state = sqlite.device_routes(cfg.db_path)
    pinned = [r for r in route_state.values() if r.get("route") in ("WAN1", "WAN2")]
    timed = [r for r in pinned if r.get("expires_at") is not None]
    overdue = overdue_route_expiry_count(
        cfg.db_path, int(time.time()), time.monotonic(), _system_boot_id())
    print(f"NetPulse router monitoring configured: {'yes' if cfg.router.enabled else 'no'}")
    print(f"Manual route controls configured: {'yes' if cfg.router.controls_enabled else 'no (safe default)'}")
    print(f"Local control kill switch active: {'yes' if Path(cfg.router.kill_switch).exists() else 'no'}")
    print(f"Saved NetPulse device WAN preferences (database): {len(pinned)} ({len(timed)} with expiry)")
    print(f"Timed WAN preferences currently overdue: {overdue}")
    if overdue:
        print("A NetPulse service start may return these preferences to Auto after fresh router checks.")

    creds = load_router_credentials(cfg.router.credentials_file)
    client = ER605Client(cfg.router.host, creds.username, creds.password, creds.cert_sha256)
    try:
        with client.session() as router:
            info = router.public_info()
            balance = router.get("balance", "balance_basic")
            reservations = router.get("dhcps", "reservation")
            groups = sqlite.device_groups(cfg.db_path)
            try:
                policy_routes = router.get("policy_route", "policy_route")
            except RouterError:
                policy_routes = None
    except RouterError as exc:
        raise SystemExit(f"Read-only router preflight failed: {exc}") from None

    model = _first(info if isinstance(info, dict) else {}, "model", "model_name", "hardware_version")
    if model:
        print(f"Router: {model}")
    uptime = info.get("uptime") if isinstance(info, dict) else None
    try:
        uptime = int(uptime)
    except (TypeError, ValueError):
        uptime = None
    if uptime is not None:
        print(f"ER605 uptime: {uptime // 60} minutes")
    enabled = _balance_enabled(balance)
    state = "enabled" if enabled is True else "disabled" if enabled is False else "unknown (firmware field unavailable)"
    print(f"ER605 load balancing: {state}")
    route_summary = summarize_netpulse_routes(policy_routes, route_state)
    if route_summary is None:
        print("Live ER605 NetPulse policy-route state: unavailable")
    else:
        print("Live ER605 NetPulse policy routes: "
              f"{route_summary['rules']} total, {route_summary['enabled']} enabled, "
              f"{route_summary['disabled']} disabled; WAN-down behavior: "
              f"{route_summary['priority_enabled']} Priority (router online detection), "
              f"{route_summary['only_enabled']} Only (ignores online detection), "
              f"{route_summary['unknown_mode_enabled']} unknown; saved preference: "
              f"{route_summary['saved_match']} match, {route_summary['saved_drift']} differ, "
              f"{route_summary['saved_unknown']} unknown; "
              f"{route_summary['untracked_rules']} without a saved preference")
    fallback = assess_native_fallback_prerequisites(enabled, route_summary)
    if fallback["status"] == "prerequisites_pass":
        print("Pi-offline NetPulse rule prerequisites: pass; load balancing is enabled and "
              "every enabled NetPulse policy uses a known Priority WAN with matching saved state.")
        print("This checks NetPulse-owned rules only, not proof of client traffic failover; use a WAN-disconnect drill.")
    elif fallback["status"] == "unavailable":
        print("Pi-offline NetPulse rule prerequisites: unavailable; router fallback is not verified.")
    else:
        print("Pi-offline NetPulse rule prerequisites: needs review; " + "; ".join(fallback["blockers"]) + ".")
    if route_summary is not None:
        if route_summary["only_enabled"] or route_summary["unknown_mode_enabled"]:
            print("Review enabled NetPulse route modes before relying on router-native WAN fallback.")
    rows = [r for r in reservations if isinstance(r, dict)] if isinstance(reservations, list) else []
    eligible = [r for r in rows if str(r.get("enable", "1")).lower() not in ("0", "false", "off")]
    print(f"Enabled DHCP reservations: {len(eligible)}")
    for group in summarize_group_reservations(groups, reservations):
        print(f"Group {group['name']}: {group['reserved']}/{group['members']} members have "
              f"one enabled DHCP reservation with a unique IPv4 address; "
              f"{group['needs_reservation']} need attention")
    if enabled is not True:
        print("Route controls must stay disabled until load balancing is confirmed enabled.")
    elif not eligible:
        print("Add a DHCP reservation for one non-critical pilot device before enabling route controls.")
    elif uptime is None:
        print("Route controls stay locked until the router uptime can be read.")
    elif uptime < ROUTER_SETTLE_SECONDS:
        print(f"Route controls stay locked for {ROUTER_SETTLE_SECONDS - uptime} more seconds while the router settles.")


if __name__ == "__main__":
    main()
