#!/usr/bin/env python3
"""Read-only discovery of ER605 ACL, firmware-version, and WAN status forms.

This logs into the ER605 once, which can sign out an open Omada browser session.
It never submits a write; it redacts device identities and arbitrary values, showing only
known structural keys, counts for unrecognized keys, conventional interface labels, and a small set
of non-identifying policy, link-state, and WAN-protocol values.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from netpulse.config import load, load_router_credentials  # noqa: E402
from netpulse.router.er605 import ER605Client, RouterError  # noqa: E402


# Guesses are deliberately confined to reads. A successful response identifies
# the real firmware form; no candidate is ever written by this tool.
FORMS = (
    # Confirmed in this firmware's public UI form map (chunk-common), not guessed.
    ("access_ctl", "acl_inner"),
    ("firewall", "mac_filter"),
    ("firewall", "mac_filtering"),
    ("firewall", "macfilter"),
    ("firewall", "macfiltering"),
    ("firewall", "access_control"),
    ("firewall", "acl"),
    ("mac_filter", "mac_filter"),
    ("macfilter", "macfilter"),
    ("interface", "status"),
    ("interface", "status2"),
    # Exact read forms listed by the certificate-pinned firmware UI form map.
    ("system", "getproduct"),
    ("status", "router"),
    ("status", "all"),
    ("firmware", "config"),
)
ACL_FORMS = {
    ("access_ctl", "acl_inner"),
    ("firewall", "mac_filter"),
    ("firewall", "mac_filtering"),
    ("firewall", "macfilter"),
    ("firewall", "macfiltering"),
    ("firewall", "access_control"),
    ("firewall", "acl"),
    ("mac_filter", "mac_filter"),
    ("macfilter", "macfilter"),
}
SAFE_FIELDS = {
    "enable", "enabled", "state", "direction", "policy", "filter_policy", "mode",
    "error_code", "max_rules",
    "version", "firmware", "firmware_version", "firmwarever", "software_version",
    "softwarever", "software_ver", "soft_version", "soft_ver", "softver", "swver",
    "fw_version", "firmware_ver", "hardware_version", "hardware_ver", "hardwarever",
    "hard_ver", "hardver", "hwver", "model", "model_name",
    "product", "product_name", "uptime", "build", "build_date",
}
SAFE_NUMERIC_FIELDS = {"error_code", "max_rules"}
SAFE_NUMERIC_RANGES = {"error_code": (-10000, 10000), "max_rules": (0, 4096)}
WAN_STATUS_VALUES = {
    "t_isup": {"true", "false", "1", "0", "up", "down", "online", "offline",
                "connected", "disconnected"},
    "t_proto": {"pppoe", "dynamic", "static", "dhcp", "pptp", "l2tp"},
    "t_type": {"pppoe", "dynamic", "static", "dhcp", "pptp", "l2tp", "physical"},
    "t_linktype": {"pppoe", "dynamic", "static", "dhcp", "pptp", "l2tp", "physical"},
    "t_linkstatus": {"up", "down", "online", "offline", "connected", "disconnected",
                     "connecting", "unknown"},
    "connection_status": {"up", "down", "online", "offline", "connected", "disconnected",
                          "connecting", "unknown"},
    "connect_status": {"up", "down", "online", "offline", "connected", "disconnected",
                       "connecting", "unknown"},
}
SAFE_KEYS = SAFE_FIELDS | {
    "id", "name", "mac", "macaddr", "mac_address", "ip", "ipaddr", "address",
    "type", "flag", "index", "key", "comment", "service", "protocol", "source",
    "destination", "timeobj", "row_count", "action", "src_type", "dst_type",
    "src_ip", "dst_ip", "src_mac", "dst_mac", "src_ipgroup", "dst_ipgroup",
    "source_ip", "destination_ip", "source_mac", "destination_mac",
    "source_ipgroup", "destination_ipgroup", "src_port", "dst_port", "service_type",
    "t_label", "t_name", "rule", "rules", "entries", "data", "result",
    "t_isup", "t_proto", "t_type", "t_linktype", "t_linkstatus",
    "connection_status", "connect_status",
}
SCHEMA_KEY = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,63}\Z")
SAFE_INTERFACE_LABEL = re.compile(r"(?:WAN(?:[1-3])?|LAN(?:[1-5])?)\Z", re.I)
MAX_SUMMARY_DEPTH = 8
MAX_ACL_RULES = 128
ACL_COLLECTION_KEYS = {"rules", "acl", "acl_list", "acl_rules", "entries", "acl_inner", "result"}
ACL_ROW_FIELDS = {"policy", "zone", "iptype", "is_src", "src", "is_dst", "dest", "service"}


def _acl_rows(value, depth: int = 0):
    """Find one unambiguous ACL row list without returning router-supplied values."""
    if depth >= MAX_SUMMARY_DEPTH:
        return []
    candidates = []
    if isinstance(value, list):
        if value and all(isinstance(row, dict) for row in value):
            if any({str(key).lower() for key in row} & ACL_ROW_FIELDS for row in value):
                candidates.append(value)
        for row in value:
            if isinstance(row, (dict, list)):
                candidates.extend(_acl_rows(row, depth + 1))
    elif isinstance(value, dict):
        for key, child in value.items():
            if str(key).lower() in ACL_COLLECTION_KEYS and isinstance(child, list):
                if (not child or all(isinstance(row, dict) for row in child)
                        and any({str(field).lower() for field in row} & ACL_ROW_FIELDS for row in child)):
                    candidates.append(child)
            if isinstance(child, (dict, list)):
                candidates.extend(_acl_rows(child, depth + 1))
    # Different possible row collections make the snapshot ambiguous; never pick one by chance.
    unique = {id(rows): rows for rows in candidates}
    return list(unique.values())


def _acl_enum(value, allowed: dict[str, str]) -> str:
    """Map a router value to an explicit safe enum or the generic unknown marker."""
    if not isinstance(value, (str, int)):
        return "unknown"
    return allowed.get(str(value).strip().lower(), "unknown")


def _acl_object_kind(value, any_values: set[str] | None = None) -> str:
    """Classify source/destination references without echoing owner-defined names."""
    if not isinstance(value, str):
        return "unknown"
    normalized = value.strip().upper()
    if any_values and normalized in any_values:
        return "any"
    if re.fullmatch(r"NP_[A-Z0-9_]{1,60}", normalized):
        return "NetPulse-managed"
    return "owner/unknown"


def summarize_acl_order(value) -> dict:
    """Return an identity-redacted ACL order snapshot; this is not an enforcement verdict."""
    rows = _acl_rows(value)
    if len(rows) > 1:
        return {"readable": False, "reason": "ambiguous row collections"}
    if rows:
        acl_rows = rows[0]
    elif (isinstance(value, dict) and str(value.get("error_code")) == "0"
          and isinstance(value.get("result"), dict) and not value["result"]):
        # This exact empty response shape was read from the live acl_inner form with max_rules present.
        acl_rows = []
    else:
        return {"readable": False, "reason": "ACL rows not isolated"}
    if len(acl_rows) > MAX_ACL_RULES:
        return {"readable": False, "reason": "rule count exceeds inspected limit"}

    rules = []
    for position, row in enumerate(acl_rows, 1):
        state_raw = row.get("enable", row.get("enabled", row.get("state")))
        state = _acl_enum(state_raw, {
            "1": "enabled", "on": "enabled", "true": "enabled", "enabled": "enabled",
            "0": "disabled", "off": "disabled", "false": "disabled", "disabled": "disabled",
        })
        source = row.get("src", row.get("source", row.get("src_ipgroup", row.get("source_ipgroup"))))
        destination = row.get("dest", row.get("destination", row.get("dst_ipgroup",
                                row.get("destination_ipgroup"))))
        rules.append({
            "order": position,
            "policy": _acl_enum(row.get("policy"), {"drop": "Block", "accept": "Allow"}),
            "direction": _acl_enum(row.get("zone"), {"lan": "LAN-to-WAN", "wan": "WAN-to-LAN"}),
            "ip_version": _acl_enum(row.get("iptype"), {"ipv4": "IPv4", "ipv6": "IPv6"}),
            "service": "ALL" if isinstance(row.get("service"), str)
                       and row["service"].strip().upper() == "ALL" else "custom/unknown",
            "source": _acl_object_kind(source),
            "destination": _acl_object_kind(destination, {"IPGROUP_ANY", "ANY"}),
            "state": state,
        })
    return {"readable": True, "count": len(rules), "order_source": "ACL read order",
            "priority_note": "TP-Link documents the first ACL row as highest priority.",
            "rules": rules,
            "enforcement_verified": False}


def _safe_status_value(key: str, value):
    """Return only a known enum or boolean-like WAN diagnostic value."""
    allowed = WAN_STATUS_VALUES.get(key)
    if allowed is None or not isinstance(value, (str, int, float, bool, type(None))):
        return None
    text = str(value).strip().lower()
    return text if text in allowed else None


def _safe_interface_label(value):
    """Expose only conventional ER605 port labels, never custom interface names."""
    if not isinstance(value, str):
        return None
    label = value.strip().upper()
    return label if SAFE_INTERFACE_LABEL.fullmatch(label) else None


def _safe_numeric_value(key: str, value):
    """Expose only bounded numeric ACL status fields, never arbitrary strings."""
    if key not in SAFE_NUMERIC_FIELDS or isinstance(value, bool):
        return None
    if isinstance(value, int):
        number = value
    elif isinstance(value, str) and re.fullmatch(r"-?\d{1,5}", value.strip()):
        number = int(value.strip())
    else:
        return None
    low, high = SAFE_NUMERIC_RANGES[key]
    return number if low <= number <= high else None


def summarize(value, key: str = "", _depth: int = 0):
    """Expose nested form shape and field names while redacting all row values and keys."""
    if _depth >= MAX_SUMMARY_DEPTH:
        return "<depth-limit>"
    if isinstance(value, dict):
        result = {str(k): summarize(v, str(k).lower(), _depth + 1)
                  for k, v in value.items() if str(k).lower() in SAFE_KEYS}
        safe_values = {}
        for field, field_value in value.items():
            numeric = _safe_numeric_value(str(field).lower(), field_value)
            if numeric is not None:
                result[str(field)] = numeric
            safe = _safe_status_value(str(field).lower(), field_value)
            if safe is not None:
                safe_values.setdefault(str(field).lower(), set()).add(safe)
        if safe_values:
            result["safe_values"] = {field: sorted(values) for field, values in safe_values.items()}
        # Router forms often wrap their list in an undocumented container such as
        # ``data`` or ``acl_rules``. Inspect nested structure without printing the
        # wrapper key (which could itself be a dynamic device identity).
        collections = [summarize(v, "", _depth + 1) for v in value.values()
                       if isinstance(v, list)]
        objects = [summarize(v, "", _depth + 1) for v in value.values()
                   if isinstance(v, dict)]
        if collections:
            result["nested_collections"] = collections
        if objects:
            result["nested_objects"] = objects
        hidden = sum(1 for k in value if str(k).lower() not in SAFE_KEYS)
        if hidden:
            result["other_field_count"] = hidden
        return result
    if isinstance(value, list):
        # Router/device supplied strings can become object keys in some firmware
        # responses. Never echo an arbitrary key, even if it happens to look like
        # a Python/JSON identifier (for example, a hostname such as ``KitchenTV``).
        # Show only the small vocabulary of known structural fields and count the
        # remaining names so operators still know the form contains more fields.
        fields = {str(k) for row in value if isinstance(row, dict) for k in row
                  if str(k).lower() in SAFE_KEYS and SCHEMA_KEY.fullmatch(str(k))}
        hidden = sum(1 for row in value if isinstance(row, dict)
                     for k in row if str(k).lower() not in SAFE_KEYS
                     or not SCHEMA_KEY.fullmatch(str(k)))
        safe_values = {}
        for row in value:
            if not isinstance(row, dict):
                continue
            for field, field_value in row.items():
                field = str(field).lower()
                if field in SAFE_FIELDS and isinstance(field_value, (str, int, float, bool, type(None))):
                    numeric = _safe_numeric_value(field, field_value)
                    if field not in SAFE_NUMERIC_FIELDS or numeric is not None:
                        safe_values.setdefault(field, set()).add(str(
                            numeric if field in SAFE_NUMERIC_FIELDS else field_value
                        ))
                safe = _safe_status_value(field, field_value)
                if safe is not None:
                    safe_values.setdefault(field, set()).add(safe)
        nested = [summarize(v, "", _depth + 1) for row in value if isinstance(row, dict)
                  for v in row.values() if isinstance(v, (dict, list))]
        result = {"row_count": len(value), "row_fields": sorted(fields),
                  "other_field_count": hidden}
        if safe_values:
            result["safe_values"] = {field: sorted(values) for field, values in safe_values.items()}
        interfaces = []
        for row in value:
            if not isinstance(row, dict):
                continue
            label = _safe_interface_label(row.get("t_label")) or _safe_interface_label(row.get("t_name"))
            if label is None:
                continue
            fields = {field: safe for key, field in (
                ("t_isup", "is_up"), ("t_proto", "protocol"),
                ("t_type", "type"), ("t_linktype", "link_type"),
                ("t_linkstatus", "link_status"), ("connection_status", "connection_status"),
                ("connect_status", "connect_status"),
            ) if (safe := _safe_status_value(key, row.get(key))) is not None}
            interfaces.append({"interface": label, **fields})
        if interfaces:
            result["known_interfaces"] = interfaces
        if nested:
            result["nested_values"] = nested
        return result
    if key in SAFE_NUMERIC_FIELDS:
        numeric = _safe_numeric_value(key, value)
        return numeric if numeric is not None else "<redacted>"
    if key in SAFE_FIELDS and isinstance(value, (str, int, float, bool, type(None))):
        return value
    return "<redacted>"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-c", "--config", default="/etc/netpulse/config.toml",
                        help="NetPulse config path (default: /etc/netpulse/config.toml)")
    args = parser.parse_args()

    try:
        cfg = load(args.config)
        if not cfg.router.enabled:
            print("ER605 monitoring is disabled in this config; nothing queried.")
            return 2
        credentials = load_router_credentials(cfg.router.credentials_file)
        client = ER605Client(cfg.router.host, credentials.username, credentials.password,
                             credentials.cert_sha256)
        acl_found = 0
        with client.session():
            for module, form in FORMS:
                try:
                    result = client.get(module, form)
                except RouterError:
                    print(f"not available: {module}/{form}")
                    continue
                if (module, form) in ACL_FORMS:
                    acl_found += 1
                print(f"READ OK: {module}/{form}: {summarize(result)}")
                if (module, form) == ("access_ctl", "acl_inner"):
                    print(f"  ACL order summary (identifiers redacted): {summarize_acl_order(result)}")
        if not acl_found:
            print("No candidate ACL form responded. No router settings were changed.")
            return 1
        print("Read-only ACL/firmware/WAN status discovery complete. No router settings were changed.")
        return 0
    except (OSError, ValueError, RouterError) as exc:
        print(f"Discovery stopped ({type(exc).__name__}); no router settings were changed.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
