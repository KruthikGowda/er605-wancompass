#!/usr/bin/env bash
# Find which ER605 SNMP interface counters move for each source-bound Pi WAN.
# Router operations are reads only; this downloads about 2 MB total from Cloudflare.
set -euo pipefail

TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=tools/lib/snmp_community.sh
source "$TOOLS_DIR/lib/snmp_community.sh"
trap 'snmp_community_cleanup' EXIT

for cmd in snmpwalk curl python3; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "$cmd is missing. Install with: sudo apt install snmp curl python3" >&2
        exit 2
    fi
done

read -r -p "ER605 LAN address [192.168.0.1]: " ROUTER_IP
ROUTER_IP=${ROUTER_IP:-192.168.0.1}
if [[ ! $ROUTER_IP =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
    echo "Enter the router's IPv4 LAN address." >&2
    exit 2
fi

snmp_community_setup

NAME_OID=.1.3.6.1.2.1.31.1.1.1.1
RX_OID=.1.3.6.1.2.1.31.1.1.1.6
TX_OID=.1.3.6.1.2.1.31.1.1.1.10

walk() {
    snmp_community_walk -t 2 -r 1 -On "$ROUTER_IP" "$1"
}

snapshot() {
    local file=$1
    {
        echo NAMES
        walk "$NAME_OID" || return 1
        echo RX
        walk "$RX_OID" || return 1
        echo TX
        walk "$TX_OID" || return 1
    } > "$file"
}

echo "Checking SNMP response from $ROUTER_IP..."
if ! walk .1.3.6.1.2.1.1.1.0 >/dev/null; then
    echo "SNMP check failed. No download was attempted; verify community, SNMP enablement, and trusted host." >&2
    exit 1
fi

report_delta() {
    python3 - "$1" "$2" "$3" <<'PY'
import re
import sys

def read_snapshot(path):
    result = {"NAMES": {}, "RX": {}, "TX": {}}
    section = None
    with open(path, encoding="utf-8") as stream:
        for raw in stream:
            line = raw.strip()
            if line in result:
                section = line
                continue
            match = re.match(r"^(\.\S+)\s+=\s+(.*)$", line)
            if not match or section is None:
                continue
            index = match.group(1).rsplit(".", 1)[-1]
            value = match.group(2)
            if section == "NAMES":
                value = re.sub(r"^STRING:\s*", "", value).strip().strip('"')
                result[section][index] = value
            else:
                counter = re.search(r"Counter64:\s*(\d+)", value)
                if counter:
                    result[section][index] = int(counter.group(1))
    return result

before, after = map(read_snapshot, sys.argv[1:3])
label = sys.argv[3]
changes = []
for index, current_rx in after["RX"].items():
    old_rx = before["RX"].get(index)
    current_tx = after["TX"].get(index)
    old_tx = before["TX"].get(index)
    if None in (old_rx, current_tx, old_tx):
        continue
    if current_rx < old_rx or current_tx < old_tx:
        changes.append((0, index, before["NAMES"].get(index, "?"), "counter reset"))
        continue
    rx_delta, tx_delta = current_rx - old_rx, current_tx - old_tx
    if rx_delta or tx_delta:
        changes.append((max(rx_delta, tx_delta), index, after["NAMES"].get(index, "?"),
                        f"RX +{rx_delta} B, TX +{tx_delta} B"))

print(f"\nCounter changes during the {label} transfer:")
if not changes:
    print("  No 64-bit interface counters changed.")
else:
    for _, index, name, detail in sorted(changes, reverse=True)[:12]:
        print(f"  ifIndex {index:>5}  {name:<28} {detail}")
PY
}

measure_wan() {
    local label=$1 src=$2 before="$NP_SNMP_TMP_DIR/$1-before.txt" after="$NP_SNMP_TMP_DIR/$1-after.txt"
    echo
    echo "=== $label via Pi source $src ==="
    snapshot "$before" || {
        echo "Could not read all interface counters before the transfer; stopping." >&2
        return 1
    }
    curl -4 --interface "$src" --fail --location --silent --show-error --max-time 60 \
        --output /dev/null --write-out 'Downloaded %{size_download} bytes.\n' \
        'https://speed.cloudflare.com/__down?bytes=1000000'
    snapshot "$after" || {
        echo "Could not read all interface counters after the transfer; result is unknown." >&2
        return 1
    }
    report_delta "$before" "$after" "$label"
}

measure_wan WAN1 192.168.0.201
measure_wan WAN2 192.168.0.202

echo
echo "Validation complete. Use the matching rows to confirm WAN attribution; no router settings were changed."
echo "SNMP community is passed to Net-SNMP while queries run; use a dedicated read-only community and trusted-host limit."
