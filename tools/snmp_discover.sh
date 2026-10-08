#!/usr/bin/env bash
# Discover ER605 WAN interface rows and read-only SNMP counter availability.
# Run on the Pi after enabling SNMP read access and restricting Get Trusted Host to the Pi.
set -euo pipefail

TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=tools/lib/snmp_community.sh
source "$TOOLS_DIR/lib/snmp_community.sh"
trap 'snmp_community_cleanup' EXIT

if ! command -v snmpwalk >/dev/null 2>&1; then
    echo "snmpwalk is missing. Install it with: sudo apt install snmp" >&2
    exit 2
fi

read -r -p "ER605 LAN address [192.168.0.1]: " ROUTER_IP
ROUTER_IP=${ROUTER_IP:-192.168.0.1}
if [[ ! $ROUTER_IP =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
    echo "Enter the router's IPv4 LAN address." >&2
    exit 2
fi
IFS=. read -r -a OCTETS <<< "$ROUTER_IP"
for OCTET in "${OCTETS[@]}"; do
    if ((10#$OCTET > 255)); then
        echo "Enter a valid IPv4 LAN address." >&2
        exit 2
    fi
done

snmp_community_setup

FAILED=0
while IFS="|" read -r LABEL OID; do
    [[ -z $LABEL ]] && continue
    echo
    echo "=== $LABEL ($OID) ==="
    if ! snmp_community_walk -t 2 -r 1 -On "$ROUTER_IP" "$OID"; then
        echo "Walk failed for $LABEL; check SNMP enablement, community, trusted host, and OID." >&2
        FAILED=1
    fi
done <<'OIDS'
Interface descriptions|.1.3.6.1.2.1.2.2.1.2
Interface names|.1.3.6.1.2.1.31.1.1.1.1
Link operational status|.1.3.6.1.2.1.2.2.1.8
64-bit received octets|.1.3.6.1.2.1.31.1.1.1.6
64-bit transmitted octets|.1.3.6.1.2.1.31.1.1.1.10
32-bit received octets fallback|.1.3.6.1.2.1.2.2.1.10
32-bit transmitted octets fallback|.1.3.6.1.2.1.2.2.1.16
OIDS

echo
echo "Discovery complete. Match WAN rows to the ER605 status page; do not assume index 19 or 20."
echo "SNMPv2c is unencrypted. This script only performs reads and does not change router settings."
exit "$FAILED"
