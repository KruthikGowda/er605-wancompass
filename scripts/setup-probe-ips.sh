#!/usr/bin/env bash
# Add the two per-WAN probe addresses to the Pi's Ethernet connection.
#   sudo ./scripts/setup-probe-ips.sh 192.168.0.201 192.168.0.202
# The Pi keeps its normal DHCP address for SSH/dashboard; these are extra.
# Pick addresses OUTSIDE the ER605's DHCP pool so nothing else can get them.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then echo "Run with sudo" >&2; exit 1; fi
if [[ $# -ne 2 ]]; then echo "usage: $0 <wan1-probe-ip> <wan2-probe-ip>" >&2; exit 1; fi

PREFIX=$(ip -4 -o addr show dev eth0 | awk '{print $4}' | head -1 | cut -d/ -f2)
PREFIX=${PREFIX:-24}

for ip in "$1" "$2"; do
    if ping -c 2 -W 1 -q "$ip" >/dev/null 2>&1 && ! ip -4 addr show dev eth0 | grep -q " $ip/"; then
        echo "ERROR: $ip already answers on the network - pick a free address." >&2
        exit 1
    fi
done

CON=$(nmcli -t -f NAME,DEVICE connection show --active | awk -F: '$2=="eth0"{print $1; exit}')
if [[ -z "$CON" ]]; then echo "No active NetworkManager connection on eth0" >&2; exit 1; fi

echo "==> Adding $1/$PREFIX and $2/$PREFIX to '$CON' (DHCP address is kept)"
nmcli connection modify "$CON" +ipv4.addresses "$1/$PREFIX" +ipv4.addresses "$2/$PREFIX"
nmcli device reapply eth0

sleep 2
ip -br -4 addr show dev eth0
echo
echo "Next: add ER605 policy routes (source $1 -> WAN1, source $2 -> WAN2),"
echo "then run ./tools/verify_paths.sh $1 $2"
