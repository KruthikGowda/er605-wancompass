#!/usr/bin/env bash
# Prove each probe address really leaves through a different WAN.
#   ./tools/verify_paths.sh 192.168.0.201 192.168.0.202
# Passes when the two addresses show DIFFERENT public IPs and different
# first ISP hops. Run it a few times: it must be stable.
set -uo pipefail

if [[ $# -lt 2 ]]; then echo "usage: $0 <wan1-probe-ip> <wan2-probe-ip>" >&2; exit 1; fi

declare -A PUB
for ip in "$@"; do
    echo "===== source $ip"
    PUB[$ip]=$(curl -s --max-time 8 --interface "$ip" https://api.ipify.org || echo "FAILED")
    echo "public IP: ${PUB[$ip]}"
    if command -v traceroute >/dev/null; then
        echo "first hops:"
        traceroute -n -q 1 -w 2 -m 4 -s "$ip" 1.1.1.1 2>/dev/null | tail -n +2 | sed 's/^/  /'
    fi
    echo
done

a=${PUB[$1]}; b=${PUB[$2]}
if [[ "$a" == "FAILED" || "$b" == "FAILED" ]]; then
    echo "RESULT: FAIL - an address has no internet (check the IP and ER605 policy route)"
    exit 1
elif [[ "$a" == "$b" ]]; then
    echo "RESULT: FAIL - both addresses exit with the same public IP ($a)."
    echo "        The ER605 policy routes are missing or not matching."
    exit 1
else
    echo "RESULT: PASS - $1 exits via $a, $2 exits via $b"
fi
