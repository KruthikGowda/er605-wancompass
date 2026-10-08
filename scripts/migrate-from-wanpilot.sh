#!/usr/bin/env bash
# One-time migration of a WAN Pilot install to NetPulse. Run from the repo root:
#   sudo ./scripts/migrate-from-wanpilot.sh
# Keeps /etc/wanpilot and /var/lib/wanpilot untouched as a backup.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then echo "Run with sudo" >&2; exit 1; fi

echo "==> Stop old service"
if systemctl list-unit-files wanpilot.service &>/dev/null; then
    systemctl disable --now wanpilot.service 2>/dev/null || true
    rm -f /etc/systemd/system/wanpilot.service
    systemctl daemon-reload
fi

echo "==> Service user 'netpulse'"
id netpulse &>/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin netpulse

echo "==> Config /etc/wanpilot -> /etc/netpulse"
install -d -m 750 -o root -g netpulse /etc/netpulse
if [[ -f /etc/wanpilot/config.toml && ! -f /etc/netpulse/config.toml ]]; then
    sed 's#/var/lib/wanpilot/wanpilot.db#/var/lib/netpulse/netpulse.db#' /etc/wanpilot/config.toml > /etc/netpulse/config.toml
    chown root:netpulse /etc/netpulse/config.toml
    chmod 640 /etc/netpulse/config.toml
    echo "    copied (db_path updated)"
fi

echo "==> Data /var/lib/wanpilot -> /var/lib/netpulse"
install -d -m 750 -o netpulse -g netpulse /var/lib/netpulse
if [[ -f /var/lib/wanpilot/wanpilot.db && ! -f /var/lib/netpulse/netpulse.db ]]; then
    for ext in "" -wal -shm; do
        [[ -f /var/lib/wanpilot/wanpilot.db$ext ]] && cp -p /var/lib/wanpilot/wanpilot.db$ext /var/lib/netpulse/netpulse.db$ext
    done
    chown netpulse:netpulse /var/lib/netpulse/netpulse.db*
    echo "    copied history"
fi

rm -rf /opt/wanpilot
echo "Done. Now run: sudo ./scripts/install.sh"
echo "Old files kept as backup: /etc/wanpilot, /var/lib/wanpilot (remove when happy)."
