#!/usr/bin/env bash
# Install or upgrade NetPulse on the Pi. Run from the repo root:
#   sudo ./scripts/install.sh
# Safe to re-run: it never overwrites an existing /etc/netpulse/config.toml.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Run with sudo: sudo ./scripts/install.sh" >&2
    exit 1
fi

REPO="$(cd "$(dirname "$0")/.." && pwd)"
# Don't leave root-owned __pycache__ folders in the user's copy of the repo.
export PYTHONDONTWRITEBYTECODE=1

# BEGIN first-install config helpers (kept sourceable for isolated installer tests).
CONFIG_PATH=/etc/netpulse/config.toml
CONFIG_SOURCE="${NETPULSE_CONFIG_SOURCE:-$REPO/config.example.toml}"

select_and_validate_config_source() {
    # Existing installations keep their config and ignore NETPULSE_CONFIG_SOURCE entirely.
    if [[ -f "$CONFIG_PATH" ]]; then
        CONFIG_SOURCE=""
        return 0
    fi
    if [[ ! -f "$CONFIG_SOURCE" ]]; then
        echo "First-install config source is missing or is not a regular file; no install changes were made." >&2
        return 1
    fi
    if ! PYTHONPATH="$REPO" python3 -c 'from netpulse.config import load; import sys; load(sys.argv[1])' \
        "$CONFIG_SOURCE" >/dev/null 2>&1; then
        echo "First-install config source is invalid for this NetPulse version; no install changes were made." >&2
        return 1
    fi
}

install_first_config() {
    if [[ -f "$CONFIG_PATH" ]]; then
        echo "    kept existing config"
        return 0
    fi
    install -m 640 -o root -g netpulse "$CONFIG_SOURCE" "$CONFIG_PATH"
    echo "    created from selected config - review it: sudo nano /etc/netpulse/config.toml"
}
# END first-install config helpers.

python3 -c 'import sys; assert sys.version_info >= (3, 11), "Python 3.11+ required"'

# Regression gate: never install a version that fails its own tests.
# (Live network checks skip themselves here. Emergency override: SKIP_TESTS=1.)
if [[ "${SKIP_TESTS:-0}" != "1" ]]; then
    echo "==> Running tests (about a minute on a Pi 3)"
    if ! (cd "$REPO" && python3 -m unittest discover -s tests -t . >/tmp/netpulse-tests.log 2>&1); then
        tail -n 30 /tmp/netpulse-tests.log >&2
        echo >&2
        echo "Tests FAILED: not installing. Full log: /tmp/netpulse-tests.log" >&2
        exit 1
    fi
    grep -E "^Ran [0-9]+ tests" /tmp/netpulse-tests.log | sed 's/^/    /'
fi

# Validate first-install input before apt, user creation, or changes to installed files.
select_and_validate_config_source

# A service restart also resumes timed route expiry handling. Check before installing files so an
# owner can stop cleanly if one or more pinned devices are already due (or due during this upgrade).
if [[ -f /etc/netpulse/config.toml ]]; then
    echo "==> Checking timed WAN preferences before any install changes"
    ROUTES_AT_RISK=$(PYTHONPATH="$REPO" python3 "$REPO/tools/route_expiry_preflight.py" \
        --config /etc/netpulse/config.toml --window-seconds 900 --count-only)
    if [[ ! "$ROUTES_AT_RISK" =~ ^[0-9]+$ ]]; then
        echo "Could not safely read timed route state; not installing." >&2
        exit 1
    fi
    if (( ROUTES_AT_RISK > 0 )); then
        echo "Warning: $ROUTES_AT_RISK timed WAN preference(s) are due or may expire within 15 minutes."
        echo "Restarting NetPulse can return them to Auto after fresh router checks."
        if [[ ! -t 0 ]]; then
            echo "Install requires an interactive confirmation while timed preferences are near expiry." >&2
            exit 1
        fi
        read -r -p "Continue with the install and service restart? [y/N] " ROUTE_EXPIRY_ANSWER
        if [[ ! "$ROUTE_EXPIRY_ANSWER" =~ ^[Yy]([Ee][Ss])?$ ]]; then
            echo "Install cancelled before changing installed files or restarting NetPulse."
            exit 1
        fi
    fi
fi

echo "==> Tools (traceroute, curl for path verification)"
apt-get install -y --no-install-recommends traceroute curl >/dev/null

echo "==> Service user 'netpulse'"
if ! id netpulse &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin netpulse
fi

echo "==> Code -> /opt/netpulse"
install -d -m 755 /opt/netpulse
rm -rf /opt/netpulse/netpulse
cp -r "$REPO/netpulse" /opt/netpulse/
cp "$REPO/README.md" /opt/netpulse/
install -d -m 755 /opt/netpulse/tools
install -m 644 "$REPO/tools/router_acl_pilot.py" "$REPO/tools/router_firewall_discover.py" /opt/netpulse/tools/
find /opt/netpulse -name __pycache__ -prune -exec rm -rf {} +

echo "==> Config -> $CONFIG_PATH"
install -d -m 750 -o root -g netpulse /etc/netpulse
install_first_config

echo "==> Dashboard password"
AUTH_FILE=$(PYTHONPATH="$REPO" python3 -c 'from netpulse import config; print(config.load("/etc/netpulse/config.toml").web.auth_file)')
if [[ ! -f "$AUTH_FILE" ]]; then
    python3 "$REPO/tools/web_setup.py" --path "$AUTH_FILE"
else
    echo "    existing dashboard password retained"
fi
chown root:netpulse "$AUTH_FILE"

echo "==> Check config"
PYTHONPATH=/opt/netpulse python3 -c 'from netpulse import config; config.load("/etc/netpulse/config.toml"); print("    config OK")'

echo "==> systemd unit"
install -m 644 "$REPO/systemd/netpulse.service" /etc/systemd/system/netpulse.service
install -m 644 "$REPO/systemd/netpulse-acl-recovery.service" /etc/systemd/system/netpulse-acl-recovery.service
systemctl daemon-reload
systemctl enable netpulse.service >/dev/null
systemctl restart netpulse.service

sleep 3
if ! systemctl is-active --quiet netpulse.service; then
    echo "NetPulse did not remain active after restart; installation is incomplete." >&2
    journalctl -u netpulse.service --no-pager --lines=40 >&2 || true
    exit 1
fi
systemctl --no-pager --lines=8 status netpulse.service
# The address the Pi normally uses (not the WAN probe addresses).
IP=$(ip route get 1.1.1.1 | awk '{for (i = 1; i < NF; i++) if ($i == "src") print $(i + 1)}')
echo
echo "Dashboard: http://${IP}:8080/   (or http://$(hostname).local:8080/)"
echo "Dashboard login: username netpulse, password from the first setup output"
echo "For LAN use only; HTTP does not encrypt the password. Do not port-forward this service."
echo "Logs:      journalctl -u netpulse -f"
