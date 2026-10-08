# Troubleshooting

Use these checks before changing router settings. Capture the specific error and relevant timestamps. Redact passwords, tokens, router exports, private addresses, MACs, device names, and chat IDs before sharing logs.

## Check the service first

```sh
sudo systemctl status netpulse --no-pager
sudo journalctl -u netpulse -n 100 --no-pager
```

After a config edit, validate and restart:

```sh
sudo python3 -c 'from netpulse.config import load; load("/etc/netpulse/config.toml"); print("config OK")'
sudo systemctl restart netpulse
sudo systemctl is-active netpulse
```

The installed package is under `/opt/netpulse`; if the import check cannot find `netpulse`, use the repository checkout or set `PYTHONPATH=/opt/netpulse`. Never paste the complete config into a support request.

## A WAN shows offline or both probes appear to use one connection

WAN-specific health requires all three pieces to match: a probe IP alias on the Linux host, the same `source_ip` under that WAN in `/etc/netpulse/config.toml`, and an ER605 source policy rule that pins that source to the intended WAN.

Check the alias list and routes:

```sh
ip -br -4 addr show dev eth0
ip route get 1.1.1.1 from <WAN1-probe-IP>
ip route get 1.1.1.1 from <WAN2-probe-IP>
```

The ordinary DHCP/management address is separate; do not substitute it for a probe source. In ER605, measurement source rules should use the WAN-only setting so each test stays on its assigned provider. Then run:

```sh
./tools/verify_paths.sh <WAN1-probe-IP> <WAN2-probe-IP>
```

Look for `RESULT: PASS` and distinct observed public egress addresses. Run it multiple times. If WAN2 is physically down, source-bound tests on WAN2 are expected to fail; that alone does not prove the source rule is wrong. Restore the link and repeat. If WAN2 is up but still fails, inspect its source address, source policy route, gateway/session, and provider reachability. Do not change settings just to make the verifier pass.

Use `sudo python3 tools/wan_asn_discover.py` only if you want to identify candidate egress ASNs. It makes external route-trace lookups; verify the result with your ISP before configuring it. Do not mistake ASN lookup failure for proof of a router problem.

## Dashboard will not open or login fails

- Confirm the service is active and the host's address is reachable from the same trusted LAN.
- Confirm the configured web port (default `8080`) and authentication path in `/etc/netpulse/config.toml`.
- The dashboard is HTTP and should not be exposed through router port forwarding or an untrusted network.
- The first install prints the generated dashboard password once. If it was lost, reset it from the repository checkout:

  ```sh
  sudo python3 tools/web_setup.py --reset
  ```

  Follow the helper's output and update any trusted local clients that store the old password. Repeated login failures are throttled.

## Router status is unavailable or controls are locked

Read-only router polling is off until `[router].enabled = true`. Check the configured host, the protected `/etc/netpulse/router.toml` file, and service logs. Do not print router credentials when diagnosing.

Router TLS uses a pinned certificate. A certificate mismatch means stop and verify the device and certificate change through a trusted local path; do not bypass the pin. A login can end an open Omada browser session. Pause router checks from the dashboard before using the router UI, then resume them afterward.

Control readiness can be locked by stale authenticated state, load balancing not enabled, a firmware version requiring owner review, the local kill switch file, or a failed ACL recovery check. Check the status shown in the dashboard and the recovery unit:

```sh
sudo systemctl status netpulse-acl-recovery.service --no-pager
sudo journalctl -u netpulse-acl-recovery.service --no-pager
```

Do not delete an ACL recovery record or change a router object to silence a lock. Resolve the recorded issue and verify exact router read-back. Internet pause is stricter than ordinary route controls and currently accepts only the firmware stated in [ER605 API notes](er605-api.md).

## Telegram bot does not respond

Check the dedicated bot token was entered using [the Telegram setup helper](TELEGRAM.md), `[telegram].enabled = true`, the authorized chat is the one messaging the bot, and only one running process polls that bot. Never share the token to debug. Check logs for error type and service state, not a copied config line. If the token may have leaked, revoke it with BotFather and rerun setup.

## Speed tests or reports are missing

Scheduled speed tests default to off. Check `[speedtest].schedule_enabled`, configured test times, monthly budget, and logs. A speed test makes active downloads/uploads and can use WAN capacity; WANCompass has no reliable passive traffic counter to defer it during a busy period. ASN checks can skip a run when the lookup fails or the observed origin does not match. Configure only ISP-confirmed ASNs.

The printable report needs stored measurements for the requested period. A recently installed service will not have a full 30 days of history yet.

## Backup or database issues

Backups default to disabled. Confirm the destination is mounted at the configured `mount_path`, the service can write there, and there is free space. Do not point backups to a path that merely exists when the remote share is unmounted.

Use the backup rehearsal tool on a disposable snapshot, never on the active database:

```sh
python3 tools/backup_restore_rehearsal.py /path/to/netpulse-db-snapshot.sqlite3
```

Keep backups private; they may contain network history and local device labels. Router credentials and Telegram tokens are separate and should not be included.

## Still stuck?

Check [Setup](SETUP.md), [Configuration](CONFIGURATION.md), and [ER605 API notes](er605-api.md). For a live router issue, stop writes and involve the network owner. Share only generic status and redacted logs; never publish real addresses, MACs, device labels, credentials, or router exports.
