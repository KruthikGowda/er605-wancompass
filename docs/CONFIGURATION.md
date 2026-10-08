# Configuration reference

Start with [`config.example.toml`](../config.example.toml) and install the customized file at `/etc/netpulse/config.toml`. The example is intended to contain placeholders only. Keep the installed configuration root-owned and group-readable by the service (normally mode `0640`). NetPulse reads TOML; unknown keys are ignored with a startup warning so an older configuration can survive upgrades, but verify warnings after every upgrade because an obsolete key may no longer have an effect.

Router credentials are separate from this file. `/etc/netpulse/router.toml` stores the administrator username, password, and pinned TLS certificate SHA-256 fingerprint, normally root-owned with group `netpulse` and mode `0640`. Do not commit credentials or copy them into examples, issue reports, or AI prompts.

## Sections

### `[general]`

- `mode`: `monitor` records measurements only; `dry-run` (default) also records which WAN the recommendation engine would select. Neither mode changes router routes.
- `interval_seconds`, `window_seconds`: sample interval and health aggregation window.
- `db_path`: SQLite database location.
- `preferred_wan`: initial preference for monitor-only recommendations.

### `[probe]`

`targets`, `count`, `packet_interval`, and `timeout_seconds` configure ICMP targets and probe pacing. Each WAN can bind to its own `source_ip`; this only proves WAN-specific measurements when the router has a matching policy route for that source. `source_ip` may be empty, but then NetPulse cannot claim the probe used a specific WAN.

### `[[wan]]`

Define the two WANs by `name` (normally `WAN1` and `WAN2`), with optional dashboard `label`, `source_ip`, `plan_mbps`, and `expected_asns`. Labels are operator display text; use generic labels in public examples. ASN checks can send the observed public egress IP to RIPEstat for origin lookup; configure only provider-confirmed ASNs and account for that external lookup. An empty `expected_asns` list leaves the same-public-IP check in place.

### `[thresholds]` and `[decision]`

Thresholds set absolute and baseline-relative limits for degraded/bad health and the number of failed cycles before offline. Decision settings govern the monitor-only recommendation's score advantage, hold time, cooldown, and recovery interval. These do not enable route writes.

### `[web]`

`host`, `port`, and `auth_file` configure the HTTP dashboard/API listener. Defaults bind to all interfaces on port 8080 and use the installer-generated `/etc/netpulse/web.auth` password verifier. The interface uses HTTP; restrict access to a trusted network and do not port-forward it or expose it directly to the public Internet.

### `[speedtest]`

`download_mb`, `upload_mb`, `streams`, and `dip_pct` configure manual and scheduled throughput checks. `schedule_enabled` defaults to `false`; `times` matter only when scheduled tests are enabled. `monthly_budget_mb = 0` disables the measured-payload cap. Speed tests send active traffic from the NetPulse host; the service does not detect general LAN busy periods and automatically suppress tests.

### `[router]`

| Key | Default | Purpose |
|---|---:|---|
| `enabled` | `false` | Enable optional ER605 polling and inventory. |
| `host` | router-local address | ER605 host/address. Set for the local network. |
| `poll_minutes` | `10` | Interval between full authenticated polls. Each login can end an existing Omada browser session. |
| `credentials_file` | `/etc/netpulse/router.toml` | Separate protected router credentials and certificate pin. |
| `controls_enabled` | `false` | Allow owner-reviewed manual device route/reservation operations after readiness checks. |
| `internet_controls_enabled` | `false` | Allow IPv4 Internet pause/resume only after exact firmware and live acceptance. |
| `protected_macs` | `[]` | Additional owner-designated client exclusions for Internet pause. |
| `kill_switch` | `/etc/netpulse/controls.disabled` | Presence of this file blocks router writes. |
| `presence_probes_enabled` | `false` | Optional LAN ICMP hints; no reply does not prove a device is offline. |
| `presence_probe_interval_seconds` | `60` | LAN reachability sampling interval. |
| `presence_confirm_misses` | `3` | Misses after a prior reply before a stopped-replying transition. |
| `syslog_enabled` | `false` | Receive optional DHCP allocation hints. Router log forwarding must be separately enabled by its owner. |
| `syslog_port` | `514` | UDP port; messages are accepted only from the configured router host. |

Keep `controls_enabled` and `internet_controls_enabled` false by default. Turning either on is an operator decision and does not itself prove the router is ready. Readiness, a fresh preview, owner confirmation, exact object read-back, audit state, firmware review, and the kill switch still apply. Permanent Internet pause is IPv4-only and currently restricted in code to the reviewed ER605 firmware listed in [the API notes](er605-api.md).

The global `mode = "dry-run"` and the separate `[router]` controls have different roles: recommendations remain non-mutating even if a user later explicitly enables an eligible router control.

### `[system_health]`

`enabled`, `interval_seconds`, `low_disk_pct`, `low_memory_pct`, and `memory_recovery_pct` configure host-health sampling and warning thresholds. Missing measurements are treated as unavailable, not as healthy.

### `[backup]`

Backups default to disabled. Configure `directory` and, for mounted storage, `mount_path`; the service verifies the mount before writing. `interval_days` and `keep` control schedule and retention. Verify snapshot integrity and rehearse a restore before relying on off-host recovery. Database backups can contain network history and device labels; restrict access. Router and Telegram credentials are stored separately and are not included.

### `[telegram]`

`enabled`, `bot_token`, and `chat_id` enable the optional bot. Store real tokens only in the protected local configuration. `quiet_start`/`quiet_end` delay non-critical alerts; `digest_time` and `weekly_report_time` opt into daily/weekly reports. `device_activity_notifications` defaults to `false`; enabling it can disclose client activity to the configured chat. Telegram API acceptance does not prove the recipient saw a message.

## Ownership and opt-ins

NetPulse's config does not contain the pilot's private endpoint approval. The bounded ER605 ACL pilot separately requires `/etc/netpulse/acl-pilot-devices.json`, an owner-reviewed root-owned regular file with mode `0600`. It maps a canonical MAC address to the exact private IPv4 address, and the pilot cross-checks that pair against the current router lease and reservation. See the setup and safeguards in [ER605 API notes](er605-api.md). Do not add real identities to this repository.

Read-only router polling, route controls, Internet pause, presence pings, syslog event hints, speed-test scheduling, Telegram reports, activity notifications, and backups each have separate defaults and setup prerequisites. Enabling one does not implicitly enable another.

## Development and live tests

- `python -m unittest discover -s tests -t .` runs the standard unit/scenario/contract suite.
- `NETPULSE_UPDATE_GOLDEN=1 python -m unittest tests.test_contracts` deliberately rewrites Telegram golden fixtures; review the diff.
- `NETPULSE_SLOW=1 python -m unittest tests.test_scale -v` opts into the larger scale case.
- `NETPULSE_LIVE=1 python -m unittest tests.test_live -v` opts into live network probes on an explicitly configured test host. It can send real ICMP/DNS/HTTPS traffic.
- `NETPULSE_ROUTER_PIN=<sha256-fingerprint>` enables the optional certificate-pinning check within the live test suite. Treat the pin as deployment-specific configuration.

The live suite is not a router write authorization and does not test ACL enforcement or client failover. Never run router-writing helpers unless the network owner explicitly authorized the named operation and the exact firmware has been verified.
