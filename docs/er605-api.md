# ER605 API and safety notes

NetPulse supports an optional adapter for the standalone TP-Link ER605 web interface. The adapter uses firmware-specific forms, so treat each model revision and firmware build as a separate compatibility target. Read-only success, protocol mocks, or a returned success code do not prove that clients are filtered or that failover works.

## TLS certificate pinning

The ER605 commonly presents a self-signed HTTPS certificate. NetPulse stores its SHA-256 fingerprint in the protected router credentials file and checks the leaf certificate's DER fingerprint on every HTTPS connection. A mismatch aborts the request; the adapter does not silently accept a changed certificate. The first fingerprint capture is a trust-on-first-use step. Before approving it, compare the displayed value with the router's certificate through a trusted local path, and repeat this review after a router replacement or certificate change.

Run `sudo python3 tools/router_setup.py` on the host to configure router access. It asks for the router host, displays the fingerprint, and prompts for an administrator username and hidden password. It saves the credentials and pin in `/etc/netpulse/router.toml` (root-owned, group `netpulse`, mode `0640`) and enables read-only router checks. Keep that file private. Never paste its contents, session cookies, or fingerprints tied to a private router into public issues or AI prompts.

The adapter's login exchange fetches the router's RSA public key, reads uptime, and encrypts the password with the uptime suffix as expected by this firmware's UI. The session token and `sysauth` cookie stay in memory and are not logged.

## Single administrator session

The observed ER605 firmware supports one administrator session. A NetPulse login can sign out a person using the Omada web UI. Full router polls therefore log in briefly, read the needed forms, and log out. Avoid editing the router UI during a poll or live transaction. Use the dashboard's **Pause router checks** action before working in Omada; it waits for an active check and prevents another scheduled login until resumed. Device/router information becomes stale while checks are paused and controls lock if required state is stale.

Within a process, the adapter holds a reentrant session lock across login, requests, and logout. Control transactions also serialize router writes and refresh state immediately before applying. Failed authentication backs off from 30 minutes with exponential growth up to six hours; do not retry repeatedly, since the router may lock the account.

## Verified read forms

`ER605Client.get(module, form)` sends an authenticated `method=get` request and returns `result`. `get_response` retains the response envelope so safety checks can inspect `error_code`, `result`, and metadata such as `others.max_rules`. A list is considered empty only when the response shape is recognized as an explicit empty collection. Unknown or ambiguous collection shapes fail closed.

The current runtime reads these forms when available:

| Module / form | Use |
|---|---|
| `online/online` | WAN link and status data |
| `interface/status2` | WAN interface details |
| `sys_status/all_usage` | Router usage counters |
| `dhcps/client` | Current client leases |
| `dhcps/reservation` | DHCP reservations |
| `firmware/upgrade` | Model/firmware values, with only version fields retained |
| `ipgroup/ipscope_list` | LAN scopes used by reservation checks |
| `dhcps/lan` | DHCP pool/scope settings |
| `balance/balance_global`, `balance/balance_basic` | Load balancing readiness |
| `policy_route/policy_route` | Saved per-device route read-back and drift detection |
| `ipstats/setting`, `ipstats/list` | On-demand per-IP traffic samples when the ER605 statistics setting is explicitly enabled |
| `access_ctl/acl_inner` | ACL rows for pilot and pause safety checks |

The device bandwidth view reads per-IP `rx_bytes` and `tx_bytes` counters twice,
normally two seconds apart, and computes router RX/TX rates from the differences.
It validates the `addr` as IPv4, bounds the table at 8,192 rows, and does not rely
on an unverified scale for the router's `rx_bps` or `tx_bps` fields. It binds a
selected MAC to an IP only when the fresh DHCP client list has unique MAC and IP
bindings before and after the sample. Results are cached in memory for up to 15
seconds; cache use still checks that selected device identity. Invalid, reset,
ambiguous, disabled, or stale data is unavailable, not zero. RX/TX are router-side
directions; client upload/download semantics and per-WAN attribution are not
established. This is read-only telemetry and does not configure QoS.

`tools/router_firewall_discover.py` probes a bounded list of candidate forms using reads only and redacts device identities and unrecognized values. The principal ACL read is `access_ctl/acl_inner`. Discovery is useful for compatibility diagnosis; a readable form does not establish that a write form is supported or correctly enforced.

## QoS form schema observed in the ER605 UI

Read-only inspection of the reviewed firmware's bundled UI source identifies these
forms: `/admin/qos?form=global` for global settings, `/admin/qos?form=rule` for
rate rules, and `/admin/qos_ctl?form=class` for classification rules. The UI also
loads `/admin/qos_ctl?form=dscp` and service, IPv4 group, IPv6 group, DHCP LAN,
and interface status catalogs. These are UI endpoints and fields, not a verified
router write contract; response envelopes, exact row payloads, and enforcement
have not yet been validated by NetPulse.

The global form exposes `qos_enable`, `threshold_enable`, and `qos_threshold`.
The UI accepts a threshold from 0 to 100, with a maximum input length of three
digits. Turning global QoS off disables threshold input, forces its checkbox off,
and sets its value to 0. This source does not establish whether a disabled global
setting preserves, ignores, or otherwise affects saved rules. NetPulse must not
enable or change this global setting as part of a per-device action.

The rate-rule editor exposes `name`, hidden `if_ping` (shown as LAN), `if_pong`
(WAN or eligible VPN interface; the UI can offer `WAN_ALL`), `source_type`
(`network` or `ip_group`), `network`, `ip_group`, `rate_max`, `rate_max_mate`,
`mode` (`share` or `priv`), `time`, `comment`, `position`, `enable`, and hidden
`ip_type` (default `src`). `rate_max` is bounded by 100 Kbps and the selected
interface's advertised `tx_max_speed` converted to Kbps; `rate_max_mate` is
bounded by 100 Kbps and `rx_max_speed` converted to Kbps. The UI labels both
values in Kbps. It offers `Any` as the default time object, limits comments to
50 characters, and validates an optional one-based position against the current
rule count. The source does not define the precise operational distinction
between `share` and `priv`; NetPulse must not infer it from the field names.

The separate classification form exposes `class` (`class1`, `class2`, or
`class3`), `status` (`enable` or `disable`), `ip` (`ipv4` or `ipv6`), `src_ip`,
`dst_ip`, `dscp`, `service`, `rule`, `ipt_order`, and `id`. It maps address
choices to IPv4/IPv6 group catalogs and loads service and DSCP catalogs. This
classifies traffic and assigns a QoS class/DSCP value; it is distinct from the
rate-rule editor's per-interface rate fields. Neither UI schema alone proves
packet treatment, scheduler behavior, or that the class order corresponds to a
specific bandwidth guarantee.

### Safe implementation path

First add bounded read-only reads and canonicalizers for the global settings,
rate-rule rows, and class rows; preserve unknown fields and ambiguous envelopes
as unavailable. Use the authenticated `ER605Client.session()` and
`get_response()` pattern, serialized under the router's existing `api_lock`.
Validate the exact response shape on the reviewed firmware before adding writes.

If a later owner-approved feature adds a per-device rate rule, keep the global
QoS settings read-only and leave their current values unchanged. Require global
QoS to already be enabled, a fresh unique device/IP-group mapping, an explicit
WAN/interface, and a preview of the selected interface plus both Kbps values and
mode. Implement only the exact observed add/delete protocol after separately
verifying its request envelope and read-back behavior. Before writing, re-read
the full rule collection; after writing, require exact row read-back. Roll back
only the exact newly-created row if its identity and full payload still match;
on ambiguous state, retain a recovery lock and require operator review. Never
remove or rewrite pre-existing QoS rules as cleanup. Until these protocol,
global-setting, and controlled endpoint checks pass, per-device QoS remains
unavailable. The existing `ER605Client.set_row()` allowlist does not include
QoS forms and is not a basis for adding them without those checks.

## Allowlisted configuration writes

The generic row helpers refuse arbitrary forms. The allowed row collection forms are:

- `ipgroup/ipscope_reservation`
- `ipgroup/ipgroup_reservation`
- `policy_route/policy_route`

Add, update, and delete methods require the `NP_` namespace. Updates preserve the object name and use a freshly read list index and key. Deletes resolve the current row position immediately before deletion and verify that the named object is absent afterward. Reservation creation uses a dedicated `dhcps/reservation` flow with additional checks: a NetPulse note, valid MAC and IPv4, LAN1 interface, and IP-MAC binding disabled.

ACL writes are separate, narrowly validated methods on `access_ctl/acl_inner`; they do not expose arbitrary ACL editing. The bounded phone pilot adds one temporary row only to an explicitly empty ACL and deletes only that exact unchanged row. Permanent pause adds/deletes accept only canonical NetPulse pause rows. On the reviewed firmware, ACL read-back may include `srcIf=""`, `destIf=""`, `dst_domain={}`, `t_label=["LAN"]`, and `v6flag="0"`. Only these exact neutral values are accepted; non-neutral or unknown fields are rejected. The write payload stays unchanged. These controls are disabled by default, and the pause capability additionally locks to its code-reviewed firmware target.

NetPulse object names use the `NP_` prefix. Device address, group, and route objects are named from the MAC identity as `NP_I_<12 hex digits>`, `NP_G_<12 hex digits>`, and `NP_R_<12 hex digits>`. Temporary pilot rows use `NP_TEST_P_<32 hex digits>`; durable pause rows use `NP_PAUSE_<32 hex digits>`. Prefixes are an ownership boundary: do not edit or delete similarly named objects unless their full identity and expected fields match the current saved intent.

## Priority and Only routing modes

For a single-WAN device preference, NetPulse creates or updates a per-device policy route with `mode = "Priority"`, selected `interfaces` (`WAN1` or `WAN2`), the device's source IP group, and an any-destination group. The ER605's own WAN detection then allows the route to stop applying if its selected WAN is reported offline. This is router-native behavior and can continue when the NetPulse host is unavailable, subject to firmware and router configuration.

The staged strict path writes `mode = "Only"`, requires exact interface/mode read-back, and stores the distinct intent `WAN1_ONLY` or `WAN2_ONLY`. Unknown or missing enabled-row modes are treated as unreadable, never as Priority. New strict actions are blocked by `STRICT_WAN_TRANSITIONS_VERIFIED = False`, even when the configuration flag is true. Auto and Prefer remain available to clear existing strict rules.

On the reviewed firmware, adding a new Only rule blocked the alternate WAN in controlled IPv4 probes, but changing an existing Priority rule to Only left forwarding on the previous WAN despite exact form read-back. Keep strict controls unavailable until transition, rollback, and interrupted-operation recovery pass packet-level acceptance. The intended exclusion applies to IPv4 through this router; it never controls IPv6, mobile data, VPNs through other paths, or other routers.

## Firmware review and persisted locks

Router controls require enabled configuration, fresh authenticated router status, load balancing readiness, a functioning kill switch state, and no unresolved ACL recovery failure. The current firmware value and accepted value are stored in the local database. When a different firmware is observed, NetPulse marks it pending and locks controls until an owner reviews the exact displayed version and accepts it through the dashboard. A firmware rollback to the previously accepted version clears the pending marker. If the firmware cannot be read, controls remain locked.

Internet pause/resume has a stricter gate: the implementation currently accepts only `2.3.3 Build 20251029 Rel.18054`. A generic firmware review click does not expand this feature to other builds. Keep `router.internet_controls_enabled = false` until code compatibility and live acceptance are complete for the exact firmware.

The `router.kill_switch` path is configurable and defaults to `/etc/netpulse/controls.disabled`. Creating the configured file immediately blocks new router writes and keeps cleanup/readiness behavior conservative. An interrupted temporary ACL pilot has a separate root-private cleanup record and a boot-time oneshot recovery service. Failed or ambiguous cleanup leaves the record/failure marker in place and locks controls; never remove it simply to clear a warning.

## Canonical IPv4 ACL row and state coverage

The temporary one-device pilot constructs a LAN-to-WAN IPv4 block row with these semantics:

- Policy `DROP`, service `ALL`, IP version `ipv4`, zone `LAN`.
- Source is the exact device's NetPulse IP group (`NP_G_<MAC>`); destination is `IPGROUP_ANY`.
- Time is `Any`; connection states include exactly `new`, `established`, `related`, and `invalid`.
- The firmware payload also contains the empty `position`, `flag = "1"`, and `user = "1"` fields.

The four lowercase connection states were observed in the reviewed firmware's Access Control UI. Canonicalization tolerates only known response normalization such as `zone` returned as `["LAN"]`, a list index, and recognized metadata. It refuses missing fields, unknown fields, duplicate/unknown state values, ambiguous ACL collections, and snapshots over the parser limit. This is IPv4-only behavior; it says nothing about IPv6 paths.

## ACL order and live acceptance gates

ACL summaries report the router's returned row order and the interface notes that TP-Link treats the first row as highest priority. This does not prove the effect of an append request. Temporary pilot behavior requires a readable empty ACL. Permanent pause code currently appends after existing NetPulse pause rows and verifies the new row appears at the expected index while preserving prior rows. The firmware's placement behavior with a nonempty live ACL has not been established. Keep permanent controls disabled until insertion order, interaction with existing rules, and multirow behavior are verified on the target firmware.

Before enabling any live writes:

1. Verify model and exact firmware; review the feature's supported firmware and router behavior.
2. Obtain explicit network-owner authorization for the named endpoint and test window.
3. Confirm the local kill switch, router readiness, and recovery state.
4. Read and preserve the exact before-state. For the bounded ACL pilot, the allowlisted endpoint must have a unique current lease, an exact enabled DHCP reservation, matching `NP_I_`, `NP_G_`, and `NP_R_` objects, a WAN1 `Priority` route, fresh stable uptime, and an empty readable ACL.
5. Use a disposable endpoint. Confirm a successful IPv4 Internet and local Pi heartbeat baseline, add one temporary rule, observe IPv4 block while Pi LAN remains reachable, remove it, and verify recovery plus unchanged ACL state.
6. Validate WAN2, IPv6, multirow order, interrupted cleanup, and host-offline limits as separate gates. A WAN1 IPv4 pass cannot satisfy these checks.

### Private pilot device approval file

The ACL pilot requires a separate owner-reviewed file at `/etc/netpulse/acl-pilot-devices.json`. It must be a root-owned regular file with mode `0600`; symlinks and permissive files are rejected. The file maps a canonical uppercase hyphen-separated MAC address to the endpoint's exact private IPv4 address. The selected endpoint must match this explicit pair and the live router lease. The file is limited in size, requires unique JSON keys, and is never printed by the tool.

Synthetic example only:

```json
{
  "02-00-00-00-00-10": "10.0.0.50"
}
```

The locally administered MAC and private address above are placeholders. Replace them only in the protected local file after the device owner authorizes the test and the router readiness preflight has passed. Do not add real values to the repository or send them to public documentation or an AI service.

The preflight is read-only:

```sh
sudo python3 tools/router_pause_readiness.py "Test endpoint"
```

Then, only after reviewing preflight output and authorization, first do a dry preflight run:

```sh
sudo python3 tools/router_acl_pilot.py --device "Test endpoint"
```

`--device` is required and must identify exactly one current lease by exact name, MAC, or IPv4; the resolved MAC/IP pair must also match the private allowlist. `--apply` is a live router write request and may only be added after the owner reviewed the target and accepted the exact firmware and cleanup plan:

```sh
sudo python3 tools/router_acl_pilot.py --device "Test endpoint" --apply
```

The tool creates a short-lived local Pi page. Keep the approved Android phone on Wi-Fi with mobile data and VPN off, and open the printed URL. It tests baseline, blocked, and recovered IPv4 from the phone while a same-LAN callback verifies access to the Pi. The URL uses private HTTP, is tokenized, and expires. Do not publish it.

For the Android ADB reporter, all identity arguments are required so the script can verify the explicitly selected phone and its active Wi-Fi network. Use the current URL printed by the pilot:

```sh
python3 tools/adb_acl_probe.py \
  --url 'http://<private-pi-ip>:<port>/probe/?t=<temporary-token>' \
  --serial '<adb-serial>' \
  --phone-mac '02-00-00-00-00-10' \
  --phone-ip '10.0.0.50'
```

This reporter does not change phone settings. It refuses if mobile data is enabled, the reviewed MAC/IP is not on the active Wi-Fi network, a VPN is active, HTTPS validation fails, or a probe phase changes during a request. It sends only the phase result (IPv4 Internet pass/fail and LAN reachability) to the Pi.

The pilot starts an independent Pi cleanup watchdog before stopping the NetPulse service, writes one temporary rule, and removes that exact unchanged rule. On interruption or reboot, a root recovery unit attempts cleanup before the main service starts. A changed or ambiguous rule is not deleted automatically and keeps controls locked for manual review. The watchdog cannot run if the Pi is powered off, and timed cleanup is not router-native. The bounded pilot is not evidence of permanent pause safety or general dual-WAN behavior.
