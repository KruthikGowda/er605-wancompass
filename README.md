# WANCompass

**Open-source TP-Link ER605 dual-WAN monitoring and device controls for Raspberry Pi.**

This is an independent community project, not affiliated with or endorsed by TP-Link.
Licensed under [MIT](LICENSE). WANCompass is the public project name; existing installations use the `netpulse` service and package names.

NetPulse monitors two Internet connections from a small Linux host, records per-WAN latency, packet loss and jitter, and presents health history in a local dashboard. It can send optional Telegram alerts and make monitor-only WAN recommendations. Optional router integration adds device inventory and owner-reviewed WAN preference controls.

The probe host must have a separate IPv4 source address for each WAN, and the router must route each source through its intended WAN. Replace the RFC 5737 documentation addresses below with free addresses from your own LAN that are outside the DHCP pool.

```
Probe host -- 192.0.2.10/32 --> WAN1 policy route
           -- 198.51.100.10/32 --> WAN2 policy route
```

NetPulse binds probes to those source addresses. Without matching router policy routes, measurements may follow the router's normal load balancing and cannot prove which WAN was tested. The example addresses are documentation-only and are not usable LAN assignments.

## Scope and safety

Global monitor/dry-run recommendations never change routes. Separate device route controls are disabled by default and require an explicit owner action, a short-lived preview, verification by router read-back, and audit logging. Smart WAN is separately opt-in. Router-native Priority failover can operate without the probe host; NetPulse timed changes and cleanup require the service to be running.

Device Internet pause/resume controls target IPv4 ACL behavior only. Their live enforcement is firmware- and topology-dependent. Keep them disabled until an authorized owner has verified IPv4 behavior, IPv6 paths, every WAN, ACL ordering, recovery, and cleanup on the exact firmware. Never test against a device without its owner's approval. Do not perform router writes without explicit network-owner authorization and verified firmware. Stop writes after a firmware update until behavior has been reviewed again. See [Internet controls](docs/internet-controls.md) and [the live validation runbook](docs/LIVE_VALIDATION_RUNBOOK.md).

## Requirements

- Raspberry Pi 3 B+ or newer, or another supported Linux host with wired Ethernet
- Raspberry Pi OS / Debian 12 or 13 and Python 3.11+
- A reliable power supply appropriate for the host
- A supported TP-Link ER605 for optional router integration; validate the exact firmware before enabling writes

## Setup

### 1. Choose two free probe addresses

Choose addresses outside the router's DHCP pool and within your LAN subnet. The following examples are from RFC 5737 documentation ranges; replace them before use:

```text
WAN1: 192.0.2.10
WAN2: 198.51.100.10
```

### 2. Copy the project to the Linux host

From the repository checkout, for example:

```sh
scp -r ./netpulse user@netpulse-host:~/
```

Then on the host:

```sh
cd ~/netpulse
chmod +x scripts/*.sh tools/*.sh
sudo ./scripts/setup-probe-ips.sh 192.0.2.10 198.51.100.10
```

### 3. Add matching router policy routes

In the router's policy-routing UI, create one source group for each probe address and route it to the corresponding WAN. Use names such as `netpulse-wan1` and `netpulse-wan2`. Create the required IP groups first if the router UI requires them. Menu names and behavior vary by firmware; consult the router manual and verify each rule in the UI.

### 4. Verify source-bound paths

```sh
./tools/verify_paths.sh 192.0.2.10 198.51.100.10
```

Require a successful result and distinct observed public egress addresses before relying on WAN-specific measurements. If the result fails, check addressing, policy routes, and ISP connectivity; do not proceed with a guessed configuration.

### 5. Install

```sh
sudo ./scripts/install.sh
```

Open `http://<host-or-address>:8080/` on a trusted local network. The installer creates a dashboard password on first setup and prints it once. The verifier is stored in `/etc/netpulse/web.auth` with restricted permissions; reset it from the project directory with `sudo python3 tools/web_setup.py --reset`. The dashboard uses HTTP, so do not port-forward it or expose it to an untrusted network. Repeated failed logins are throttled.

The installer runs the unit suite before installation. It also checks whether timed WAN preferences are due or nearly due; an interactive confirmation may be required because installation can restart the service.

## Reports and speed tests

Open `/report?days=30` for a printable report and CSV export. Select a WAN with `&wan=WAN1` or `&wan=WAN2`, using names from the configuration. To check an ISP's expected egress origin, set `expected_asns = ["AS12345"]` under its `[[wan]]` configuration using a value confirmed with that provider. When set, NetPulse looks up the observed public address and skips a test if the origin does not match or lookup fails. An empty list leaves the same-public-IP check in place.

Speed test sizes and optional monthly payload budget are configured in `[speedtest]`. Scheduled tests are off by default. NetPulse cannot reliably determine general LAN traffic load and therefore does not automatically defer a test when other clients are busy. A test can temporarily use WAN capacity; choose a suitable time and budget.

## Operating

| Task | Command |
|---|---|
| Follow logs | `journalctl -u netpulse -f` |
| Restart after config change | `sudo systemctl restart netpulse` |
| Stop | `sudo systemctl stop netpulse` |
| Edit config | `sudo nano /etc/netpulse/config.toml` |
| Upgrade | Copy the updated checkout and run `sudo ./scripts/install.sh` |

Data is stored at `/var/lib/netpulse/netpulse.db`. Per-WAN minute data is retained for 400 days and per-server detail for 30 days. Optional weekly SQLite backups can be enabled in `[backup]` after configuring and verifying a mounted destination. Database backups include monitoring history and locally saved device labels; protect them as private data. Router and Telegram credentials are stored separately and are not copied into backups.

Optional Telegram setup: run `sudo python3 -m tools.telegram_setup`, then enable/configure the bot as directed. Keep bot tokens private. Do not paste actual credentials into issues, logs, examples, or AI prompts. Daily and weekly reports and device activity notices are disabled by default.

Optional router inventory is enabled with `sudo python3 tools/router_setup.py`. It reads router data and stores local device labels. Inventory and DHCP history identify network clients and should be treated as sensitive. LAN ping is off by default; a device that does not answer may be asleep or filtering ICMP.

## Health model

Each WAN is probed every 10 seconds against three targets. NetPulse aggregates median loss, round-trip time, and jitter over a rolling five-minute window and learns a separate baseline for each WAN and target. Default degraded/bad thresholds are configurable. A WAN is marked offline after all targets fail for three consecutive cycles.

The score combines availability (40), loss (30), latency (15), jitter (10), and stability (5). Monitor-only recommendations require a 15-point advantage held for 180 seconds, observe a 10-minute cooldown, and avoid a recently bad WAN; confirmed offline state triggers an immediate recommendation. These global recommendations do not apply router changes.

## Development

Run the standard-library unit suite:

```sh
python -m unittest discover -s tests -t .
```

Run a local simulated dashboard:

```sh
python -m tools.demo
```

It serves at `http://127.0.0.1:8080/` and uses simulated data.

See [configuration reference](docs/CONFIGURATION.md), [CONTRIBUTING.md](CONTRIBUTING.md) for contributor and AI-agent guidance, [the release status](docs/CURRENT_STATUS.md), [the roadmap](docs/ROADMAP.md), and [ER605 protocol notes](docs/er605-api.md).
