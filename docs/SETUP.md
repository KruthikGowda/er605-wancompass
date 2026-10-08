# Setup guide

Install WANCompass on a Raspberry Pi running Raspberry Pi OS or Debian 12/13. Python 3.11 or newer is required. The probe-address helper expects a wired NetworkManager interface named `eth0`; adapt networking for another host or network manager.

The public project name does not change compatible installed identifiers: the Python package, systemd service, and configuration paths remain `netpulse` and `/etc/netpulse`.

## 1. Install prerequisites and clone

On the Linux host:

```sh
sudo apt update
sudo apt install -y git python3 curl traceroute
git clone https://github.com/KruthikGowda/er605-wancompass.git ~/wancompass
cd ~/wancompass
```

The installer adds `curl` and `traceroute` for path verification. The runtime uses the Python standard library.

## 2. Choose two probe addresses

Choose two free IPv4 addresses in the LAN subnet, outside the router DHCP pool and static assignments. Keep the host's ordinary management address, usually DHCP, separate from these two extra addresses. The helper adds probe aliases without replacing the management address.

Check the router DHCP range and reservations first. A failed ping does not prove an address is unused. Confirm candidates against the router and network inventory, then reserve them so another device cannot receive them.

The examples below use documentation-only addresses. Replace them with free addresses in your LAN:

```text
WAN1 probe: 192.0.2.10
WAN2 probe: 198.51.100.10
```

The `[[wan]]` source IP values in your config must match the addresses you choose.

## 3. Configure your network values

Make a working copy and edit it:

```sh
cp config.example.toml config.toml
nano config.toml
```

Set both `[[wan]].source_ip` values to your two free probe addresses. Replace the router host with the ER605's LAN address. Set generic WAN labels and `plan_mbps` to your own values, or leave plan speeds at zero if unknown. Keep `expected_asns = []` unless you independently confirmed each provider's origin ASN.

Do not add Telegram or router credentials to this file. Telegram setup writes its token into the protected installed config; router setup stores credentials separately in `/etc/netpulse/router.toml`. See [Configuration](CONFIGURATION.md) for defaults and opt-ins.

## 4. Add probe IP aliases

From the repository directory on the host:

```sh
chmod +x scripts/*.sh tools/*.sh
sudo ./scripts/setup-probe-ips.sh 192.0.2.10 198.51.100.10
```

Replace both example addresses. The helper derives the prefix from the first IPv4 address on `eth0`, adds addresses through the active NetworkManager connection, and reapplies it. Confirm the output preserves the normal management address and shows both probes. For another interface or network manager, configure aliases using its normal tooling.

## 5. Pin each probe to its WAN in the ER605

In the ER605 policy-routing UI, create a source address group for each probe address and a rule for each group:

| Source | Destination | WAN selection |
|---|---|---|
| WAN1 probe address | Any | WAN1 only |
| WAN2 probe address | Any | WAN2 only |

The WAN-only selection keeps probe traffic on its assigned WAN instead of following failover/load-balancing policy. Menu names vary by firmware. Consult the router manual and read back both rules in the UI.

This measurement route differs from a device route using ER605 `Priority` mode. A device `Priority` route lets the router use its own WAN state for native failover. Probe routes must stay fixed to one WAN so each connection can be measured independently.

## 6. Verify both paths

Run the verifier with your addresses:

```sh
./tools/verify_paths.sh 192.0.2.10 198.51.100.10
```

It checks source-bound HTTPS egress and passes when the addresses show different public IPs. Run it several times and confirm the result is stable. Traceroute first hops are hints, not proof. If a request fails or both addresses have the same public IP, stop and check the aliases and policy rules before installing.

## 7. Install

Pass your edited file on first install:

```sh
sudo env NETPULSE_CONFIG_SOURCE="$PWD/config.toml" bash scripts/install.sh
```

The installer runs tests, installs the `netpulse` service, and uses this config only if `/etc/netpulse/config.toml` does not already exist. It preserves an existing installed config on upgrades. The first install creates a dashboard password and prints it once.

The service starts at boot. Open `http://<host-or-address>:8080/` from a trusted LAN and sign in as `netpulse` with the password printed by setup. The dashboard uses plain HTTP. Do not port-forward it or expose it to untrusted networks.

Before restarting an existing service, the installer checks whether timed WAN preferences are due or near expiry. It may ask for confirmation because restart can return routes to Auto. Review the prompt and any active device changes before answering.

## 8. Optional router inventory

To enable read-only ER605 polling, first set `[router].enabled = true` in `/etc/netpulse/config.toml`, then run:

```sh
sudo python3 tools/router_setup.py
```

The helper displays the router HTTPS certificate fingerprint and asks for confirmation, then prompts for the router username and hidden password. Verify the fingerprint through a trusted local path before accepting it. Credentials and pin are saved separately in `/etc/netpulse/router.toml` with restricted permissions. Router login can end an open Omada browser session.

Keep `controls_enabled` and `internet_controls_enabled` false until the network owner authorizes writes and the exact firmware passes readiness and live acceptance gates. See [ER605 API notes](er605-api.md), [Internet controls](internet-controls.md), and the [live validation runbook](LIVE_VALIDATION_RUNBOOK.md). A passing test or preflight is not proof of packet enforcement.

## 9. Set up your own Telegram bot

Each installation owner should create a dedicated bot and configure their own private chat. Do not reuse a shared or project bot. Follow [Telegram setup](TELEGRAM.md).

## 10. Upgrade and back up

Update from the project checkout:

```sh
cd ~/wancompass
git pull --ff-only
sudo bash scripts/install.sh
```

The installer keeps `/etc/netpulse/config.toml`, dashboard/router credentials, and the database. Check prompts about timed routes before continuing. History is stored in `/var/lib/netpulse/netpulse.db`. Optional weekly SQLite backups are disabled by default; configure and verify a mounted destination, inspect snapshot integrity, and rehearse a restore of a disposable copy before relying on backups.
