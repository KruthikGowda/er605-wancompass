# WANCompass

WANCompass monitors two Internet connections from a Raspberry Pi or supported Linux host. Its dashboard shows latency, packet loss, jitter, health history, and monitor-only WAN recommendations. Optional features add Telegram reports, router inventory, and owner-reviewed device controls.

WANCompass is an independent community project, not affiliated with or endorsed by TP-Link. The public project is [KruthikGowda/er605-wancompass](https://github.com/KruthikGowda/er605-wancompass), licensed under the [MIT License](LICENSE). Existing installs keep the `netpulse` package, service, and configuration paths for compatibility.

## Quick start

Follow the [setup guide](docs/SETUP.md) to install prerequisites, clone the repository, choose two free probe addresses, configure both WAN paths, and install the service:

```sh
sudo apt update
sudo apt install -y git python3 iproute2 iputils-ping curl traceroute
git clone https://github.com/KruthikGowda/er605-wancompass.git ~/wancompass
cd ~/wancompass
cp config.example.toml config.toml
# Edit config.toml with your LAN, router, WAN labels, and plan values.
sudo env NETPULSE_CONFIG_SOURCE="$PWD/config.toml" bash scripts/install.sh
```

Replace all example addresses with free addresses in your own LAN. Complete the policy-route setup and verify both WAN paths before relying on the readings.

See [requirements](docs/REQUIREMENTS.md) for the practical host baseline and prerequisites, plus [configuration](docs/CONFIGURATION.md), [Telegram setup](docs/TELEGRAM.md), [troubleshooting](docs/TROUBLESHOOTING.md), and the [documentation index](docs/index.md) for complete guides.

## What it does

- Measures each WAN from its own configured probe address when the router has a matching policy route.
- Tracks latency, packet loss, jitter, health scores, and trends.
- Provides monitor-only recommendations. Global `monitor` and `dry-run` modes never change routes.
- Offers optional authenticated router inventory and owner-reviewed device WAN preferences. Device Smart WAN is separately opt-in.
- Provides IPv4 Internet pause/resume controls that remain disabled until the exact firmware and deployment pass live acceptance.

Router-native `Priority` routing can fail over according to the router's WAN status while the Pi is offline. A measurement probe must stay pinned to one WAN. These are distinct policies.

## Safety and limits

Router controls are disabled by default. Never make a live router change without network-owner authorization, a reviewed target, and verified firmware. Unit tests do not prove router enforcement.

Internet pause/resume currently covers IPv4 only. It does not control IPv6 or mobile-data paths. WAN2 enforcement, ACL ordering with existing rows, and timed cleanup while the host is off need separate validation. Timed actions require the service to be running. See [ER605 API notes](docs/er605-api.md) and [Internet controls](docs/internet-controls.md).

The dashboard uses HTTP. Keep it on a trusted local network, do not port-forward it, and do not expose it directly to the public Internet.

## Useful commands

```sh
sudo systemctl status netpulse
sudo journalctl -u netpulse -f
sudo systemctl restart netpulse
sudo systemctl stop netpulse
```

The service stores configuration in `/etc/netpulse/config.toml` and history in `/var/lib/netpulse/netpulse.db`. The first install prints a dashboard password once. Keep config, database, Telegram tokens, router credentials, backups, and device inventory private.

For development, use Python 3.11+ and run `python3 -m unittest discover -s tests -t .`. See [CONTRIBUTING.md](CONTRIBUTING.md) and [AI contributor instructions](AGENTS.md).
