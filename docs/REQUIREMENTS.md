# Requirements

## Practical host recommendation

For a straightforward home installation, use a **wired Raspberry Pi 3B, Pi 3B+, or newer** with **1 GB RAM** and a healthy **16 GB microSD card**. Use a reliable power supply. These are practical recommendations for a small always-on monitoring host, not measured minimums or application-enforced limits. Storage use depends on how long you retain monitoring history and whether you enable backups.

The project has passed its automated suite on a private Raspberry Pi 3 deployment. That is evidence for that deployment class, not a benchmark of minimum CPU, memory, or storage. Raspberry Pi Zero and Pi 1 support has not been verified. Containerized deployments and a Windows installer are not verified or supported installation paths.

## Required software and access

- Raspberry Pi OS based on Debian 12/13, or Debian 12/13 on a compatible Linux host. Check `python3 --version`; older OS images may not meet the Python requirement.
- Python **3.11 or newer** and systemd. The application runtime uses Python's standard library.
- `apt`, Bash, Git, and `sudo` access. The installer must run as root (normally through `sudo`).
- `curl` and `traceroute` for setup path verification; the installer installs these packages through apt.
- `ip` (`iproute2`) and `ping` (`iputils-ping`) for host setup and ICMP monitoring. For the included probe-IP helper, also use NetworkManager's `nmcli` on an existing NetworkManager-managed connection.
- Network access from the host to both WAN probe destinations and to the dashboard from a trusted local network.

The systemd service runs as its own unprivileged `netpulse` user and receives the capability it needs for ICMP probes from the included unit. Do not run the monitoring process as root to enable ping.

The included probe-IP helper assumes a wired Ethernet interface named `eth0`, managed by NetworkManager, with `nmcli` available. It adds two extra IPv4 addresses while keeping the host's normal management address. If your interface has another name, or you use another network manager, configure the two addresses through your system's normal networking tools instead of using that helper.

## Network and router prerequisites

- Two Internet connections connected to a **standalone TP-Link ER605**. Router adapter behavior is firmware-specific; consult [ER605 API and safety notes](er605-api.md) before enabling optional router features.
- Two unused probe IPv4 addresses in the same LAN subnet. Keep them outside the DHCP pool and existing static assignments, and exclude/reserve them in the router so DHCP cannot give them to another device. The host's ordinary management address is separate.
- Two ER605 source policy rules, one pinning each probe address to its corresponding WAN only. The host and router need Internet access for their respective probes and path verification.

Initial setup requires you to configure the router's WANs, DHCP pool, and probe policy rules. Optional device controls can manage reviewed reservations and device routes after their separate activation checks. Router behavior is firmware-specific. Internet pause/resume currently accepts only ER605 firmware `2.3.3 Build 20251029 Rel.18054`; other builds require code compatibility review and live acceptance before this feature can be enabled. See the [ER605 API and safety notes](er605-api.md). Setup and verification steps are in the [setup guide](SETUP.md).

## Optional features

- **SNMP diagnostics:** only for the optional SNMP discovery/validation tools; install the `snmp` package when you intend to run those tools. The core monitor does not require SNMP.
- **Telegram reports:** your own Telegram bot and private chat, configured locally. See [Telegram setup](TELEGRAM.md). Never put bot tokens in the repository or public issues.
- **Home Assistant:** a separate Home Assistant installation if you want the optional read-only REST sensors. See [Home Assistant](home-assistant.md).
- **Backups:** a writable destination accessible to the service user. For off-host backups, mount your own private NAS share with appropriate credentials and permissions; the NAS helper supports SMB and needs `cifs-utils`. Backups are optional and disabled by default; see [configuration](CONFIGURATION.md#backup).
