# NetPulse release status

This page describes repository capabilities and acceptance limits. It is not a report about a particular installation. Live router behavior depends on the router model, firmware, network topology, and owner configuration.

## Available

- Dual-WAN health monitoring with source-bound IPv4 probes, learned latency baselines, loss/jitter scoring, history, and dashboard.
- Monitor-only recommendations, optional Telegram alerts, reports, and speed tests. Scheduled tests and notifications are opt-in.
- Optional authenticated router inventory and device/group views. Telegram offers list-based device actions and list-driven group create, add, remove, rename, and delete previews; group membership edits do not reroute devices or clear pause intents.
- Owner-reviewed per-device and group WAN preference controls, guarded by read-back, audit records, cooldowns, recovery checks, and a local kill switch. Smart WAN is opt-in.
- IPv4 Internet pause/resume for devices and groups is implemented, but must remain disabled until the target router firmware and topology pass the live acceptance gates below.
- On-demand per-device router RX/TX rate estimates from ER605 byte-counter deltas, bound to a unique fresh DHCP MAC-to-IPv4 mapping and cached for up to 15 seconds. These are router-side directions; client upload/download meaning, per-WAN attribution, and QoS enforcement are not established.

## Acceptance limits

- Do not treat unit or simulated tests as proof of router enforcement or client failover.
- Internet pause is IPv4 only. IPv6 behavior is unverified and may provide another path.
- Strict Only controls are unavailable pending a reliable mode-transition protocol. On the reviewed firmware, an existing Priority rule changed to Only can read back correctly while traffic continues through the previous WAN. Creating a new Only rule is not sufficient validation of later edits.
- Live router writes are opt-in and must be tested on the exact firmware in use. Obtain explicit authorization from the network owner, review each preview, and verify the write by reading the router state back. Stop if firmware changes or state is ambiguous.
- Validate every WAN and multirow ACL behavior with a controlled endpoint before enabling Internet controls. A single-WAN test does not establish dual-WAN behavior.
- Timed cleanup requires NetPulse to be running. The router's native Priority WAN failover can continue while NetPulse is offline; these are separate mechanisms.
- NAS backups, IPv6 enforcement, Pi power-loss cleanup, and WAN2 enforcement are deployment-specific checks, not guaranteed by this repository.

## Release checks

Run the documented unit suite before a release. For a live installation, follow [the validation runbook](LIVE_VALIDATION_RUNBOOK.md) using a disposable endpoint and owner-approved maintenance window. Record router model, firmware, test path, expected result, observed result, and cleanup read-back without recording personal device identifiers or credentials.

The current configuration defaults router controls and Internet controls off. See [the example configuration](../config.example.toml), [Internet controls](internet-controls.md), and [the roadmap](ROADMAP.md).
