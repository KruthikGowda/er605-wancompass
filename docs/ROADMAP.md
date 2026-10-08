# Roadmap

This roadmap tracks general project capabilities and acceptance work. It contains no status for a particular household or router installation. Deployment results belong in private operator records, not public project documentation.

## Available capabilities

- Dual-WAN IPv4 health monitoring, learned baselines, scoring, history, and a local dashboard.
- Monitor-only WAN recommendations, optional Telegram alerts and reports, and configurable speed tests.
- Optional router inventory, local device labels, and group management.
- Owner-reviewed per-device and group WAN preferences with verification, audit records, recovery checks, and opt-in Smart WAN.
- IPv4 device/group pause and resume with durable intent, timed cleanup, repair flow, and audit history. Keep activation disabled until the exact firmware passes live acceptance.
- Optional Home Assistant read-only REST examples and SQLite backup support.

## General release acceptance

1. Run the unit suite and review changes to test contracts and dashboard/API interfaces.
2. Confirm defaults keep router writes, Internet controls, scheduled speed tests, and optional notifications disabled.
3. For router integrations, verify the exact model and firmware, owner authorization, authentication behavior, state read-back, recovery, and kill switch before enabling writes.
4. Validate every supported WAN and relevant ACL ordering using an approved expendable endpoint. IPv4 tests do not validate IPv6.
5. Verify cleanup and document that timed actions require NetPulse to be running. Test router-native Priority failover separately from NetPulse decisions.
6. Keep public release notes free of credentials, private IP assignments, real MACs, ISP account identifiers, device names, and household deployment narratives.

## Known limitations

- Internet pause/resume validates IPv4 only; IPv6 enforcement is not established.
- Live router write behavior is firmware-specific. Repository tests cannot prove network enforcement.
- WAN2 enforcement and multirow ACL ordering must be verified on each target deployment.
- Timed cleanup cannot run while the NetPulse host is powered off. Native router Priority failover is separate.
- Reliable passive per-WAN traffic attribution is not available in the current implementation; speed tests do not automatically avoid busy LAN periods.
- Off-host backup reliability depends on operator storage, mount, credentials, and restore testing.
- Home Assistant examples are read-only and require validation in the target Home Assistant installation.

See [current release status](CURRENT_STATUS.md), [Internet controls](internet-controls.md), and [live validation](LIVE_VALIDATION_RUNBOOK.md).
