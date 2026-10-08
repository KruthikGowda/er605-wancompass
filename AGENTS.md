# AI contributor instructions

These instructions guide AI coding agents contributing to WANCompass. Follow the user's request and repository scope. Do not infer permission for external actions or live network changes from the presence of a tool.

## Navigate the repository

```text
netpulse/       application package: config/main, probes, health, decisions,
                router controls, devices, storage, notifications, web UI
tools/          operator setup, recovery, and diagnostic commands
tests/          unit, scenario, API, dashboard, and message contract checks
scripts/        host setup and installation
systemd/        service and recovery units
docs/           setup, config, feature, troubleshooting, and validation guides
```

Read the relevant implementation and tests before editing. Keep core decisions in service/domain modules, persistence in `storage/`, and presentation in `web/`. Preserve the established package, service, and config paths named `netpulse` for existing installations. See [Contributing](CONTRIBUTING.md) and [Configuration](docs/CONFIGURATION.md).

## Safety rules

- Global `monitor` and `dry-run` recommendations never apply router changes.
- Preserve authentication, owner-reviewed previews, explicit confirmation, exact router read-back, audit history, rollback/recovery locks, cooldowns, and firmware review.
- Never perform a live router write without explicit network-owner authorization for that operation and verified exact firmware. Stop if target identity, firmware, or object state is ambiguous.
- Keep router writes disabled by default. Do not infer enforcement from tests, code, or a readiness check.
- Internet pause/resume is IPv4-only. Do not claim IPv6 protection. Timed cleanup needs the service running; ER605 Priority failover is separate.
- Prefer mocks and synthetic fixtures. Live probes can send real network traffic and require operator authorization. A live probe authorization does not permit router writes.

## Tests

When the user requests or authorizes implementation verification, run relevant tests and report exactly what ran:

```sh
python3 -m unittest discover -s tests -t .
python3 -m tools.demo
```

The live suite is opt-in and sends network probes:

```sh
NETPULSE_LIVE=1 python3 -m unittest tests.test_live -v
```

Do not run the live suite without explicit authorization and a configured test host. Do not claim its results prove ACL enforcement or client failover. Follow [Contributing](CONTRIBUTING.md) for optional validators and message fixture updates.

## Privacy

Never expose credentials, private LAN assignments, real MAC addresses, ISP account names, device identities, router exports, or raw private logs in public docs or tool output. Use RFC 5737 IPv4 documentation ranges and synthetic locally administered MACs. Do not send secrets or inventories to AI services. Keep changes within the user's requested files; do not commit or publish unless explicitly requested.

## Documentation entry points

- [Setup](docs/SETUP.md) for install and upgrade.
- [Configuration](docs/CONFIGURATION.md) for actual settings and defaults.
- [Telegram](docs/TELEGRAM.md) for a user's own bot and private chat.
- [Troubleshooting](docs/TROUBLESHOOTING.md) for operator diagnostics.
- [ER605 API notes](docs/er605-api.md) and [live validation](docs/LIVE_VALIDATION_RUNBOOK.md) for router-specific work.
- [Documentation index](docs/index.md) for the full guide map.
