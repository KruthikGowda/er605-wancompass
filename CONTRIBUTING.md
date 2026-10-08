# Contributing to WANCompass

Thanks for contributing. Keep changes focused, describe user-visible effects, preserve safe defaults, and include evidence for behavior changes.

## Architecture map

```text
netpulse/
  main.py, __main__.py, config.py    service entry point and config parsing
  probes/                            ICMP, DNS, HTTPS, and WAN-bound probes
  health/, decision/                 health state, scoring, and dry-run advice
  router/, devices/                  ER605 adapter, route controls, client/group logic
  storage/                           SQLite persistence and migrations
  notifications/                     Telegram bot and delivery policy
  web/                               authenticated API and dashboard assets
  speedtest.py, system_health.py     active tests and host health checks
tools/                                operator setup, recovery, and validation CLIs
tests/                               unit, scenario, HTTP/API, and contract checks
scripts/, systemd/                   installation and service/recovery units
docs/                                operator, contributor, and feature guides
```

The public project is WANCompass; installed package/service/config paths retain `netpulse` for compatibility. See [AI contributor instructions](AGENTS.md) for navigation rules and [Configuration](docs/CONFIGURATION.md) for actual defaults.

## Development

Use Python 3.11+. Runtime dependencies are standard-library only. To exercise the local simulated dashboard:

```sh
python3 -m tools.demo
```

For YAML/Jinja validation of Home Assistant examples, install the optional extra and run:

```sh
python3 -m pip install -e ".[ha-validation]"
python3 tools/validate_home_assistant.py
```

Run tests relevant to an implementation change when the user requests or authorizes verification. The full unit/scenario/contract suite is:

```sh
python3 -m unittest discover -s tests -t .
```

This suite mocks router operations. The opt-in live suite sends real network probes and requires an explicitly configured host:

```sh
NETPULSE_LIVE=1 python3 -m unittest tests.test_live -v
```

Do not run live network or router checks without the operator's explicit authorization. `NETPULSE_LIVE=1` does not authorize router writes. Read [ER605 API notes](docs/er605-api.md) and the [live validation runbook](docs/LIVE_VALIDATION_RUNBOOK.md) before any firmware-specific live validation.

If changing an intentional Telegram message contract, regenerate and review its fixtures:

```sh
NETPULSE_UPDATE_GOLDEN=1 python3 -m unittest tests.test_contracts
```

On PowerShell, set the variable for the command with `$env:NETPULSE_UPDATE_GOLDEN="1"; python -m unittest tests.test_contracts`.

## Design and safety expectations

- Keep global health recommendations in monitor/dry-run code separate from router mutation paths.
- Preserve authentication, short-lived owner confirmation, exact object read-back, audit history, rollback/recovery locks, cooldowns, firmware review, and kill-switch checks.
- Router write behavior is firmware-specific. Unit tests and readiness output do not establish enforcement.
- IPv4 pause/resume does not establish IPv6 behavior. Timed cleanup requires NetPulse running; router-native Priority failover is separate.
- Use synthetic fixtures and mocked clients. Never use personal network inventories in tests or examples.

## Privacy and reports

Use RFC 5737 documentation addresses and synthetic locally administered MACs. Never commit credentials, tokens, private LAN addresses, real MACs, ISP account names, personal hostnames, or deployment notes. Treat router exports, logs, databases, and backups as private. Report vulnerabilities using [SECURITY.md](SECURITY.md).

## Pull requests

Describe the change, its safety impact, checks performed, and known limits. Add or update tests for code changes and document new settings or setup steps. Do not claim live router acceptance unless the exact firmware and owner-authorized checks were completed and read-back confirmed.
