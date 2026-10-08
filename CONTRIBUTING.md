# Contributing to NetPulse

Thanks for helping improve NetPulse. Keep changes focused, explain user-visible behavior, and preserve the fail-safe defaults around router access.

## Architecture

`netpulse/main.py` assembles the service. Configuration lives in `config.py`; `probes/`, `health/`, and `decision/` handle measurement and recommendations; `router/` and `devices/` implement optional router-backed features; `storage/` owns SQLite persistence; `notifications/` handles Telegram; and `web/` serves the API and dashboard. `tools/` contains operator utilities and `tests/` covers the implementation. Keep each safety check in the layer that owns the operation.

For actual setting defaults and live-test opt-ins, see [the configuration reference](docs/CONFIGURATION.md). Router protocol and firmware details are in [ER605 API notes](docs/er605-api.md).\n\n## Before changing code

- Read the relevant module, its tests, and [the release status](docs/CURRENT_STATUS.md).
- Keep the global monitor and dry-run recommendation paths separate from opt-in router controls.
- Preserve authentication, owner confirmation, router read-back, audit history, recovery locks, cooldowns, and kill-switch checks when changing controls.
- Prefer the Python standard library. Optional development dependencies are documented in `pyproject.toml`.

## Development checks

The project targets Python 3.11+ and uses `unittest`:

```sh
python -m unittest discover -s tests -t .
```

Run the simulated dashboard with:

```sh
python -m tools.demo
```

For Home Assistant YAML/Jinja examples, install the optional validation dependencies and run:

```sh
python -m pip install -e ".[ha-validation]"
python tools/validate_home_assistant.py
```

If intentionally changing a Telegram message contract, regenerate and inspect golden fixtures:

```sh
$env:NETPULSE_UPDATE_GOLDEN="1"; python -m unittest tests.test_contracts
```

On POSIX shells, use `NETPULSE_UPDATE_GOLDEN=1 python -m unittest tests.test_contracts`.

The opt-in live suite (`NETPULSE_LIVE=1 python -m unittest tests.test_live -v`) sends real network probes and expects an explicitly configured dual-WAN host. Do not run it against a system unless its operator authorized the traffic. It does not authorize router writes.

## Router safety

Never make live router writes without explicit authorization from the network owner and verification of the exact router firmware. Keep tests mocked or simulated by default. For an authorized live validation, use an expendable endpoint, inspect the preview, capture the exact before-state, perform one bounded change, read the result back, and confirm cleanup. Stop if firmware, rule ownership, state, or target is ambiguous. Do not infer live enforcement from unit tests or staging results.

IPv4 pause/resume does not establish IPv6 behavior. Validate each WAN and ACL ordering on the target firmware. Timed cleanup requires NetPulse to run; router-native Priority failover is a separate router capability.

## Privacy and security

- Never commit credentials, tokens, private IP assignments, real MAC addresses, ISP account names, hostnames, or personal deployment logs.
- Use RFC 5737 documentation IPv4 addresses (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and synthetic locally administered MAC addresses in examples.
- Do not paste secrets, router exports, raw device inventories, or private logs into AI tools or public issues.
- Avoid logging sensitive device identifiers or authentication material. Treat databases and backups as private because they can contain device labels and network history.
- Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## Pull requests

Describe the behavior change, safety implications, and checks run. Include limitations and firmware-specific assumptions. Add or update tests for code changes; document new setup steps and configuration fields. Never claim live router acceptance unless the exact firmware and owner-authorized checks have been completed and recorded without private household details.
