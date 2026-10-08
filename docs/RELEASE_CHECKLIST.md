# Public release checklist

## Source and privacy

- Publish only the reviewed source snapshot in a fresh Git repository. Do not push the private
  development history, its reflogs, dangling objects, or production archives.
- Run `python tools/publication_audit.py` against the staged snapshot. Its output contains file
  paths and finding categories, not matched secrets. A private `--deny-file` outside the repository
  can add operator-specific identifiers; never commit that file.
- Review examples, test fixtures, binary assets, author metadata, and commit messages manually.
  The automated audit is a guard, not proof that all sensitive data is absent.
- The generated `tests/fixtures/fake-router.pem` is a disposable loopback test identity. Never use
  it for a real router or service. Other private keys, runtime databases, config, exports, auth files,
  credentials, and logs must stay outside the repository.

## Verification

- Run `python -B -m unittest discover -s tests -t .` on the exact snapshot.
- Run `python tools/validate_home_assistant.py` with the optional validation dependencies installed.
- Verify installation and startup on the target host without replacing its private config.
- Record live acceptance separately from simulated test results. Publish model/firmware and generic
  outcomes, never household inventory or credentials.
- Keep Internet controls disabled until the deployment passes every gate in
  [Internet controls](internet-controls.md). A public release does not complete those gates.

## Publication

- Confirm the project name, repository destination, MIT licensing, and reviewed snapshot with the owner.
- Create the public repository from the clean snapshot, then wait for the configured CI checks.
- Add descriptive repository topics: `tp-link`, `er605`, `omada`, `dual-wan`, `raspberry-pi`,
  `network-monitoring`, and `telegram-bot`.
- Use a clear description mentioning TP-Link ER605, dual-WAN monitoring, smart routing, and
  device controls. Describe firmware limits and opt-in behavior near the top of the README.
- Follow [CONTRIBUTING.md](../CONTRIBUTING.md), [SECURITY.md](../SECURITY.md), and
  [AGENTS.md](../AGENTS.md) for subsequent changes and AI-assisted contributions.
