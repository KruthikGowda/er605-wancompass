# Security policy

## Supported versions

Security fixes are applied to the current repository version. Users should upgrade from older checkouts after reviewing release notes and backing up their configuration and database.

## Reporting a vulnerability

Please use [GitHub private vulnerability reporting](https://github.com/KruthikGowda/er605-wancompass/security/advisories/new) for security issues. Do not publish exploit details, credentials, router exports, device inventories, or personal network addresses in a public issue. A regular GitHub issue is public once the repository is public.

Include the affected version, relevant component, impact, and a minimal reproduction that uses synthetic data. Redact tokens, passwords, private IP addresses, MAC addresses, hostnames, and ISP identifiers. Allow maintainers time to investigate and prepare a fix before public disclosure.

## Security boundaries

NetPulse is intended for a trusted local network. The dashboard uses HTTP; do not expose it directly to the public Internet. Keep system configuration, Telegram tokens, router credentials, database files, and backups access-restricted.

Router controls are disabled by default. Enable them only after the network owner explicitly authorizes the change and the exact router firmware has been verified. Read back and inspect every live change. Router firmware updates can change API behavior, so revalidate before further writes.

Internet pause/resume controls currently cover IPv4 behavior. They do not establish IPv6 blocking. Timed cleanup depends on the NetPulse host being online; the router's native Priority WAN failover is a separate function.
