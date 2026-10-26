# Optional password-free routine administration

You can let one Linux operator check NetPulse readiness and restart its service without
entering a sudo password each time. This is optional and does not enable router controls.

Run once from a reviewed checkout on the Pi:

```sh
sudo python3 tools/setup_admin_access.py
```

Setup uses the account that invoked sudo. It installs a root-owned helper and a
`visudo`-validated rule allowing only these commands:

```sh
sudo -n /usr/local/sbin/wancompass-admin status
sudo -n /usr/local/sbin/wancompass-admin readiness
sudo -n /usr/local/sbin/wancompass-admin restart
```

Readiness reads the protected configuration and contacts the configured router, but
prints only the existing readiness tool's summary. The helper does not accept paths,
shell commands, environment overrides, configuration edits, or router write requests.
Restart briefly pauses monitoring and alerts; it does not reset saved router routes.

General deployments and security changes still need normal sudo authentication. The
helper refuses readiness checks if its installed Python dependencies are writable by
another account. Run the reviewed installer to repair unexpected file permissions;
do not weaken the ownership check.

To revoke this optional access:

```sh
sudo rm -- /etc/sudoers.d/wancompass-admin
```

Keep the helper root-owned. Never grant password-free execution of Python, a shell,
or an installer in a user-writable checkout.
