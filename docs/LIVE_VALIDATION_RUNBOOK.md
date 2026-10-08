# Live validation runbook

Use this checklist only for a deployment whose network owner has authorized the specific checks. It supplements automated tests; it does not establish that another router or firmware behaves the same way.

## Before validation

- Confirm the router model and exact firmware version, and review the current release status and [Internet controls](internet-controls.md).
- Obtain explicit owner authorization before any live router write. Verify the authorization covers the target device, route/rule, test window, and cleanup.
- Choose an expendable endpoint whose owner is present. Confirm its ordinary connectivity first and ensure it is not the NetPulse host or router management path.
- Save a restricted before-state record of the exact NetPulse-owned router objects. Do not put credentials or device identifiers into public logs.
- Confirm the local kill switch and recovery service behavior, and arrange immediate rollback and physical access if needed.
- Do not log in to the router UI while NetPulse is starting an authenticated poll; use the dashboard's router-check pause feature where available.

## Read-only checks

Run the local Home Assistant example validator if that integration is used:

```sh
python3 tools/validate_home_assistant.py
```

On a configured live host, inspect service status, logs, and route-expiry preflight before any control test:

```sh
sudo systemctl is-active netpulse
sudo python3 tools/route_expiry_preflight.py
```

The router readiness helper is read-only:

```sh
sudo python3 tools/router_control_readiness.py
```

A passing readiness check is configuration evidence only. It does not prove endpoint traffic moved or failover occurred.

## Source-bound WAN checks

When the host is configured with one source address per WAN and matching policy routes, run the optional live suite only with operator authorization for the generated probe traffic:

```sh
NETPULSE_LIVE=1 python3 -m unittest tests.test_live -v
```

It can check source-bound reachability, public egress, and dashboard response. It does not write router settings, run speed tests, or prove client failover. WAN-specific checks require configured addresses from the operator's own LAN; never use the documentation addresses from README as real assignments.

## Router write acceptance

For each write capability and each supported WAN:

1. Read and record the exact firmware and relevant router state.
2. Review the NetPulse preview and confirm the target is eligible and not a protected management path.
3. Apply one bounded operation to the approved endpoint.
4. Read the exact owned router object back and compare it with the intended state.
5. Verify endpoint behavior from a fresh request, keeping local management reachability separate from Internet reachability.
6. Remove or restore the exact object, read back again, and confirm the endpoint recovered.
7. Exercise interrupted-operation recovery where the maintenance plan permits it. Do not simulate power loss without a separate approved procedure.

Stop on any unexpected state, ambiguous ownership, failed read-back, or firmware mismatch. Preserve the failure evidence for the owner and do not retry by creating another rule.

## Specific limits to record

- Internet pause/resume is IPv4 only. Test IPv6 separately where present; passing IPv4 does not prove IPv6 is blocked.
- Validate WAN1 and WAN2 independently. A WAN1-only success is not dual-WAN acceptance.
- Validate ACL ordering and behavior when existing rules are present on the target firmware.
- Timed cleanup requires NetPulse to be running. A Pi-offline test does not cause NetPulse to clean up a rule.
- Router-native Priority failover is separate from NetPulse's timed cleanup and Smart WAN control. Verify client traffic during a controlled WAN outage.
- If using Smart WAN, confirm all group members have eligible reservations and matching live route read-back before opt-in. Observe stable recommendations and cooldown behavior before permitting automatic updates.

Record generic outcomes in release notes: model, firmware, test category, pass/fail, cleanup result, and remaining limit. Keep household-specific results and identifiers in private operator records.
