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

## ER605 v2.30 / 2.4.10 compatibility and rollback plan

Prepared 2026-11-13. This is a proposed acceptance procedure, not authorization to run it or evidence of firmware compatibility. Target the exact build **2.4.10 Build 20260916 Rel.63334** in standalone mode. Keep production feature gates unchanged until the relevant evidence is complete. No firmware installation, downgrade, Omada adoption, DPI change, global routing change, or WAN disconnection is part of the initial trial.

### Findings and required engineering changes

| Area | Current implementation and evidence | Work required before enabling 2.4.10 |
| --- | --- | --- |
| Pause/resume | `netpulse/router/pause.py` pins `FIRMWARE` to 2.3.3 in readiness, preflight and cleanup checks. Pause writes IPv4 LAN-to-WAN ACLs. | Capture and sanitize 2.4.10 ACL envelopes/fields and IP scope/group metadata; verify canonical add/delete, ordering, all four connection states, exact preservation and cleanup. Extend every relevant check only for the exact tested feature/build. |
| Only WAN | `netpulse/router/control.py` pins `STRICT_WAN_FIRMWARE` to 2.3.3 and sets `STRICT_WAN_TRANSITIONS_VERIFIED = False`. Previous live testing found stale forwarding after an in-place Priority-to-Only update despite matching read-back. | Establish correct forwarding for every transition, WAN direction and rollback. If an in-place update fails, investigate a separately reviewed transaction/replacement strategy; do not blindly retry, flush all connections or briefly remove protection. Keep the gate closed if safe transitions cannot be demonstrated. |
| Protocol parsers | `netpulse/router/er605.py` accepts a narrow ACL schema and verifies row identity, placement and preservation. Known 2.4.10 changes already include IP-group `uniq_id` and a new DHCP pool shape. | Inspect ACL and policy-route schemas independently; do not infer their compatibility from working counters or Priority routing. Accept only observed, semantically neutral response metadata, with synthetic regression fixtures. Never strip unknown fields indiscriminately. |
| Pilot and recovery | `tools/router_acl_pilot.py` has its own 2.3.3 `PILOT_FIRMWARE` gate and an independent ACL watchdog/boot recovery service. It requires an empty ACL and reviewed endpoint prerequisites. | Prepare a 2.4.10-specific, one-endpoint trial path and recovery journal before permitting an add. Do not run the old pilot with its constant edited. Verify recovery independently of the polling service and Telegram. Prepare equivalent owned-object recovery for route trials; the existing ACL service is not a generic route rollback service. |
| Rollback | Normal pause cleanup still needs supported firmware, fresh state and no kill switch. Strict restore checks also inspect firmware. | Ensure the reviewed recovery runner can restore its exact journaled objects even when new actions are disabled. Keep ownership, schema, firmware and conflict checks. The normal kill switch is not an undo button: it can block normal cleanup too. |
| Telegram | Devices/Groups already expose the existing reviewed action hooks, pause durations, confirmation, cancellation and expiry. | Retain the same buttons; feed them truthful per-feature readiness. No additional chat command or pasted MAC/token should be needed. Show IPv4-only limits and Only-mode no-fallback behavior in the review. Revalidate backend capability at preview and confirmation. |

Prefer one shared, exact-build capability profile with separate pause, strict-routing and recovery acceptance evidence over scattered version substitutions or a global firmware-accepted flag. Track single-device, group and multirow acceptance separately; add backend scope gates before a single-device pass could expose unvalidated group actions. Unknown hardware/build/schema combinations stay disabled. Generic firmware acceptance alone must never enable these features. A passing pause trial must not unlock Only WAN, or vice versa.

The official [2.4.10 release notes](https://support.omadanetworks.com/en/document/136663/) list online-detection, IP-conflict, ARP-scanning and SIP ALG fixes; they do not document resolution of the observed Only-transition problem or compatibility of this private web API. This absence does not prove the issue remains; behavior needs measurement on the exact target.

### Preparation and local checks

1. Refresh a restricted authenticated read-only snapshot of model, exact firmware, stable uptime, WAN identity/detection state, DHCP/leases, scopes, groups, policy routes and the ordered ACL. Coordinate router login with the monitoring service; the router permits only one admin session. Do not change settings during discovery. Record incompatible or unknown schemas as a stop condition.
2. Export a fresh router configuration and back up application configuration, code version, database (including route/pause intents), and exact affected router objects. Store these root-private with hashes; keep an accessible offline copy. Confirm management access and recovery materials. A config export is insurance, not the normal rollback action.
3. Select one owner-approved disposable endpoint with a unique current lease and matching DHCP reservation. The router, Pi, administration PC, cameras and other critical devices are excluded. OnePlus devices are excluded by default; an owner may approve one positively identified test phone through the exact operation approval's `oneplus_trial_confirmed = true` field. This exception never overrides protected IP/MAC entries or saved-control/Smart WAN exclusions and must not be applied to the owner's other phones. If prerequisite scope/group/route/reservation objects must be created, include each exact write and its restoration in the approval; do not create them implicitly.
4. Record the endpoint's original route and expiry, ACL membership, reservation and relevant saved intents. Disable automatic steering for that endpoint only if necessary and explicitly approved, restoring its prior setting afterward. Do not silently disable group automation for unrelated members.
5. Build sanitized 2.4.10 fixtures and tests for protocol normalization, unknown/missing fields, reordered rows, concurrent edits, lost acknowledgements, duplicate callbacks, expiry, partial group failure, rollback, and unsupported builds. Keep the existing button-only end-to-end coverage. Run the repository unit suite and demo before releasing candidate code.
6. Rehearse the recovery runner against fixtures, including process termination, API timeout, retry after restart, and already-cleaned state. Use a monotonic/boot-aware deadline and persist a reboot-readable journal before the first mutation; existing wall-clock deadline assumptions require review. Verify service and boot recovery configuration, not just file presence.

### Proposed initial live trial: one endpoint, at most ten minutes

Approval must identify the private endpoint MAC/IP pair, exact firmware, a scheduled window, all prerequisite object writes, the individual ACL/routing operations and the recovery runner's permitted restoration. This document does not grant that approval. Use a temporary root-private allowlist and a narrow reviewed plan; never expose an unrestricted Telegram router-write command.

Bound each disruptive observation to at most 60 seconds, with an independent hard cleanup deadline of ten minutes for the trial. Use small endpoint-generated requests with a total trial cap of 25 MB; no throughput tests. A missed deadline or failed observation ends the trial and starts cleanup rather than extending the window. Stable power and someone able to reach the router are prerequisites. Cleanup requires the Pi to be powered; a Pi watchdog cannot guarantee recovery while the Pi is off.

Start the independent cleanup runner and confirm its health **before** any test object is added. Quiesce competing control writers and serialize router sessions without disabling Internet monitoring unnecessarily. Keep a separate LAN management session and collect endpoint-to-Pi heartbeats; Telegram is a status channel, not the recovery mechanism.

| Stage | Allowed experiment | Required evidence / stop condition |
| --- | --- | --- |
| Baseline | Endpoint uses its reviewed original route; no pause or strict rule is added. | Successful fresh IPv4 Internet requests, continuous LAN heartbeat, and distinguishable verified egress for both WANs. Use endpoint-originated evidence; Pi aliases do not establish client forwarding. If public egress cannot distinguish the WANs, arrange an independent packet-level observation or stop. |
| Pause on WAN1 | Add one uniquely named, journaled managed IPv4 drop rule for the approved endpoint; remove that exact unchanged rule. | Multiple independent Internet destinations fail for both new traffic and an established test flow, while Pi LAN heartbeat continues. After removal, Internet recovers and the full ACL and unrelated objects match the before-state. Stop immediately on another client's impact or lost LAN access. |
| Pause on WAN2 | Repeat only after WAN1 cleanup is verified, using the separately approved temporary endpoint preference if needed. | Same block/recovery evidence on WAN2, exact restore of the original preference and expiry, no unapproved residual objects. A WAN1 success cannot satisfy this stage. |
| Strict mode with both WANs up | Test Auto → Only WAN1/2, each Prefer WAN → each Only WAN, Only WAN1 ↔ Only WAN2, and Only → Prefer/Auto. One transition at a time with cleanup checkpoints. | Exact mode/interface read-back plus endpoint egress for fresh TCP/UDP requests and an already-established test flow. Old-WAN traffic after the operation reports success is a failure even when the form reads correctly. If established flows cannot be observed, acceptance is incomplete. Resolve stale flows with a separately reviewed device-scoped mechanism or keep strict mode blocked; do not silently redefine Only as new-connections-only. |
| Resume interaction | Review a saved pause, then resume it while preserving its original route, and test a paused endpoint's route change only in a separately journaled sequence. | Resume removes only its owned ACL. Route changes must not lift an active pause. Saved intents, router state and actual endpoint behavior agree. Never claim a rollback succeeded from database state alone. |

The old bounded ACL pilot requires an empty ACL. If discovery finds owner/unmanaged ACL rows, stop that pilot rather than moving, deleting or replacing those rows. Multirow pause support needs a later, specifically approved second disposable endpoint and insertion/removal-order tests. Do not enable group pause for all clients based on a one-row pass.

**Strict no-fallback acceptance is a separate gate.** Test each selected-WAN-unavailable condition in a lab/spare gateway or a separately approved brief household outage window. Only mode must lose IPv4 Internet without leaking via the other WAN, retain LAN access, and recover when its selected WAN returns. Prefer mode should retain its separate failover semantics. Endpoint firewall changes or a Pi-source probe do not simulate the router deciding a WAN is down. Do not unplug WAN cables or change global online-detection settings during the initial trial. Strict mode stays disabled until this gate and all transitions pass.

**Restart/expiry acceptance is separate too.** After safe add/remove behavior is established, approve a controlled worker termination/service restart to prove the independent deadline cleanup and persisted-state reconciliation. Test timed expiry, repeated Resume, already-absent rules, and loss of Telegram/SSH. A physical Pi power-loss or router reboot experiment needs a separate window and approval; fixtures alone do not establish real reboot cleanup. Permanent timed controls require a documented Pi-offline limitation, not a claim of router-native expiry.

### Abort and rollback procedure

1. Stop issuing new actions. Trigger the independent recovery runner; do not rely on pressing Telegram Resume, refreshing the dashboard or engaging the normal kill switch. Prevent normal control workers from racing with recovery.
2. Re-read exact firmware and all affected objects. Remove only the unique test ACL whose effective content matches the journal. Restore the original route fields, ordering where relevant, and expiry/intents; remove only prerequisite objects created by this trial, in dependency-safe order. Preserve all pre-existing scopes, groups, reservations and owner rules.
3. For a lost acknowledgement, inspect current state before deciding whether cleanup is needed. Do not repeat an add or delete by a stale row index. If an object has changed, has duplicates, or cannot be identified unambiguously, retain the recovery lock and journal for operator review; never delete a similar-looking owner object.
4. Compare complete affected lists with the before-state and prove endpoint Internet and LAN recovery. Restore endpoint steering settings and the monitor's prior running state. Confirm the dashboard and Telegram worker are healthy, without starting another speed test or sending inventories.
5. Keep feature-specific 2.4.10 production gates disabled on any failed or ambiguous result. If candidate software contributed, roll back the backed-up code/configuration while retaining the cleanup runner until router state is verified. Do not restore an old database blindly while test router objects remain.
6. If exact-object recovery fails, use the separate wired management path and saved object plan. A full configuration restore affects the household and is an explicitly reviewed escalation, not an automatic test retry. Firmware recovery/factory reset is a last resort requiring a person at the router and a separate decision; the vendor's [recovery procedure](https://support.omadanetworks.com/us/document/13056/) requires compatible firmware and physical access. Firmware downgrade is not the rollback strategy for this trial.

### Release acceptance and button behavior

Enable each feature independently only after exact-build schema tests, both-WAN packet evidence, transitions, interruption recovery and all relevant single/multirow or single/group cases pass. Keep group actions disabled until partial-failure rollback and member ownership have separate acceptance. Store generic evidence with build, hardware, test categories, date, software revision and cleanup result; keep endpoint identities and raw captures private. Firmware or ownership changes invalidate outstanding confirmations and require re-review.

The intended owner flow remains **Devices / Groups → select → Choose action → Pause / Resume / Only WAN1 / Only WAN2 → review → Confirm**. Pause includes duration; Only mode explicitly warns that there is no fallback. Unsupported builds, missing evidence or unresolved recovery show a reason and offer no apply path. The first acceptance test uses a scoped operator runner; production Telegram buttons are enabled only after acceptance, then checked against the same backend and read-back path. No permanent root-access button is needed.

### Local candidate implementation

The candidate code is implemented separately from production enforcement:

- `netpulse/router/compatibility.py` prepares an exact single-endpoint 2.4.10 operation. It requires a matching TLS pin/host, narrow hardware/build identity, unique current lease and reservation, pre-existing matching scope/group/route, empty ACL, settled readiness and explicit approval. Unknown route fields and protected endpoints are rejected. The candidate profile does not enable production pause or strict routing.
- `netpulse/router/trial.py` provides `build_plan`/`run_trial` integration with an operator-supplied endpoint observer. A trial performs one pause add/remove or one existing-route Only-mode transition/restore, always attempting restoration of the original state. It is not the full acceptance matrix or an automatic feature-acceptance tool. Each operation has a deadline of at most 60 seconds, after which cleanup starts; API failures or a powered-off Pi can prevent recovery by that deadline. Firmware, host/TLS identity, fresh target prerequisites, collections, watchdog readiness and deadline are checked before writing. The monitor's prior running state is journaled before quiescing it, and restored before clearing the recovery record; failed/abandoned workers retain the same restoration intent.
- The root-private journal is `/var/lib/netpulse/router-compat-trial/journal.json`; its directory must be root-owned mode `0700`. Journal, lock and readiness files are mode `0600`, bounded and reject symlinks/hardlinks or ambiguous data. The separate `/var/lib/netpulse/router-compat-status/pending` marker contains no inventory and blocks ordinary control writes while a trial or unresolved recovery is pending. Its status directory must be root-owned mode `0755` so the application can stat the marker and the capability-restricted root recovery unit can remove it without requiring write permission on the application-owned parent. Do not remove this marker to bypass a failed recovery.
- `tools/router_compat_trial.py` includes the real narrow router adapter, detached systemd watchdog and fixed-path recovery worker. It intentionally exposes no unrestricted `--apply` CLI. After owner selection/approval, the operator supplies a reviewed plan and endpoint probe to `run_trial`; no Telegram write bypass is added. `RouterTrialAdapter.for_trial` also requires the separate administration endpoint's IP for protection. The normal monitoring service must be quiesced before the candidate opens a router session.
- `IndependentWatchdog` requires the candidate boot recovery unit to be installed and enabled, starts a separate root systemd unit, then checks a per-journal nonce acknowledgment and active unit before allowing mutation. Boot-aware monotonic deadlines are immune to wall-clock changes; dead workers, changed boot identity and elapsed deadlines trigger exact recovery. Abnormal watchdog process exits can restart through systemd. Cleanup errors retain the journal/marker instead of repeatedly adding or deleting rules.
- `systemd/netpulse-compat-recovery.service` supplies boot recovery before the main service. The installer stages the worker and unit but does not enable candidate recovery or feature acceptance. Installing/enabling it and rehearsing the actual Pi/systemd behavior are required pre-trial steps; local Windows/mocked service tests do not establish reboot recovery. Verify the unit's boot ordering on the target Pi before any mutation.

Recovery does not depend on Telegram or ordinary new-action enable flags. It restores only the exact journaled ACL or route on the original router/build, checks unchanged related collections, and refuses ambiguous/changed ownership. A failed endpoint recovery observation retains a manual-review marker even if router objects were restored. Already-absent trial ACLs and already-restored routes are idempotent; an unrelated rule is never deleted as a substitute. Model/firmware or certificate changes, an orphan marker, corrupt journal, failed cleanup or a missing original route require operator review.

Before the live trial, collect the real 2.4.10 ACL/route schema and hardware strings and compare them to these intentionally narrow assumptions. The new fixtures are synthetic, not captured proof of compatibility. Prepare the protected journal directory, install and enable boot recovery, rehearse a no-mutation watchdog lifecycle, and review the chosen endpoint and observer. Existing production firmware gates and `STRICT_WAN_TRANSITIONS_VERIFIED = False` remain unchanged. Multirow/group pause, no-fallback under a selected-WAN outage, and full transition/reboot acceptance still need their separate planned stages.

Local verification: the full suite ran 901 tests with 7 skipped; the focused candidate/recovery suite passed 28 tests. The demo HTTP endpoint started, Python compilation and installer shell syntax checks passed. These local checks use synthetic router state and mocked systemd lifecycle calls; they do not establish live enforcement or acceptance.

The worker also supports an explicitly journaled `rehearsal` mode. It selects a synthetic no-network adapter before any configuration or credentials are loaded; it never constructs an ER605 client and rejects mutation attempts. This exercises actual process/deadline handling, service restoration, journal locking/clearing and the boot recovery entry point without selecting a real endpoint. Normal trials retain the default `live` mode and exact plan validation. Staging checks can exercise the boot entry point without a physical reboot; that is not proof of full power-loss recovery. Read-only discovery also confirmed the target's literal model and hardware strings are both `ER605 v2.30`; that exact spelling is accepted alongside the existing narrow forms.

Pi staging and synthetic rehearsal completed after local verification. Runtime file hashes, unchanged configuration, dashboard authentication, monitoring health and the enabled recovery unit were verified. The actual systemd checks covered deadline cleanup, abandoned operator-process cleanup, watchdog SIGKILL/restart and the restricted boot-recovery entry point without a physical reboot. The first boot-entry attempt exposed a status-marker parent-directory permission problem and monitoring restart-rate limiting during the repeated rehearsal; the root-owned status directory fixes the permission issue, and marker-removal failures now retain the exact journal. The corrected restricted boot entry passed. Temporary rehearsal locks were cleared and the prior control guard state restored.

Read-only authenticated router snapshots before and after rehearsal matched for policy routes, ACLs, IP scopes/groups and DHCP reservations. The rehearsal selected no real endpoint and made no router-rule writes. This establishes staging and synthetic recovery behavior only; it does not satisfy live enforcement, selected-WAN outage, real reboot, multirow or group acceptance.

### Temporary preparation-object recovery

`netpulse/router/preparation.py` now provides a separate reviewed preparation plan and bounded `run_preparation` transaction for a reservation, exact-IP scope, source group and Priority route. These four objects must all be absent before the plan is built. A unique current lease, exact hardware/build, protected management endpoints, unambiguous IPv4 LAN/DHCP pool, empty ACL and no saved pause/route/Smart WAN intent are required. The plan is specific to the reviewed MAC/IP, note and WAN; it cannot adopt pre-existing objects or references to its proposed namespace.

The version-2 journal retains the immutable before-state and proposed objects plus a write-ahead `inflight` position and append-only read-back receipts. Each create intent is fsynced before its RPC. Exact returned row IDs and known generated metadata are persisted after read-back. Lost acknowledgments never cause an automatic repeat of the create: recovery can capture a uniquely matching attempted row before deleting it. Unknown fields, duplicate identities, edited objects, changed generated identities, foreign configuration edits or a mismatched journal generation preserve the recovery lock for operator review.

Recovery deletes only the attempted/created prefix, in reverse dependency order: route, group, scope, reservation. It re-resolves row positions/IDs immediately before deletion, verifies exact receipt content and preservation of the remaining list, and treats already-absent owned objects as clean. Missing parent/child rows are not recreated during recovery. The original collections, monitor state and marker lifecycle are verified before recovery is cleared. Preparation does not change saved device intents, force a DHCP release, or enable production enforcement.

The matcher accounts only for narrowly observed 2.4.10 response conventions: write-only scope start/end fields may be derived from its exact range, an omitted empty group comment stays empty, and known configuration metadata is bounded. Group reference counts are derived from the route list and can change as the transaction creates/removes its own route; semantic group fields and generated identities remain checked. Route interface display labels must agree with the selected firmware interface mapping. Non-neutral reservation options, different rule types or unknown metadata are not silently discarded.

`run_preparation` defaults to preparation-only create/read-back/teardown. An explicitly reviewed optional pause child can now share the same version-2 journal. The observer must first verify the prepared endpoint's IPv4/LAN connectivity and WAN1 egress. A durable child intent and separate deadline of at most 60 seconds precede the ACL RPC; read-back precedes the block observation. Resume removes the exact child ACL before observing connectivity, and recovery always removes that child before the route, group, scope and reservation. Lost child acknowledgments use the same narrow ownership matching. Do not nest independent journals at the fixed path. Code availability does not grant permission for real router changes.

The no-network rehearsal worker recognizes a version-2 preparation journal and uses only a root-private `rehearsal-state.json` fixture. It simulates deletion of synthetic objects without loading router credentials or constructing an ER605 client. A synthetic rehearsal can cover every partial prefix, missing create acknowledgment, owner exit, watchdog restart, boot recovery entry and retained-lock failure, without creating any actual router reservation, address object or rule.

Preparation recovery validation completed locally (917 tests run, 7 skipped; 44 focused preparation/candidate tests passed) and on the Pi. Nine actual systemd/no-network scenarios passed: rollback after each of the four created prefixes, missing add acknowledgment, abandoned owner process, watchdog SIGKILL/restart, restricted boot recovery, and an edited synthetic object that retained its lock until the fixture was explicitly repaired. The staged runtime hashes matched the tested code. Read-only authenticated before/after router collections were identical; the selected endpoint's real preparation objects remained absent. Configuration and dashboard authentication were retained, monitoring was active, and temporary guards/journals/markers were cleared or restored to their prior state. No reservation/routing changes or live endpoint probes were authorized or performed by this validation.

The watchdog follows validated append-only preparation receipts instead of treating normal journal progress as a different generation. Its effective deadline includes the child pause deadline, which cannot be extended by later updates. The opt-in endpoint observer uses independent IPv4-only destinations, requires LAN heartbeat during blocking, and records public egress for WAN attribution. When ISP NAT hides the native WAN address, an operator must verify the existing exact-source Only routes and distinct external WAN references before comparing endpoint egress. These checks do not establish IPv6 enforcement or dedicated established-session acceptance.

Combined local verification ran 923 tests with 7 skipped; 73 focused tests passed, both endpoint JavaScript variants passed Node syntax checking, and the synthetic demo served HTTP 200. Two actual Pi/systemd no-network combined rehearsals covered acknowledged and missing child acknowledgments, journal progress, the child deadline and complete synthetic teardown. Live endpoint results must be recorded separately.

The owner-authorized first endpoint attempt stopped at the initial page baseline timeout, before any preparation or ACL RPC. Read-only comparison verified all reservation, scope, group, route and ACL collections unchanged. Monitoring and dashboard authentication remained active; configuration was unchanged and the temporary guard, journal and pending marker were clear. This is a safe abort, not live enforcement acceptance. A new owner-present page session is required to run the bounded trial.

For a replacement test phone, expire the old probe link and discard the old endpoint plan. Identify the new endpoint through an owner-opened, tokenized, read-only page whose direct LAN peer matches one unique current lease; router labels alone are insufficient when several phones share a brand/model name. Recheck the lease, management exclusions, existing reservation/routing and group membership before generating its own private plan. Preserve group membership rather than removing a device from a group implicitly. An exception approval remains immutable inside the recovery journal.

Single-phone exception verification: 925 local tests ran with 7 skipped, including 51 focused compatibility/preparation tests. Tests cover default OnePlus exclusion, strict boolean approval, immutable journal preservation, protected IP/MAC rejection and retained saved-control exclusions. The two updated modules were staged with verified hashes; no production protection configuration was changed.

Authenticated 2.4.10 preparation exposed another response convention: `ipscope_list` includes the created user scope as well as LAN scopes. Validation removes at most one full row identical to the already ownership-validated preparation scope before comparing the original list. Different metadata, duplicates, unrelated new scopes or missing original scopes still retain the recovery lock. The initial live attempt stopped after reservation/scope creation, before group/route/ACL creation; exact journal recovery then removed those two objects and cleared its locks. No pause enforcement was attempted. The full suite passed with 926 tests run and 7 skipped; 52 focused compatibility/preparation tests passed, including mirrored-scope lifecycle and foreign-edit rejection. Repeated operator checks can hit the existing monitor restart limit; restore and verify monitoring before retrying, without disabling that limit.

### Bounded single-phone WAN1 result

The owner positively identified a replacement test phone through its direct LAN peer, approved its exact private plan, and passed the endpoint baseline. Four temporary setup objects were created with durable receipts. Endpoint public egress matched the independently source-verified WAN1 reference. The temporary IPv4 ACL was created and read back, but enforcement failed acceptance: the ipify probe still succeeded while the independent Cloudflare probe failed and LAN heartbeat remained healthy. The observer therefore rejected the pause and entered full recovery; it did not report a successful normal resume trial. This does not determine whether connection reuse, forwarding acceleration or another firmware behavior explains the surviving traffic.

Full rollback was verified by exact before/after router collection equality. The temporary ACL, policy route, group, scope and reservation were removed, endpoint IPv4/LAN recovery was observed, and dashboard groups/saved routes and configuration were unchanged. Monitoring was active, dashboard authentication returned HTTP 401 without credentials, temporary guards were restored and recovery journal/marker were clear. Other phones were not selected. The final private report and artifacts remain outside the repository. Production pause/Only gates remain locked. A later separately reviewed diagnosis must distinguish fresh and established traffic and explain the surviving path before acceptance; this attempt does not establish IPv6, strict routing, both-WAN or physical power-loss behavior.

The next diagnostic path is documented in [Pause diagnostics](PAUSE_DIAGNOSTICS.md). Its opt-in `native_flow` preparation plan requires native socket evidence in addition to the existing WAN1/identity checks; a browser-only observation cannot satisfy it. It preserves the same single journal, child deadline, protected endpoints and complete teardown. The owner deferred USB/live work, so passive staging and synthetic recovery checks do not authorize an unattended phone trial or enable production controls.
