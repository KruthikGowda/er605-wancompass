# Diagnosing traffic that survives a pause

The bounded 2.4.10 trial verified WAN1 egress and read back the IPv4 drop ACL, but one public check still succeeded. Exact router rollback and endpoint recovery completed. Pause and strict Only-WAN production gates remain locked. Rule read-back is not enforcement evidence.

## What is known

The browser observer used fresh URLs and `cache: no-store`. Those settings address HTTP response caching, not TCP connection reuse. [HTTP/2 permits connection reuse](https://www.rfc-editor.org/rfc/rfc9113.html#section-9.1.1), and the [Fetch cache option](https://developer.mozilla.org/en-US/docs/Web/API/Request/cache) controls response-cache behavior. The previous result therefore cannot distinguish a surviving existing connection from an allowed new connection, nor establish the router's internal offload mechanism. The escaped request's complete socket/path evidence was not preserved.

The corrected test must also rule out mobile-data/VPN fallback and establish that both destinations work through WAN1 before interpreting their failures. Existing-session/forwarding-cache bypass is a hypothesis, not a confirmed firmware diagnosis.

Read-only inspection of the installed firmware's public form map exposed ACL, MAC-filter and session-limit forms, but no device-only connection-clear operation. This does not prove that every possible vendor interface lacks one. MAC filtering and session limiting were disabled at inspection. Neither setting was enabled; no global connection flush, DPI change, router reboot, WAN disruption or unrelated phone change was attempted.

## Prepared diagnostic path

`tools/adb_flow_probe.py` performs phone-originated observations without changing phone settings or router rules. The operator supplies private files for the already reviewed USB serial/MAC/IP and current Pi probe URL. It verifies the selected phone's active Wi-Fi identity, mobile data off and VPN absence before contacting test endpoints and again for each phase. Public requests bind to the reviewed Wi-Fi IPv4 address, bypass proxies, retain TLS verification and use HTTP/1.1.

- Fresh checks use separate native curl processes. A successful fresh request must report a new connection, the reviewed local address and a public IPv4 remote socket. The ipify destination is pinned to its baseline public IPv4 address while retaining hostname/certificate verification; Cloudflare uses its explicit IPv4 endpoint.
- One curl process makes a verified public request, waits at the private Pi barrier, then requests the same public origin after ACL read-back. The baseline must be available to the controller before applying the ACL. Reuse requires zero new connects and identical local/remote socket endpoints. A successful reconnect is inconclusive, not evidence about an established flow. Curl's [write-out connection metrics](https://curl.se/docs/manpage.html#-w) support these checks. Metrics use unbuffered stderr merged into the private evidence pipe so the baseline cannot remain buffered behind the barrier.
- The one-use barrier is available only to the selected phone/token during `prepared`. It releases only on `blocked`, cancels on recovery/close and times out independently. The browser page for a native endpoint runs no probes and cannot accidentally supply the native report.
- `netpulse/router/flow_evidence.py` validates reports in the HTTP endpoint and trial controller. A plan created with `native_flow=True` retains `observation: native_flow` in its immutable journaled plan. Browser-only booleans cannot satisfy that requirement. Both native destinations must pass in prepared/recovery observations; prepared egress must independently match WAN1.
- If either fresh traffic or the verified reused request succeeds during the pause, the trial fails and rolls back. Certificate, identity, unsupported curl, protocol, barrier or ambiguous response errors are inconclusive and cannot count as blocking.

Raw socket evidence, observed public egress and Pi acknowledgment status are saved atomically after each phase to the operator's private output file, including partial evidence on failure. Do not commit these files or paste raw output into chats, issues or public logs.

## Next owner-present trial

The owner deferred USB/live phone work. The diagnostic code is staged passively; no new live trial is armed. A root-private Nord-specific proposed test recipe is prepared outside the repository. Do not reuse an old page or silently select another OnePlus phone.

1. Positively match the currently authorized Nord USB connection to its fresh router lease and reviewed MAC/IP. Keep all other phones protected. Confirm the owner is available and review the exact current reservation/scope/group/Priority-WAN1/ACL payloads. Recheck groups, saved intents, router TLS identity and exact firmware; stop on drift or competing configuration.
2. Start the opt-in native endpoint with `EndpointProbe(..., include_egress=True, native_flow=True)`. Supply its private URL file to the native reporter. Use `preparation_plan(..., pause_name=<reviewed unique name>, native_flow=True)` and the existing `run_preparation` API with the native observer. There is no unrestricted apply CLI.
3. Require a healthy phone-originated IPv4/LAN baseline before setup. Arm and acknowledge the independent watchdog before mutations. The overall bundle remains bounded to 480 seconds, with a separate pause cleanup deadline of at most 60 seconds. Pi/router failure can prevent cleanup by that deadline.
4. Verify both WAN1 destinations and the prepared persistent socket before the ACL. After ACL read-back, release the barrier and collect fresh-versus-reused results within the remaining pause window. Lost USB/LAN/observer evidence must cause recovery, not an optimistic success.
5. Remove the exact unchanged ACL before route, group, scope and reservation. Verify original router collections, groups/saved routes and configuration, endpoint IPv4/LAN recovery, active monitoring/authentication and clear recovery journal/marker. Never force a DHCP release or remove the phone from a dashboard group implicitly.

Interpretation:

| Observation | Supported conclusion |
|---|---|
| Fresh requests fail; a socket-proven reused request succeeds | Existing-session survival is observed; investigate a supported device-scoped remedy before enabling pause. This does not by itself prove hardware offload is the internal cause. |
| A verified fresh request succeeds | New-connection enforcement also failed; investigate rule installation/matching/forwarding rather than blaming reuse alone. |
| Fresh and existing observations fail, healthy LAN and before/after recovery brackets pass | The tested IPv4 paths stopped in this bounded trial. Full feature acceptance still needs the documented both-WAN/flow matrix. |
| Reconnection, TLS/identity failure, missing metrics, lost barrier or incomplete recovery evidence | Inconclusive; recover and keep controls locked. |

The existing watchdog/journal remains responsible for router cleanup independently of ADB, Telegram and ordinary new-action flags. IPv6, other protocols, selected-WAN outage behavior and physical power-loss recovery remain separate acceptance requirements.

## Verification

Local tests include a real loopback-only HTTP/1.1 curl rehearsal that proves the same socket is retained across a different LAN origin/barrier. No phone or router is used. Contract tests cover fresh-connection metrics, false blocking from TLS/protocol errors, reconnect rejection, a surviving reused flow, partial evidence retention, stale/wrong endpoint rejection and full setup/ACL rollback. Pi/systemd synthetic rehearsals cover the native-observation journal, child cleanup deadline, acknowledged/missing child receipts and exact synthetic teardown. These rehearsals are not live packet-enforcement acceptance.

Verification completed on 2026-11-14: 944 local tests ran with 7 skipped; 94 focused native-probe/candidate/recovery tests passed. The synthetic dashboard served HTTP 200, Python compilation and diff checks passed. Three runtime modules were staged on the Pi with verified hashes; both actual systemd synthetic watchdog cases passed. Configuration and dashboard authentication were preserved, monitoring was active, and temporary guard/journal/marker state was clear or restored. No router-setting writes or new live Nord trial were performed in this diagnostic preparation.
