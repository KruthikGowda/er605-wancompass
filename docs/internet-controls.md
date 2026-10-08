# Internet pause and resume

Device and group IPv4 Internet pause/resume is implemented, but live activation must remain disabled until the exact router firmware and deployment pass the acceptance gates below. Unit tests do not prove packet enforcement. Obtain explicit authorization from the network owner for every live validation and verify the firmware before writing.

The feature controls IPv4 Internet access through the configured router. It does not control IPv6, a device mobile connection, or other network paths. Router-native Priority WAN failover operates independently. Timed resume requires NetPulse to be running; an ACL can remain active while the host is offline.

## Owner controls

Device and group actions use the same flow: select Pause or Resume, review every target and
duration, then confirm a short-lived preview. Telegram commands are owner-only:

- `/pause <MAC or exact device name> [15m|1h|6h|until-resumed]`
- `/resume <MAC or exact device name>`
- `/group_pause <exact group name> [15m|1h|6h|until-resumed]`
- `/group_resume <exact group name>`
- `/paused` and `/pause_confirm TOKEN`

Resume can find an exact saved pause name even when the device is no longer in the router list.
If that name matches multiple MAC addresses, use the MAC shown by `/paused`. Saved-name lookup
is limited to resume; it does not make an offline device eligible for a new pause or WAN change.

Durations default to one hour. Timed resume needs the Pi running; the router ACL persists while
the Pi is off, and cleanup resumes when safe checks succeed after it returns. This is separate
from the router's native Priority WAN failover, which does not need the Pi. The feature controls
IPv4 Internet access through this router, not a phone's mobile data or other networks.

## Saved state and repair

Before a router write, NetPulse saves the exact target, rule identity, actor, and expiry. A verified
pause becomes `paused`. Interrupted or uncertain changes retain an intent marked `applying`,
`resuming`, or `error`; they must not be described as proven Internet status. A fresh read-back
must prove the exact owned rule is absent before a saved pause can be cleared. Changed or
ambiguous rules need investigation and are left untouched.

Every saved pause intent prevents device route and reservation changes, including Smart WAN.
Timed WAN preference expiry waits for verified pause removal. Group actions recheck membership
between writes and restore completed changes if a member fails; unresolved rollback remains
visible. Removing a group or member does not silently resume Internet access: the individual
saved pause remains available for owner repair.

New pauses default to disabled with `router.internet_controls_enabled = false`. Turning off new
pauses must still permit verified cleanup of saved rules when router safety checks pass.
`router.protected_macs` adds owner-designated exclusions to the Pi and management-path checks.
The local kill switch, reviewed firmware, fresh router state, and recovery locks still apply.

## Activation gates

Before enabling controls on a deployment:

1. Pass the controller, durable-store, protocol, HTTP, Telegram, renderer, and full regression
   suites, including interrupted writes, group rollback, saved-state repair, and expiry.
2. Verify the current firmware and IPv6 configuration. Test every supported Internet path;
   IPv4-only success cannot prove IPv6 blocking.
3. With WAN2 available, repeat client-originated block, LAN callback, cleanup, and recovery
   through that WAN. Use the approved expendable endpoint.
4. Verify multirow insertion/order and preservation of existing owned rules on this firmware.
   Insertion and ordering behavior with existing rules must be measured on the target firmware.
5. Rehearse timed resume and interruption recovery, and review the Pi-offline expiry limitation
   before opting in. A saved-state unit test does not prove a physical power-loss drill.

Off-host backup configuration and restore testing are separate deployment prerequisites.
