# Everyday controls

## Telegram

Open **Devices** or **Groups**. Tap a listed item, or reply with its number; `1,2`
selects two items on the current page. Choose an action and confirm its review.
You do not need to type a MAC address, a command, or a confirmation token.

Pause offers **15 minutes**, **1 hour**, **6 hours**, or **Until resumed** before
the final review. Timed resume requires NetPulse to be running.

**Groups** also offers Create, Add devices, Remove devices, Rename, and Delete.
Create and Rename ask for an ordinary group name. All other choices come from
lists. **Help / More** contains reports, Pi health, speed tests, and alert controls.
Typed commands remain available for advanced use.

Controls and device lists are restricted to configured owners in their private
bot chats. A member who can receive alerts does not gain device-control access.
Old buttons expire; changes to a reviewed target require a new confirmation.

## Dashboard

Select devices, or choose **Manage** on one device or **Choose action** on a group.
The shared action panel shows the available choices. **Review action** lists every
target and any required DHCP reservations before confirmation. Device details and
advanced controls are expandable, separate from the everyday workflow.

## What each connection action means

| Action | Result |
|---|---|
| Auto balance | Remove the NetPulse WAN preference and use the ER605's normal policy. |
| Prefer WAN1 / WAN2 | Use a Priority rule. The router's own WAN detection can permit fallback. |
| Only WAN1 / WAN2 | Staged and unavailable until mode-transition forwarding and recovery are verified. |
| Pause Internet | Add the reviewed IPv4 LAN-to-WAN pause rule. |
| Resume Internet | Remove the exact saved NetPulse pause rule after verification. |

Strict WAN routing and Internet pause are separately disabled by default and limited to
the reviewed firmware. They do not control IPv6, mobile data, VPNs through another
path, or another router. A strict rule can leave a device without IPv4 Internet
when its selected WAN fails. Timed cleanup requires the Pi to be running.

## Reservations and multi-step changes

For an eligible DHCP client, a connection action prepares its missing reservation
automatically. The review shows the current IP and the reservation that will be
created. The device stays on automatic DHCP; IP-MAC binding remains off.
Conflicting, protected, ambiguous, or stale targets are rejected.

The server rechecks the entire reviewed selection before writing. Each router
change is read back. A later failure triggers verified rollback of completed route
or pause changes. If a newly created DHCP reservation must remain after a failure,
the result reports that partial state; it does not claim everything was undone.
Uncertain cleanup remains visible for repair.

Group membership updates use one SQLite transaction and compare the reviewed
group version. They do not silently change WAN routes or resume paused devices.
Membership changes stop Smart WAN until it is enabled again for the new members;
renaming the same membership preserves it. Removing a group leaves existing
device routes and pause intents available for individual management.

## Bandwidth and priority

A connection preference is not a bandwidth reservation or a traffic-priority
setting. The device bandwidth view reports router RX and TX rates from per-IP
byte-counter differences across two read-only ER605 samples, normally two seconds
apart. It binds results to a device only when fresh DHCP lists before and after
the sample show a unique, unchanged MAC-to-IPv4 address. Whole-IP rates are cached
for up to 15 seconds; stale, ambiguous, disabled, reset, or malformed data is
marked unavailable instead of shown as zero.

RX and TX are the router's observed directions; their client upload/download
meaning has not been validated. These measurements do not identify a WAN path.

WAN2 IPv4 caps are staged behind a code acceptance gate and
`router.bandwidth_controls_enabled = false`. When accepted and enabled, the
bandwidth submenu offers 2, 5, 10, 25, or 50 Mbps per device, applied equally to
upload and download, plus removal. A group applies the chosen cap separately to
each member; it does not share one allowance. Telegram uses the same selection,
review, and confirmation flow as connection actions. The dashboard keeps these
choices in a separate Bandwidth category.

The first cap review explicitly includes turning on the router-wide bandwidth
engine if it is off. This setup is allowed only when both QoS rule lists are
empty. Existing or unknown external QoS rules require manual review. Changing
caps can take 20 seconds. Failed operations attempt to restore the recorded
before-state; ambiguous recovery locks further controls. Recovery resumes after
service restart when the router is ready. Stored router caps remain effective
while the Pi is offline.

Traffic-class priority remains unavailable pending a congestion test. Choosing
Prefer WAN changes the route; it does not reserve bandwidth or increase a
device's traffic priority.

See [Internet controls](internet-controls.md), [configuration](CONFIGURATION.md),
and [optional administration access](ADMIN_ACCESS.md).
