# Home Assistant (read-only)

NetPulse exposes an authenticated JSON API that Home Assistant can poll. These examples create WAN
health and latency sensors, router-reported link state, Pi health sensors, and home-device counts.
DHCP lease counts and LAN ping responders are not counts of people or proof of Internet access.
Telegram delivery sensors distinguish API acceptance and local delivery failures from device-notice
suppression by quiet hours, mute, or rate limiting. These process counters reset when NetPulse
restarts and do not prove that a person saw a notification.
The per-device LAN ping cycle sensor estimates how often each device is checked after fair rotation;
the inventory-supported binary sensor goes off when the device list exceeds the safe scan cap. An
unavailable cycle sensor means NetPulse has no supported inventory estimate to report.
Home Assistant cannot change the router through these examples.

Home Assistant's RESTful integration supports HTTP Basic authentication and configurable polling
intervals; see the [RESTful integration documentation](https://www.home-assistant.io/integrations/rest/).
The status API may include source-bound DNS/HTTPS diagnosis samples: once every two minutes during
normal or degraded operation, and once a minute after ICMP confirms a WAN offline. Each sample
includes the ICMP state observed when it ran and remains available for up to three minutes. The
diagnosis sensors below become unavailable when evidence is absent or expired; these secondary
checks never change NetPulse's WAN health state or routing decisions. Per-WAN binary sensors also
show whether a fresh ER605-assigned DNS resolver responded; they remain unavailable when the router
resolver is missing or stale.

Add the following to Home Assistant's `configuration.yaml`, replacing `netpulse-host.example` with the host name or address configured by the operator.

Check the YAML and Jinja templates locally with
`python tools/validate_home_assistant.py`. In a local development virtual environment, install its
optional dependencies with `python -m pip install -e ".[ha-validation]"`. This does not replace
Home Assistant's own configuration check.

```yaml
rest:
  - resource: http://netpulse-host.example:8080/api/status
    authentication: basic
    username: netpulse
    password: !secret netpulse_password
    scan_interval: 60
    sensor:
      - name: NetPulse WAN1 state
        value_template: >-
          {{ (value_json.wans | selectattr('name', 'equalto', 'WAN1')
              | map(attribute='state') | list | first | default('UNKNOWN')) }}
      - name: NetPulse WAN1 latency
        unit_of_measurement: ms
        state_class: measurement
        availability: >-
          {{ (value_json.wans | selectattr('name', 'equalto', 'WAN1')
              | map(attribute='rtt_ms') | list | first | default(none)) is not none }}
        value_template: >-
          {{ (value_json.wans | selectattr('name', 'equalto', 'WAN1')
              | map(attribute='rtt_ms') | list | first | default(0, true) | round(1)) }}
      - name: NetPulse WAN2 state
        value_template: >-
          {{ (value_json.wans | selectattr('name', 'equalto', 'WAN2')
              | map(attribute='state') | list | first | default('UNKNOWN')) }}
      - name: NetPulse WAN2 latency
        unit_of_measurement: ms
        state_class: measurement
        availability: >-
          {{ (value_json.wans | selectattr('name', 'equalto', 'WAN2')
              | map(attribute='rtt_ms') | list | first | default(none)) is not none }}
        value_template: >-
          {{ (value_json.wans | selectattr('name', 'equalto', 'WAN2')
              | map(attribute='rtt_ms') | list | first | default(0, true) | round(1)) }}
      - name: NetPulse WAN1 outage diagnosis
        availability: >-
          {{ (value_json.wans | selectattr('name', 'equalto', 'WAN1')
              | map(attribute='connectivity') | list | first | default(none)) is not none }}
        value_template: >-
          {{ (value_json.wans | selectattr('name', 'equalto', 'WAN1')
              | map(attribute='connectivity') | list | first | default({}, true))
              .get('diagnosis', 'Unknown') }}
      - name: NetPulse WAN2 outage diagnosis
        availability: >-
          {{ (value_json.wans | selectattr('name', 'equalto', 'WAN2')
              | map(attribute='connectivity') | list | first | default(none)) is not none }}
        value_template: >-
          {{ (value_json.wans | selectattr('name', 'equalto', 'WAN2')
              | map(attribute='connectivity') | list | first | default({}, true))
              .get('diagnosis', 'Unknown') }}
      - name: NetPulse Telegram API accepted messages since service start
        availability: >-
          {{ value_json.alert_policy.telegram_enabled
             and value_json.alert_policy.delivery_since_start is not none }}
        value_template: "{{ value_json.alert_policy.delivery_since_start.accepted | int(0) }}"
      - name: NetPulse Telegram messages queued
        availability: >-
          {{ value_json.alert_policy.telegram_enabled
             and value_json.alert_policy.delivery_since_start is not none }}
        value_template: "{{ value_json.alert_policy.delivery_since_start.queued | int(0) }}"
      - name: NetPulse Telegram messages failed since service start
        availability: >-
          {{ value_json.alert_policy.telegram_enabled
             and value_json.alert_policy.delivery_since_start is not none }}
        value_template: "{{ value_json.alert_policy.delivery_since_start.failed | int(0) }}"
      - name: NetPulse Telegram messages dropped locally since service start
        availability: >-
          {{ value_json.alert_policy.telegram_enabled
             and value_json.alert_policy.delivery_since_start is not none }}
        value_template: "{{ value_json.alert_policy.delivery_since_start.queue_dropped | int(0) }}"
      - name: NetPulse device notices accepted by Telegram since service start
        availability: >-
          {{ value_json.alert_policy.telegram_enabled
             and value_json.alert_policy.delivery_since_start is not none
             and value_json.alert_policy.delivery_since_start.get('categories', {}).get('device_notice') is not none }}
        value_template: >-
          {{ value_json.alert_policy.delivery_since_start.get('categories', {})
             .get('device_notice', {}).get('accepted', 0) | int(0) }}
      - name: NetPulse device notices queued
        availability: >-
          {{ value_json.alert_policy.telegram_enabled
             and value_json.alert_policy.delivery_since_start is not none
             and value_json.alert_policy.delivery_since_start.get('categories', {}).get('device_notice') is not none }}
        value_template: >-
          {{ value_json.alert_policy.delivery_since_start.get('categories', {})
             .get('device_notice', {}).get('queued', 0) | int(0) }}
      - name: NetPulse device notices failed since service start
        availability: >-
          {{ value_json.alert_policy.telegram_enabled
             and value_json.alert_policy.delivery_since_start is not none
             and value_json.alert_policy.delivery_since_start.get('categories', {}).get('device_notice') is not none }}
        value_template: >-
          {{ value_json.alert_policy.delivery_since_start.get('categories', {})
             .get('device_notice', {}).get('failed', 0) | int(0) }}
      - name: NetPulse device notices dropped locally since service start
        availability: >-
          {{ value_json.alert_policy.telegram_enabled
             and value_json.alert_policy.delivery_since_start is not none
             and value_json.alert_policy.delivery_since_start.get('categories', {}).get('device_notice') is not none }}
        value_template: >-
          {{ value_json.alert_policy.delivery_since_start.get('categories', {})
             .get('device_notice', {}).get('queue_dropped', 0) | int(0) }}
      - name: NetPulse device notices held by quiet hours since service start
        availability: >-
          {{ value_json.alert_policy.telegram_enabled
             and value_json.alert_policy.device_notice_suppressed_since_start is defined }}
        value_template: "{{ value_json.alert_policy.device_notice_suppressed_since_start.get('quiet_hours', 0) | int(0) }}"
      - name: NetPulse device notices muted since service start
        availability: >-
          {{ value_json.alert_policy.telegram_enabled
             and value_json.alert_policy.device_notice_suppressed_since_start is defined }}
        value_template: "{{ value_json.alert_policy.device_notice_suppressed_since_start.get('mute', 0) | int(0) }}"
      - name: NetPulse device notices rate-limited since service start
        availability: >-
          {{ value_json.alert_policy.telegram_enabled
             and value_json.alert_policy.device_notice_suppressed_since_start is defined }}
        value_template: "{{ value_json.alert_policy.device_notice_suppressed_since_start.get('rate_limited', 0) | int(0) }}"
    binary_sensor:
      - name: NetPulse WAN1 WAN DNS
        device_class: connectivity
        availability: >-
          {{ (value_json.wans | selectattr('name', 'equalto', 'WAN1')
              | map(attribute='connectivity') | list | first | default(none)) is not none
             and (value_json.wans | selectattr('name', 'equalto', 'WAN1')
              | map(attribute='connectivity') | list | first | default({}, true))
              .get('wan_dns_ok') is not none }}
        value_template: >-
          {{ 'ON' if (value_json.wans | selectattr('name', 'equalto', 'WAN1')
              | map(attribute='connectivity') | list | first | default({}, true))
              .get('wan_dns_ok') else 'OFF' }}
      - name: NetPulse WAN2 WAN DNS
        device_class: connectivity
        availability: >-
          {{ (value_json.wans | selectattr('name', 'equalto', 'WAN2')
              | map(attribute='connectivity') | list | first | default(none)) is not none
             and (value_json.wans | selectattr('name', 'equalto', 'WAN2')
              | map(attribute='connectivity') | list | first | default({}, true))
              .get('wan_dns_ok') is not none }}
        value_template: >-
          {{ 'ON' if (value_json.wans | selectattr('name', 'equalto', 'WAN2')
              | map(attribute='connectivity') | list | first | default({}, true))
              .get('wan_dns_ok') else 'OFF' }}

  - resource: http://netpulse-host.example:8080/api/devices
    authentication: basic
    username: netpulse
    password: !secret netpulse_password
    scan_interval: 300
    sensor:
      - name: NetPulse DHCP lease entries
        availability: "{{ value_json.configured and value_json.ready }}"
        value_template: "{{ value_json.devices | selectattr('listed') | list | length }}"
      - name: NetPulse LAN ping responders
        availability: "{{ value_json.configured and value_json.ready and value_json.presence_enabled }}"
        value_template: >-
          {{ value_json.devices | selectattr('listed')
             | selectattr('lan_presence.state', 'equalto', 'replying') | list | length }}
      - name: NetPulse LAN ping cycle per device
        unit_of_measurement: s
        state_class: measurement
        availability: >-
          {{ value_json.configured and value_json.ready
             and value_json.presence_probe_cycle_seconds is not none }}
        value_template: "{{ value_json.presence_probe_cycle_seconds | int }}"
      - name: NetPulse DHCP allocation records since service start
        availability: >-
          {{ value_json.configured and value_json.syslog.enabled }}
        value_template: "{{ value_json.syslog.accepted_allocations | int(0) }}"
      - name: NetPulse DHCP change events since service start
        availability: >-
          {{ value_json.configured and value_json.syslog.enabled }}
        value_template: "{{ value_json.syslog.device_events | int(0) }}"
      - name: NetPulse known DHCP renewals ignored since service start
        availability: >-
          {{ value_json.configured and value_json.syslog.enabled }}
        value_template: "{{ value_json.syslog.known_renewals_suppressed | int(0) }}"
      - name: NetPulse last DHCP allocation age
        unit_of_measurement: s
        state_class: measurement
        availability: >-
          {{ value_json.configured and value_json.syslog.enabled
             and value_json.syslog.listening and value_json.syslog.last_allocation_at is not none }}
        value_template: >-
          {{ (as_timestamp(now()) - (value_json.syslog.last_allocation_at | float)) | int }}
      - name: NetPulse Example Work Group group members
        availability: >-
          {{ value_json.groups is defined
             and (value_json.groups | selectattr('name', 'equalto', 'Example Work Group') | list | length) == 1 }}
        value_template: >-
          {{ (value_json.groups | selectattr('name', 'equalto', 'Example Work Group') | list | first).members | length }}
      - name: NetPulse Example Work Group enabled reservations
        availability: >-
          {{ value_json.groups is defined
             and (value_json.groups | selectattr('name', 'equalto', 'Example Work Group') | list | length) == 1 }}
        value_template: >-
          {{ (value_json.groups | selectattr('name', 'equalto', 'Example Work Group') | list | first).reserved_count | int(0) }}
      - name: NetPulse Example Work Group members blocked from routing
        availability: >-
          {{ value_json.groups is defined
             and (value_json.groups | selectattr('name', 'equalto', 'Example Work Group') | list | length) == 1 }}
        value_template: >-
          {{ (value_json.groups | selectattr('name', 'equalto', 'Example Work Group') | list | first).blocked_count | int(0) }}
      - name: NetPulse Example Work Group route readback
        availability: >-
          {{ value_json.groups is defined
             and (value_json.groups | selectattr('name', 'equalto', 'Example Work Group') | list | length) == 1 }}
        value_template: >-
          {{ (value_json.groups | selectattr('name', 'equalto', 'Example Work Group') | list | first).route_readback | default('unavailable') }}
      - name: NetPulse Example Work Group smart WAN
        availability: >-
          {{ value_json.groups is defined
             and (value_json.groups | selectattr('name', 'equalto', 'Example Work Group') | list | length) == 1 }}
        value_template: >-
          {{ 'On' if (value_json.groups | selectattr('name', 'equalto', 'Example Work Group')
              | list | first).smart_routing_enabled else 'Off' }}
    binary_sensor:
      - name: NetPulse DHCP event listener
        device_class: connectivity
        availability: >-
          {{ value_json.configured and value_json.syslog.enabled }}
        value_template: "{{ value_json.syslog.listening }}"
      - name: NetPulse LAN ping inventory supported
        availability: >-
          {{ value_json.configured and value_json.ready
             and value_json.presence_inventory_supported is not none }}
        value_template: "{{ value_json.presence_inventory_supported }}"
      - name: NetPulse Example Work Group route ready
        device_class: connectivity
        availability: >-
          {{ value_json.groups is defined and value_json.control is defined
             and (value_json.groups | selectattr('name', 'equalto', 'Example Work Group') | list | length) == 1 }}
        value_template: >-
          {%- set g = value_json.groups | selectattr('name', 'equalto', 'Example Work Group') | list | first -%}
          {{ 'ON' if value_json.control.enabled and g.blocked_count == 0
             and g.route_readback == 'matches' else 'OFF' }}
  - resource: http://netpulse-host.example:8080/api/router
    authentication: basic
    username: netpulse
    password: !secret netpulse_password
    scan_interval: 60
    sensor:
      - name: NetPulse ER605 firmware version
        availability: >-
          {{ value_json.router is defined and value_json.router is not none
             and value_json.router.firmware_version is not none }}
        value_template: "{{ value_json.router.firmware_version }}"
      - name: NetPulse ER605 uptime
        unit_of_measurement: s
        state_class: measurement
        availability: >-
          {{ value_json.router is defined and value_json.router is not none
             and value_json.router.uptime is not none }}
        value_template: "{{ value_json.router.uptime }}"
      - name: NetPulse ER605 full check age
        unit_of_measurement: s
        state_class: measurement
        availability: >-
          {{ value_json.router is defined and value_json.router is not none
             and value_json.router.checked_at is not none }}
        value_template: >-
          {{ (as_timestamp(now()) - (value_json.router.checked_at | float)) | int }}
    binary_sensor:
      - name: NetPulse ER605 uptime API reachable
        device_class: connectivity
        availability: "{{ value_json.router is defined and value_json.router is not none }}"
        value_template: "{{ value_json.router.ok }}"
      - name: NetPulse WAN1 WAN online detection
        device_class: connectivity
        availability: >-
          {{ value_json.router is defined and value_json.router is not none
             and value_json.router.links.WAN1.up is defined
             and value_json.router.links.WAN1.up is not none }}
        value_template: "{{ value_json.router.links.WAN1.up }}"
      - name: NetPulse WAN2 WAN online detection
        device_class: connectivity
        availability: >-
          {{ value_json.router is defined and value_json.router is not none
             and value_json.router.links.WAN2.up is defined
             and value_json.router.links.WAN2.up is not none }}
        value_template: "{{ value_json.router.links.WAN2.up }}"

  - resource: http://netpulse-host.example:8080/api/control
    authentication: basic
    username: netpulse
    password: !secret netpulse_password
    scan_interval: 60
    sensor:
      - name: NetPulse ER605 route-control state
        availability: "{{ value_json.configured is defined }}"
        value_template: >-
          {{ 'Not configured' if not value_json.configured else
             'Ready' if value_json.enabled else 'Locked' }}
      - name: NetPulse ER605 route-control lock reason
        availability: >-
          {{ value_json.configured and not value_json.enabled
             and value_json.reason is defined and value_json.reason | length > 0 }}
        value_template: "{{ value_json.reason }}"
    binary_sensor:
      - name: NetPulse ER605 route controls ready
        device_class: connectivity
        availability: "{{ value_json.configured }}"
        value_template: "{{ value_json.configured and value_json.enabled }}"
      - name: NetPulse ER605 firmware review required
        device_class: problem
        availability: >-
          {{ value_json.configured and value_json.firmware_review_required is defined }}
        value_template: "{{ value_json.firmware_review_required }}"

  - resource: http://netpulse-host.example:8080/api/system
    authentication: basic
    username: netpulse
    password: !secret netpulse_password
    scan_interval: 300
    sensor:
      - name: NetPulse Pi disk free
        unit_of_measurement: "%"
        state_class: measurement
        availability: >-
          {{ value_json.enabled and value_json.health is not none and not value_json.health.stale
             and value_json.health.disk_free_pct is not none }}
        value_template: "{{ value_json.health.disk_free_pct }}"
      - name: NetPulse Pi power check
        availability: >-
          {{ value_json.enabled and value_json.health is not none and not value_json.health.stale
             and value_json.health.power_check_status is defined
             and value_json.health.power_check_status is not none }}
        value_template: >-
          {{ {'available': 'available', 'tool_missing': 'vcgencmd missing from service PATH',
              'command_failed': 'vcgencmd command failed',
              'unexpected_response': 'unrecognized vcgencmd response'}
             .get(value_json.health.power_check_status, 'unknown') }}
      - name: NetPulse Pi SoC temperature
        unit_of_measurement: "°C"
        device_class: temperature
        state_class: measurement
        availability: >-
          {{ value_json.enabled and value_json.health is not none and not value_json.health.stale
             and value_json.health.temperature_c is not none }}
        value_template: "{{ value_json.health.temperature_c }}"
      - name: NetPulse Pi one minute load per core
        unit_of_measurement: "load/core"
        state_class: measurement
        availability: >-
          {{ value_json.enabled and value_json.health is not none and not value_json.health.stale
             and value_json.health.load_per_core is not none }}
        value_template: "{{ value_json.health.load_per_core }}"
      - name: NetPulse Pi memory available
        unit_of_measurement: "%"
        state_class: measurement
        availability: >-
          {{ value_json.enabled and value_json.health is not none and not value_json.health.stale
             and value_json.health.memory_available_pct is not none }}
        value_template: "{{ value_json.health.memory_available_pct }}"
      - name: NetPulse database backup status
        availability: >-
          {{ value_json.enabled and value_json.health is not none and not value_json.health.stale
             and value_json.health.backup is defined }}
        value_template: >-
          {%- set b = value_json.health.backup -%}{{ 'disabled' if not b.enabled else b.status | default('unknown') }}
      - name: NetPulse database backup age
        unit_of_measurement: h
        state_class: measurement
        availability: >-
          {{ value_json.enabled and value_json.health is not none and not value_json.health.stale
             and value_json.health.backup is defined and value_json.health.backup.enabled
             and value_json.health.backup.age_seconds is not none }}
        value_template: "{{ (value_json.health.backup.age_seconds / 3600) | round(1) }}"
      - name: NetPulse database backups retained
        availability: >-
          {{ value_json.enabled and value_json.health is not none and not value_json.health.stale
             and value_json.health.backup is defined and value_json.health.backup.enabled
             and value_json.health.backup.count is not none }}
        value_template: "{{ value_json.health.backup.count }}"
      - name: NetPulse backup destination free space
        unit_of_measurement: MB
        state_class: measurement
        availability: >-
          {{ value_json.enabled and value_json.health is not none and not value_json.health.stale
             and value_json.health.backup is defined and value_json.health.backup.enabled
             and value_json.health.backup.free_bytes is not none }}
        value_template: "{{ (value_json.health.backup.free_bytes / 1000000) | round(1) }}"
    binary_sensor:
      - name: NetPulse Pi health data stale
        device_class: problem
        availability: >-
          {{ value_json.enabled and value_json.health is not none
             and value_json.health.stale is defined }}
        value_template: "{{ value_json.health.stale }}"
      - name: NetPulse Pi disk low
        device_class: problem
        availability: >-
          {{ value_json.enabled and value_json.health is not none and not value_json.health.stale
             and value_json.health.disk_low is defined }}
        value_template: "{{ value_json.health.disk_low }}"
      - name: NetPulse Pi memory low
        device_class: problem
        availability: >-
          {{ value_json.enabled and value_json.health is not none and not value_json.health.stale
             and value_json.health.memory_low is not none }}
        value_template: "{{ value_json.health.memory_low }}"
      - name: NetPulse Pi undervoltage now
        device_class: problem
        availability: >-
          {{ value_json.enabled and value_json.health is not none and not value_json.health.stale
             and value_json.health.undervoltage is not none }}
        value_template: "{{ value_json.health.undervoltage }}"
      - name: NetPulse Pi undervoltage occurred this boot
        device_class: problem
        availability: >-
          {{ value_json.enabled and value_json.health is not none and not value_json.health.stale
             and value_json.health.undervoltage_occurred is not none }}
        value_template: "{{ value_json.health.undervoltage_occurred }}"
      - name: NetPulse Pi ARM frequency capped now
        device_class: problem
        availability: >-
          {{ value_json.enabled and value_json.health is not none and not value_json.health.stale
             and value_json.health.arm_frequency_capped is not none }}
        value_template: "{{ value_json.health.arm_frequency_capped }}"
      - name: NetPulse Pi CPU throttling now
        device_class: problem
        availability: >-
          {{ value_json.enabled and value_json.health is not none and not value_json.health.stale
             and value_json.health.throttled is not none }}
        value_template: "{{ value_json.health.throttled }}"
      - name: NetPulse Pi soft temperature limit now
        device_class: problem
        availability: >-
          {{ value_json.enabled and value_json.health is not none and not value_json.health.stale
             and value_json.health.soft_temp_limit is not none }}
        value_template: "{{ value_json.health.soft_temp_limit }}"
      - name: NetPulse Pi performance limiting occurred this boot
        device_class: problem
        availability: >-
          {{ value_json.enabled and value_json.health is not none and not value_json.health.stale
             and value_json.health.arm_frequency_capped_occurred is not none
             and value_json.health.throttled_occurred is not none
             and value_json.health.soft_temp_limit_occurred is not none }}
        value_template: >-
          {{ value_json.health.arm_frequency_capped_occurred
             or value_json.health.throttled_occurred
             or value_json.health.soft_temp_limit_occurred }}
```

In Home Assistant's `secrets.yaml`, add the password printed when NetPulse was installed:

```yaml
netpulse_password: "replace-with-the-NetPulse-dashboard-password"
```

Keep Home Assistant and NetPulse on a trusted home network. The NetPulse dashboard uses HTTP, so
Basic authentication protects access from casual LAN clients but does not encrypt traffic. Do not
port-forward the dashboard. ER605 WAN binary sensors describe the router's reported link/session
state; use the NetPulse WAN state sensors for Internet reachability and quality. The LAN responder
count is ICMP-only evidence, not an online-device or Internet-access count. Pi health entities become
unavailable when the sample is stale; **NetPulse Pi health data stale** remains available to show
that sampling stopped. Backup sensors report status, age, retained count, and free capacity without
exposing the configured path. Disabled backups report `disabled`; age, count, and free space are
unavailable until backups are enabled and a destination can be inspected. These examples are
read-only and do not expose controls to Home Assistant.
