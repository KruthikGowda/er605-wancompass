#!/usr/bin/env python3
"""Validate the read-only Home Assistant YAML example and render its Jinja templates.

Optional developer tool. Requires PyYAML and Jinja2; neither is a NetPulse runtime dependency.
Run from any directory with ``python3 tools/validate_home_assistant.py``.
"""

from __future__ import annotations

import re
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "home-assistant.md"
EXPECTED_RESOURCES = (
    "/api/status", "/api/devices", "/api/router", "/api/control", "/api/system",
)


def _dependencies():
    try:
        import yaml
        from jinja2 import Environment, StrictUndefined
    except ImportError as exc:
        raise SystemExit(
            "This optional check requires PyYAML and Jinja2; install them in your development "
            "environment and retry."
        ) from exc
    return yaml, Environment, StrictUndefined


def _config_from_markdown(path: Path, yaml):
    text = path.read_text(encoding="utf-8")
    match = re.search(r"```yaml\s*\n(.*?)```", text, re.DOTALL)
    if not match:
        raise ValueError(f"No YAML configuration block found in {path}.")

    class Loader(yaml.SafeLoader):
        def construct_mapping(self, node, deep=False):
            self.flatten_mapping(node)
            result = {}
            for key_node, value_node in node.value:
                key = self.construct_object(key_node, deep=deep)
                if key in result:
                    raise ValueError(f"Duplicate YAML key: {key}")
                result[key] = self.construct_object(value_node, deep=deep)
            return result

    # Home Assistant's !secret is a scalar reference; retain it as a string while parsing.
    Loader.add_constructor("!secret", lambda loader, node: loader.construct_scalar(node))
    config = yaml.load(match.group(1), Loader=Loader)
    if not isinstance(config, dict) or not isinstance(config.get("rest"), list):
        raise ValueError("Expected a top-level 'rest' list in the Home Assistant example.")
    return config


def _sample_payloads(now: datetime):
    timestamp = now.timestamp()
    return (
        {
            "alert_policy": {
                "telegram_enabled": True,
                "device_notice_suppressed_since_start": {
                    "mute": 1, "quiet_hours": 2, "rate_limited": 3,
                },
                "delivery_since_start": {
                    "accepted": 9, "queued": 1, "failed": 2, "queue_dropped": 3,
                    "categories": {"device_notice": {
                        "accepted": 4, "queued": 2, "failed": 1, "queue_dropped": 2,
                    }},
                },
            },
            "wans": [
                {
                    "name": "WAN1", "state": "OFFLINE", "rtt_ms": None,
                    "connectivity": {
                        "checked_at": timestamp, "dns_ok": True, "https_ok": True,
                        "wan_dns_ok": True,
                        "diagnosis": "ICMP probes failed, but DNS and HTTPS are reachable",
                    },
                },
                {"name": "WAN2", "state": "HEALTHY", "rtt_ms": 17.2, "connectivity": None},
            ],
        },
        {
            "configured": True, "ready": True, "presence_enabled": True,
            "presence_probe_cycle_seconds": 120,
            "presence_inventory_supported": True,
            "syslog": {
                "enabled": True, "listening": True, "accepted_allocations": 7,
                "duplicates_suppressed": 2, "device_events": 3,
                "known_renewals_suppressed": 4, "last_allocation_at": timestamp - 42,
            },
            "control": {"configured": True, "enabled": True},
            "groups": [{
                "name": "Example Work Group", "members": [f"member-{i}" for i in range(8)],
                "reserved_count": 1, "blocked_count": 7, "route_readback": "matches",
                "smart_routing_enabled": False,
            }],
            "devices": [{"listed": True, "lan_presence": {"state": "replying"}}],
        },
        {
            "router": {
                "uptime": 12345, "checked_at": timestamp, "ok": True,
                "firmware_version": "2.3.3 Build 20251029 Rel.18054",
                "links": {"WAN1": {"up": True}, "WAN2": {"up": False}},
            },
        },
        {
            "configured": True,
            "enabled": False,
            "reason": "ER605 firmware 2.4.0 needs review before route controls unlock.",
            "firmware_review_required": True,
            "firmware_version": "2.4.0 Build 20261001",
            "accepted_firmware_version": "2.3.3 Build 20251029 Rel.18054",
        },
        {
            "enabled": True,
            "health": {
                "disk_free_pct": 76.2, "disk_low": False,
                "memory_low": False,
                "checked_at": timestamp, "age_seconds": 15.0,
                "max_age_seconds": 600, "stale": False,
                "power_check_status": "tool_missing",
                "undervoltage": False, "undervoltage_occurred": False,
                "arm_frequency_capped": False, "arm_frequency_capped_occurred": False,
                "throttled": False, "throttled_occurred": False,
                "soft_temp_limit": False, "soft_temp_limit_occurred": False,
                "temperature_c": 48.5,
                "load_per_core": 0.12, "memory_available_pct": 64.5,
                "memory_available_mb": 642.0,
                "backup": {"enabled": True, "status": "ok", "latest_at": timestamp - 3600,
                           "age_seconds": 3600, "count": 3, "free_bytes": 5_000_000_000},
            },
        },
    )


def validate(path: Path = DOC) -> int:
    yaml, Environment, StrictUndefined = _dependencies()
    config = _config_from_markdown(path, yaml)
    resources = config["rest"]
    if len(resources) != len(EXPECTED_RESOURCES):
        raise ValueError(f"Expected {len(EXPECTED_RESOURCES)} REST resources; found {len(resources)}.")

    for resource, expected_path in zip(resources, EXPECTED_RESOURCES):
        url = resource.get("resource", "")
        if not url.endswith(expected_path):
            raise ValueError(f"Expected a REST resource ending in {expected_path}; found {url!r}.")

    now = datetime.now(timezone.utc)
    env = Environment(undefined=StrictUndefined)
    env.filters["float"] = float
    env.globals["as_timestamp"] = lambda value: (
        value.timestamp() if hasattr(value, "timestamp") else float(value)
    )
    payloads = _sample_payloads(now)
    templates = 0
    rendered: dict[tuple[str, str], str] = {}
    for resource, payload in zip(resources, payloads):
        for kind in ("sensor", "binary_sensor"):
            for entity in resource.get(kind, []):
                name = entity.get("name")
                if not isinstance(name, str) or not name:
                    raise ValueError(f"Found a {kind} without a name.")
                for field in ("availability", "value_template"):
                    template = entity.get(field)
                    if template is None:
                        continue
                    rendered[(name, field)] = env.from_string(template).render(
                        value_json=payload, now=lambda: now,
                    )
                    templates += 1

    expected_diagnosis = "ICMP probes failed, but DNS and HTTPS are reachable"
    if rendered.get(("NetPulse WAN1 outage diagnosis", "value_template")) != expected_diagnosis:
        raise ValueError("The WAN1 outage diagnosis did not render the expected sample value.")
    if rendered.get(("NetPulse WAN2 outage diagnosis", "availability")) != "False":
        raise ValueError("The WAN2 diagnosis should be unavailable when no recent result exists.")
    if rendered.get(("NetPulse WAN1 WAN DNS", "availability")) != "True":
        raise ValueError("The sample WAN1-assigned DNS sensor should be available.")
    if rendered.get(("NetPulse WAN1 WAN DNS", "value_template")) != "ON":
        raise ValueError("The sample WAN1-assigned DNS sensor should be on.")
    if rendered.get(("NetPulse WAN2 WAN DNS", "availability")) != "False":
        raise ValueError("The WAN2-assigned DNS sensor should be unavailable without fresh evidence.")

    system_resource = next(resource for resource in resources
                           if resource.get("resource", "").endswith("/api/system"))
    system_index = resources.index(system_resource)
    memory_sensor = next((entity for entity in system_resource.get("binary_sensor", [])
                          if entity.get("name") == "NetPulse Pi memory low"), None)
    if memory_sensor is None:
        raise ValueError("The Home Assistant Pi memory alert entity is missing.")
    if rendered.get(("NetPulse Pi memory low", "value_template")) != "False":
        raise ValueError("The healthy Pi memory sample should render the memory-low sensor off.")
    low_memory_payload = dict(payloads[system_index])
    low_memory_payload["health"] = {**payloads[system_index]["health"], "memory_low": True}
    if env.from_string(memory_sensor["value_template"]).render(value_json=low_memory_payload) != "True":
        raise ValueError("The low-memory sample should render the Pi memory-low sensor on.")
    unavailable_memory_payload = dict(payloads[system_index])
    unavailable_memory_payload["health"] = {**payloads[system_index]["health"], "memory_low": None}
    if env.from_string(memory_sensor["availability"]).render(value_json=unavailable_memory_payload) != "False":
        raise ValueError("The Pi memory-low sensor should be unavailable without a valid reading.")

    failed_dns_payload = payloads[0]
    failed_dns_payload["wans"][0]["connectivity"]["wan_dns_ok"] = False
    failed_dns_template = next(entity["value_template"] for entity in resources[0]["binary_sensor"]
                               if entity["name"] == "NetPulse WAN1 WAN DNS")
    if env.from_string(failed_dns_template).render(value_json=failed_dns_payload) != "OFF":
        raise ValueError("A failed WAN1-assigned DNS check should render off.")

    status_resource = next(resource for resource in resources
                           if resource.get("resource", "").endswith("/api/status"))
    status_payload = payloads[resources.index(status_resource)]
    status_entities = {entity["name"]: entity for entity in status_resource.get("sensor", [])}
    required_delivery_entities = {
        "NetPulse Telegram API accepted messages since service start": "9",
        "NetPulse Telegram messages queued": "1",
        "NetPulse Telegram messages failed since service start": "2",
        "NetPulse Telegram messages dropped locally since service start": "3",
        "NetPulse device notices accepted by Telegram since service start": "4",
        "NetPulse device notices queued": "2",
        "NetPulse device notices failed since service start": "1",
        "NetPulse device notices dropped locally since service start": "2",
        "NetPulse device notices held by quiet hours since service start": "2",
        "NetPulse device notices muted since service start": "1",
        "NetPulse device notices rate-limited since service start": "3",
    }
    if any(name not in status_entities for name in required_delivery_entities):
        raise ValueError("Telegram delivery or device-notice health entities are missing.")
    for name, expected in required_delivery_entities.items():
        entity = status_entities[name]
        actual = env.from_string(entity["value_template"]).render(value_json=status_payload)
        if actual != expected:
            raise ValueError(f"Home Assistant delivery sensor {name!r} rendered {actual!r}.")
        if env.from_string(entity["availability"]).render(value_json=status_payload) != "True":
            raise ValueError(f"Home Assistant delivery sensor {name!r} should be available.")
    no_telegram = {**status_payload, "alert_policy": {
        **status_payload["alert_policy"], "telegram_enabled": False,
    }}
    for name in required_delivery_entities:
        if env.from_string(status_entities[name]["availability"]).render(
                value_json=no_telegram) != "False":
            raise ValueError(f"Home Assistant delivery sensor {name!r} should be unavailable when Telegram is off.")
    no_category = {**status_payload, "alert_policy": {
        **status_payload["alert_policy"],
        "delivery_since_start": {**status_payload["alert_policy"]["delivery_since_start"],
                                 "categories": {}},
    }}
    for name in ("NetPulse device notices accepted by Telegram since service start",
                 "NetPulse device notices failed since service start",
                 "NetPulse device notices dropped locally since service start"):
        if env.from_string(status_entities[name]["availability"]).render(
                value_json=no_category) != "False":
            raise ValueError(f"Home Assistant device-notice sensor {name!r} should be unavailable without category data.")

    devices_resource = next(resource for resource in resources
                            if resource.get("resource", "").endswith("/api/devices"))
    devices_payload = payloads[resources.index(devices_resource)]
    device_entities = {entity["name"]: entity
                       for kind in ("sensor", "binary_sensor")
                       for entity in devices_resource.get(kind, [])}
    listener = device_entities.get("NetPulse DHCP event listener")
    count = device_entities.get("NetPulse DHCP allocation records since service start")
    event_count = device_entities.get("NetPulse DHCP change events since service start")
    renewal_count = device_entities.get("NetPulse known DHCP renewals ignored since service start")
    age = device_entities.get("NetPulse last DHCP allocation age")
    cycle = device_entities.get("NetPulse LAN ping cycle per device")
    inventory_supported = device_entities.get("NetPulse LAN ping inventory supported")
    if not listener or not count or not event_count or not renewal_count or not age or not cycle or not inventory_supported:
        raise ValueError("The DHCP or LAN presence health entities are missing.")
    if env.from_string(listener["value_template"]).render(value_json=devices_payload) != "True":
        raise ValueError("The sample DHCP syslog listener should be on.")
    if env.from_string(count["value_template"]).render(value_json=devices_payload) != "7":
        raise ValueError("The DHCP allocation counter did not render the sample value.")
    if env.from_string(event_count["value_template"]).render(value_json=devices_payload) != "3":
        raise ValueError("The DHCP change-event counter did not render the sample value.")
    if env.from_string(renewal_count["value_template"]).render(value_json=devices_payload) != "4":
        raise ValueError("The known DHCP renewal counter did not render the sample value.")
    if env.from_string(age["value_template"]).render(value_json=devices_payload, now=lambda: now) != "42":
        raise ValueError("The last DHCP allocation age did not render the sample value.")
    disabled_devices = {**devices_payload, "syslog": {
        "enabled": False, "listening": False, "accepted_allocations": 0,
        "duplicates_suppressed": 0, "device_events": 0,
        "known_renewals_suppressed": 0, "last_allocation_at": None,
    }}
    if env.from_string(listener["availability"]).render(value_json=disabled_devices) != "False":
        raise ValueError("The DHCP listener entity should be unavailable when syslog is disabled.")
    no_event_devices = {**devices_payload, "syslog": {
        **devices_payload["syslog"], "last_allocation_at": None,
    }}
    if env.from_string(age["availability"]).render(value_json=no_event_devices) != "False":
        raise ValueError("The DHCP age entity should be unavailable before an allocation is seen.")
    if env.from_string(cycle["value_template"]).render(value_json=devices_payload) != "120":
        raise ValueError("The LAN ping cycle sensor did not render the per-device interval.")
    if env.from_string(inventory_supported["value_template"]).render(
            value_json=devices_payload) != "True":
        raise ValueError("The LAN ping inventory support sensor did not render the sample value.")
    unsupported_presence = {
        **devices_payload,
        "presence_probe_cycle_seconds": None,
        "presence_inventory_supported": False,
    }
    if env.from_string(cycle["availability"]).render(value_json=unsupported_presence) != "False":
        raise ValueError("The LAN ping cycle sensor should be unavailable without a supported inventory.")
    if env.from_string(inventory_supported["availability"]).render(
            value_json=unsupported_presence) != "True":
        raise ValueError("The inventory support sensor should report unsupported inventories as false.")

    group_entities = {entity["name"]: entity
                      for kind in ("sensor", "binary_sensor")
                      for entity in devices_resource.get(kind, [])
                      if entity["name"].startswith("NetPulse Example Work Group ")}
    required_group_entities = (
        "NetPulse Example Work Group group members", "NetPulse Example Work Group enabled reservations",
        "NetPulse Example Work Group members blocked from routing",
        "NetPulse Example Work Group route readback", "NetPulse Example Work Group smart WAN",
        "NetPulse Example Work Group route ready",
    )
    if any(name not in group_entities for name in required_group_entities):
        raise ValueError("The read-only Example Work Group group readiness entities are incomplete.")
    group_expectations = {
        "NetPulse Example Work Group group members": "8",
        "NetPulse Example Work Group enabled reservations": "1",
        "NetPulse Example Work Group members blocked from routing": "7",
        "NetPulse Example Work Group route readback": "matches",
        "NetPulse Example Work Group smart WAN": "Off",
        "NetPulse Example Work Group route ready": "OFF",
    }
    for name, expected in group_expectations.items():
        entity = group_entities[name]
        actual = env.from_string(entity["value_template"]).render(value_json=devices_payload)
        if actual != expected:
            raise ValueError(f"Home Assistant group sensor {name!r} rendered {actual!r}.")
        if env.from_string(entity["availability"]).render(value_json=devices_payload) != "True":
            raise ValueError(f"Home Assistant group sensor {name!r} should be available.")
    ready_group = {**devices_payload,
                   "groups": [{**devices_payload["groups"][0],
                               "reserved_count": 8, "blocked_count": 0}],
                   "control": {"configured": True, "enabled": True}}
    if env.from_string(group_entities["NetPulse Example Work Group route ready"]["value_template"]).render(
            value_json=ready_group) != "ON":
        raise ValueError("The Example Work Group route-ready sensor should turn on when all readiness checks pass.")
    no_group = {**devices_payload, "groups": []}
    for name in required_group_entities:
        if env.from_string(group_entities[name]["availability"]).render(
                value_json=no_group) != "False":
            raise ValueError(f"Home Assistant group sensor {name!r} should be unavailable when the group is absent.")

    control_resource = next(resource for resource in resources
                            if resource.get("resource", "").endswith("/api/control"))
    control_payload = payloads[resources.index(control_resource)]
    control_entities = {entity["name"]: entity
                        for kind in ("sensor", "binary_sensor")
                        for entity in control_resource.get(kind, [])}
    required_control_entities = (
        "NetPulse ER605 route-control state", "NetPulse ER605 route-control lock reason",
        "NetPulse ER605 route controls ready", "NetPulse ER605 firmware review required",
    )
    if any(name not in control_entities for name in required_control_entities):
        raise ValueError("The read-only ER605 control readiness entities are incomplete.")
    if env.from_string(control_entities["NetPulse ER605 route-control state"]["value_template"]).render(
            value_json=control_payload) != "Locked":
        raise ValueError("The sample firmware change must show route controls as locked.")
    if env.from_string(control_entities["NetPulse ER605 route-control lock reason"]["value_template"]).render(
            value_json=control_payload) != control_payload["reason"]:
        raise ValueError("The route-control lock reason did not render the sample warning.")
    if env.from_string(control_entities["NetPulse ER605 route controls ready"]["value_template"]).render(
            value_json=control_payload) != "False":
        raise ValueError("Route controls must not appear ready while firmware review is pending.")
    if env.from_string(control_entities["NetPulse ER605 firmware review required"]["value_template"]).render(
            value_json=control_payload) != "True":
        raise ValueError("The firmware review sensor must activate for an unreviewed version.")
    ready_control = {**control_payload, "enabled": True, "firmware_review_required": False, "reason": ""}
    if env.from_string(control_entities["NetPulse ER605 route-control state"]["value_template"]).render(
            value_json=ready_control) != "Ready":
        raise ValueError("The reviewed, enabled sample must show route controls as ready.")
    unconfigured_control = {**control_payload, "configured": False, "enabled": False}
    if env.from_string(control_entities["NetPulse ER605 route-control state"]["value_template"]).render(
            value_json=unconfigured_control) != "Not configured":
        raise ValueError("The route-control state must distinguish disabled configuration from a lock.")
    if env.from_string(control_entities["NetPulse ER605 route controls ready"]["availability"]).render(
            value_json=unconfigured_control) != "False":
        raise ValueError("The readiness binary sensor must be unavailable when controls are not configured.")

    system_resource = next(resource for resource in resources
                           if resource.get("resource", "").endswith("/api/system"))
    system_payload = payloads[resources.index(system_resource)]
    power_entity = next((entity for entity in system_resource.get("sensor", [])
                         if entity.get("name") == "NetPulse Pi power check"), None)
    if power_entity is None:
        raise ValueError("The Pi power-check status sensor is missing.")
    power_states = {
        "available": "available",
        "tool_missing": "vcgencmd missing from service PATH",
        "command_failed": "vcgencmd command failed",
        "unexpected_response": "unrecognized vcgencmd response",
    }
    for status, expected in power_states.items():
        sample = {**system_payload, "health": {**system_payload["health"],
                                                "power_check_status": status}}
        actual = env.from_string(power_entity["value_template"]).render(
            value_json=sample, now=lambda: now,
        )
        if actual != expected:
            raise ValueError(f"Pi power-check status {status!r} rendered {actual!r}.")

    backup_entities = {entity["name"]: entity for entity in system_resource.get("sensor", [])
                       if entity["name"].startswith("NetPulse database backup")
                       or entity["name"] == "NetPulse backup destination free space"}
    backup_names = (
        "NetPulse database backup status", "NetPulse database backup age",
        "NetPulse database backups retained", "NetPulse backup destination free space",
    )
    if any(name not in backup_entities for name in backup_names):
        raise ValueError("The read-only Home Assistant backup sensors are incomplete.")
    status_entity = backup_entities["NetPulse database backup status"]
    for status in ("ok", "stale", "missing", "unavailable"):
        sample = {**system_payload, "health": {**system_payload["health"],
                                                "backup": {**system_payload["health"]["backup"],
                                                           "status": status}}}
        actual = env.from_string(status_entity["value_template"]).render(
            value_json=sample, now=lambda: now,
        )
        if actual != status:
            raise ValueError(f"Backup status {status!r} rendered {actual!r}.")
    disabled_backup = {**system_payload, "health": {**system_payload["health"],
                                                     "backup": {"enabled": False}}}
    if env.from_string(status_entity["value_template"]).render(
            value_json=disabled_backup, now=lambda: now) != "disabled":
        raise ValueError("Disabled backups must be reported explicitly.")
    absent_backup = {**system_payload, "health": dict(system_payload["health"])}
    absent_backup["health"].pop("backup")
    if env.from_string(status_entity["availability"]).render(
            value_json=absent_backup, now=lambda: now) != "False":
        raise ValueError("Backup status must be unavailable when backup data is absent.")

    stale_payload = dict(payloads[resources.index(system_resource)])
    stale_payload["health"] = {**stale_payload["health"], "stale": True}
    stale_rendered = {}
    for kind in ("sensor", "binary_sensor"):
        for entity in system_resource.get(kind, []):
            name = entity["name"]
            for field in ("availability", "value_template"):
                template = entity.get(field)
                if template is not None:
                    stale_rendered[(name, field)] = env.from_string(template).render(
                        value_json=stale_payload, now=lambda: now,
                    )
    if stale_rendered.get(("NetPulse Pi health data stale", "value_template")) != "True":
        raise ValueError("A stale Pi sample must activate the dedicated stale-data sensor.")
    for kind in ("sensor", "binary_sensor"):
        for entity in system_resource.get(kind, []):
            if entity.get("name") == "NetPulse Pi health data stale":
                continue
            if stale_rendered.get((entity["name"], "availability")) != "False":
                raise ValueError(f"Pi health entity {entity['name']!r} must be unavailable for stale data.")

    print(f"Validated {len(resources)} REST resources and rendered {templates} templates.")
    print("Sample outage diagnosis, unavailable states, and stale Pi-health behavior are correct.")
    return templates


def main() -> int:
    try:
        validate()
    except (OSError, ValueError) as exc:
        print(f"Home Assistant example validation failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
