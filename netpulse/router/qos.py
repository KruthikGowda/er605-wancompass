"""Conservative read-only QoS inventory for the ER605 UI schema.

The QoS forms are known from the reviewed firmware's bundled UI, but their API
response and write contracts are not validated. This module reads snapshots only
and rejects shapes that cannot be interpreted without guessing.
"""
from __future__ import annotations

import re
import time
from netpulse.router.er605 import RouterAuthError

MAX_QOS_ROWS = 128
MAX_NAME_LENGTH = 50
MAX_TEXT_LENGTH = 128
MAX_RATE_KBPS = 1_000_000  # parser guard only; not a verified interface capacity
MAX_SETTING_COUNTER_DIGITS = 10
MAX_POSITION = MAX_QOS_ROWS

_IDENTIFIER = re.compile(r"[A-Za-z0-9_.-]{1,64}\Z")
_DECIMAL = re.compile(r"\d{1,10}\Z")


class QoSError(ValueError):
    """QoS data could not be interpreted as a bounded known schema."""


def _text(value: object, *, limit: int, allow_empty: bool = True) -> str | None:
    if not isinstance(value, str) or len(value) > limit:
        return None
    if not allow_empty and not value:
        return None
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        return None
    return value


def _choice(value: object, choices: set[str]) -> str | None:
    return value if isinstance(value, str) and value in choices else None


def _integer(value: object, *, minimum: int, maximum: int) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str) and _DECIMAL.fullmatch(value):
        parsed = int(value)
    else:
        return None
    return parsed if minimum <= parsed <= maximum else None


def canonical_qos_global(observed: object) -> dict | None:
    """Return the documented global settings plus typed known UI metadata."""
    global_fields = {
            ".name", ".type", "qos_threshold", "threshold_enable", "bandwidth",
            ".anonymous", "qos_enable", "interface"}
    if (not isinstance(observed, dict)
            or set(observed) not in (global_fields, global_fields | {"qos_setting_number"})):
        return None
    flags = {}
    for key in ("qos_enable", "threshold_enable"):
        value = observed[key]
        if not isinstance(value, str) or value not in ("on", "off"):
            return None
        flags[key] = value
    threshold = _integer(observed["qos_threshold"], minimum=0, maximum=100)
    if threshold is None:
        return None
    name = _text(observed[".name"], limit=MAX_NAME_LENGTH, allow_empty=False)
    form_type = _text(observed[".type"], limit=MAX_NAME_LENGTH, allow_empty=False)
    bandwidth = _integer(observed["bandwidth"], minimum=0, maximum=MAX_RATE_KBPS)
    anonymous = observed[".anonymous"]
    interfaces = observed["interface"]
    if (name is None or form_type is None or bandwidth is None or anonymous is not False
            or not isinstance(interfaces, list) or len(interfaces) > 32
            or any(not isinstance(item, str) or not _IDENTIFIER.fullmatch(item) for item in interfaces)
            or len(set(interfaces)) != len(interfaces)):
        return None
    setting_number = observed.get("qos_setting_number")
    if ("qos_setting_number" in observed
            and (not isinstance(setting_number, str)
                 or not re.fullmatch(rf"\d{{1,{MAX_SETTING_COUNTER_DIGITS}}}", setting_number))):
        return None
    result = {".name": name, ".type": form_type, **flags, "qos_threshold": threshold,
              "bandwidth": bandwidth, ".anonymous": anonymous, "interface": list(interfaces)}
    if "qos_setting_number" in observed:
        result["qos_setting_number"] = setting_number
    return result


_RATE_FIELDS = {
    ".name", ".type", ".anonymous", "setting_index", "t_ping_label", "t_pong_label",
    "position", "name", "if_ping", "if_pong", "source_type", "ip_group",
    "rate_max", "rate_max_mate", "mode", "time", "comment", "enable", "ip_type",
}


def canonical_rate_rule_row(observed: object) -> dict | None:
    """Canonicalize the observed exact-schema ip-group rate-rule row."""
    if not isinstance(observed, dict) or set(observed) != _RATE_FIELDS:
        return None
    name = _text(observed["name"], limit=MAX_NAME_LENGTH, allow_empty=False)
    if (name is None or observed[".name"] != name or observed[".type"] != "rule"
            or observed[".anonymous"] is not False):
        return None
    setting_index = observed["setting_index"]
    if not isinstance(setting_index, str) or not re.fullmatch(r"\d{1,10}", setting_index):
        return None
    ping_label = _text(observed["t_ping_label"], limit=MAX_TEXT_LENGTH, allow_empty=False)
    pong_label = _text(observed["t_pong_label"], limit=MAX_TEXT_LENGTH, allow_empty=False)
    if ping_label is None or pong_label is None:
        return None
    if observed["if_ping"] != "LAN":
        return None
    interface = observed["if_pong"]
    if not isinstance(interface, str) or not _IDENTIFIER.fullmatch(interface):
        return None
    source_type = _choice(observed["source_type"], {"ip_group"})
    mode = _choice(observed["mode"], {"share", "priv"})
    enabled = _choice(observed["enable"], {"on", "off"})
    if source_type is None or mode is None or enabled is None or observed["ip_type"] != "src":
        return None
    ip_group = _text(observed["ip_group"], limit=MAX_NAME_LENGTH, allow_empty=False)
    time_value = _text(observed["time"], limit=MAX_NAME_LENGTH, allow_empty=False)
    comment = _text(observed["comment"], limit=50)
    if ip_group is None or time_value is None or comment is None:
        return None
    rate_out = _integer(observed["rate_max"], minimum=100, maximum=MAX_RATE_KBPS)
    rate_in = _integer(observed["rate_max_mate"], minimum=100, maximum=MAX_RATE_KBPS)
    position = _integer(observed["position"], minimum=1, maximum=MAX_POSITION)
    if rate_out is None or rate_in is None or position is None:
        return None
    return {".name": name, ".type": "rule", ".anonymous": False,
            "setting_index": setting_index, "t_ping_label": ping_label,
            "t_pong_label": pong_label, "position": position, "name": name,
            "if_ping": "LAN", "if_pong": interface, "source_type": source_type,
            "ip_group": ip_group, "rate_max": rate_out, "rate_max_mate": rate_in,
            "mode": mode, "time": time_value, "comment": comment,
            "enable": enabled, "ip_type": "src"}


_CLASS_FIELDS = {".name", ".type", ".anonymous", "dscp", "class", "ip", "service",
                 "id", "src_ip", "status", "dst_ip", "rule", "ipt_idx"}


def canonical_classification_row(observed: object) -> dict | None:
    """Canonicalize one complete class row while rejecting unrecognized states."""
    if not isinstance(observed, dict) or set(observed) != _CLASS_FIELDS:
        return None
    name = _text(observed[".name"], limit=MAX_TEXT_LENGTH, allow_empty=False)
    if (name is None or observed[".type"] != "rule" or observed[".anonymous"] is not False):
        return None
    qos_class = _choice(observed["class"], {"class1", "class2", "class3"})
    status = _choice(observed["status"], {"enable", "disable"})
    ip_version = _choice(observed["ip"], {"ipv4", "ipv6"})
    if qos_class is None or status is None or ip_version is None:
        return None
    values = {}
    for key, limit in (("src_ip", MAX_NAME_LENGTH), ("dst_ip", MAX_NAME_LENGTH),
                       ("dscp", MAX_NAME_LENGTH), ("service", MAX_NAME_LENGTH),
                       ("rule", MAX_TEXT_LENGTH), ("id", MAX_TEXT_LENGTH),
                       ("ipt_idx", MAX_TEXT_LENGTH)):
        value = _text(observed[key], limit=limit, allow_empty=(key in ("rule", "ipt_idx")))
        if value is None:
            return None
        values[key] = value
    # id, rule, and ipt_idx are opaque firmware-generated strings. Keep their
    # observed spelling and do not interpret their numeric-looking values.
    return {".name": name, ".type": "rule", ".anonymous": False,
            "class": qos_class, "status": status, "ip": ip_version, **values}


def _response_result(response: object, expected: type, *, allow_nonempty: bool = False) -> object:
    """Accept the observed global or collection response envelope."""
    if (not isinstance(response, dict) or str(response.get("error_code")) != "0"
            or "result" not in response):
        raise QoSError("QoS response envelope is unknown or ambiguous")
    result = response["result"]
    if expected is dict:
        if (set(response) != {"id", "result", "error_code"}
                or isinstance(response.get("id"), bool) or not isinstance(response.get("id"), int)):
            raise QoSError("QoS global response envelope is unknown or ambiguous")
        if not isinstance(result, dict):
            raise QoSError("QoS response result has an unknown shape")
        return result
    if expected is list:
        if (set(response) != {"id", "others", "result", "error_code"}
                or isinstance(response.get("id"), bool) or not isinstance(response.get("id"), int)):
            raise QoSError("QoS collection response envelope is unknown or ambiguous")
        others = response.get("others")
        if (not isinstance(others, dict) or set(others) != {"max_rules"}
                or isinstance(others.get("max_rules"), bool)
                or not isinstance(others.get("max_rules"), int)
                or not 1 <= others["max_rules"] <= 4096):
            raise QoSError("QoS collection metadata is unknown or malformed")
        if result == {}:
            return []
        if (allow_nonempty and isinstance(result, list) and len(result) <= MAX_QOS_ROWS
                and len(result) <= others["max_rules"]):
            return result
        raise QoSError("QoS collection is not a verified supported shape")
    if not isinstance(result, expected):
        raise QoSError("QoS response result has an unknown shape")
    return result


def _unique_rows(value: object, canonicalizer, identity_key: str) -> list[dict]:
    if not isinstance(value, list) or len(value) > MAX_QOS_ROWS:
        raise QoSError("QoS row collection is malformed or oversized")
    rows, seen = [], set()
    for item in value:
        row = canonicalizer(item)
        if row is None:
            raise QoSError("QoS row has unknown fields or values")
        identity = row[identity_key]
        if identity in seen:
            raise QoSError("QoS row identities are duplicated")
        seen.add(identity)
        rows.append(row)
    return rows


class QoSInventory:
    """Read QoS settings and rows under the watch's shared router API lock."""

    def __init__(self, watch, clock=time.time):
        self.watch = watch
        self.clock = clock
        self._retry_after = 0.0
        self._retry_reason = ""

    def read(self) -> dict:
        guard = self._watch_guard()
        if guard:
            return self._unavailable(guard)
        try:
            with self.watch.api_lock:
                guard = self._watch_guard()
                if guard:
                    return self._unavailable(guard)
                with self.watch.client.session() as client:
                    global_response = client.get_response("qos", "global")
                    rate_response = client.get_response("qos", "rule")
                    class_response = client.get_response("qos_ctl", "class")
            global_result = canonical_qos_global(_response_result(global_response, dict))
            if global_result is None:
                raise QoSError("QoS global settings have unknown fields or values")
            rates = _unique_rows(_response_result(rate_response, list, allow_nonempty=True),
                                 canonical_rate_rule_row, "name")
            classes = _unique_rows(_response_result(class_response, list, allow_nonempty=True),
                                   canonical_classification_row, "id")
            return {"available": True, "global": global_result, "rate_rules": rates,
                    "class_rules": classes, "reason": ""}
        except RouterAuthError:
            self._retry_after = max(self._retry_after, self.clock() + 1800)
            self._retry_reason = "ER605 authentication is in backoff; wait for its normal router check."
            return self._unavailable(self._retry_reason)
        except Exception:
            # Do not surface router response details or private router data.
            self._retry_after = max(self._retry_after, self.clock() + 15)
            self._retry_reason = "ER605 QoS response is unknown, malformed, or unavailable; retry shortly."
            return self._unavailable(self._retry_reason)

    def _watch_guard(self) -> str:
        now = self.clock()
        if self._retry_after > now:
            return self._retry_reason or "ER605 QoS inventory is temporarily unavailable; retry shortly."
        if getattr(self.watch, "client", None) is None or not hasattr(self.watch, "api_lock"):
            return "ER605 QoS inventory is unavailable."
        if getattr(self.watch, "_login_blocked_until", 0) > now:
            return "ER605 authentication is in backoff; wait for its normal router check."
        if getattr(self.watch, "_paused_until", 0) > now:
            return "ER605 checks are paused; QoS inventory is unavailable."
        if getattr(self.watch, "_unreachable", 0):
            return "ER605 is unreachable; wait for its normal router check."
        snap = getattr(self.watch, "snap", None)
        if getattr(snap, "ok", True) is False:
            return "ER605 status is not ready; wait for its normal router check."
        try:
            age = now - float(getattr(snap, "checked_at", None))
        except (TypeError, ValueError, OverflowError):
            return "ER605 inventory is not fresh; wait for its normal router check."
        max_age = max(120, float(getattr(self.watch, "poll_seconds", 0)) * 2)
        if not (0 <= age <= max_age):
            return "ER605 inventory is stale; wait for its normal router check."
        error = str(getattr(snap, "error", "") or "").casefold()
        if "login" in error or "auth" in error:
            return "ER605 authentication is unavailable; wait for its normal router check."
        return ""

    @staticmethod
    def _unavailable(reason: str) -> dict:
        return {"available": False, "global": None, "rate_rules": [],
                "class_rules": [], "reason": reason}
