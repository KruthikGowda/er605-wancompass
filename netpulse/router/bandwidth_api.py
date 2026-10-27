"""Narrow ER605 bandwidth-rule API helper for the reviewed QoS rule contract.

The caller must persist durable operation intent before calling either writer.
This helper never logs in, toggles the global QoS engine, retries a write, or
cleans up an uncertain result. It must be called with an already active client
session, and is intentionally not wired into production controls.
"""
from __future__ import annotations

import copy
import json
import re

from netpulse.devices.identity import MAC_RE, normalize_mac
from netpulse.router.er605 import RouterError
from netpulse.router.qos import MAX_QOS_ROWS, canonical_qos_global, canonical_rate_rule_row

MODULE = "qos"
RULE_FORM = "rule"
GLOBAL_FORM = "global"
ADD_INTERFACE = "WAN2"  # Only interface allowed by this staged API contract.
MIN_RATE_KBPS = 100
MAX_RATE_KBPS = 1_000_000
MAX_RULES_LIMIT = 4096

_MANAGED_NAME = re.compile(r"NP_Q_[0-9A-F]{12}\Z")
_GROUP_NAME = re.compile(r"NP_G_[0-9A-F]{12}\Z")


class BandwidthAPIError(RouterError):
    """A bandwidth API operation stopped on an unsupported or uncertain state."""


def _mac_identity(mac: str) -> tuple[str, str, str]:
    normalized = normalize_mac(mac)
    if not isinstance(normalized, str) or not MAC_RE.fullmatch(normalized):
        raise ValueError("bandwidth rule requires a valid device MAC") from None
    hexmac = normalized.replace("-", "")
    name, group = f"NP_Q_{hexmac}", f"NP_G_{hexmac}"
    if not _MANAGED_NAME.fullmatch(name) or not _GROUP_NAME.fullmatch(group):
        raise ValueError("bandwidth rule requires a valid device MAC")
    return normalized, name, group


def _strict_envelope(response: object, *, collection: bool) -> tuple[object, int | None]:
    if not isinstance(response, dict) or str(response.get("error_code")) != "0":
        raise BandwidthAPIError("ER605 bandwidth response is unavailable or ambiguous")
    if isinstance(response.get("id"), bool) or not isinstance(response.get("id"), int):
        raise BandwidthAPIError("ER605 bandwidth response is unavailable or ambiguous")
    if collection:
        if set(response) != {"id", "others", "result", "error_code"}:
            raise BandwidthAPIError("ER605 bandwidth collection envelope is unknown")
        others = response.get("others")
        if (not isinstance(others, dict) or set(others) != {"max_rules"}
                or isinstance(others.get("max_rules"), bool)
                or not isinstance(others.get("max_rules"), int)
                or not 1 <= others["max_rules"] <= MAX_RULES_LIMIT):
            raise BandwidthAPIError("ER605 bandwidth collection limit is unknown")
        result = response.get("result")
        if result == {}:
            rows = []
        elif isinstance(result, list) and len(result) <= MAX_QOS_ROWS:
            rows = result
        else:
            raise BandwidthAPIError("ER605 bandwidth collection shape is unknown")
        return rows, others["max_rules"]
    if set(response) != {"id", "result", "error_code"} or not isinstance(response.get("result"), dict):
        raise BandwidthAPIError("ER605 bandwidth settings envelope is unknown")
    return response["result"], None


def _canonical_rows(raw_rows: object) -> list[dict]:
    if not isinstance(raw_rows, list) or len(raw_rows) > MAX_QOS_ROWS:
        raise BandwidthAPIError("ER605 bandwidth rules are malformed or oversized")
    rows: list[dict] = []
    names: set[str] = set()
    for raw in raw_rows:
        row = canonical_rate_rule_row(raw)
        if row is None:
            raise BandwidthAPIError("ER605 bandwidth rule has unknown fields or values")
        if row["name"] in names:
            raise BandwidthAPIError("ER605 bandwidth rule names are duplicated")
        names.add(row["name"])
        rows.append(row)
    return rows


class BandwidthRuleAPI:
    """Append/delete exact managed NP_Q_<MAC> source-group rules on WAN2.

    Operates through the supplied, already logged-in ER605 client. The caller is
    responsible for holding its router API lock and persisting durable intent
    before calling ``add_rule`` or ``delete_rule``. Exact row read-back alone
    does not establish immediate packet enforcement; callers own settling waits
    and packet measurements.
    """

    def __init__(self, client):
        self.client = client

    def _require_active_session(self) -> str:
        token = getattr(self.client, "_stok", None)
        if not isinstance(token, str) or not token:
            raise BandwidthAPIError("ER605 bandwidth operation requires an active client session")
        return token

    def _global_state(self) -> dict:
        try:
            response = self.client.get_response(MODULE, GLOBAL_FORM)
            raw, _ = _strict_envelope(response, collection=False)
            settings = canonical_qos_global(raw)
        except BandwidthAPIError:
            raise
        except Exception:
            raise BandwidthAPIError("ER605 bandwidth engine state could not be read") from None
        if settings is None:
            raise BandwidthAPIError("ER605 bandwidth engine settings have an unknown schema")
        return settings

    def _global_on_for_add(self) -> None:
        settings = self._global_state()
        if settings.get("qos_enable") != "on":
            raise BandwidthAPIError("ER605 global bandwidth engine is off; no setting was changed")
        if settings.get("threshold_enable") != "off":
            raise BandwidthAPIError("ER605 bandwidth threshold mode is on; no rule was added")

    def _collection(self) -> tuple[list[dict], list[dict], int]:
        try:
            response = self.client.get_response(MODULE, RULE_FORM)
            raw, max_rules = _strict_envelope(response, collection=True)
            canonical = _canonical_rows(raw)
        except BandwidthAPIError:
            raise
        except Exception:
            raise BandwidthAPIError("ER605 bandwidth rules could not be read") from None
        return copy.deepcopy(raw), canonical, int(max_rules)

    def _post(self, token: str, payload: dict) -> dict:
        try:
            result = self.client._post(
                f"/cgi-bin/luci/;stok={token}/admin/qos?form=rule",
                {"data": json.dumps(payload)},
            )
        except Exception:
            raise BandwidthAPIError("ER605 bandwidth write outcome is uncertain; retain operation intent") from None
        if not isinstance(result, dict) or str(result.get("error_code")) != "0":
            raise BandwidthAPIError("ER605 rejected the bandwidth operation; retain operation intent")
        return result

    @staticmethod
    def _effective_expected(name: str, group: str, rate_out: int, rate_in: int) -> dict:
        return {"name": name, "if_ping": "LAN", "if_pong": ADD_INTERFACE,
                "source_type": "ip_group", "ip_group": group,
                "rate_max": rate_out, "rate_max_mate": rate_in, "mode": "priv",
                "time": "Any", "comment": "NetPulse validation", "enable": "on",
                "ip_type": "src"}

    @staticmethod
    def _validate_managed(canonical: dict, name: str, group: str) -> None:
        setting_index = canonical.get("setting_index")
        if (not _MANAGED_NAME.fullmatch(str(canonical.get("name", "")))
                or canonical.get("name") != name or canonical.get(".name") != name
                or canonical.get(".type") != "rule" or canonical.get(".anonymous") is not False
                or not isinstance(setting_index, str)
                or re.fullmatch(r"\d{1,10}", setting_index) is None
                or canonical.get("t_ping_label") != "LAN"
                or canonical.get("t_pong_label") != "WAN/LAN2"
                or canonical.get("if_pong") != ADD_INTERFACE
                or canonical.get("source_type") != "ip_group"
                or canonical.get("ip_group") != group or canonical.get("mode") != "priv"
                or canonical.get("time") != "Any" or canonical.get("comment") != "NetPulse validation"
                or canonical.get("enable") != "on" or canonical.get("ip_type") != "src"):
            raise BandwidthAPIError("ER605 bandwidth row is not the exact managed WAN2 rule")

    @classmethod
    def _validate_managed_collection(cls, rows: list[dict]) -> None:
        """Reject external/overlapping rules and require display positions 1..N."""
        groups: set[str] = set()
        names: set[str] = set()
        for index, row in enumerate(rows):
            name = row.get("name", "")
            if not isinstance(name, str) or not _MANAGED_NAME.fullmatch(name):
                raise BandwidthAPIError("QoS table contains an unrecognized non-NetPulse rule")
            group = "NP_G_" + name.removeprefix("NP_Q_")
            if not _GROUP_NAME.fullmatch(group):
                raise BandwidthAPIError("Managed QoS rule identity is malformed")
            cls._validate_managed(row, name, group)
            if name in names or group in groups:
                raise BandwidthAPIError("Managed QoS rule names or source groups overlap")
            if row.get("position") != index + 1:
                raise BandwidthAPIError("Managed QoS rule positions are not consecutive")
            names.add(name)
            groups.add(group)

    @staticmethod
    def _same_after_delete(before: list[dict], after: list[dict]) -> bool:
        """Compare ordered survivors, allowing only position/index renumbering."""
        if len(before) != len(after):
            return False
        for index, (old, new) in enumerate(zip(before, after), start=1):
            if (any(old.get(key) != new.get(key) for key in old
                    if key not in ("position", "setting_index"))
                    or any(key not in old for key in new if key not in ("position", "setting_index"))
                    or new.get("position") != index):
                return False
        return True

    def add_rule(self, mac: str, rate_max: int = 1000, rate_max_mate: int = 1000) -> dict:
        """Add a fixed 1-device WAN2 rule after exact fresh-snapshot validation.

        A network owner must persist durable intent before this call. Errors after
        the POST can represent a completed write with a lost response; this method
        leaves that state untouched for caller-led recovery.
        """
        token = self._require_active_session()
        normalized, name, group = _mac_identity(mac)
        for value in (rate_max, rate_max_mate):
            if isinstance(value, bool) or not isinstance(value, int) or not MIN_RATE_KBPS <= value <= MAX_RATE_KBPS:
                raise ValueError("bandwidth rates must be integers from 100 through 1000000 kbps")
        self._global_on_for_add()
        before_raw, before, maximum = self._collection()
        if len(before) >= min(maximum, MAX_QOS_ROWS):
            raise BandwidthAPIError("ER605 bandwidth rule table is full or at its parser bound")
        self._validate_managed_collection(before)
        if any(row["name"] == name for row in before):
            raise BandwidthAPIError("managed ER605 bandwidth rule already exists or is ambiguous")
        # Re-read the entire table immediately before the write. We do not rewrite
        # or normalize unrelated rows when their collection has changed.
        self._global_on_for_add()
        current_raw, current, current_maximum = self._collection()
        if current_raw != before_raw or current != before or current_maximum != maximum:
            raise BandwidthAPIError("ER605 bandwidth rules changed during review; no write was sent")
        payload_row = {"name": name, "if_ping": "LAN", "if_pong": ADD_INTERFACE,
                       "source_type": "ip_group", "network": "", "ip_group": group,
                       "rate_max": str(rate_max), "rate_max_mate": str(rate_max_mate),
                       "mode": "priv", "time": "Any", "comment": "NetPulse validation",
                       "position": "", "enable": "on", "ip_type": "src"}
        index = len(before)
        self._post(token, {"method": "add", "params": {"index": index, "key": f"key-{index}",
                    "old": "add", "new": payload_row}})
        # Never issue an automatic cleanup after an uncertain read-back.
        try:
            _post_raw, observed, _post_max = self._collection()
        except BandwidthAPIError:
            raise
        self._validate_managed_collection(observed)
        matches = [row for row in observed if row.get("name") == name]
        if len(matches) != 1:
            raise BandwidthAPIError("ER605 bandwidth add read-back is missing or ambiguous; retain intent")
        self._validate_managed(matches[0], name, group)
        expected = self._effective_expected(name, group, rate_max, rate_max_mate)
        if any(matches[0].get(field) != value for field, value in expected.items()):
            raise BandwidthAPIError("ER605 bandwidth add read-back differs; retain intent")
        preserved = [row for row in observed if row.get("name") != name]
        if (len(matches) != 1 or matches[0].get("position") != len(before) + 1
                or preserved != before):
            raise BandwidthAPIError("ER605 bandwidth add changed another row or its order; retain intent")
        return copy.deepcopy(matches[0])

    def delete_rule(self, mac: str, expected_row: dict) -> list[dict]:
        """Delete only the fresh exact WAN2 row returned by a prior add/read.

        The caller must persist durable cleanup intent before this call. No row is
        deleted when any field, its position, or another row differs from review.
        """
        token = self._require_active_session()
        _normalized, name, group = _mac_identity(mac)
        expected = canonical_rate_rule_row(expected_row)
        if expected is None:
            raise ValueError("expected bandwidth row does not match the verified row schema")
        self._validate_managed(expected, name, group)
        self._global_state()
        before_raw, before, _maximum = self._collection()
        self._validate_managed_collection(before)
        matches = [(index, row) for index, row in enumerate(before) if row.get("name") == name]
        if len(matches) != 1 or matches[0][1] != expected:
            raise BandwidthAPIError("exact managed bandwidth rule changed or is ambiguous; refusing delete")
        index, _row = matches[0]
        self._global_state()
        current_raw, current, _ = self._collection()
        self._validate_managed_collection(current)
        if current_raw != before_raw or current != before:
            raise BandwidthAPIError("ER605 bandwidth rules changed during cleanup review; no delete was sent")
        self._post(token, {"method": "delete", "params": {"index": str(index), "key": f"key-{index}"}})
        try:
            _after_raw, after, _maximum = self._collection()
        except BandwidthAPIError:
            raise
        self._validate_managed_collection(after)
        if any(row.get("name") == name for row in after):
            raise BandwidthAPIError("ER605 bandwidth cleanup read-back failed; retain intent")
        preserved = before[:index] + before[index + 1:]
        if not self._same_after_delete(preserved, after):
            raise BandwidthAPIError("ER605 bandwidth cleanup changed another row or order; retain intent")
        return copy.deepcopy(after)

