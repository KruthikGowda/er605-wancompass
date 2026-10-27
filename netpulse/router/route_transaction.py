"""Crash-recoverable coordinator for delayed strict route transitions.

RouterControl owns the shared write lock, intent store, confirmation, audit, and
the policy decision to invoke it. A successful row read-back is not evidence of
forwarding; the injected settling delay is followed by a second fresh check.
"""
from __future__ import annotations

import copy
import ipaddress
import math
import re
import threading
import time
from collections.abc import Callable, Iterable

from netpulse.devices.identity import MAC_RE, normalize_mac
from netpulse.storage.route_intents import RouteIntentError, RouteIntentStore

STRICT_WAN_FIRMWARE = "2.3.3 Build 20251029 Rel.18054"
ROUTE_FIELDS = (".name", "name", "service_type", "src_ipgroup", "dst_ipgroup", "interfaces", "timeobj",
                "mode", "comment", "state", "index", "src", "dst", "dst_country_group",
                "dst_domain", "flag")
_ROUTE_FIELD_SET = set(ROUTE_FIELDS)
_RAW_ROUTE_FIELDS = _ROUTE_FIELD_SET | {"t_label"}
_TARGET_NAME = re.compile(r"NP_R_[0-9A-F]{12}\Z")
_MAX_POLICY_ROWS = 128
_MAX_LABEL = 128


class RouteTransactionError(RuntimeError):
    """A strict route transaction stopped and may require owner recovery."""


class RouteTransaction:
    """Journal, apply, settle, verify, or recover one strict-route batch.

    ``routes`` is the existing route-control coordinator-like object. The caller
    holds ``routes._router_write_lock`` around the enclosing owner action; this
    class also acquires it reentrantly for standalone use. ``store`` is a
    ``RouteIntentStore`` sharing the application database. ``sleep`` and
    ``clock`` are injectable for deterministic offline tests.
    """

    def __init__(self, routes, store: RouteIntentStore, *, sleep: Callable[[float], None] = time.sleep,
                 clock: Callable[[], float] = time.time, settle_seconds: float = 30.0):
        if (isinstance(settle_seconds, bool) or not isinstance(settle_seconds, (int, float))
                or not math.isfinite(settle_seconds) or settle_seconds < 0):
            raise ValueError("settle_seconds must be a nonnegative number")
        self.routes = routes
        self.store = store
        self.sleep = sleep
        self.clock = clock
        self.settle_seconds = float(settle_seconds)
        self._owner_thread: int | None = None
        self._owner_macs: set[str] = set()
        self._owner_route: str | None = None
        self._owner_allowed_routes: dict[str, set[str]] = {}

    @property
    def owns_current_thread(self) -> bool:
        return self._owner_thread == threading.get_ident()

    @property
    def pending_count(self) -> int:
        return len(self.store.pending())

    def run(self, macs: Iterable[str], route: str, actor: str,
            workcallback: Callable[[], object]):
        """Run callback under a durable strict-route transaction when needed.

        A nested call from this transaction's owner thread is allowed only for a
        subset of the original target set and either the desired route or its
        exact recorded before route. A durable intent is required when the new
        route is strict or when any target is leaving an active Only route.
        """
        normalized = self._macs(macs)
        if route not in {"WAN1_ONLY", "WAN2_ONLY", "AUTO", "WAN1", "WAN2"}:
            raise RouteTransactionError("unsupported route transaction target")
        if not callable(workcallback):
            raise TypeError("workcallback must be callable")
        lock = getattr(self.routes, "_router_write_lock", None)
        if lock is None:
            raise RouteTransactionError("shared router write lock is unavailable")
        with lock:
            pending = self.store.pending()
            if pending and not self.owns_current_thread:
                raise RouteTransactionError("an unresolved route intent must be recovered first")
            if self.owns_current_thread:
                if (not set(normalized) <= self._owner_macs
                        or any(route not in self._owner_allowed_routes.get(mac, set()) for mac in normalized)):
                    raise RouteTransactionError("nested route work exceeds the active intent scope")
                return workcallback()
            targets, before_rows = self._capture_targets(normalized, route)
            needs_intent = (route in {"WAN1_ONLY", "WAN2_ONLY"}
                            or any(self._row_route(target["before_row"]) in {"WAN1_ONLY", "WAN2_ONLY"}
                                   for target in targets))
            if not needs_intent:
                return workcallback()
            self._assert_ready()
            self._owner_thread = threading.get_ident()
            self._owner_macs = set(normalized)
            self._owner_route = route
            self._owner_allowed_routes = self._allowed_nested_routes(targets, route)
            entry = None
            callback_started = False
            try:
                record = {"actor": actor, "created_at": self.clock(),
                          "firmware": STRICT_WAN_FIRMWARE, "targets": targets,
                          "phase": "prepared"}
                intent_id = self.store.prepare(record)
                entry = self.store.get(intent_id)
                entry = self._set_phase(entry, "applying")
                callback_started = True
                result = workcallback()
                desired_rows, actual_targets = self._verify_desired(entry["record"], before_rows)
                saved_after = self._verify_saved_targets(entry["record"])
                updated = copy.deepcopy(entry["record"])
                updated["targets"] = actual_targets
                updated["phase"] = "settling"
                revision = self.store.replace(entry["id"], entry["revision"], updated)
                entry = self.store.get(entry["id"])
                # Every API session used above has exited before this wait.
                self.sleep(self.settle_seconds)
                self._assert_ready()
                _settled_rows, settled_targets = self._verify_desired(entry["record"], desired_rows)
                if settled_targets != entry["record"]["targets"]:
                    raise RouteTransactionError("strict route rows drifted during settling")
                if self._verify_saved_targets(entry["record"]) != saved_after:
                    raise RouteTransactionError("saved route metadata drifted during settling")
                current = self.store.get(entry["id"])
                if not current or current["revision"] != revision:
                    raise RouteTransactionError("route intent changed during settling")
                self.store.finish(current["id"], current["revision"])
                return result
            except Exception:
                recovered = False
                if entry is not None:
                    self._mark_error(entry["id"])
                    try:
                        self._recover_one(entry["id"])
                        recovered = True
                    except Exception:
                        self._mark_error(entry["id"])
                if recovered:
                    raise RouteTransactionError("route action failed; previous router and saved states were restored and verified") from None
                if entry is not None:
                    raise RouteTransactionError("route action failed; unresolved intent remains locked") from None
                if callback_started:
                    raise RouteTransactionError("route action failed before intent recovery was available") from None
                raise RouteTransactionError("route transaction stopped before router work began") from None
            finally:
                self._clear_owner()

    def recover_pending(self) -> int:
        """Roll back every pending uncommitted batch; retain journal on ambiguity."""
        lock = getattr(self.routes, "_router_write_lock", None)
        if lock is None:
            raise RouteTransactionError("shared router write lock is unavailable")
        with lock:
            entries = self.store.pending()
            if not entries:
                return 0
            recovered = 0
            for entry in entries:
                targets = entry["record"]["targets"]
                self._owner_thread = threading.get_ident()
                self._owner_macs = {target["mac"] for target in targets}
                try:
                    self._owner_route = self._record_route(entry["record"])
                    self._owner_allowed_routes = self._allowed_nested_routes(
                        targets, self._owner_route)
                    self._recover_one(entry["id"])
                    recovered += 1
                except Exception:
                    self._mark_error(entry["id"])
                    raise RouteTransactionError("pending route recovery stopped; intent remains locked") from None
                finally:
                    self._clear_owner()
            return recovered

    @staticmethod
    def _macs(macs: Iterable[str]) -> list[str]:
        try:
            values = list(macs)
        except TypeError:
            raise RouteTransactionError("route transaction targets are invalid") from None
        normalized = [normalize_mac(mac) for mac in values]
        if (not normalized or len(normalized) > 128
                or any(not MAC_RE.fullmatch(mac) for mac in normalized)
                or len(normalized) != len(set(normalized))):
            raise RouteTransactionError("route transaction targets must be unique valid MACs")
        return normalized

    def _clear_owner(self) -> None:
        self._owner_thread = None
        self._owner_macs = set()
        self._owner_route = None
        self._owner_allowed_routes = {}

    def _assert_ready(self) -> None:
        try:
            refresh_uptime = getattr(self.routes, "_refresh_transaction_uptime", None)
            if callable(refresh_uptime):
                refresh_uptime()
            status = self.routes.state()
            snap = self.routes.router.snap
            firmware = getattr(snap, "firmware_version", None) or status.get("firmware_version")
        except Exception:
            raise RouteTransactionError("fresh ER605 readiness could not be confirmed") from None
        if (not isinstance(status, dict) or status.get("enabled") is not True
                or firmware != STRICT_WAN_FIRMWARE
                or status.get("accepted_firmware_version") != STRICT_WAN_FIRMWARE
                or status.get("firmware_review_required") is not False):
            raise RouteTransactionError("ER605 readiness or exact firmware review is unavailable")

    @staticmethod
    def _valid_raw_row(row: object) -> dict:
        if not isinstance(row, dict) or not row or set(row) - _RAW_ROUTE_FIELDS:
            raise RouteTransactionError("policy route has unknown fields or shape")
        label = row.get("t_label")
        if label is not None and (not isinstance(label, str) or len(label) > _MAX_LABEL
                                  or any(ord(ch) < 32 or ord(ch) == 127 for ch in label)):
            raise RouteTransactionError("policy route display metadata is invalid")
        if not isinstance(row.get("name"), str) or not row["name"]:
            raise RouteTransactionError("policy route identity is unavailable")
        return copy.deepcopy(row)

    @classmethod
    def _policy_snapshot(cls, raw: object) -> tuple[list[dict], list[dict]]:
        if not isinstance(raw, list) or len(raw) > _MAX_POLICY_ROWS:
            raise RouteTransactionError("policy route collection is unavailable or oversized")
        rows = [cls._valid_raw_row(row) for row in raw]
        names = [row["name"] for row in rows]
        if len(names) != len(set(names)):
            raise RouteTransactionError("policy route names are duplicated")
        return rows, [cls._project(row) for row in rows]

    @staticmethod
    def _project(row: dict) -> dict:
        return {field: copy.deepcopy(row.get(field)) for field in ROUTE_FIELDS}

    @staticmethod
    def _wire_fields(row: dict) -> dict:
        return {key: copy.deepcopy(value) for key, value in row.items() if value is not None}

    @staticmethod
    def _identity(mac: str) -> tuple[str, str]:
        hexmac = mac.replace("-", "")
        return f"NP_R_{hexmac}", f"NP_G_{hexmac}"

    @classmethod
    def _validate_owned_row(cls, row: dict, mac: str) -> None:
        name, group = cls._identity(mac)
        if not _TARGET_NAME.fullmatch(name):
            raise RouteTransactionError("NetPulse route identity is malformed")
        if (row.get("name") != name or row.get("service_type") != "ALL"
                or row.get("src_ipgroup") != group or row.get("dst_ipgroup") != "IPGROUP_ANY"
                or row.get("interfaces") not in {"WAN1", "WAN2"}
                or row.get("timeobj") != "Any" or row.get("mode") not in {"Priority", "Only"}
                or row.get("state") not in {"on", "off"} or row.get("comment") != "NetPulse"
                or row.get("index") is not None and (isinstance(row["index"], bool)
                    or not isinstance(row["index"], int) or not 0 <= row["index"] <= _MAX_POLICY_ROWS)
                or row.get(".name") not in (None, name)
                or any(row.get(key) is not None for key in ("dst_country_group", "dst_domain", "flag"))
                or any(row.get(key) != "ipgroup" for key in ("src", "dst"))):
            raise RouteTransactionError("owned route row differs from its exact device policy")

    def _read(self, macs: list[str]) -> tuple[list[dict], list[dict], dict[str, str]]:
        client = self.routes.client
        try:
            with client.session() as api:
                leases = api.get("dhcps", "client") or []
                reservations = api.get("dhcps", "reservation") or []
                raw_policy = api.get("policy_route", "policy_route")
        except Exception:
            raise RouteTransactionError("fresh ER605 route and DHCP read failed") from None
        if not isinstance(leases, list) or not isinstance(reservations, list):
            raise RouteTransactionError("ER605 DHCP collections are unavailable")
        rows, projection = self._policy_snapshot(raw_policy)
        ip_owners: dict[str, str] = {}
        for lease in leases:
            if not isinstance(lease, dict):
                continue
            try:
                lease_mac = normalize_mac(self.routes._client_mac(lease))
                lease_ip = str(ipaddress.ip_address(self.routes._client_ip(lease)))
            except Exception:
                continue
            if lease_ip in ip_owners and ip_owners[lease_ip] != lease_mac:
                raise RouteTransactionError("two DHCP clients share one active IP lease")
            ip_owners[lease_ip] = lease_mac
        target_ips = {}
        for mac in macs:
            try:
                _reservation, ip = self.routes._reservation(leases, reservations, mac)
                address = ipaddress.ip_address(ip)
            except Exception:
                raise RouteTransactionError("target lacks one valid stable IPv4 reservation") from None
            matching_leases = [row for row in leases if isinstance(row, dict)
                               and self.routes._client_mac(row) == mac]
            if (len(matching_leases) != 1 or self.routes._client_ip(matching_leases[0]) != ip
                    or address.version != 4):
                raise RouteTransactionError("target DHCP lease is missing, duplicated, or changed")
            route_name = self._identity(mac)[0]
            target_route = [row for row in rows if row.get("name") == route_name]
            if target_route and (isinstance(target_route[0].get("index"), bool)
                                 or not isinstance(target_route[0].get("index"), int)):
                raise RouteTransactionError("owned policy route index is unavailable")
            target_ips[mac] = ip
        return rows, projection, target_ips

    @staticmethod
    def _row_route(row: dict | None) -> str:
        if row is None or row.get("state") == "off":
            return "AUTO"
        if row.get("mode") == "Only":
            return str(row.get("interfaces")) + "_ONLY"
        return str(row.get("interfaces"))

    @staticmethod
    def _allowed_nested_routes(targets: list[dict], desired_route: str) -> dict[str, set[str]]:
        allowed = {}
        for target in targets:
            choices = {desired_route, RouteTransaction._row_route(target.get("before_row"))}
            saved = target.get("before_saved")
            if isinstance(saved, dict) and saved.get("route") in {
                    "AUTO", "WAN1", "WAN2", "WAN1_ONLY", "WAN2_ONLY"}:
                choices.add(saved["route"])
            allowed[target["mac"]] = choices
        return allowed

    def _capture_targets(self, macs: list[str], route: str) -> tuple[list[dict], list[dict]]:
        rows, projection, ips = self._read(macs)
        saved = self.routes.route_state()
        target_records = []
        for mac in macs:
            name, _group = self._identity(mac)
            found = [(ix, raw, projected) for ix, (raw, projected) in enumerate(zip(rows, projection))
                     if raw.get("name") == name]
            if len(found) > 1:
                raise RouteTransactionError("owned route row is duplicated")
            if found:
                _index, raw, before = found[0]
                self._validate_owned_row(before, mac)
                before_row = copy.deepcopy(before)
            else:
                before_row = None
            after = self._build_after_row(mac, before_row, route)
            target_records.append({"mac": mac, "ip": ips[mac],
                                   "before_saved": copy.deepcopy(saved.get(mac)),
                                   "before_row": before_row, "after_row": after})
        return target_records, rows

    @classmethod
    def _build_after_row(cls, mac: str, before: dict | None, route: str) -> dict | None:
        if route == "AUTO":
            if before is None:
                return None
            after = copy.deepcopy(before)
            after["state"] = "off"
            return after
        interface = route.removesuffix("_ONLY")
        mode = "Only" if route.endswith("_ONLY") else "Priority"
        if before is None:
            name, group = cls._identity(mac)
            after = {"name": name, "service_type": "ALL", "src_ipgroup": group,
                     "dst_ipgroup": "IPGROUP_ANY", "interfaces": interface,
                     "timeobj": "Any", "mode": mode, "comment": "NetPulse",
                     "state": "on", "src": "ipgroup", "dst": "ipgroup"}
        else:
            after = copy.deepcopy(before)
            after.update(interfaces=interface, mode=mode, state="on")
        return after

    @classmethod
    def _record_route(cls, record: dict) -> str:
        routes = {cls._row_route(target.get("after_row")) for target in record["targets"]}
        if len(routes) != 1:
            raise RouteTransactionError("pending route batch has mixed desired routes")
        route = routes.pop()
        if route not in {"AUTO", "WAN1", "WAN2", "WAN1_ONLY", "WAN2_ONLY"}:
            raise RouteTransactionError("pending route batch target is invalid")
        return route

    def _validate_intent_record(self, record: dict) -> None:
        if record.get("firmware") != STRICT_WAN_FIRMWARE or record.get("phase") not in {
                "prepared", "applying", "settling", "recovering", "error"}:
            raise RouteTransactionError("pending route intent firmware or phase is invalid")
        self._record_route(record)
        for target in record["targets"]:
            before, after = target["before_row"], target["after_row"]
            if before is not None:
                self._validate_owned_row(before, target["mac"])
            if after is not None:
                self._validate_owned_row(after, target["mac"])
            elif before is not None:
                raise RouteTransactionError("an existing route cannot have an absent desired row")

    def _set_phase(self, entry: dict, phase: str, *, targets: list[dict] | None = None) -> dict:
        updated = copy.deepcopy(entry["record"])
        updated["phase"] = phase
        if targets is not None:
            updated["targets"] = copy.deepcopy(targets)
        revision = self.store.replace(entry["id"], entry["revision"], updated)
        return self.store.get(entry["id"])

    def _verify_desired(self, record: dict, baseline_rows: list[dict]) -> tuple[list[dict], list[dict]]:
        macs = [target["mac"] for target in record["targets"]]
        rows, projections, ips = self._read(macs)
        if any(ips[target["mac"]] != target["ip"] for target in record["targets"]):
            raise RouteTransactionError("target reservation changed during route apply")
        target_by_name = {self._identity(t["mac"])[0]: t for t in record["targets"]}
        found: dict[str, tuple[int, dict, dict]] = {}
        for ix, (raw, projected) in enumerate(zip(rows, projections)):
            mac_target = target_by_name.get(raw["name"])
            if mac_target is None:
                continue
            if raw["name"] in found:
                raise RouteTransactionError("owned route row is duplicated after apply")
            self._validate_owned_row(projected, mac_target["mac"])
            expected = mac_target["after_row"]
            if expected is None:
                raise RouteTransactionError("route row exists although the intent expects it absent")
            if any(projected.get(key) != value for key, value in expected.items()):
                raise RouteTransactionError("owned route read-back differs from the intent")
            found[raw["name"]] = (ix, raw, projected)
        expected_present = {name for name, target in target_by_name.items()
                            if target["after_row"] is not None}
        if set(found) != expected_present:
            raise RouteTransactionError("route row presence differs from the intent")
        # Preserve every unrelated raw row and its order. Existing target rows
        # stay in their original slots; newly created targets append in request order.
        before_names = {row["name"] for row in baseline_rows}
        base_non_targets = [row for row in baseline_rows if row["name"] not in target_by_name]
        now_non_targets = [row for row in rows if row["name"] not in target_by_name]
        if now_non_targets != base_non_targets:
            raise RouteTransactionError("an unrelated policy row or its order changed")
        new_names = [self._identity(mac)[0] for mac in macs
                     if self._identity(mac)[0] not in before_names
                     and target_by_name[self._identity(mac)[0]]["after_row"] is not None]
        appended = [row["name"] for row in rows if row["name"] not in before_names]
        if appended != new_names:
            raise RouteTransactionError("new owned route rows are not appended in target order")
        expected_names = []
        for row in baseline_rows:
            expected_names.append(row["name"])
        expected_names.extend(new_names)
        if [row["name"] for row in rows] != expected_names:
            raise RouteTransactionError("owned route position changed in the policy table")
        # Existing target rows may change only the requested policy fields.
        before_by_name = {row["name"]: row for row in baseline_rows}
        for target in record["targets"]:
            name = self._identity(target["mac"])[0]
            if name in before_by_name and target["after_row"] is not None:
                original = before_by_name[name]
                expected_raw = copy.deepcopy(original)
                expected_raw.update(interfaces=target["after_row"]["interfaces"],
                                    mode=target["after_row"]["mode"], state=target["after_row"]["state"])
                if found[name][1] != expected_raw:
                    raise RouteTransactionError("route update changed another field")
        actual_targets = []
        for target in record["targets"]:
            name = self._identity(target["mac"])[0]
            updated = copy.deepcopy(target)
            updated["after_row"] = (copy.deepcopy(found[name][2]) if name in found else None)
            actual_targets.append(updated)
        return rows, actual_targets

    def _verify_saved_targets(self, record: dict) -> dict[str, dict]:
        saved = self.routes.route_state()
        observed = {}
        for target in record["targets"]:
            item = saved.get(target["mac"])
            expected_route = self._row_route(target["after_row"])
            if (not isinstance(item, dict) or item.get("ip") != target["ip"]
                    or item.get("route") != expected_route
                    or item.get("actor") != record["actor"]):
                raise RouteTransactionError("saved route preference does not match the strict route read-back")
            observed[target["mac"]] = copy.deepcopy(item)
        return observed

    def _verify_before(self, record: dict) -> tuple[list[dict], bool, list[tuple[dict, object, str]]]:
        macs = [target["mac"] for target in record["targets"]]
        rows, projections, ips = self._read(macs)
        if any(ips[target["mac"]] != target["ip"] for target in record["targets"]):
            raise RouteTransactionError("target reservation changed during recovery")
        by_name = {raw["name"]: (raw, projected) for raw, projected in zip(rows, projections)}
        changed = False
        plans = []
        for target in record["targets"]:
            name = self._identity(target["mac"])[0]
            current = by_name.get(name)
            before = target["before_row"]
            after = target["after_row"]
            if current is None:
                if before is None:
                    plans.append((target, None, "before"))
                    continue
                raise RouteTransactionError("an owned route row is missing from both recorded states")
            raw, projected = current
            self._validate_owned_row(projected, target["mac"])
            is_before = before is not None and projected == before
            is_after = after is not None and all(projected.get(key) == value for key, value in after.items())
            if not is_before and not is_after:
                raise RouteTransactionError("owned route row differs from exact before/after intent")
            if before is None and is_before:
                raise RouteTransactionError("new route intent has an impossible before-row state")
            plans.append((target, (raw, projected), "before" if is_before else "after"))
            changed |= not is_before
        return rows, changed, plans

    def _recover_one(self, intent_id: str) -> None:
        entry = self.store.get(intent_id)
        if not entry:
            raise RouteTransactionError("route intent disappeared during recovery")
        self._validate_intent_record(entry["record"])
        self._assert_ready()
        entry = self._set_phase(entry, "recovering")
        record = entry["record"]
        macs = [target["mac"] for target in record["targets"]]
        current_rows, _changed, plans = self._verify_before(record)
        # All target states and the complete raw collection have been validated
        # before the first restore write. Unrelated rows remain byte-for-byte
        # equal to this recovery snapshot throughout the rollback.
        state_by_mac = {target["mac"]: state for target, _current, state in plans}
        restore_updates = [target for target in record["targets"]
                           if target["before_row"] is not None
                           and state_by_mac[target["mac"]] == "after"]
        new_deletes = [target for target in record["targets"]
                       if target["before_row"] is None
                       and state_by_mac[target["mac"]] == "after"]
        # Remove appended new objects from right to left, then restore in-place rows.
        client = self.routes.client
        with client.session() as api:
            live_rows, _ = self._policy_snapshot(api.get("policy_route", "policy_route"))
            if live_rows != current_rows:
                raise RouteTransactionError("policy routes changed during recovery review")
            for target in reversed(new_deletes):
                name = self._identity(target["mac"])[0]
                rows_now, _projection = self._policy_snapshot(api.get("policy_route", "policy_route"))
                matches = [(ix, row) for ix, row in enumerate(rows_now) if row.get("name") == name]
                if len(matches) != 1:
                    raise RouteTransactionError("exact newly created route is missing or ambiguous")
                ix, raw = matches[0]
                if ix != len(rows_now) - 1 or not self._projection_matches(raw, target["after_row"]):
                    raise RouteTransactionError("new route no longer matches exact append state")
                api.delete_row("policy_route", "policy_route", name)
                remaining, _ = self._policy_snapshot(api.get("policy_route", "policy_route"))
                expected = rows_now[:ix] + rows_now[ix + 1:]
                if remaining != expected:
                    raise RouteTransactionError("new-route cleanup changed another row or order")
            for target in restore_updates:
                name = self._identity(target["mac"])[0]
                raw_rows, projected = self._policy_snapshot(api.get("policy_route", "policy_route"))
                matches = [(ix, raw, proj) for ix, (raw, proj) in enumerate(zip(raw_rows, projected))
                           if raw.get("name") == name]
                if len(matches) != 1:
                    raise RouteTransactionError("owned route is missing or ambiguous during restore")
                ix, raw, current = matches[0]
                if not self._projection_matches(raw, target["after_row"]):
                    raise RouteTransactionError("owned route changed before restore write")
                old = self._wire_fields(current)
                new = self._wire_fields(target["before_row"])
                api.set_row("policy_route", "policy_route", ix, f"key-{ix}", old, new)
            restored_rows, restored_projection = self._policy_snapshot(api.get("policy_route", "policy_route"))
        expected_rows = copy.deepcopy(current_rows)
        for target in record["targets"]:
            name = self._identity(target["mac"])[0]
            before = target["before_row"]
            matches = [(ix, raw) for ix, raw in enumerate(expected_rows) if raw.get("name") == name]
            if before is None:
                if matches:
                    ix, _ = matches[0]
                    expected_rows.pop(ix)
            elif matches:
                ix, old_raw = matches[0]
                restored_raw = copy.deepcopy(old_raw)
                for key, value in before.items():
                    if key in restored_raw:
                        restored_raw[key] = copy.deepcopy(value)
                expected_rows[ix] = restored_raw
            else:
                raise RouteTransactionError("original owned route cannot be placed safely")
        if restored_rows != expected_rows:
            raise RouteTransactionError("route recovery changed an unrelated row or order")
        # Confirm all targets are back to their recorded rows before waiting.
        for target in record["targets"]:
            name = self._identity(target["mac"])[0]
            actual = [row for row in restored_projection if row.get("name") == name]
            before = target["before_row"]
            if before is None:
                if actual:
                    raise RouteTransactionError("new route still exists after recovery")
            elif len(actual) != 1 or actual[0] != before:
                raise RouteTransactionError("previous route row did not restore exactly")
        # Close the router session before a rollback settling wait, then verify again.
        self.sleep(self.settle_seconds)
        self._assert_ready()
        settled_rows, settled_projection, settled_ips = self._read(macs)
        if settled_rows != restored_rows or any(settled_ips[t["mac"]] != t["ip"] for t in record["targets"]):
            raise RouteTransactionError("route or DHCP state drifted during recovery settling")
        for target in record["targets"]:
            name = self._identity(target["mac"])[0]
            actual = [row for row in settled_projection if row.get("name") == name]
            before = target["before_row"]
            if (actual if before is None else len(actual) != 1 or actual[0] != before):
                raise RouteTransactionError("recovered target route is not stable")
        latest = self.store.get(intent_id)
        if not latest:
            raise RouteTransactionError("route intent disappeared before saved-state rollback")
        latest = self._set_phase(latest, "recovering")
        self.store.restore_saved(latest["id"], latest["revision"])
        self.store.finish(latest["id"], latest["revision"])

    @classmethod
    def _projection_matches(cls, raw: dict, expected: dict) -> bool:
        projected = cls._project(raw)
        return all(projected.get(key) == value for key, value in expected.items())

    def _mark_error(self, intent_id: str) -> None:
        try:
            entry = self.store.get(intent_id)
            if entry and entry["record"]["phase"] != "error":
                self._set_phase(entry, "error")
        except Exception:
            pass

