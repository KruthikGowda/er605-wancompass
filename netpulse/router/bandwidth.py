"""Owner-reviewed, durable WAN2 per-device bandwidth rule control.

Read-back verifies router configuration only. It does not prove packet-rate
enforcement; that requires a separately authorized measurement pilot.
"""
from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import secrets
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from netpulse.devices.identity import MAC_RE, normalize_mac
from netpulse.router.bandwidth_api import (
    ADD_INTERFACE, BandwidthAPIError, BandwidthRuleAPI, _canonical_rows, _strict_envelope,
)
from netpulse.router.control import STRICT_WAN_FIRMWARE
from netpulse.router.qos import (
    MAX_QOS_ROWS, QoSError, _response_result, _unique_rows, canonical_classification_row,
    canonical_qos_global,
)
from netpulse.storage.bandwidth import BandwidthStore, BandwidthStoreConflict, BandwidthStoreError

SETTLE_SECONDS = 20
TOKEN_SECONDS = 120
MAX_TARGETS = 128
MAX_PENDING_TOKENS = 32
_RATE_CHOICES_MBPS = (2, 5, 10, 25, 50)
# Keep the production candidate disabled until the owner accepts the complete
# provider, persistence, settle, and crash-recovery verification.
BANDWIDTH_TRANSACTIONS_VERIFIED = False


class BandwidthControlError(ValueError):
    """Bandwidth control is unavailable or a reviewed operation changed."""


@dataclass
class _Preview:
    actor: str
    expires_at: float
    targets: list[dict]
    remove: bool
    down_kbps: int | None
    up_kbps: int | None
    setup_global: bool
    fingerprint: str
    group_digest: str | None
    target_context: list[dict]


class BandwidthControl:
    def __init__(self, routes, db_path, enabled: bool = False, sleep=time.sleep, clock=time.time):
        self.routes = routes
        self.db_path = str(db_path)
        self.enabled = bool(enabled)
        self.sleep = sleep
        self.clock = clock
        self.store = BandwidthStore(self.db_path, clock)
        self._tokens: dict[str, _Preview] = {}
        self._token_lock = threading.Lock()
        self._lock = getattr(routes, "_router_write_lock", None) or threading.RLock()
        self._owner_thread: int | None = None

    @property
    def pending_count(self) -> int:
        try:
            return len(self.store.pending())
        except BandwidthStoreError:
            return 1

    @property
    def owns_current_thread(self) -> bool:
        return self._owner_thread == threading.get_ident()

    @contextmanager
    def _owner(self):
        previous = self._owner_thread
        self._owner_thread = threading.get_ident()
        try:
            yield
        finally:
            self._owner_thread = previous

    def state(self) -> dict:
        status = self._route_status()
        try:
            pending = self.store.pending()
            saved_caps = self.store.caps()
        except BandwidthStoreError:
            pending = [{"record": {}}]
            saved_caps = {}
        reason = self._gate_reason(status, pending=bool(pending))
        cleanup_reason = self._gate_reason(status, pending=bool(pending), cleanup=True)
        return {"available": not bool(reason), "enabled": not bool(reason),
                "configured": self.enabled,
                "cleanup_enabled": bool(saved_caps) and not bool(cleanup_reason),
                "supported": status.get("firmware_version") == STRICT_WAN_FIRMWARE,
                "supported_interfaces": [ADD_INTERFACE], "interface": ADD_INTERFACE,
                "firmware_version": status.get("firmware_version"),
                "pending_count": len(pending), "recovery_pending": bool(pending), "reason": reason,
                "cleanup_reason": cleanup_reason,
                "enforcement_verified": False,
                "rate_presets_mbps": list(_RATE_CHOICES_MBPS)}

    def records(self) -> list[dict]:
        try:
            caps = self.store.caps()
        except BandwidthStoreError:
            return []
        return [{"mac": mac, "ip": cap["ip"], "interface": ADD_INTERFACE,
                 "down_kbps": cap["down_kbps"], "up_kbps": cap["up_kbps"],
                 "updated_at": cap["updated_at"]}
                for mac, cap in caps.items()]

    def preview(self, targets, actor: str, down_kbps: int | None = None,
                up_kbps: int | None = None, remove: bool = False,
                group_snapshot=None) -> dict:
        actor = self._validate_actor(actor)
        normalized = self._validate_targets(targets)
        if not isinstance(remove, bool):
            raise BandwidthControlError("Choose either a cap or removal.")
        if remove:
            if down_kbps is not None or up_kbps is not None:
                raise BandwidthControlError("Remove caps without rate values.")
        else:
            down_kbps = self._rate(down_kbps)
            up_kbps = self._rate(up_kbps)
        group_digest = self._group_digest(group_snapshot)
        with self._lock:
            self._require_ready(removal=remove)
            with self.routes.client.session() as client:
                snapshot = self._snapshot(client)
                target_context = self._validate_target_context(client, normalized, require_reservation=False,
                                                               allow_offline=remove)
            self._validate_existing_caps(snapshot["rules"], normalized)
            target_names = {self._managed_name(target["mac"]) for target in normalized}
            before_rows = {row["name"]: row for row in snapshot["rules"]}
            prior = [before_rows.get(self._managed_name(target["mac"])) for target in normalized]
            changed_indexes = [i for i, row in enumerate(snapshot["rules"])
                               if row["name"] in target_names and
                               (remove or row["rate_max"] != up_kbps or row["rate_max_mate"] != down_kbps)]
            if (not remove and changed_indexes and any(row["name"] not in target_names
                                       for row in snapshot["rules"][min(changed_indexes):])):
                raise BandwidthControlError("This batch would change the order of other bandwidth limits. Select all affected devices together for review.")
            if remove and not any(prior):
                raise BandwidthControlError("None of these devices has a verified bandwidth cap to remove.")
            if not remove and all(row and row["rate_max"] == up_kbps and row["rate_max_mate"] == down_kbps
                                  for row in prior):
                raise BandwidthControlError("These devices already have the requested cap.")
            setup_global = False
            global_state = snapshot["global"]
            if not remove:
                if global_state["qos_enable"] == "off":
                    if snapshot["rules"] or snapshot["classes"]:
                        raise BandwidthControlError("The global QoS engine is off with existing QoS rules; manual review is required.")
                    setup_global = True
                elif global_state["qos_enable"] != "on" or global_state["threshold_enable"] != "off":
                    raise BandwidthControlError("ER605 global QoS mode is not supported for reviewed bandwidth caps.")
                if snapshot["classes"]:
                    raise BandwidthControlError("Existing classification rules need manual QoS review before cap changes.")
            elif global_state["qos_enable"] != "on" or global_state["threshold_enable"] != "off":
                raise BandwidthControlError("Global QoS must be on with threshold mode off before removing caps safely.")
            if not remove and len(snapshot["rules"]) + sum(row is None for row in prior) > min(snapshot["max_rules"], MAX_QOS_ROWS):
                raise BandwidthControlError("ER605 QoS rule table has no room for this batch.")
            fingerprint = self._fingerprint(actor, normalized, remove, down_kbps, up_kbps,
                                            snapshot, group_digest)
            token = secrets.token_urlsafe(24)
            with self._token_lock:
                self._prune_tokens_locked()
                if len(self._tokens) >= MAX_PENDING_TOKENS:
                    oldest = min(self._tokens, key=lambda key: self._tokens[key].expires_at)
                    del self._tokens[oldest]
                self._tokens[token] = _Preview(actor, self.clock() + TOKEN_SECONDS,
                                               normalized, remove, down_kbps, up_kbps,
                                               setup_global, fingerprint, group_digest, target_context)
        setup = ("Turn on the router's bandwidth engine (affects traffic processing across the router). "
                 "The current QoS rule and classification lists are empty.") if setup_global else ""
        text = (f"Review WAN2 bandwidth limits for {len(normalized)} device(s). "
                + (f"Download {down_kbps / 1000:g} Mbps; upload {up_kbps / 1000:g} Mbps. "
                   "IPv4 only; other WANs are not limited. " if not remove else "Remove the selected devices' saved WAN2 limits. ")
                + (setup + " " if setup else "")
                + "Allow up to 20 seconds for the router to apply the change. Limits saved on the router remain if NetPulse is offline. "
                + "Configuration read-back does not verify packet-rate enforcement.")
        return {"token": token, "expires_in": TOKEN_SECONDS, "fingerprint": fingerprint,
                "effect": text, "interface": ADD_INTERFACE, "global_setup": setup_global,
                "global_setup_fields": ({"qos_enable": "on", "threshold_enable": "off",
                                          "qos_threshold": 0} if setup_global else None),
                "enforcement_verified": False}

    def check_review(self, token: str, actor: str) -> dict:
        """Revalidate a review without consuming it or writing router state."""
        actor = self._validate_actor(actor)
        with self._token_lock:
            preview = self._tokens.get(token) if isinstance(token, str) else None
            if not preview or preview.expires_at <= self.clock():
                raise BandwidthControlError("This bandwidth review expired; create a new review.")
            if preview.actor != actor:
                raise BandwidthControlError("This bandwidth review belongs to a different operator.")
        with self._lock:
            self._require_ready(removal=preview.remove)
            with self.routes.client.session() as client:
                snapshot = self._snapshot(client)
                self._validate_target_context(client, preview.targets, require_reservation=False,
                                              allow_offline=preview.remove)
            self._validate_existing_caps(snapshot["rules"], preview.targets)
            fingerprint = self._fingerprint(actor, preview.targets, preview.remove,
                                            preview.down_kbps, preview.up_kbps,
                                            snapshot, preview.group_digest)
            if fingerprint != preview.fingerprint:
                raise BandwidthControlError("QoS rules or global settings changed since review.")
        return {"valid": True, "fingerprint": fingerprint,
                "global_setup": preview.setup_global, "effect": "Review is still current."}

    def apply(self, token: str, actor: str, check_unchanged=None) -> dict:
        actor = self._validate_actor(actor)
        if not isinstance(token, str):
            raise BandwidthControlError("This bandwidth review expired; create a new review.")
        with self._token_lock:
            preview = self._tokens.get(token)
            if not preview or preview.expires_at <= self.clock():
                self._tokens.pop(token, None)
                raise BandwidthControlError("This bandwidth review expired or was already used.")
            if preview.actor != actor:
                raise BandwidthControlError("This bandwidth review belongs to a different operator.")
            self._tokens.pop(token, None)
        if preview.group_digest is not None and not callable(check_unchanged):
            raise BandwidthControlError("Refresh the group and confirm it is unchanged before applying.")
        intent_id = None
        revision = None
        did_write = False
        intent_completed = False
        try:
            with self._lock, self._owner():
                self._require_ready(removal=preview.remove)
                with self.routes.client.session() as client:
                    snapshot = self._snapshot(client)
                    target_context = self._validate_target_context(client, preview.targets, require_reservation=True,
                                                                   allow_offline=preview.remove)
                    self._validate_existing_caps(snapshot["rules"], preview.targets)
                    fingerprint = self._fingerprint(actor, preview.targets, preview.remove,
                                                    preview.down_kbps, preview.up_kbps,
                                                    snapshot, preview.group_digest)
                    if fingerprint != preview.fingerprint:
                        raise BandwidthControlError("QoS rules or global settings changed since review; no write was made.")
                    self._check_group(check_unchanged)
                    record = self._intent_record(preview, snapshot)
                    intent_id = self.store.prepare(record)
                    record["phase"] = "applying"
                    revision = self.store.replace(intent_id, 1, record)
                    api = BandwidthRuleAPI(client)
                    with self._guard_router_posts(client, check_unchanged):
                        if preview.setup_global:
                            self._check_group(check_unchanged)
                            self._set_global(client, snapshot["global_raw"], snapshot["global_after_setup"])
                            did_write = True
                        before_by_name = {row["name"]: row for row in snapshot["rules"]}
                        # Remove the selected suffix from the tail before re-adding;
                        # this keeps all unrelated rows in their exact relative order.
                        existing = [(i, target, before_by_name.get(self._managed_name(target["mac"])))
                                    for i, target in enumerate(preview.targets)]
                        for _target_index, target, _row in sorted(
                                (item for item in existing if item[2] is not None),
                                key=lambda item: before_by_name[item[2]["name"]]["position"], reverse=True):
                            self._check_group(check_unchanged)
                            current_rows = api._collection()[1]
                            current = next((row for row in current_rows
                                            if row["name"] == self._managed_name(target["mac"])), None)
                            if current is None:
                                continue
                            api.delete_rule(target["mac"], current)
                            did_write = True
                        if not preview.remove:
                            for target in preview.targets:
                                self._check_group(check_unchanged)
                                api.add_rule(target["mac"], preview.up_kbps, preview.down_kbps)
                                did_write = True
                        record = self.store.get(intent_id)["record"]
                        record["phase"] = "settling"
                        revision = self.store.replace(intent_id, revision, record)
                if did_write:
                    self.sleep(SETTLE_SECONDS)
                with self.routes.client.session() as client:
                    verified = self._snapshot(client)
                    self._validate_target_context(client, preview.targets, require_reservation=True,
                                                  allow_offline=preview.remove)
                    self._verify_final(preview, snapshot, verified)
                self._check_group(check_unchanged)
                caps = self._caps_after(preview)
                self.store.complete(intent_id, revision, caps)
                intent_completed = True
                try:
                    self.store.audit(actor, "remove" if preview.remove else "set", "applied", len(preview.targets))
                except BandwidthStoreError:
                    pass
            return {"applied": True, "count": len(preview.targets), "interface": ADD_INTERFACE,
                    "remove": preview.remove, "enforcement_verified": False,
                    "detail": "ER605 QoS rows were read back after the settle interval; packet-rate enforcement is not claimed."}
        except Exception as exc:
            recovery = None
            if intent_id is not None:
                self._mark_recovering(intent_id)
                try:
                    recovered = self.recover_pending()
                    if recovered.get("recovered"):
                        recovery = recovered
                except Exception:
                    recovery = None
                try:
                    self.store.audit(actor, "remove" if preview.remove else "set", "failed", len(preview.targets))
                except Exception:
                    pass
            original = (str(exc) if isinstance(exc, BandwidthControlError)
                        else "The bandwidth operation failed.")
            if intent_completed:
                raise BandwidthControlError(
                    f"{original} The router change and durable record were already verified; review current state before retrying.") from None
            if recovery and recovery.get("reason") == "Saved router QoS state was restored and verified.":
                raise BandwidthControlError(
                    f"{original} The previous router state was restored and verified.") from None
            if recovery and recovery.get("reason") == "Saved router QoS state was already at its reviewed baseline and was verified.":
                raise BandwidthControlError(
                    f"{original} The previous router state was already at its reviewed baseline and was verified.") from None
            if recovery and not recovery.get("pending"):
                raise BandwidthControlError(
                    f"{original} No recovery lock remains, but the previous router state could not be confirmed; review current state before retrying.") from None
            if intent_id is not None:
                try:
                    is_pending = any(item.get("id") == intent_id for item in self.store.pending())
                except Exception:
                    is_pending = True
                if is_pending:
                    raise BandwidthControlError(
                        f"{original} Recovery is unresolved; the durable operation remains pending and bandwidth controls are locked. Do not retry until it is recovered.") from None
                raise BandwidthControlError(
                    f"{original} The recovery result is unknown and no durable lock could be confirmed; review router and saved cap state before retrying.") from None
            if isinstance(exc, BandwidthControlError):
                raise
            raise BandwidthControlError("Bandwidth change stopped before a durable operation was created; no router write was made.") from None

    def recover_pending(self) -> dict:
        try:
            pending = self.store.pending()
        except BandwidthStoreError:
            return {"recovered": False, "pending": True, "reason": "Durable bandwidth state needs manual repair."}
        if not pending:
            return {"recovered": True, "pending": False, "reason": ""}
        entry = pending[0]
        record = entry["record"]
        try:
            with self._lock, self._owner():
                self._require_recovery_ready()
                if record["phase"] != "recovering":
                    record["phase"] = "recovering"
                    revision = self.store.replace(entry["id"], entry["revision"], record)
                else:
                    revision = entry["revision"]
                changed = False
                with self.routes.client.session() as client:
                    snapshot = self._snapshot(client)
                    target_names = {target["after_row"]["name"] if target["after_row"] else
                                    self._managed_name(target["mac"]) for target in record["targets"]}
                    self._verify_recoverable_rows(record, snapshot["rules"])
                    global_before = record["global_before"]
                    global_after = record["global_after"]
                    global_current = snapshot["global"]
                    global_matches_before = self._global_equal(global_current, global_before)
                    global_matches_after = self._global_equal(global_current, global_after)
                    if snapshot["classes"] != record["classes_before"]:
                        raise BandwidthControlError("QoS classification rules changed outside the pending operation.")
                    if record["engine_setup"]:
                        if not (global_matches_before or global_matches_after):
                            raise BandwidthControlError("Global QoS settings changed outside the pending operation.")
                    elif not global_matches_before:
                        raise BandwidthControlError("Global QoS settings changed outside the pending operation.")
                    baseline_equal = self._rows_equal(snapshot["rules"], record["rules_before"])
                    if record["engine_setup"] and global_matches_before and not baseline_equal:
                        raise BandwidthControlError("QoS rows changed while global QoS was off; recovery is ambiguous.")
                    if not baseline_equal:
                        api = BandwidthRuleAPI(client)
                        current = list(snapshot["rules"])
                        for target in reversed(record["targets"]):
                            name = self._managed_name(target["mac"])
                            row = next((item for item in current if item["name"] == name), None)
                            if row:
                                api.delete_rule(target["mac"], row)
                                current = api._collection()[1]
                                changed = True
                        for target in record["targets"]:
                            prior = target["before_row"]
                            if prior:
                                api.add_rule(target["mac"], prior["rate_max"], prior["rate_max_mate"])
                                changed = True
                    if record["engine_setup"] and global_matches_after:
                        self._set_global(client, snapshot["global_raw"], global_before)
                        changed = True
                    current_global, current_rules, _ = self._qos(client)
                    if not self._global_equal(current_global, global_before):
                        raise BandwidthControlError("Global QoS restoration could not be verified.")
                    # No settle wait inside a router authentication session.
                    if changed:
                        record = self.store.get(entry["id"])["record"]
                        record["phase"] = "settling"
                        revision = self.store.replace(entry["id"], revision, record)
                if changed:
                    self.sleep(SETTLE_SECONDS)
                    with self.routes.client.session() as client:
                        current = self._snapshot(client)
                        if (not self._global_equal(current["global"], record["global_before"]) or
                                not self._rows_equal(current["rules"], record["rules_before"]) or
                                current["classes"] != record["classes_before"]):
                            raise BandwidthControlError("Restored QoS state did not verify after settling.")
                else:
                    if not self._rows_equal(current_rules, record["rules_before"]):
                        raise BandwidthControlError("Saved QoS state is not at the reviewed baseline.")
                self.store.finish(entry["id"], revision)
                try:
                    self.store.audit(record["actor"], "recover", "recovered", len(record["targets"]))
                except BandwidthStoreError:
                    pass
            reason = ("Saved router QoS state was restored and verified." if changed else
                      "Saved router QoS state was already at its reviewed baseline and was verified.")
            return {"recovered": True, "pending": False, "reason": reason}
        except Exception:
            return {"recovered": False, "pending": True,
                    "reason": "Bandwidth recovery is unresolved; controls remain locked for manual review."}

    def _snapshot(self, client) -> dict:
        global_raw = client.get_response("qos", "global")
        raw_global, _ = _strict_envelope(global_raw, collection=False)
        global_state = canonical_qos_global(raw_global)
        if global_state is None:
            raise BandwidthControlError("ER605 global QoS settings have an unknown shape.")
        raw_rules, rules, maximum = BandwidthRuleAPI(client)._collection()
        BandwidthRuleAPI._validate_managed_collection(rules)
        classes_response = client.get_response("qos_ctl", "class")
        try:
            classes = _unique_rows(_response_result(classes_response, list), canonical_classification_row, "id")
        except Exception:
            raise BandwidthControlError("ER605 classification table has an unknown shape.") from None
        global_after_setup = copy.deepcopy(global_state)
        global_after_setup.update({"qos_enable": "on", "threshold_enable": "off", "qos_threshold": 0})
        return {"global": global_state, "global_raw": copy.deepcopy(raw_global), "global_after_setup": global_after_setup,
                "rules": copy.deepcopy(rules), "raw_rules": copy.deepcopy(raw_rules),
                "classes": classes, "max_rules": maximum}

    @staticmethod
    def _qos(client) -> tuple[dict, list[dict], list[dict]]:
        raw, _ = _strict_envelope(client.get_response("qos", "global"), collection=False)
        global_state = canonical_qos_global(raw)
        if global_state is None:
            raise BandwidthControlError("ER605 global QoS settings have an unknown shape.")
        _raw, rows, _maximum = BandwidthRuleAPI(client)._collection()
        BandwidthRuleAPI._validate_managed_collection(rows)
        classes = _unique_rows(_response_result(client.get_response("qos_ctl", "class"), list),
                               canonical_classification_row, "id")
        return global_state, rows, classes

    def _validate_target_context(self, client, targets: list[dict], *, require_reservation: bool,
                                 allow_offline: bool = False) -> list[dict]:
        try:
            reservations = client.get("dhcps", "reservation") or []
            clients = client.get("dhcps", "client") or []
            ip_rows = client.get("ipgroup", "ipscope_reservation") or []
            group_rows = client.get("ipgroup", "ipgroup_reservation") or []
        except Exception:
            raise BandwidthControlError("Fresh DHCP reservation and device groups could not be read.") from None
        if not all(isinstance(rows, list) for rows in (reservations, clients, ip_rows, group_rows)):
            raise BandwidthControlError("Fresh DHCP reservation and device groups are malformed.")
        context = []
        enabled_ip_counts = {}
        for row in reservations:
            if isinstance(row, dict) and self._enabled(row):
                ip = str(row.get("ip", row.get("ipaddr", "")) or "")
                enabled_ip_counts[ip] = enabled_ip_counts.get(ip, 0) + 1
        for target in targets:
            mac, ip = target["mac"], target["ip"]
            if self.routes.is_local_device(mac):
                raise BandwidthControlError("The NetPulse host is protected from bandwidth changes.")
            if ip == str(getattr(self.routes.client, "host", "")):
                raise BandwidthControlError("The router management address is protected from bandwidth changes.")
            try:
                address = ipaddress.ip_address(ip)
            except ValueError:
                raise BandwidthControlError("Target address is not a valid IPv4 host.") from None
            if (address.version != 4 or not address.is_private or address.is_loopback or
                    address.is_link_local or address.is_multicast or address.is_reserved or address.is_unspecified):
                raise BandwidthControlError("Target address is not an eligible private IPv4 host.")
            try:
                self.routes._assert_not_paused(mac)
            except Exception:
                raise BandwidthControlError("A paused or unresolved device cannot receive a bandwidth change.") from None

            by_mac = [row for row in reservations if isinstance(row, dict) and
                      normalize_mac(row.get("mac", row.get("macaddr", ""))) == mac]
            enabled = [row for row in by_mac if self._enabled(row)]
            active_by_mac = [row for row in clients if isinstance(row, dict) and
                             normalize_mac(row.get("macaddr", row.get("mac", ""))) == mac]
            active_by_ip = [row for row in clients if isinstance(row, dict) and
                            str(row.get("ipaddr", row.get("ip", "")) or "") == ip]
            if any(normalize_mac(row.get("macaddr", row.get("mac", ""))) != mac
                   for row in active_by_ip):
                raise BandwidthControlError("Another active device currently claims this IP address.")
            if len(active_by_mac) > 1 or (active_by_mac and
                    str(active_by_mac[0].get("ipaddr", active_by_mac[0].get("ip", ""))) != ip):
                raise BandwidthControlError("The active DHCP identity or IP address changed.")
            if len(enabled) == 1 and len(by_mac) == 1:
                reserved_ip = str(enabled[0].get("ip", enabled[0].get("ipaddr", "")) or "")
                if reserved_ip != ip or enabled_ip_counts.get(ip) != 1:
                    raise BandwidthControlError("The enabled DHCP reservation is missing, duplicated, or changed.")
                if not active_by_mac and not allow_offline:
                    raise BandwidthControlError("One fresh active DHCP identity is required for this bandwidth change.")
                reservation_state = "reserved"
            elif not by_mac and not require_reservation and target["reservation_needed"]:
                if (len(active_by_mac) != 1 or
                        len(active_by_ip) != 1 or str(active_by_mac[0].get("ipaddr", active_by_mac[0].get("ip", ""))) != ip or
                        any(self._enabled(row) and str(row.get("ip", row.get("ipaddr", ""))) == ip
                            for row in reservations)):
                    raise BandwidthControlError("The missing reservation is not supported by one fresh DHCP client.")
                reservation_state = "candidate"
            else:
                raise BandwidthControlError("One unique enabled DHCP reservation is required for every selected device.")

            hexmac = mac.replace("-", "")
            ip_name, group_name = f"NP_I_{hexmac}", f"NP_G_{hexmac}"
            matching_ip = [row for row in ip_rows if isinstance(row, dict) and row.get("name") == ip_name]
            matching_group = [row for row in group_rows if isinstance(row, dict) and row.get("name") == group_name]
            if len(matching_ip) > 1 or len(matching_group) > 1:
                raise BandwidthControlError("NetPulse address or source group is ambiguous.")
            if matching_ip:
                exact_scope = f"{ip}-{ip}"
                row = matching_ip[0]
                expected_keys = {".name", ".type", "name", "flag", "scope", "comment", ".anonymous", "type"}
                optional_keys = {"scope_start", "scope_end"}
                if (set(row) - expected_keys - optional_keys or
                        not expected_keys.issubset(row) or
                        row.get(".name") != ip_name + "_ipscope" or row.get(".type") != "rule_ipscope" or
                        row.get("name") != ip_name or row.get("flag") != "user" or
                        row.get("scope") != exact_scope or row.get("comment") != "NetPulse" or
                        row.get(".anonymous") is not False or row.get("type") != "range" or
                        ("scope_start" in row and row.get("scope_start") != ip) or
                        ("scope_end" in row and row.get("scope_end") != ip)):
                    raise BandwidthControlError("The NetPulse address entry does not contain exactly the selected IP.")
            elif require_reservation:
                raise BandwidthControlError("The exact NetPulse address entry is missing; route controls must prepare it first.")
            if matching_group:
                row = matching_group[0]
                expected_keys = {".name", ".type", ".anonymous", "flag", "name", "rule_scope", "ref"}
                optional_keys = {"comment"}
                if (set(row) - expected_keys - optional_keys or not expected_keys.issubset(row) or
                        row.get(".name") != group_name + "_ipgroup" or row.get(".type") != "rule_ipgroup" or
                        row.get(".anonymous") is not False or row.get("flag") != "user" or
                        row.get("name") != group_name or row.get("rule_scope") != [ip_name] or
                        str(row.get("ref")) not in {"0", "1", "2"} or
                        ("comment" in row and row.get("comment") != "")):
                    raise BandwidthControlError("The NetPulse source group is not bound to exactly this address entry.")
            elif require_reservation:
                raise BandwidthControlError("The exact NetPulse source group is missing; route controls must prepare it first.")
            for row in group_rows:
                if (isinstance(row, dict) and row.get("name") != group_name and
                        isinstance(row.get("rule_scope"), list) and ip_name in row["rule_scope"]):
                    raise BandwidthControlError("Another router group references the selected device address entry.")
            context.append({"mac": mac, "ip": ip, "reservation": reservation_state,
                            "ip_entry": bool(matching_ip), "group": bool(matching_group)})
        return context

    def _validate_existing_caps(self, rows: list[dict], targets: list[dict]) -> None:
        saved = self.store.caps()
        observed_macs = {self._mac_from_rule(row["name"]) for row in rows}
        if observed_macs != set(saved):
            raise BandwidthControlError("Router QoS rows do not match the durable verified cap state; manual review is required.")
        for row in rows:
            mac = self._mac_from_rule(row["name"])
            cap = saved.get(mac)
            if cap is None or cap["down_kbps"] != row["rate_max_mate"] or cap["up_kbps"] != row["rate_max"]:
                raise BandwidthControlError("Router QoS rows do not match the durable verified cap state; manual review is required.")
        for target in targets:
            cap = saved.get(target["mac"])
            if cap and (cap["ip"] != target["ip"] or
                        not any(row["name"] == self._managed_name(target["mac"]) for row in rows)):
                raise BandwidthControlError("The saved bandwidth cap is missing from the router; manual recovery is required.")

    def _intent_record(self, preview: _Preview, snapshot: dict) -> dict:
        by_name = {row["name"]: row for row in snapshot["rules"]}
        targets = []
        for target in preview.targets:
            name = self._managed_name(target["mac"])
            before = by_name.get(name)
            after = None if preview.remove else self._desired_row(target["mac"], preview.down_kbps, preview.up_kbps,
                                                                  (before or {}).get("position", len(snapshot["rules"]) + 1),
                                                                  (before or {}).get("setting_index", "0"))
            targets.append({"mac": target["mac"], "ip": target["ip"],
                            "before_row": copy.deepcopy(before), "after_row": after})
        global_after = copy.deepcopy(snapshot["global_after_setup"] if preview.setup_global else snapshot["global"])
        return {"actor": preview.actor, "created_at": self.clock(),
                "firmware": STRICT_WAN_FIRMWARE, "phase": "prepared", "targets": targets,
                "global_before": copy.deepcopy(snapshot["global"]), "global_after": global_after,
                "rules_before": copy.deepcopy(snapshot["rules"]),
                "classes_before": copy.deepcopy(snapshot["classes"]),
                "engine_setup": preview.setup_global,
                "remove": preview.remove, "down_kbps": preview.down_kbps, "up_kbps": preview.up_kbps}

    @staticmethod
    def _desired_row(mac: str, down: int, up: int, position: int, setting_index: str) -> dict:
        name = BandwidthControl._managed_name(mac)
        return {".name": name, ".type": "rule", ".anonymous": False,
                "setting_index": str(setting_index), "t_ping_label": "LAN", "t_pong_label": "WAN/LAN2",
                "position": position, "name": name, "if_ping": "LAN", "if_pong": "WAN2",
                "source_type": "ip_group", "ip_group": "NP_G_" + mac.replace("-", ""),
                "rate_max": up, "rate_max_mate": down, "mode": "priv", "time": "Any",
                "comment": "NetPulse validation", "enable": "on", "ip_type": "src"}

    def _verify_final(self, preview: _Preview, before: dict, after: dict) -> None:
        if preview.setup_global:
            if not self._global_equal(after["global"], before["global_after_setup"]):
                raise BandwidthControlError("Global QoS setup did not read back as reviewed.")
        elif not self._global_equal(after["global"], before["global"]):
            raise BandwidthControlError("Global QoS settings changed during the batch.")
        target_names = {self._managed_name(target["mac"]) for target in preview.targets}
        if preview.remove:
            expected = [row for row in before["rules"] if row["name"] not in target_names]
        else:
            expected = [row for row in before["rules"] if row["name"] not in target_names]
            for target in preview.targets:
                expected.append(self._desired_row(target["mac"], preview.down_kbps, preview.up_kbps,
                                                  len(expected) + 1, "0"))
        if not self._rows_equal(after["rules"], expected):
            raise BandwidthControlError("QoS rule read-back differed from the reviewed batch.")
        if after["classes"] != before["classes"]:
            raise BandwidthControlError("QoS classification rules changed during the batch.")

    def _verify_recoverable_rows(self, record: dict, current: list[dict]) -> None:
        before = record["rules_before"]
        if self._rows_equal(current, before):
            return
        targets = record["targets"]
        names = {target["after_row"]["name"] if target["after_row"] else
                 self._managed_name(target["mac"]) for target in targets}
        first = next((i for i, row in enumerate(before) if row["name"] in names), len(before))
        if any(row["name"] not in names for row in before[first:]):
            raise BandwidthControlError("Selected caps are not a recoverable final suffix.")
        prefix = before[:first]
        old = before[first:]
        current_names = [row["name"] for row in current]
        prefix_names = [row["name"] for row in prefix]
        if current_names[:len(prefix)] != prefix_names:
            raise BandwidthControlError("An unrelated QoS rule changed during the pending operation.")
        current_suffix = current[len(prefix):]
        old_names = [row["name"] for row in old]
        after = [target["after_row"] for target in targets if target["after_row"] is not None]
        after_names = [row["name"] for row in after]
        if current_suffix:
            candidates = []
            if current_suffix and all(row["name"] in old_names for row in current_suffix):
                candidates.append(old)
            if current_suffix and all(row["name"] in after_names for row in current_suffix):
                candidates.append(after)
            valid_sequence = any([row["name"] for row in sequence[:len(current_suffix)]] ==
                                 [row["name"] for row in current_suffix] for sequence in candidates)
            if not valid_sequence:
                raise BandwidthControlError("Current QoS rows are not a known before or in-progress target state.")
        for index, row in enumerate(current):
            if index < len(prefix):
                expected = prefix[index]
                if not self._row_equal(row, expected, ignore_index=True):
                    raise BandwidthControlError("An unrelated QoS rule changed during recovery.")
            else:
                target = next((item for item in targets if self._managed_name(item["mac"]) == row["name"]), None)
                if not target:
                    raise BandwidthControlError("An unknown QoS row blocks recovery.")
                candidates = [item for item in (target["before_row"], target["after_row"]) if item]
                if not any(self._row_equal(row, item, ignore_index=True) for item in candidates):
                    raise BandwidthControlError("A target QoS row is not a known before or desired state.")

    def _set_global(self, client, current_raw: dict, desired: dict) -> None:
        current = canonical_qos_global(current_raw)
        if current is None:
            raise BandwidthControlError("Global QoS settings have an unknown shape.")
        desired_canonical = canonical_qos_global(desired)
        if desired_canonical is None:
            raise BandwidthControlError("Global QoS target settings are invalid.")
        token = getattr(client, "_stok", None)
        if not isinstance(token, str) or not token:
            raise BandwidthControlError("ER605 session ended before the global QoS update.")
        payload = {"method": "set", "params": {
            "qos_enable": desired_canonical["qos_enable"],
            "threshold_enable": desired_canonical["threshold_enable"],
            "qos_threshold": str(desired_canonical["qos_threshold"]),
        }}
        try:
            response = client._post(f"/cgi-bin/luci/;stok={token}/admin/qos?form=global",
                                    {"data": json.dumps(payload)})
            if not isinstance(response, dict) or str(response.get("error_code")) != "0":
                raise BandwidthControlError("ER605 rejected the reviewed global QoS update.")
            readback, _ = _strict_envelope(client.get_response("qos", "global"), collection=False)
            observed = canonical_qos_global(readback)
            if observed is None or not self._global_equal(observed, desired_canonical):
                raise BandwidthControlError("Global QoS setup did not read back exactly.")
        except BandwidthControlError:
            raise
        except Exception:
            raise BandwidthControlError("Global QoS update outcome is uncertain; retain the operation intent.") from None

    def _require_ready(self, *, removal: bool = False) -> None:
        status = self._route_status()
        try:
            pending = bool(self.store.pending())
        except BandwidthStoreError:
            pending = True
        reason = self._gate_reason(status, pending=pending, cleanup=removal)
        if reason:
            raise BandwidthControlError(reason)

    def _require_recovery_ready(self) -> None:
        status = self._route_status()
        reason = self._gate_reason(status, pending=False, cleanup=True)
        if reason:
            raise BandwidthControlError("Router recovery is locked until the exact firmware and manual readiness are available.")

    def _route_status(self) -> dict:
        try:
            status = self.routes.state()
            status = dict(status) if isinstance(status, dict) else {}
            status["kill_switch"] = bool(status.get("kill_switch") or
                                           getattr(self.routes, "kill_switch", None) and
                                           Path(self.routes.kill_switch).exists())
            return status
        except Exception:
            return {"enabled": False, "firmware_version": None, "kill_switch": False}

    def _gate_reason(self, status: dict, *, pending: bool, cleanup: bool = False) -> str:
        if pending:
            return "A bandwidth operation needs recovery; new caps are locked."
        if not cleanup and not self.enabled:
            return "Bandwidth controls are disabled in config."
        if not cleanup and not BANDWIDTH_TRANSACTIONS_VERIFIED:
            return "Bandwidth transactions are not enabled until provider and recovery verification is accepted."
        if status.get("firmware_version") != STRICT_WAN_FIRMWARE:
            return f"WAN2 bandwidth controls are supported only on ER605 firmware {STRICT_WAN_FIRMWARE}."
        if status.get("kill_switch"):
            return "The local router-control kill switch is active."
        if not status.get("enabled") and not (cleanup and self._cleanup_route_ready(status)):
            return str(status.get("reason") or "Router controls are not ready.")
        if self._manual_block_reason():
            return self._manual_block_reason()
        return ""

    def _cleanup_route_ready(self, status: dict) -> bool:
        return (status.get("firmware_version") == STRICT_WAN_FIRMWARE and
                not status.get("firmware_review_required") and
                not status.get("acl_recovery_failed") and
                status.get("load_balancing") is True and
                status.get("router_age_seconds") is not None and
                0 <= status.get("router_age_seconds") <= 300 and
                status.get("router_uptime_seconds") is not None and
                status.get("router_uptime_seconds") >= 300 and
                status.get("router_uptime_age_seconds") is not None and
                0 <= status.get("router_uptime_age_seconds") <= 120)

    def _manual_block_reason(self) -> str:
        router = getattr(self.routes, "router", None)
        if router is None:
            return "Router readiness is unavailable."
        if getattr(router, "_paused_until", 0) > self.clock():
            return "Router checks are paused while the operator uses Omada."
        if getattr(router, "_login_blocked_until", 0) > self.clock():
            return "ER605 authentication is in backoff."
        if getattr(router, "_unreachable", 0):
            return "ER605 is unreachable."
        snap = getattr(router, "snap", None)
        if getattr(snap, "ok", True) is False:
            return "The latest authenticated router sample is not ready."
        return ""

    @staticmethod
    def _enabled(row: dict) -> bool:
        return str(row.get("enable", row.get("enabled", "1"))).casefold() not in {"0", "false", "off", "disabled"}

    @staticmethod
    def _validate_actor(actor: object) -> str:
        if (not isinstance(actor, str) or not actor or len(actor) > 128 or
                any(ord(char) < 32 or ord(char) == 127 for char in actor)):
            raise BandwidthControlError("An operator identity is required.")
        return actor

    @staticmethod
    def _rate(value: object) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or not 100 <= value <= 1_000_000:
            raise BandwidthControlError("Bandwidth rates must be integers from 100 to 1000000 kbps.")
        return value

    def _validate_targets(self, targets) -> list[dict]:
        if not isinstance(targets, list) or not 1 <= len(targets) <= MAX_TARGETS:
            raise BandwidthControlError("Select between 1 and 128 devices.")
        result, seen_macs, seen_ips = [], set(), set()
        for item in targets:
            if not isinstance(item, dict):
                raise BandwidthControlError("A selected device identity is invalid.")
            try:
                mac = normalize_mac(item.get("mac", ""))
            except Exception:
                mac = None
            ip = item.get("ip")
            name = item.get("name")
            reservation_needed = item.get("reservation_needed", False)
            current = item.get("current")
            if (not isinstance(mac, str) or not MAC_RE.fullmatch(mac) or
                    not isinstance(ip, str) or not isinstance(name, str) or not name or len(name) > 128 or
                    not isinstance(reservation_needed, bool) or not isinstance(current, str) or
                    current not in {"AUTO", "WAN1", "WAN2", "WAN1_ONLY", "WAN2_ONLY", "active"}):
                raise BandwidthControlError("A selected device identity is invalid.")
            try:
                address = ipaddress.ip_address(ip)
            except ValueError:
                raise BandwidthControlError("A selected device IP is invalid.") from None
            if address.version != 4 or str(address) != ip:
                raise BandwidthControlError("A selected device IP must be canonical IPv4.")
            if mac in seen_macs or ip in seen_ips:
                raise BandwidthControlError("Selected device MAC and IP identities must be unique.")
            seen_macs.add(mac)
            seen_ips.add(ip)
            result.append({"mac": mac, "ip": ip, "name": " ".join(name.split())[:128],
                           "reservation_needed": reservation_needed,
                           "current": current})
        return result

    @staticmethod
    def _managed_name(mac: str) -> str:
        return "NP_Q_" + mac.replace("-", "")

    @staticmethod
    def _mac_from_rule(name: str) -> str:
        hexmac = name.removeprefix("NP_Q_")
        return "-".join(hexmac[index:index + 2] for index in range(0, 12, 2))

    @staticmethod
    def _global_equal(left: dict, right: dict) -> bool:
        if not isinstance(left, dict) or not isinstance(right, dict):
            return False
        return {key: value for key, value in left.items() if key != "qos_setting_number"} == \
               {key: value for key, value in right.items() if key != "qos_setting_number"}

    @staticmethod
    def _row_equal(left: dict, right: dict, *, ignore_index: bool = False) -> bool:
        ignored = {"position", "setting_index"} if ignore_index else set()
        return ({key: value for key, value in left.items() if key not in ignored} ==
                {key: value for key, value in right.items() if key not in ignored})

    @classmethod
    def _rows_equal(cls, left: list[dict], right: list[dict]) -> bool:
        return (len(left) == len(right) and
                all(cls._row_equal(a, b, ignore_index=True) for a, b in zip(left, right)))

    @staticmethod
    def _fingerprint(actor, targets, remove, down, up, snapshot, group_digest) -> str:
        fingerprint_global = copy.deepcopy(snapshot["global"])
        # This counter is volatile on some ER605 responses even when settings
        # and rules are unchanged. Keep it in the reviewed snapshot, but do not
        # bind the operator confirmation to it.
        fingerprint_global.pop("qos_setting_number", None)
        value = {"actor": actor, "targets": [{"mac": row["mac"], "ip": row["ip"],
                                               "reservation_needed": row["reservation_needed"],
                                               "current": row.get("current")} for row in targets],
                 "remove": remove, "down_kbps": down, "up_kbps": up,
                 "global": fingerprint_global, "rules": snapshot["rules"],
                 "classes": snapshot["classes"], "group": group_digest}
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    @staticmethod
    def _group_digest(snapshot) -> str | None:
        if snapshot is None:
            return None
        try:
            data = json.dumps(snapshot, sort_keys=True, separators=(",", ":"), allow_nan=False)
        except (TypeError, ValueError):
            raise BandwidthControlError("The reviewed group snapshot is invalid.") from None
        if len(data.encode("utf-8")) > 16 * 1024:
            raise BandwidthControlError("The reviewed group snapshot is too large.")
        return hashlib.sha256(data.encode("utf-8")).hexdigest()

    @staticmethod
    def _check_group(callback) -> None:
        if not callable(callback):
            return
        try:
            result = callback()
        except Exception:
            raise BandwidthControlError("The selected group changed; no further router writes were made.") from None
        if result is False:
            raise BandwidthControlError("The selected group changed; no further router writes were made.")

    @contextmanager
    def _guard_router_posts(self, client, callback):
        if not callable(callback):
            yield
            return
        original = client._post

        def guarded(*args, **kwargs):
            self._check_group(callback)
            return original(*args, **kwargs)

        client._post = guarded
        try:
            yield
        finally:
            client._post = original

    def _caps_after(self, preview: _Preview) -> list[dict]:
        return [{"mac": target["mac"], "ip": target["ip"],
                 "down_kbps": None if preview.remove else preview.down_kbps,
                 "up_kbps": None if preview.remove else preview.up_kbps,
                 "actor": preview.actor} for target in preview.targets]

    def _mark_recovering(self, intent_id: str) -> None:
        try:
            entry = self.store.get(intent_id)
            if entry and entry["record"]["phase"] != "recovering":
                record = entry["record"]
                record["phase"] = "recovering"
                self.store.replace(intent_id, entry["revision"], record)
        except Exception:
            return

    def _prune_tokens_locked(self) -> None:
        now = self.clock()
        for token, value in list(self._tokens.items()):
            if value.expires_at <= now:
                del self._tokens[token]
