"""Owner reviewed, combined device and group actions."""
from __future__ import annotations

import copy
import hashlib
import json
import secrets
import threading
import time

from netpulse.devices.identity import MAC_RE, normalize_mac
from netpulse.freshness import age_seconds
from netpulse.router.control import (ControlError, MAX_ROUTER_AGE_SECONDS,
                                     ROUTE_EXPIRY_OPTIONS, _balance_enabled,
                                     observed_netpulse_route)
from netpulse.storage import sqlite

ACTION_ROUTES = {"auto": "AUTO", "prefer_wan1": "WAN1", "prefer_wan2": "WAN2",
                 "only_wan1": "WAN1_ONLY", "only_wan2": "WAN2_ONLY"}
ACTION_SECONDS = 120
MAX_TARGETS = 128
MAX_PENDING = 2048
BANDWIDTH_ACTIONS = {
    f"bandwidth_wan2_{rate}m": (rate * 1000, rate * 1000)
    for rate in (2, 5, 10, 25, 50)
}
BANDWIDTH_ACTIONS["bandwidth_wan2_remove"] = None


class ActionControl:
    """Combine existing verified router and pause controls behind one reviewed token."""

    def __init__(self, routes, pause=None, bandwidth=None):
        self.routes = routes
        self.pause = pause
        self.bandwidth = bandwidth
        self.router = routes.router
        self.client = routes.client
        self.db_path = routes.db_path
        self._lock = threading.RLock()
        self._write_lock = routes._router_write_lock
        self._pending: dict[str, dict] = {}

    def state(self):
        route = self.routes.state()
        pause = self.pause.state() if self.pause is not None else {"enabled": False,
                                                                     "reason": "Internet pause controls are unavailable."}
        actions = [{"id": key, "label": label, "enabled": bool(route.get("enabled")),
                    "reason": route.get("reason", "")}
                   for key, label in (("auto", "Auto"), ("prefer_wan1", "Prefer WAN 1"),
                                      ("prefer_wan2", "Prefer WAN 2"))]
        for key, label in (("pause", "Pause"), ("resume", "Resume")):
            enabled = pause.get("enabled") if key == "pause" else pause.get("cleanup_enabled")
            actions.append({"id": key, "label": label, "enabled": bool(enabled),
                            "reason": pause.get("reason", "") if not enabled else ""})
        for key, label in (("only_wan1", "Only WAN 1"), ("only_wan2", "Only WAN 2")):
            actions.append({"id": key, "label": label,
                            "enabled": bool(route.get("strict_wan_available")),
                            "reason": route.get("strict_wan_reason", "")
                            if not route.get("strict_wan_available") else ""})
        return {"enabled": bool(route.get("enabled")), "actions": actions,
                "bandwidth_options": self.bandwidth_options(),
                "bandwidth_caps": self.bandwidth.records() if self.bandwidth else [],
                "reason": route.get("reason", "")}

    def bandwidth_options(self):
        if self.bandwidth is None:
            return []
        state = self.bandwidth.state()
        options = []
        for action, rates in BANDWIDTH_ACTIONS.items():
            enabled = state.get("enabled") if rates else state.get("cleanup_enabled", state.get("enabled"))
            label = (f"WAN 2 · {rates[0] // 1000} Mbps per device" if rates
                     else "Remove WAN 2 limits")
            options.append({"id": action, "label": label, "enabled": bool(enabled),
                            "reason": state.get("reason", "") if not enabled else ""})
        return options

    def preview(self, *, macs=None, group_id=None, action, actor, duration_seconds=0,
                management_ip=None):
        if (macs is None) == (group_id is None):
            raise ControlError("Choose devices or one device group.")
        if not isinstance(actor, str) or not actor.strip():
            raise ControlError("An actor is required for confirmation.")
        action = str(action or "").lower()
        if action not in (*ACTION_ROUTES, *BANDWIDTH_ACTIONS, "pause", "resume"):
            raise ControlError("Choose Auto, Prefer WAN 1, Prefer WAN 2, pause, or resume.")
        if action in BANDWIDTH_ACTIONS:
            option = next((item for item in self.bandwidth_options() if item["id"] == action), None)
            if not option or not option["enabled"]:
                raise ControlError((option or {}).get("reason") or "Bandwidth controls are unavailable.")
            if isinstance(duration_seconds, bool) or duration_seconds != 0:
                raise ControlError("Bandwidth limits stay until changed; no duration is supported.")
        elif action in ("pause", "resume"):
            if self.pause is None:
                raise ControlError("Internet pause controls are unavailable.")
            status = self.pause.state()
            if action == "pause" and not status.get("enabled"):
                raise ControlError(status.get("reason") or "Internet pause controls are locked.")
            if action == "resume" and not status.get("cleanup_enabled"):
                raise ControlError(status.get("reason") or "Pause cleanup is locked.")
            if isinstance(duration_seconds, bool) or duration_seconds not in (0, 900, 3600, 21600):
                raise ControlError("Choose until resumed, 15 minutes, 1 hour, or 6 hours.")
            if action == "resume":
                duration_seconds = 0
        else:
            if (isinstance(duration_seconds, bool) or duration_seconds not in ROUTE_EXPIRY_OPTIONS):
                raise ControlError("Choose until changed, 1 hour, 6 hours, 24 hours, or 7 days.")
            if action == "auto":
                duration_seconds = 0

        group = None
        if group_id is not None:
            if isinstance(group_id, bool) or not isinstance(group_id, int):
                raise ControlError("Choose a valid device group.")
            group = next((g for g in sqlite.device_groups(self.db_path) if g["id"] == group_id), None)
            if not group:
                raise ControlError("This device group no longer exists.")
            selected = list(group["members"])
            if action == "resume":
                selected = [m for m in selected if (self.pause.store.get(m) or {}).get("status")
                            in ("paused", "applying", "resuming", "error")]
            group_snapshot = {"id": group["id"], "name": group["name"],
                              "updated_at": group["updated_at"], "members": list(group["members"]),
                              "smart_routing_enabled": group["smart_routing_enabled"]}
        else:
            if not isinstance(macs, (list, tuple)) or not macs or len(macs) > MAX_TARGETS:
                raise ControlError(f"Select between 1 and {MAX_TARGETS} devices.")
            selected = [normalize_mac(m) for m in macs]
            if any(not MAC_RE.fullmatch(m) for m in selected) or len(set(selected)) != len(selected):
                raise ControlError("Select unique, valid devices.")
            group_snapshot = None
        if not selected:
            raise ControlError("There are no eligible devices for this action.")
        if len(selected) > MAX_TARGETS:
            raise ControlError(f"Select no more than {MAX_TARGETS} devices.")
        if not self.routes.state()["enabled"]:
            raise ControlError("Router controls are locked; no combined action preview is available.")
        if action in ("only_wan1", "only_wan2") and not self.routes.state().get("strict_wan_available"):
            if not self.routes.strict_wan_enabled:
                raise ControlError("Strict WAN routing is disabled in config; no Only-mode route will be written.")
            raise ControlError(self.routes.state().get("strict_wan_reason")
                               or "Strict WAN routing is unavailable on this firmware and control state.")

        management_ip = str(management_ip or "").strip() or None
        targets = self._build_targets(selected, action, group, duration_seconds, management_ip)
        token = secrets.token_urlsafe(32)
        now = time.time()
        payload = {"targets": targets, "action": action, "route": ACTION_ROUTES.get(action),
                   "actor": actor.strip(), "duration_seconds": duration_seconds,
                   "management_ip": management_ip,
                   "group": group_snapshot, "expires": now + ACTION_SECONDS}
        bandwidth_review = None
        if action in BANDWIDTH_ACTIONS:
            rates = BANDWIDTH_ACTIONS[action]
            bandwidth_review = self.bandwidth.preview(
                targets, actor.strip(), down_kbps=rates[0] if rates else None,
                up_kbps=rates[1] if rates else None, remove=rates is None,
                group_snapshot=group_snapshot)
            payload["bandwidth_token"] = bandwidth_review["token"]
            payload["bandwidth_fingerprint"] = bandwidth_review["fingerprint"]
        payload["fingerprint"] = self._fingerprint(payload)
        with self._lock:
            self._pending = {k: v for k, v in self._pending.items() if v["expires"] > now}
            if len(self._pending) >= MAX_PENDING:
                raise ControlError("Too many pending action previews; wait for older reviews to expire.")
            self._pending[token] = payload
        result = {"token": token, "expires_in": ACTION_SECONDS, "action": action,
                  "fingerprint": payload["fingerprint"],
                  "members": [{k: t[k] for k in ("mac", "ip", "name", "reservation_needed", "current")}
                              for t in targets],
                  "count": len(targets),
                  "reservation_count": sum(t["reservation_needed"] for t in targets),
                  "effect": (bandwidth_review["effect"] if bandwidth_review else
                             self._effect(action, targets, duration_seconds))}
        if group_snapshot:
            result["group"] = group_snapshot["name"]
        return result

    @staticmethod
    def _fingerprint(payload):
        group = payload.get("group")
        normalized_group = ({key: group.get(key) for key in
                             ("id", "name", "updated_at", "members", "smart_routing_enabled")}
                            if group else None)
        targets = [{key: target.get(key) for key in
                    ("mac", "ip", "name", "reservation_needed", "current", "saved_current",
                     "route_expires_at")}
                   for target in payload["targets"]]
        value = {"action": payload["action"], "route": payload.get("route"),
                 "bandwidth_fingerprint": payload.get("bandwidth_fingerprint"),
                 "duration_seconds": payload["duration_seconds"], "actor": payload["actor"],
                 "management_ip": payload.get("management_ip"), "group": normalized_group,
                 "targets": targets}
        canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def _build_targets(self, selected, action, group, duration_seconds, management_ip):
        raw = self.router.snap.raw if isinstance(self.router.snap.raw, dict) else {}
        device_age = age_seconds(getattr(self.router.snap, "checked_at", None), time.time())
        if device_age is None or device_age > max(MAX_ROUTER_AGE_SECONDS,
                                                    getattr(self.router, "poll_seconds", 0) * 2):
            raise ControlError("The router device list is stale; wait for its next refresh before reviewing this action.")
        labels = sqlite.device_labels(self.db_path)
        targets = []
        pause_snap = None
        if action in ("pause", "resume"):
            pause_snap = self.pause._fresh_snapshot(allow_disabled=action == "resume")
            self.pause._acl_check(pause_snap["acls"], self.pause.store.list())
        for mac in selected:
            self.routes._assert_not_paused(mac) if action not in ("resume", "pause") else None
            if action == "resume":
                record = self.pause.store.get(mac)
                if not record or record.get("status") not in ("paused", "applying", "resuming", "error"):
                    raise ControlError("A selected device has no saved pause intent to resume.")
                self._check_management_target(mac, str(record.get("ip") or ""), management_ip)
                targets.append({"mac": mac, "ip": str(record.get("ip") or ""),
                                "name": str(record.get("label") or "Home device"),
                                "reservation_needed": False, "current": "paused"})
                continue

            reservation_needed = False
            reservations = raw.get("reservations") if isinstance(raw.get("reservations"), list) else []
            matches = [r for r in reservations if isinstance(r, dict)
                       and normalize_mac(r.get("mac", r.get("macaddr", ""))) == mac]
            if matches:
                reservation, ip = self.routes._cached_device(mac)
                name = labels.get(mac) or str(reservation.get("note") or "Home device")
            else:
                client, ip, name = self.routes._reservation_candidate(raw.get("clients"),
                    raw.get("reservations"), raw.get("lan_scopes"), raw.get("dhcp_settings"),
                    mac, labels.get(mac, ""))
                reservation_needed = True
            observed = observed_netpulse_route(raw, mac)
            checked = age_seconds(observed.get("checked_at"), time.time())
            if observed.get("route") is None or checked is None or checked > MAX_ROUTER_AGE_SECONDS:
                raise ControlError("The ER605's current device route is stale or unreadable; refresh before review.")
            saved = self.routes.route_state().get(mac, {})
            if action == "pause":
                if self.pause.store.get(mac):
                    raise ControlError("This device already has a pause intent or unresolved pause change.")
                if reservation_needed:
                    candidate = {**pause_snap, "reservations": list(pause_snap["reservations"] or []) +
                                 [{"mac": mac, "ip": ip, "enable": "on"}]}
                    self._check_pause_objects_candidate(mac, ip, candidate, management_ip)
                else:
                    self.pause._candidate(mac, pause_snap, management_ip)
                current = "active"
            elif action in ACTION_ROUTES:
                self._check_management_target(mac, ip, management_ip)
                if reservation_needed:
                    current = observed["route"]
                else:
                    route_preview = self.routes.preview(mac, ACTION_ROUTES[action], "action-preview",
                                                        duration_seconds)
                    with self.routes._lock:
                        self.routes._pending.pop(route_preview["token"], None)
                    current = route_preview["observed_current"]
            elif action in BANDWIDTH_ACTIONS:
                self._check_management_target(mac, ip, management_ip)
                current = observed["route"]
            else:
                raise ControlError("Unsupported combined action.")
            targets.append({"mac": mac, "ip": ip, "name": str(name)[:80],
                            "reservation_needed": reservation_needed, "current": current,
                            "saved_current": saved.get("route", "AUTO"),
                            "route_expires_at": saved.get("expires_at"),
                            "current_expiry_state": ({"expires_at": saved.get("expires_at"),
                                                      "expires_monotonic": saved.get("expires_monotonic"),
                                                      "boot_id": saved.get("boot_id")}
                                                     if saved.get("route", "AUTO") == current
                                                     and saved.get("route") in ("WAN1", "WAN2", "WAN1_ONLY", "WAN2_ONLY")
                                                     else None)})
        return targets

    def _check_management_target(self, mac, ip, management_ip=None):
        if management_ip and ip == management_ip:
            raise ControlError("This action would affect the connected management device; select another device.")
        if self.routes.is_local_device(mac):
            raise ControlError("The NetPulse host is protected from device actions.")
        if self.pause is not None and mac in self.pause.protected_macs:
            raise ControlError("This device is protected from route changes.")
        raw = self.router.snap.raw if isinstance(self.router.snap.raw, dict) else {}
        local_macs = self.routes.local_device_macs()
        local_ips = {str(c.get("ipaddr", c.get("ip", ""))) for c in raw.get("clients", [])
                     if isinstance(c, dict) and self.routes._client_mac(c) in local_macs}
        protected_ips = {str(getattr(self.client, "host", ""))}
        protected_ips.update(str(raw.get(k, "")) for k in ("router_ip", "lan_ip", "gateway_ip"))
        if ip in local_ips or ip in protected_ips:
            raise ControlError("This is a router or NetPulse management address and is protected.")

    def _check_pause_objects_candidate(self, mac, ip, snap, management_ip=None):
        iname, gname = f"NP_I_{mac.replace('-', '')}", f"NP_G_{mac.replace('-', '')}"
        ips = [r for r in snap["ipscopes"] if isinstance(r, dict) and r.get("name") == iname]
        groups = [r for r in snap["ipgroups"] if isinstance(r, dict) and r.get("name") == gname]
        if (ips and (len(ips) != 1 or ips[0].get("scope") != f"{ip}-{ip}" or ips[0].get("type") != "range")):
            raise ControlError("A NetPulse device address object conflicts with the reviewed lease.")
        if groups and (len(groups) != 1 or not ips or groups[0].get("rule_scope") != [iname]):
            raise ControlError("A NetPulse device group conflicts with the reviewed address object.")
        candidate = copy.deepcopy(snap)
        if not ips:
            candidate["ipscopes"] = list(candidate["ipscopes"] or []) + [
                {"name": iname, "scope": f"{ip}-{ip}", "type": "range"}]
        if not groups:
            candidate["ipgroups"] = list(candidate["ipgroups"] or []) + [
                {"name": gname, "rule_scope": [iname]}]
        self.pause._candidate(mac, candidate, management_ip)

    @staticmethod
    def _effect(action, targets, duration):
        if action == "pause":
            timed = ({900: "15 minutes", 3600: "1 hour", 21600: "6 hours"}.get(duration))
            expiry = (f" NetPulse will try to resume it after {timed}; the service must be running for timed cleanup, "
                      "or the IPv4 pause rule may remain until cleanup succeeds." if timed else
                      " It stays paused until resumed.")
            return ("Pause this device's IPv4 LAN-to-WAN traffic. IPv6 and other paths are not controlled." + expiry)
        if action == "resume":
            return "Remove this device's saved IPv4 Internet pause rule."
        route = ACTION_ROUTES[action]
        if route == "AUTO":
            return "Return selected devices to normal ER605 load balancing."
        if route.endswith("_ONLY"):
            wan = route.removesuffix("_ONLY")
            timed = (f" NetPulse will remove this rule after {ROUTE_EXPIRY_OPTIONS[duration].lower()} while its service is running."
                     if duration else " This rule stays until changed.")
            return (f"Only {wan} for selected devices' IPv4 traffic through the ER605. Only mode has no WAN fallback: "
                    f"if {wan} is down, these devices have no IPv4 Internet through this router. IPv6 and other paths "
                    "are not controlled. Other devices' Priority routes remain unchanged." + timed)
        timed = (f" Returns to Auto after {ROUTE_EXPIRY_OPTIONS[duration].lower()} while NetPulse is running."
                 if duration else " Stays until changed.")
        return f"Prefer {route} with the ER605 Priority route and its WAN online detection." + timed

    def apply(self, token, actor):
        with self._lock:
            pending = self._pending.pop(str(token or ""), None)
        if not pending or pending["expires"] <= time.time():
            raise ControlError("This combined preview expired or was already used. Review the action again.")
        if actor != pending["actor"]:
            raise ControlError("The confirmation actor differs from the reviewed actor.")
        completed_reservations = []
        with self._write_lock:
            self._check_group(pending["group"])
            fresh = self._fresh_preflight(pending)
            if pending["action"] in BANDWIDTH_ACTIONS:
                self.bandwidth.check_review(pending["bandwidth_token"], actor)
            # No write occurs until every target, lease, route and pause state passes.
            try:
                for target in pending["targets"]:
                    if not target["reservation_needed"]:
                        continue
                    self._check_group(pending["group"])
                    item = target["mac"]
                    preview = self.routes.preview_reservation(item, target["name"], pending["actor"])
                    if preview["ip"] != target["ip"]:
                        with self.routes._lock:
                            self.routes._pending_reservations.pop(preview["token"], None)
                        raise ControlError("A reviewed device IP changed; no reservation was created.")
                    self.routes.apply_reservation(preview["token"])
                    completed_reservations.append(target)
                if pending["action"] == "pause" or pending["action"] in BANDWIDTH_ACTIONS:
                    self._ensure_pause_objects(pending["targets"])
                result = self._apply_action(pending)
            except Exception as exc:
                if completed_reservations:
                    self._audit_partial(pending, completed_reservations, exc)
                    raise ControlError(f"Action stopped after {len(completed_reservations)} DHCP reservation(s) were created; "
                                       f"those reservations remain active. {type(exc).__name__}: {exc}") from exc
                if pending["action"] == "pause" or pending["action"] in BANDWIDTH_ACTIONS:
                    self._audit_partial(pending, [], exc)
                    raise ControlError(f"Device action stopped before completion. Managed address objects may remain; "
                                       f"inspect the device state before retrying. {type(exc).__name__}: {exc}") from exc
                raise
        return result

    def _fresh_preflight(self, pending):
        self.routes._refresh_transaction_uptime()
        if pending["action"] in ("pause", "resume"):
            self.pause._ensure_allowed(pending["action"])
        try:
            with self.client.session() as c:
                snap = {"clients": c.get("dhcps", "client"), "reservations": c.get("dhcps", "reservation"),
                        "lan_scopes": c.get("ipgroup", "ipscope_list"),
                        "dhcp_settings": c.get("dhcps", "lan"),
                        "policy_routes": c.get("policy_route", "policy_route"),
                        "balance": c.get("balance", "balance_basic")}
                pause_snap = None
                if pending["action"] in ("pause", "resume"):
                    pause_snap = {"clients": snap["clients"], "reservations": snap["reservations"],
                                  "ipscopes": c.get("ipgroup", "ipscope_reservation"),
                                  "lan": snap["lan_scopes"],
                                  "ipgroups": c.get("ipgroup", "ipgroup_reservation"),
                                  "acls": c.read_pause_acl_rows()}
        except Exception as exc:
            raise ControlError("Could not read fresh router state for every target; no change was made.") from exc
        self._check_group(pending["group"])
        if _balance_enabled(snap["balance"]) is not True:
            raise ControlError("ER605 load balancing is not confirmed on by a fresh read; no action was taken.")
        self._sync_snapshot(snap)
        for target in pending["targets"]:
            mac = target["mac"]
            if pending["action"] == "resume":
                record = self.pause.store.get(mac)
                if not record or record.get("ip") != target["ip"]:
                    raise ControlError("Saved pause state changed after review; no change was made.")
                self._check_management_target(mac, target["ip"], pending["management_ip"])
                continue
            if pending["action"] == "pause":
                if self.pause.store.get(mac):
                    raise ControlError("A pause intent appeared after review; no change was made.")
            else:
                self.routes._assert_not_paused(mac)
            if target["reservation_needed"]:
                _, ip, name = self.routes._reservation_candidate(snap["clients"], snap["reservations"],
                    snap["lan_scopes"], snap["dhcp_settings"], mac, target["name"])
                if ip != target["ip"] or name != target["name"]:
                    raise ControlError("A device lease or name changed after review; no change was made.")
            else:
                _, ip = self.routes._reservation(snap["clients"], snap["reservations"], mac)
                if ip != target["ip"]:
                    raise ControlError("A device reservation changed after review; no change was made.")
            observed = observed_netpulse_route({"policy_routes": snap["policy_routes"]}, mac)["route"]
            if observed != target["current"] and target["current"] != "active":
                raise ControlError("An ER605 device route changed after review; no action was taken.")
            if pending["route"] is not None:
                saved = self.routes.route_state().get(mac, {}).get("route", "AUTO")
                if saved != target.get("saved_current", "AUTO"):
                    raise ControlError("The saved device route changed after review; no action was taken.")
            if pending["action"] == "pause":
                candidate = {**pause_snap, "reservations": list(pause_snap["reservations"] or [])}
                if target["reservation_needed"]:
                    candidate["reservations"].append({"mac": mac, "ip": target["ip"], "enable": "on"})
                self._check_pause_objects_candidate(mac, target["ip"], candidate, pending["management_ip"])
            elif pending["action"] in ACTION_ROUTES or pending["action"] in BANDWIDTH_ACTIONS:
                self._check_management_target(mac, target["ip"], pending["management_ip"])
        if pending["action"] in ("pause", "resume"):
            self.pause._acl_check(pause_snap["acls"], self.pause.store.list())
        return snap

    def _sync_snapshot(self, snap):
        raw = dict(self.router.snap.raw or {})
        raw.update({"clients": snap["clients"], "reservations": snap["reservations"],
                    "lan_scopes": snap["lan_scopes"], "dhcp_settings": snap["dhcp_settings"],
                    "policy_routes": snap["policy_routes"], "policy_routes_checked_at": time.time()})
        self.router.snap.raw = raw

    def _ensure_pause_objects(self, targets):
        for target in targets:
            mac, ip = target["mac"], target["ip"]
            iname, gname = f"NP_I_{mac.replace('-', '')}", f"NP_G_{mac.replace('-', '')}"
            with self.client.session() as c:
                ips = c.get("ipgroup", "ipscope_reservation") or []
                iprows = [r for r in ips if isinstance(r, dict) and r.get("name") == iname]
                if iprows and (len(iprows) != 1 or iprows[0].get("scope") != f"{ip}-{ip}"
                               or iprows[0].get("type") != "range"):
                    raise ControlError("A NetPulse device address object changed after review.")
                if not iprows:
                    self.routes._assert_enabled()
                    created = c.add_row("ipgroup", "ipscope_reservation", ips, {
                        "name": iname, "type": "range", "flag": "user", "scope": f"{ip}-{ip}",
                        "scope_start": ip, "scope_end": ip, "comment": "NetPulse"})
                    if created.get("scope") != f"{ip}-{ip}" or created.get("type") != "range":
                        raise ControlError("The ER605 did not verify the reviewed device address object.")
                groups = c.get("ipgroup", "ipgroup_reservation") or []
                gr = [r for r in groups if isinstance(r, dict) and r.get("name") == gname]
                if gr and (len(gr) != 1 or gr[0].get("rule_scope") != [iname]):
                    raise ControlError("A NetPulse device group changed after review.")
                if not gr:
                    self.routes._assert_enabled()
                    created = c.add_row("ipgroup", "ipgroup_reservation", groups, {
                        "name": gname, "rule_scope": [iname], "comment": "", "flag": "user"})
                    if created.get("rule_scope") != [iname]:
                        raise ControlError("The ER605 did not verify the reviewed device group.")

    def _apply_action(self, pending):
        if pending["action"] in BANDWIDTH_ACTIONS:
            result = self.bandwidth.apply(
                pending["bandwidth_token"], pending["actor"],
                check_unchanged=lambda: self._check_group(pending["group"]))
            if result.get("count") != len(pending["targets"]):
                raise ControlError("The bandwidth action returned an incomplete device count; inspect recovery state.")
            return {**result, "action": pending["action"]}
        action = pending["action"]
        route = pending["route"]
        if route is not None and not self.routes.route_transaction.owns_current_thread:
            strict = route.endswith("_ONLY") or any(
                str(target.get("current", "")).endswith("_ONLY") for target in pending["targets"])
            if strict:
                return self.routes.run_route_transaction(
                    [target["mac"] for target in pending["targets"]], route, pending["actor"],
                    lambda: self._apply_action(pending),
                    previous=[target["current"] for target in pending["targets"]])
        if action in ACTION_ROUTES:
            route = ACTION_ROUTES[action]
            group = pending["group"]
            if group:
                self._check_group(group)
                preview = self.routes.preview_group(group["id"], route, pending["actor"],
                                                    pending["duration_seconds"])
                self._verify_route_group_preview(group, pending, preview)
                applied = self.routes.apply_group(preview["token"])
                members = [{"mac": t["mac"], "ip": t["ip"], "name": t["name"]}
                           for t in pending["targets"]]
                return {**applied, "applied": True, "action": action,
                        "count": applied.get("count", 0), "members": members}
            results = []
            completed = []
            try:
                for target in pending["targets"]:
                    preview = self.routes.preview(target["mac"], route, pending["actor"],
                                                  pending["duration_seconds"])
                    if preview["ip"] != target["ip"] or preview["observed_current"] != target["current"]:
                        with self.routes._lock:
                            self.routes._pending.pop(preview["token"], None)
                        raise ControlError("A device changed after review; no further route was changed.")
                    results.append(self.routes.apply(preview["token"]))
                    completed.append(target)
            except Exception as exc:
                rollback_errors = []
                for target in reversed(completed):
                    try:
                        rollback = self.routes.preview(target["mac"], target["current"], pending["actor"], 0,
                            _rollback=True, _restore_state=target.get("current_expiry_state"))
                        self.routes.apply(rollback["token"])
                    except Exception as rollback_exc:
                        rollback_errors.append(f"{target['mac']}: {type(rollback_exc).__name__}")
                status = ("rollback failed for " + ", ".join(rollback_errors)
                          if rollback_errors else "completed device routes were restored and verified")
                raise ControlError(f"Selected route change stopped after {len(completed)} of "
                                   f"{len(pending['targets'])} devices; {status}. "
                                   f"{type(exc).__name__}: {exc}") from exc
            return {"applied": True, "action": action, "count": len(results), "members": results}
        group = pending["group"]
        if group:
            self._check_group(group)
            preview = self.pause.preview_group(group["id"], action, pending["actor"],
                                                pending["duration_seconds"], pending["management_ip"])
            self._verify_pause_group_preview(group, pending, preview)
            applied = self.pause.apply(preview["token"], pending["actor"])
            return {"applied": True, "action": action, "count": applied.get("count", 0),
                    "members": applied.get("results", []), **applied}

        done, results = [], []
        rollback_plan = {"action": action, "actor": pending["actor"]}
        for target in pending["targets"]:
            prior = self.pause.store.get(target["mac"]) if action == "resume" else None
            try:
                preview = self.pause.preview(target["mac"], action, pending["actor"],
                                             pending["duration_seconds"], pending["management_ip"])
                result = self.pause.apply(preview["token"], pending["actor"])
                value = result.get("results", [{}])[0]
                results.append(value)
                done.append((target, value, prior))
            except Exception as exc:
                failures = self.pause._rollback(done, rollback_plan)
                state = "rollback failed for " + ", ".join(failures) if failures else "completed members were restored"
                raise ControlError(f"Combined {action} stopped after {len(done)} of {len(pending['targets'])} devices; "
                                   f"{state}. {type(exc).__name__}: {exc}") from exc
        return {"applied": True, "action": action, "count": len(results), "members": results}

    def _check_group(self, group):
        if group is None:
            return
        current = next((g for g in sqlite.device_groups(self.db_path) if g["id"] == group["id"]), None)
        if (not current or current["name"] != group["name"] or current["updated_at"] != group["updated_at"]
                or current["members"] != group["members"]
                or current["smart_routing_enabled"] != group.get("smart_routing_enabled", False)):
            raise ControlError("Group name or membership changed after review; create a fresh preview.")

    def _verify_route_group_preview(self, group, pending, preview):
        token = preview.get("token")
        try:
            self._check_group(group)
            with self.routes._lock:
                native = copy.deepcopy(self.routes._pending_groups.get(token))
            expected = pending["targets"]
            actual = native.get("members", []) if native else []
            keys = ("mac", "ip", "name", "current", "saved_current", "current_expiry_state")
            if (not native or native.get("group_id") != group["id"]
                    or native.get("group_name") != group["name"]
                    or native.get("group_updated_at") != group["updated_at"]
                    or native.get("smart_routing_enabled") != group["smart_routing_enabled"]
                    or native.get("members") is None
                    or native.get("route") != pending["route"]
                    or native.get("actor") != pending["actor"]
                    or native.get("expiry_seconds") != pending["duration_seconds"]
                    or [{key: item.get(key) for key in keys} for item in actual]
                       != [{key: item.get(key) for key in keys} for item in expected]
                    or preview.get("group") != group["name"]
                    or preview.get("route") != pending["route"]
                    or [{key: item.get(key) for key in keys[:-1]} for item in preview.get("members", [])]
                       != [{key: item.get(key) for key in keys[:-1]} for item in expected]):
                raise ControlError("Group members or routes changed after review; no group route was applied.")
            self._check_group(group)
        except Exception:
            if token:
                with self.routes._lock:
                    self.routes._pending_groups.pop(token, None)
            raise

    def _verify_pause_group_preview(self, group, pending, preview):
        token = preview.get("token")
        try:
            self._check_group(group)
            with self.pause._lock:
                native = copy.deepcopy(self.pause._pending.get(token))
            expected = pending["targets"]
            actual = native.get("targets", []) if native else []
            keys = ("mac", "ip", "name")
            if (not native or native.get("group_id") != group["id"]
                    or native.get("group_name") != group["name"]
                    or native.get("group_updated_at") != group["updated_at"]
                    or native.get("group_members") != group["members"]
                    or native.get("action") != pending["action"]
                    or native.get("actor") != pending["actor"]
                    or native.get("duration_seconds") != pending["duration_seconds"]
                    or native.get("management_ip") != pending["management_ip"]
                    or [{key: item.get(key) for key in keys} for item in actual]
                       != [{key: item.get(key) for key in keys} for item in expected]
                    or [{key: item.get(key) for key in keys} for item in preview.get("members", [])]
                       != [{key: item.get(key) for key in keys} for item in expected]):
                raise ControlError("Group members changed after review; no group pause action was applied.")
            self._check_group(group)
        except Exception:
            if token:
                with self.pause._lock:
                    self.pause._pending.pop(token, None)
            raise

    def _audit_partial(self, pending, completed, error):
        detail = (f"Combined {pending['action']} stopped after {len(completed)} DHCP reservation(s); "
                  f"reservations remain active. Later action failed: {type(error).__name__}.")
        group = pending["group"]
        if pending["action"] == "pause" and self.pause is not None:
            for target in (completed or pending["targets"]):
                self.pause.store.audit(int(time.time()), pending["actor"], "pause", target["mac"],
                    "partial", detail)
        if group:
            try:
                sqlite.log_device_group_action(self.db_path, int(time.time()), group["id"], group["name"],
                    pending["actor"], pending["route"] or pending["action"], "partial", len(completed), detail)
            except Exception:
                pass
