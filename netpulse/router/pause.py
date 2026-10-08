"""Fail-closed, confirmed IPv4 Internet pause controls for the ER605.

The feature is deliberately disabled by default. It stages LAN-to-WAN ACL rows
only; it does not edit DHCP, routes, or address objects.
"""
from __future__ import annotations

import ipaddress
import math
import secrets
import threading
import time
from pathlib import Path

from netpulse.devices.identity import normalize_mac
from netpulse.freshness import age_seconds
from netpulse.router.control import ControlError, _system_boot_id, MAX_ROUTER_AGE_SECONDS
from netpulse.router.er605 import (PAUSE_ACL_NAME_RE, pause_acl_effective_match,
                                   valid_pause_acl_row)
from netpulse.storage.pauses import PauseStore
from netpulse.storage import sqlite

FIRMWARE = "2.3.3 Build 20251029 Rel.18054"
DURATIONS = {0, 900, 3600, 21600}
TOKEN_SECONDS = 120
EXPIRY_LABELS = {0: "Until resumed", 900: "15 minutes", 3600: "1 hour", 21600: "6 hours"}


class PauseControl:
    def __init__(self, route_control, db_path, enabled=False, protected_macs=()):
        self.route_control = route_control
        self.router = route_control.router
        self.client = route_control.client
        self.db_path = db_path
        self.enabled = bool(enabled)
        self.protected_macs = {normalize_mac(m) for m in protected_macs if normalize_mac(m)}
        self.store = PauseStore(db_path)
        self._lock = threading.RLock()
        self._pending = {}
        self._expiry_lock = threading.Lock()
        self._retry_after = {}
        self._audited_expiry = set()
        self._failures = []
        self._boot_id = _system_boot_id()
        self._router_write_lock = getattr(route_control, "_router_write_lock", None) or threading.RLock()

    def state(self):
        snap = self.router.snap
        age = age_seconds(getattr(snap, "checked_at", None), time.time())
        fw = getattr(snap, "firmware_version", None)
        killed = Path(getattr(self.route_control, "kill_switch", "/etc/netpulse/controls.disabled")).exists()
        cfg = bool(self.enabled)
        if not cfg:
            reason = "Internet pause is disabled in config; staging is not enabled."
        elif killed:
            reason = "The local control kill switch is active."
        elif fw != FIRMWARE:
            reason = "Internet pause is staged for ER605 firmware 2.3.3 Build 20251029 Rel.18054 only."
        elif age is None or age > max(MAX_ROUTER_AGE_SECONDS, getattr(self.router, "poll_seconds", 0) * 2):
            reason = "Waiting for a fresh authenticated ER605 status check."
        elif not getattr(snap, "raw", None):
            reason = "Waiting for a complete ER605 status snapshot."
        else:
            reason = ""
        try:
            route_state = self.route_control.state() if callable(getattr(self.route_control, "state", None)) else None
        except Exception:
            route_state = {}
        cleanup_enabled = bool(not killed and fw == FIRMWARE and age is not None
                               and age <= max(MAX_ROUTER_AGE_SECONDS,
                                              getattr(self.router, "poll_seconds", 0) * 2)
                               and isinstance(route_state, dict) and route_state.get("enabled") is True)
        if cfg and not cleanup_enabled and not reason:
            reason = "Router controls are locked; pause actions require fresh, settled, reviewed router state."
        return {"enabled": bool(cfg and cleanup_enabled), "cleanup_enabled": cleanup_enabled,
                "configured": cfg, "reason": reason, "firmware_version": fw,
                "router_age_seconds": age, "kill_switch": killed,
                "effect": "IPv4 LAN-to-WAN only. A paused device may remain online through IPv6 or other paths. "
                          "A timed expiry can be delayed while the Pi is offline; the router ACL remains active until cleanup runs."}

    def records(self):
        return self.store.list()

    def _fresh_snapshot(self, allow_disabled=False):
        status = self.state()
        if status["kill_switch"] or (not allow_disabled and not status["enabled"]):
            raise ControlError(status["reason"] or "Router controls are locked.")
        if allow_disabled and not status.get("cleanup_enabled"):
            raise ControlError("Pause cleanup is locked until the exact reviewed firmware and fresh status are available.")
        try:
            with self.client.session() as c:
                return {"clients": c.get("dhcps", "client"),
                        "reservations": c.get("dhcps", "reservation"),
                        "ipscopes": c.get("ipgroup", "ipscope_reservation"),
                        "lan": c.get("ipgroup", "ipscope_list"),
                        "ipgroups": c.get("ipgroup", "ipgroup_reservation"),
                        "acls": c.read_pause_acl_rows()}
        except Exception as exc:
            raise ControlError("Could not read a fresh complete ER605 pause snapshot; no change was made.") from exc

    @staticmethod
    def _acl_check(rows, records):
        if not isinstance(rows, list):
            raise ControlError("The ER605 ACL snapshot is unreadable.")
        managed = {r.get("rule", {}).get("name"): r.get("rule") for r in records
                   if isinstance(r, dict) and isinstance(r.get("rule"), dict)}
        seen = set()
        for row in rows:
            if not isinstance(row, dict) or not PAUSE_ACL_NAME_RE.fullmatch(str(row.get("name", ""))):
                raise ControlError("The ACL contains an owner or non-pause rule; pause controls fail closed.")
            name = row["name"]
            if name in seen:
                raise ControlError("Duplicate managed pause ACL rows require manual inspection.")
            seen.add(name)
            expected = managed.get(name)
            if expected is None or not PauseControl._same_rule(row, expected):
                raise ControlError("A pause ACL row is not owned by a matching persisted pause record.")
        for name, expected in managed.items():
            if name in seen and not PauseControl._same_rule(next(r for r in rows if r["name"] == name), expected):
                raise ControlError("A persisted pause ACL row changed; refusing to modify the ACL.")

    @staticmethod
    def _same_rule(a, b):
        return pause_acl_effective_match(a, b)

    def _candidate(self, mac, snap, management_ip=None):
        mac = normalize_mac(mac)
        if not mac or mac in self.protected_macs or self.route_control.is_local_device(mac):
            raise ControlError("This device is protected from Internet pause.")
        clients, reservations = snap["clients"], snap["reservations"]
        if not isinstance(clients, list) or not isinstance(reservations, list):
            raise ControlError("The ER605 lease or reservation list is unreadable.")
        lease = [r for r in clients if isinstance(r, dict) and self.route_control._client_mac(r) == mac]
        reservation = [r for r in reservations if isinstance(r, dict)
                       and normalize_mac(r.get("mac", r.get("macaddr", ""))) == mac
                       and str(r.get("enable", "1")).lower() not in ("0", "false", "off")]
        if len(lease) != 1 or len(reservation) != 1:
            raise ControlError("Pause needs one current DHCP lease and one enabled reservation for this device.")
        ip = str(lease[0].get("ipaddr", lease[0].get("ip", "")))
        if ip != str(reservation[0].get("ip", reservation[0].get("ipaddr", ""))):
            raise ControlError("The active lease differs from the enabled reservation.")
        enabled_ip_rows = [r for r in reservations if isinstance(r, dict)
                           and str(r.get("enable", "1")).lower() not in ("0", "false", "off")
                           and str(r.get("ip", r.get("ipaddr", "")) or "") == ip]
        lease_ip_rows = [r for r in clients if isinstance(r, dict)
                         and str(r.get("ipaddr", r.get("ip", "")) or "") == ip]
        if len(enabled_ip_rows) != 1 or len(lease_ip_rows) != 1:
            raise ControlError("The current lease or reserved IP is also assigned to another router row.")
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            raise ControlError("The current lease is not a usable IPv4 address.") from None
        forbidden = {str(getattr(self.client, "host", "")), str(management_ip or "")}
        raw = getattr(getattr(self.router, "snap", None), "raw", None)
        if isinstance(raw, dict):
            forbidden.update(str(raw.get(key, "")) for key in ("router_ip", "lan_ip", "gateway_ip"))
        local_macs = set()
        try:
            local_macs = {normalize_mac(x) for x in self.route_control.local_device_macs()}
        except Exception:
            pass
        local_ips = {str(c.get("ipaddr", c.get("ip", ""))) for c in clients
                     if isinstance(c, dict) and self.route_control._client_mac(c) in local_macs}
        if ip in local_ips or any(isinstance(c, dict) and ip in
                                  (str(c.get("host", "")), str(c.get("router_ip", ""))) for c in clients):
            raise ControlError("This is a router or NetPulse host address.")
        rfc1918 = any(addr in ipaddress.ip_network(cidr) for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
        if addr.version != 4 or not rfc1918 or ip in forbidden:
            raise ControlError("Pause is limited to a private IPv4 LAN client, not the router or selected management target.")
        ips = [r for r in snap["ipscopes"] if isinstance(r, dict) and r.get("name") == f"NP_I_{mac.replace('-', '')}"]
        groups = [r for r in snap["ipgroups"] if isinstance(r, dict) and r.get("name") == f"NP_G_{mac.replace('-', '')}"]
        if (len(ips) != 1 or ips[0].get("scope") != f"{ip}-{ip}"
                or ips[0].get("type") != "range" or len(groups) != 1):
            raise ControlError("The NetPulse device IP objects do not uniquely match this current reservation.")
        scope = groups[0].get("rule_scope")
        if scope != [ips[0]["name"]]:
            raise ControlError("The NetPulse device IP group does not point exactly to its matching address object.")
        lan_rows = snap.get("lan")
        lans = [r for r in lan_rows if isinstance(r, dict) and r.get("name") == "IP_LAN"] if isinstance(lan_rows, list) else []
        if len(lans) != 1:
            raise ControlError("Could not confirm the current ER605 LAN scope.")
        try:
            network = ipaddress.ip_network(str(lans[0].get("scope", "")), strict=False)
        except ValueError:
            raise ControlError("The ER605 LAN scope is not a valid IPv4 network.") from None
        if (network.version != 4 or not any(network.subnet_of(ipaddress.ip_network(cidr))
                for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
                or addr not in network or ip in (str(network.network_address), str(network.broadcast_address))):
            raise ControlError("The current candidate is outside the usable ER605 IPv4 LAN scope.")
        return {"mac": mac, "ip": ip, "name": str(lease[0].get("hostname", lease[0].get("name", "Home device")))[:80]}

    def _preview(self, members, action, actor, duration_seconds, management_ip=None, group_id=None,
                 group_name=None, full_group_members=None):
        if action not in ("pause", "resume"):
            raise ControlError("Choose pause or resume.")
        if isinstance(duration_seconds, bool) or duration_seconds not in DURATIONS:
            raise ControlError("Choose until resumed, 15 minutes, 1 hour, or 6 hours.")
        if not isinstance(actor, str) or not actor.strip():
            raise ControlError("An actor is required for confirmation.")
        snap = self._fresh_snapshot(allow_disabled=action == "resume")
        records = self.store.list()
        self._acl_check(snap["acls"], records)
        if action == "pause":
            targets = [self._candidate(m, snap, management_ip) for m in members]
        else:
            targets = []
            for m in members:
                mac = normalize_mac(m)
                if not mac or mac in self.protected_macs or self.route_control.is_local_device(mac):
                    raise ControlError("This device is protected from Internet pause.")
                saved = self.store.get(mac)
                if not saved:
                    raise ControlError("This device has no persisted pause rule to resume.")
                targets.append({"mac": mac, "ip": saved.get("ip"), "name": saved.get("label") or "Home device"})
        for target in targets:
            record = self.store.get(target["mac"])
            if action == "pause" and record:
                raise ControlError("This device already has a pause intent; duplicate pause actions are rejected.")
            if action == "resume" and (not record or record.get("status") not in
                                         ("paused", "applying", "resuming", "error")):
                raise ControlError("This device has no persisted pause intent to repair or resume.")
        token = secrets.token_urlsafe(32)
        payload = {"action": action, "actor": actor.strip(), "targets": targets,
                   "duration_seconds": duration_seconds, "group_id": group_id,
                   "group_members": list(full_group_members or [t["mac"] for t in targets]),
                   "group_name": group_name, "expires": time.time() + TOKEN_SECONDS,
                   "management_ip": management_ip}
        with self._lock:
            self._pending = {k: v for k, v in self._pending.items() if v["expires"] > time.time()}
            self._pending[token] = payload
        result = {"token": token, "action": action, "count": len(targets), "members": targets,
                  "duration_seconds": duration_seconds,
                  "expiry_label": EXPIRY_LABELS[duration_seconds] if action == "pause" else "Resume now",
                  "expires_in": TOKEN_SECONDS,
                  "effect": "IPv4 LAN-to-WAN only; Pi-offline expiry cleanup may be delayed."}
        if group_id is not None:
            result["group"] = group_name
        elif targets:
            result.update({"device": targets[0]["name"], "mac": targets[0]["mac"], "ip": targets[0]["ip"]})
        return result

    def preview(self, mac, action="pause", actor="dashboard", duration_seconds=3600, management_ip=None):
        return self._preview([mac], action, actor, duration_seconds, management_ip)

    def preview_group(self, group_id, action, actor, duration_seconds=3600, management_ip=None):
        group = next((g for g in sqlite.device_groups(self.db_path) if g["id"] == group_id), None)
        if not group or not group["members"]:
            raise ControlError("This device group no longer exists or has no members.")
        targets = group["members"]
        if action == "resume":
            targets = [m for m in group["members"] if (self.store.get(m) or {}).get("status") in
                       ("paused", "applying", "resuming", "error")]
            if not targets:
                raise ControlError("No group members have a saved pause intent to resume.")
        return self._preview(targets, action, actor, duration_seconds, management_ip, group_id,
                             group["name"], group["members"])

    def _ensure_allowed(self, action="pause"):
        status = self.state()
        if status["kill_switch"] or getattr(self.router.snap, "firmware_version", None) != FIRMWARE:
            raise ControlError(status["reason"] or "Pause controls are locked.")
        if action == "pause" and not status["enabled"]:
            raise ControlError(status["reason"] or "Internet pause is disabled.")
        if action == "resume" and not status.get("cleanup_enabled"):
            raise ControlError(status["reason"] or "Pause cleanup is locked.")

    def _refresh_before_acl_write(self, action):
        refresh = getattr(self.route_control, "_refresh_transaction_uptime", None)
        if not callable(refresh):
            raise ControlError("A fresh ER605 uptime check is unavailable; no pause ACL change was made.")
        refresh()
        self._ensure_allowed(action)

    def apply(self, token, actor=None):
        with self._lock:
            p = self._pending.pop(str(token or ""), None)
        if not p or p["expires"] <= time.time():
            raise ControlError("This pause review expired or was already used. Create a new preview.")
        if actor is not None and actor != p["actor"]:
            raise ControlError("The confirmation actor differs from the reviewed actor.")
        if p["group_id"] is not None:
            group = next((g for g in sqlite.device_groups(self.db_path) if g["id"] == p["group_id"]), None)
            if not group or group["members"] != p["group_members"]:
                raise ControlError("Group membership changed after review; create a fresh pause review.")
        self._ensure_allowed(p["action"])
        done = []
        with self._router_write_lock:
            for target in p["targets"]:
                # A second reviewed token must never overwrite an existing intent
                # or trigger cleanup of the first token's successfully installed rule.
                if p["action"] == "pause" and self.store.get(target["mac"]):
                    rollback_errors = self._rollback(done, p)
                    raise ControlError("A pause intent appeared after review; create a fresh review. "
                                       f"Rollback failures: {len(rollback_errors)}.")
                try:
                    if p["group_id"] is not None:
                        group = next((g for g in sqlite.device_groups(self.db_path)
                                      if g["id"] == p["group_id"]), None)
                        if not group or group["members"] != p["group_members"]:
                            raise ControlError("Group membership changed during confirmation; no further member was changed.")
                    prior = self.store.get(target["mac"]) if p["action"] == "resume" else None
                    snap = self._fresh_snapshot(allow_disabled=p["action"] == "resume")
                    self._acl_check(snap["acls"], self.store.list())
                    if p["action"] == "pause":
                        current = self._candidate(target["mac"], snap, p["management_ip"])
                        if current["ip"] != target["ip"]:
                            raise ControlError("Lease or reservation changed after review.")
                    if p["action"] == "pause":
                        result = self._pause_one(target, p, snap)
                    else:
                        result = self._resume_one(target, p, snap)
                    done.append((target, result, prior))
                except Exception as exc:
                    cleanup_problem = None
                    if p["action"] == "pause":
                        cleanup_problem = self._cleanup_ambiguous_pause(target)
                    if p["group_id"] is None:
                        if cleanup_problem:
                            raise ControlError(f"Pause write outcome is uncertain; saved error intent remains for repair. {cleanup_problem}") from exc
                        raise
                    rollback_errors = self._rollback(done, p)
                    raise ControlError(f"Group pause stopped after {len(done)} of {len(p['targets'])}; "
                                       f"rollback failures: {len(rollback_errors) + bool(cleanup_problem)}. "
                                       f"Current member cleanup: {cleanup_problem or 'verified safe'}. {exc}") from exc
            if p["group_id"] is not None:
                group = next((g for g in sqlite.device_groups(self.db_path)
                              if g["id"] == p["group_id"]), None)
                if not group or group["members"] != p["group_members"]:
                    rollback_errors = self._rollback(done, p)
                    raise ControlError("Group membership changed during the final confirmation step; "
                                       f"rollback failures: {len(rollback_errors)}.")
        return {"applied": True, "action": p["action"], "count": len(done),
                "results": [r for _, r, _ in done],
                "detail": "Every ACL change was individually read back and verified."}

    def _pause_one(self, target, p, snap):
        mac, ip = target["mac"], target["ip"]
        suffix = secrets.token_hex(16).upper()
        rule = {"name": f"NP_PAUSE_{suffix}", "policy": "DROP", "service": "ALL", "iptype": "ipv4",
                "zone": "LAN", "is_src": "ipgroup", "src": f"NP_G_{mac.replace('-', '')}",
                "is_dst": "ipgroup", "dest": "IPGROUP_ANY", "time": "Any",
                "states": ["new", "established", "related", "invalid"], "position": "", "flag": "1", "user": "1"}
        now = int(time.time())
        record = {"mac": mac, "ip": ip, "name": rule["name"], "label": target["name"],
                  "actor": p["actor"], "created_at": now,
                  "expires_at": now + p["duration_seconds"] if p["duration_seconds"] else None,
                  "expires_monotonic": (time.monotonic() + p["duration_seconds"]
                                        if p["duration_seconds"] and self._boot_id else None),
                  "boot_id": self._boot_id if p["duration_seconds"] and self._boot_id else None,
                  "status": "applying", "rule": rule, "group_id": p["group_id"]}
        self.store.put(record)  # durable intent before router write
        self._retry_after.pop(mac, None)
        self._audited_expiry.discard(mac)
        try:
            # The uptime helper opens its own ER605 session, so run it before the
            # write session. Re-read all candidate evidence after that refresh.
            self._refresh_before_acl_write("pause")
            with self.client.session() as c:
                live_clients = c.get("dhcps", "client")
                live_reservations = c.get("dhcps", "reservation")
                live_ipscopes = c.get("ipgroup", "ipscope_reservation")
                live_lan = c.get("ipgroup", "ipscope_list")
                live_ipgroups = c.get("ipgroup", "ipgroup_reservation")
                current = self._candidate(mac, {"clients": live_clients, "reservations": live_reservations,
                    "ipscopes": live_ipscopes, "lan": live_lan, "ipgroups": live_ipgroups}, p["management_ip"])
                if current["ip"] != ip:
                    raise ControlError("Lease or reservation changed immediately before the ACL write.")
                rows = c.read_pause_acl_rows()
                self._acl_check(rows, [r for r in self.store.list() if r["mac"] != mac])
                self._ensure_allowed("pause")
                added = c.add_pause_acl_rule(rows, rule)
                if not self._same_rule(added, rule):
                    raise ControlError("ACL add read-back differed from the reviewed rule.")
            record["status"] = "paused"
            self.store.put(record)
            self.store.audit(now, p["actor"], "pause", mac, "applied", "IPv4 LAN-to-WAN pause verified")
            return {"mac": mac, "ip": ip, "status": "paused", "expires_at": record["expires_at"]}
        except Exception as exc:
            record["status"] = "error"
            self.store.put(record)
            self.store.audit(int(time.time()), p["actor"], "pause", mac, "failed", str(exc)[:240])
            raise

    def _resume_one(self, target, p, snap):
        rec = self.store.get(target["mac"])
        if not rec or not valid_pause_acl_row(rec.get("rule")):
            raise ControlError("Persisted pause rule is unavailable or invalid; refusing cleanup.")
        name = rec["rule"]["name"]
        resuming = dict(rec, status="resuming")
        self.store.put(resuming)
        try:
            # First verify the saved intent and clear it without a write if the
            # router already proves the exact row is absent.
            with self.client.session() as c:
                live_rows = c.read_pause_acl_rows()
                self._acl_check(live_rows, self.store.list())
                matches = [r for r in live_rows if isinstance(r, dict) and r.get("name") == name]
                if not matches:
                    self._ensure_allowed("resume")
                    self.store.delete(target["mac"])
                    self.store.audit(int(time.time()), p["actor"], "resume", target["mac"], "applied",
                                     "Exact managed pause rule absent after verified list")
                    return {"mac": target["mac"], "ip": rec.get("ip"), "status": "resumed"}
                if len(matches) != 1 or not self._same_rule(matches[0], rec["rule"]):
                    raise ControlError("The persisted pause ACL row changed or is ambiguous; it was left untouched.")
            self._refresh_before_acl_write("resume")
            with self.client.session() as c:
                live_rows = c.read_pause_acl_rows()
                self._acl_check(live_rows, self.store.list())
                matches = [r for r in live_rows if isinstance(r, dict) and r.get("name") == name]
                if len(matches) != 1 or not self._same_rule(matches[0], rec["rule"]):
                    raise ControlError("The persisted pause ACL row changed or is ambiguous; it was left untouched.")
                self._ensure_allowed("resume")
                # ER605 API takes canonical persisted rule and performs its own immediate fresh check.
                if matches:
                    c.delete_pause_acl_rule(name, rec["rule"])
                self.store.delete(target["mac"])
                self.store.audit(int(time.time()), p["actor"], "resume", target["mac"], "applied",
                                 "Exact managed pause rule removed and verified")
        except Exception as exc:
            failed = dict(resuming, status="error")
            self.store.put(failed)
            self.store.audit(int(time.time()), p["actor"], "resume", target["mac"], "failed", str(exc)[:240])
            raise
        return {"mac": target["mac"], "ip": rec.get("ip"), "status": "resumed"}

    def _rollback(self, done, p):
        failures = []
        for target, _, prior in reversed(done):
            try:
                inv = dict(p, action="resume" if p["action"] == "pause" else "pause")
                if p["action"] == "pause":
                    self._resume_one(target, inv, self._fresh_snapshot(allow_disabled=True))
                else:
                    # The successful resume entry retains its prior record in done.
                    old = prior
                    if not old:
                        raise ControlError("Prior pause state is unavailable for rollback.")
                    snap = self._fresh_snapshot(allow_disabled=True)
                    intent = dict(old, status="applying")
                    self.store.put(intent)
                    try:
                        self._refresh_before_acl_write("resume")
                        with self.client.session() as c:
                            rows = c.read_pause_acl_rows()
                            self._acl_check(rows, self.store.list())
                            self._ensure_allowed("resume")
                            c.add_pause_acl_rule(rows, old["rule"])
                        self.store.put(old)  # exact prior deadline and rule are retained
                    except Exception:
                        self.store.put(dict(old, status="error"))
                        raise
            except Exception as exc:
                failures.append(str(exc))
        return failures

    def _cleanup_ambiguous_pause(self, target):
        """Rollback a failed add only when a fresh list proves one exact row identity."""
        rec = self.store.get(target["mac"])
        if not rec or not isinstance(rec.get("rule"), dict):
            return
        try:
            with self.client.session() as c:
                rows = c.read_pause_acl_rows()
                self._acl_check(rows, self.store.list())
                matches = [r for r in rows if isinstance(r, dict) and r.get("name") == rec["rule"].get("name")]
                if not matches:
                    self._ensure_allowed("resume")
                    self.store.delete(target["mac"])
                    return None
                if len(matches) != 1 or not self._same_rule(matches[0], rec["rule"]):
                    reason = "A changed or duplicate pause row remains; it was not removed."
                    self.store.audit(int(time.time()), "rollback", "pause", target["mac"], "failed", reason)
                    return reason
            self._refresh_before_acl_write("resume")
            with self.client.session() as c:
                rows = c.read_pause_acl_rows()
                self._acl_check(rows, self.store.list())
                matches = [r for r in rows if isinstance(r, dict) and r.get("name") == rec["rule"].get("name")]
                if len(matches) != 1 or not self._same_rule(matches[0], rec["rule"]):
                    reason = "The managed row changed before rollback; it was not removed."
                    self.store.audit(int(time.time()), "rollback", "pause", target["mac"], "failed", reason)
                    return reason
                self._ensure_allowed("resume")
                c.delete_pause_acl_rule(rec["rule"]["name"], rec["rule"])
                self.store.delete(target["mac"])
            return None
        except Exception:
            reason = "Fresh ACL cleanup could not verify or remove the current row."
            try:
                self.store.audit(int(time.time()), "rollback", "pause", target["mac"], "failed", reason)
            except Exception:
                pass
            return reason

    def expire_due(self, now=None):
        now = time.time() if now is None else now
        if not isinstance(now, (int, float)) or isinstance(now, bool) or not math.isfinite(now):
            return 0
        status = self.state()
        if status["kill_switch"] or not status.get("cleanup_enabled"):
            return 0
        if status["router_age_seconds"] is None or status["router_age_seconds"] > max(
                MAX_ROUTER_AGE_SECONDS, getattr(self.router, "poll_seconds", 0) * 2):
            return 0
        count = 0
        with self._expiry_lock, self._router_write_lock:
            for rec in self.store.list():
                if rec.get("status") not in ("paused", "applying", "resuming", "error") or rec.get("expires_at") is None:
                    continue
                deadline = rec.get("expires_at")
                if (isinstance(deadline, bool) or not isinstance(deadline, int) or deadline <= 0
                        or deadline > now + 366 * 86400):
                    continue  # invalid/skewed persisted deadline fails closed
                mono, boot = rec.get("expires_monotonic"), rec.get("boot_id")
                due = False
                if (boot is not None and boot == self._boot_id and isinstance(mono, (int, float))
                        and not isinstance(mono, bool) and math.isfinite(mono)):
                    due = time.monotonic() >= mono
                elif boot is None and mono is None or boot != self._boot_id:
                    due = now >= deadline
                if not due or self._retry_after.get(rec["mac"], 0) > time.monotonic():
                    continue
                try:
                    with self.client.session() as c:
                        rows = c.read_pause_acl_rows()
                        self._acl_check(rows, self.store.list())
                        matches = [r for r in rows if isinstance(r, dict) and r.get("name") == rec["rule"]["name"]]
                        if len(matches) > 1 or (matches and not self._same_rule(matches[0], rec["rule"])):
                            raise ControlError("Pause ACL changed or is ambiguous; expiry left it untouched.")
                    if matches:
                        resuming = dict(rec, status="resuming")
                        self.store.put(resuming)
                        self._refresh_before_acl_write("resume")
                        with self.client.session() as c:
                            rows = c.read_pause_acl_rows()
                            self._acl_check(rows, self.store.list())
                            matches = [r for r in rows if isinstance(r, dict)
                                       and r.get("name") == rec["rule"]["name"]]
                            if len(matches) != 1 or not self._same_rule(matches[0], rec["rule"]):
                                raise ControlError("Pause ACL changed during expiry; it was left untouched.")
                            self._ensure_allowed("resume")
                            c.delete_pause_acl_rule(rec["rule"]["name"], rec["rule"])
                    else:
                        self._ensure_allowed("resume")
                    # The fresh list above verified absence, or the API verified deletion.
                    self.store.delete(rec["mac"])
                    self.store.audit(int(now), "expiry", "resume", rec["mac"], "applied", "Timed pause expired")
                    count += 1
                    self._retry_after.pop(rec["mac"], None)
                    self._audited_expiry.discard(rec["mac"])
                except Exception as exc:
                    self._retry_after[rec["mac"]] = time.monotonic() + 30
                    try:
                        self.store.put(dict(rec, status="error"))
                    except Exception:
                        pass
                    with self._lock:
                        first_notice = rec["mac"] not in self._audited_expiry
                        if first_notice:
                            self._audited_expiry.add(rec["mac"])
                            detail = str(exc)[:240]
                            self._failures.append({"key": f"internet-pause-expiry-{rec['mac']}",
                                                   "mac": rec["mac"], "action": "resume",
                                                   "reason": detail, "detail": detail})
                    if first_notice:
                        self.store.audit(int(now), "expiry", "resume", rec["mac"], "failed", str(exc)[:240])
        return count

    def drain_failures(self):
        with self._lock:
            result, self._failures = self._failures, []
        return result
