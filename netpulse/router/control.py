"""Confirmed, one-device ER605 route controls.

Only stable DHCP reservations may be pinned. Every request has a short-lived preview,
then rechecks router state before touching objects owned by NetPulse (the ``NP_`` prefix).
"""

from __future__ import annotations

import ipaddress
import logging
import secrets
import threading
import time
from pathlib import Path

from netpulse.router.er605 import ER605Client, RouterError, sanitize
from netpulse.router.watch import RouterWatch
from netpulse.devices.identity import MAC_RE, normalize_mac
from netpulse.freshness import age_seconds
from netpulse.storage import sqlite
from netpulse.storage.sqlite import KeyValueFile
from netpulse.storage.pauses import blocked_macs

log = logging.getLogger(__name__)

ROUTE_OPTIONS = {"AUTO", "WAN1", "WAN2"}
ROUTE_EXPIRY_OPTIONS = {0: "Until changed", 3600: "1 hour", 21600: "6 hours",
                        86400: "24 hours", 604800: "7 days"}
ROUTE_FIELDS = (".name", "name", "service_type", "src_ipgroup", "dst_ipgroup", "interfaces", "timeobj",
                "mode", "comment", "state", "index", "src", "dst", "dst_country_group",
                "dst_domain", "flag")
IP_FIELDS = ("flag", "name", "type", "scope", "scope_mask", "comment")
GROUP_FIELDS = ("flag", "name", "rule_scope", "comment")
PREVIEW_SECONDS = 120
MAX_ROUTER_AGE_SECONDS = 300
ROUTER_SETTLE_SECONDS = 300
MAX_UPTIME_SAMPLE_AGE_SECONDS = 120
SMART_ROUTE_COOLDOWN_SECONDS = 15 * 60
SMART_ROUTE_ACTOR = "smart automation"


def _balance_enabled(value) -> bool | None:
    if isinstance(value, list):
        value = value[0] if len(value) == 1 else None
    if not isinstance(value, dict):
        return None
    state = value.get("balance_state")
    if state is None:
        return None
    return str(state).lower() in ("on", "1", "true", "enabled")


def observed_netpulse_route(raw: dict, mac: str) -> dict:
    """Read the observed NP_R policy row; never infer a device's live per-flow WAN."""
    rows = raw.get("policy_routes") if isinstance(raw, dict) else None
    checked_at = raw.get("policy_routes_checked_at") if isinstance(raw, dict) else None
    if not isinstance(rows, list):
        return {"route": None, "checked_at": checked_at}
    name = f"NP_R_{normalize_mac(mac).replace('-', '')}"
    matches = [r for r in rows if isinstance(r, dict) and r.get("name") == name]
    if not matches:
        return {"route": "AUTO", "checked_at": checked_at}
    if len(matches) != 1:
        return {"route": None, "checked_at": checked_at}
    row = matches[0]
    state = str(row.get("state", "")).lower()
    if state in ("off", "0", "false", "disabled"):
        route = "AUTO"
    elif state in ("on", "1", "true", "enabled") and row.get("interfaces") in ("WAN1", "WAN2"):
        route = row["interfaces"]
    else:
        route = None
    return {"route": route, "checked_at": checked_at}


def summarize_group_routes(raw: dict, members: list[str], saved_routes: dict,
                           now: float, max_age_seconds: float = 1200) -> dict:
    """Aggregate observed NetPulse policy rows without inferring live traffic paths."""
    rows = raw.get("policy_routes") if isinstance(raw, dict) else None
    checked_at = raw.get("policy_routes_checked_at") if isinstance(raw, dict) else None
    if not isinstance(rows, list) or checked_at is None:
        return {"observed_route": "UNKNOWN", "route_drift_count": 0,
                "route_unknown_count": len(members), "route_stale_count": 0,
                "route_readback": "unavailable"}
    age = age_seconds(checked_at, now)
    if age is None or age > max_age_seconds:
        return {"observed_route": "UNKNOWN", "route_drift_count": 0,
                "route_unknown_count": 0, "route_stale_count": len(members),
                "route_readback": "stale"}
    observed = [observed_netpulse_route(raw, mac)["route"] for mac in members]
    unknown = sum(route not in ("AUTO", "WAN1", "WAN2") for route in observed)
    drift = sum(route is not None and route != saved_routes.get(mac, {}).get("route", "AUTO")
                for mac, route in zip(members, observed))
    same = bool(observed) and all(route == observed[0] for route in observed)
    status = "unavailable" if unknown else "drift" if drift else "matches"
    return {"observed_route": observed[0] if same and observed[0] is not None else
            "UNKNOWN" if unknown else "MIXED",
            "route_drift_count": drift, "route_unknown_count": unknown,
            "route_stale_count": 0, "route_readback": status}


def _local_interface_macs() -> set[str]:
    """MACs on this host, used to prevent NetPulse routing its own Pi connection."""
    found: set[str] = set()
    for path in Path("/sys/class/net").glob("*/address"):
        try:
            mac = path.read_text(encoding="ascii").strip().upper().replace(":", "-")
        except OSError:
            continue
        if MAC_RE.fullmatch(mac):
            found.add(mac)
    return found


def _system_boot_id() -> str | None:
    """A stable Linux boot identifier lets persisted monotonic deadlines survive service restarts."""
    try:
        value = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    except OSError:
        return None
    return value or None


class ControlError(ValueError):
    """A route action cannot safely be previewed or applied."""


class RouterControl:
    def __init__(self, router: RouterWatch, db_path: str, enabled: bool = False,
                 kill_switch: str = "/etc/netpulse/controls.disabled"):
        self.router = router
        self.client: ER605Client = router.client
        self.db_path = db_path
        self.enabled = enabled
        self.kill_switch = kill_switch
        self._firmware_store = KeyValueFile(db_path)
        self._firmware_notice_lock = threading.Lock()
        self._boot_id = _system_boot_id()
        self._lock = threading.Lock()
        self._pending: dict[str, dict] = {}
        self._pending_reservations: dict[str, dict] = {}
        self._pending_groups: dict[str, dict] = {}
        self._pending_group_reservations: dict[str, dict] = {}
        self._expiry_lock = threading.Lock()
        self._router_write_lock = getattr(router, "api_lock", None) or threading.RLock()
        self._expiry_retry_after: dict[str, float] = {}
        self._expiry_audited: set[str] = set()
        self._expiry_queue_lock = threading.Lock()
        self._expiry_failures: list[dict] = []

    def drain_expiry_failures(self) -> list[dict]:
        """Return newly failed timed expiries for owner notification."""
        with self._expiry_queue_lock:
            failures, self._expiry_failures = self._expiry_failures, []
        return failures

    def state(self) -> dict:
        age = age_seconds(self.router.snap.checked_at, time.time())
        uptime_age = age_seconds(self.router.snap.uptime_at, time.time())
        killed = Path(self.kill_switch).exists()
        raw = self.router.snap.raw if isinstance(self.router.snap.raw, dict) else {}
        firmware_version = getattr(self.router.snap, "firmware_version", None)
        accepted_firmware = self._firmware_store.get("router_firmware_accepted")
        pending_firmware = self._firmware_store.get("router_firmware_pending")
        acl_recovery_failed = self._firmware_store.get("pi_acl_recovery_failed") == "1"
        if firmware_version:
            if accepted_firmware is None:
                # Establish the first observed version as the baseline. Future changes
                # remain locked until the owner explicitly reviews and accepts them.
                self._firmware_store.set("router_firmware_accepted", firmware_version)
                accepted_firmware = firmware_version
            if firmware_version != accepted_firmware:
                pending_firmware = firmware_version
                self._firmware_store.set("router_firmware_pending", firmware_version)
            elif pending_firmware:
                # A router rollback to the previously reviewed firmware is safe to clear.
                self._firmware_store.set("router_firmware_pending", "")
                pending_firmware = None
        firmware_review_required = (not firmware_version or bool(pending_firmware)
                                    or firmware_version != accepted_firmware)
        firmware_reason = (
            "The ER605 firmware version could not be read; route controls are locked."
            if not firmware_version else
            f"ER605 firmware {firmware_version} needs review before route controls unlock."
            if firmware_review_required else ""
        )
        load_balancing = _balance_enabled(raw.get("balance_basic"))
        fresh = age is not None and age <= max(MAX_ROUTER_AGE_SECONDS, self.router.poll_seconds * 2)
        uptime_fresh = (uptime_age is not None and uptime_age <= MAX_UPTIME_SAMPLE_AGE_SECONDS)
        settled = self.router.snap.uptime is not None and self.router.snap.uptime >= ROUTER_SETTLE_SECONDS
        ready = bool(self.enabled and not killed and not acl_recovery_failed and not firmware_review_required and fresh and load_balancing is True
                     and uptime_fresh and settled)
        if killed:
            reason = "The local control kill switch is active."
        elif not self.enabled:
            reason = "Router controls are disabled in config."
        elif acl_recovery_failed:
            reason = "An interrupted temporary Internet test needs cleanup; verify the Pi recovery service before changing router controls."
        elif firmware_review_required:
            reason = firmware_reason
        elif not fresh:
            reason = "Waiting for a fresh authenticated ER605 status check."
        elif not uptime_fresh:
            reason = "Waiting for a fresh ER605 uptime check before allowing route changes."
        elif not settled:
            remaining = max(0, ROUTER_SETTLE_SECONDS - int(self.router.snap.uptime or 0))
            reason = f"The ER605 recently started or restarted; route changes unlock after it has been stable for {remaining} more seconds."
        elif load_balancing is None:
            reason = "Waiting for the router load-balancing setting to be read."
        elif not load_balancing:
            reason = "Enable ER605 Load Balancing before using policy routes."
        else:
            reason = ""
        return {"enabled": ready, "configured": self.enabled, "kill_switch": killed,
                "acl_recovery_failed": acl_recovery_failed,
                "load_balancing": load_balancing, "reason": reason,
                "firmware_version": firmware_version,
                "accepted_firmware_version": accepted_firmware,
                "firmware_review_required": firmware_review_required,
                "firmware_review_version": pending_firmware or (firmware_version if firmware_review_required else None),
                "firmware_reason": firmware_reason,
                "router_age_seconds": age, "router_uptime_seconds": self.router.snap.uptime,
                "router_uptime_age_seconds": uptime_age,
                "features": {"route": "ready", "reservation": "ready", "qos_priority": "not_ready",
                                                           "smart_failover": "not_enabled"}}

    def accept_firmware(self, version: str, confirmed: bool) -> dict:
        """Accept the exact currently reported firmware after an owner reviews compatibility."""
        if confirmed is not True:
            raise ControlError("Explicit firmware review confirmation is required.")
        if not self.enabled:
            raise ControlError("Router controls are disabled in config.")
        current = getattr(self.router.snap, "firmware_version", None)
        if not isinstance(current, str) or not current:
            raise ControlError("The current ER605 firmware version is unavailable.")
        age = age_seconds(self.router.snap.checked_at, time.time())
        if age is None or age > max(MAX_ROUTER_AGE_SECONDS, self.router.poll_seconds * 2):
            raise ControlError("Wait for a fresh authenticated firmware read before accepting this version.")
        status = self.state()
        if not status["firmware_review_required"]:
            raise ControlError("There is no firmware change waiting for review.")
        if not isinstance(version, str) or version != current:
            raise ControlError("The firmware version changed; refresh the page and review the current version.")
        with self._firmware_notice_lock:
            self._firmware_store.set("router_firmware_accepted", current)
            self._firmware_store.set("router_firmware_pending", "")
        sqlite.log_firmware_review(self.db_path, int(time.time()), current)
        return self.state()

    def claim_firmware_review_notice(self) -> dict | None:
        """Return one fresh, actionable firmware-lock notice per observed version."""
        if not self.enabled:
            return None
        with self._firmware_notice_lock:
            status = self.state()
            age = status.get("router_age_seconds")
            if (not status.get("firmware_review_required") or age is None
                    or age > max(MAX_ROUTER_AGE_SECONDS, self.router.poll_seconds * 2)):
                return None
            version = status.get("firmware_version")
            marker = version or "unavailable"
            if self._firmware_store.get("router_firmware_notice") == marker:
                return None
            self._firmware_store.set("router_firmware_notice", marker)
        return {"version": version, "reason": status.get("firmware_reason")}

    def route_state(self) -> dict[str, dict]:
        return sqlite.device_routes(self.db_path)

    def set_group_smart_routing(self, group_id: int, enabled: bool,
                                actor: str = "dashboard") -> dict:
        """Opt one fully eligible group into stable, monitor-driven WAN preference updates."""
        if not isinstance(enabled, bool):
            raise ControlError("Choose whether smart routing is on or off.")
        group = next((g for g in sqlite.device_groups(self.db_path) if g["id"] == group_id), None)
        if not group:
            raise ControlError("This device group no longer exists.")
        if enabled:
            if not self.state()["enabled"]:
                raise ControlError("Router controls are locked; smart routing cannot be enabled.")
            if not group["members"]:
                raise ControlError("Add devices before enabling smart routing for this group.")
            saved = self.route_state()
            routes = {saved.get(mac, {}).get("route", "AUTO") for mac in group["members"]}
            if len(routes) != 1:
                raise ControlError("Group members have mixed saved routes; review one group route first.")
            current = next(iter(routes))
            check_route = current if current in ("WAN1", "WAN2") else "WAN1"
            check = self.preview_group(group_id, check_route, actor, 0)
            with self._lock:
                self._pending_groups.pop(check["token"], None)
            readback = summarize_group_routes(
                self.router.snap.raw if isinstance(self.router.snap.raw, dict) else {},
                group["members"], saved, time.time(), MAX_ROUTER_AGE_SECONDS)
            if readback["route_readback"] != "matches":
                raise ControlError("ER605 route read-back must match every saved member route before enabling smart routing.")
        if not sqlite.set_group_smart_routing(self.db_path, group_id, enabled):
            raise ControlError("This device group no longer exists.")
        return {"group": group["name"], "enabled": enabled,
                "members": len(group["members"]), "route": current if enabled else None}

    def apply_smart_group_route(self, group_id: int, route: str, now: float | None = None) -> dict:
        """Apply a stable automatic recommendation via the same verified group transaction."""
        now = time.time() if now is None else float(now)
        group = next((g for g in sqlite.device_groups(self.db_path) if g["id"] == group_id), None)
        if not group or not group["smart_routing_enabled"]:
            raise ControlError("Smart routing is no longer enabled for this group.")
        if route not in ("WAN1", "WAN2"):
            raise ControlError("Smart routing only accepts a measured WAN recommendation.")
        last = group.get("smart_last_action_at")
        if last is not None and now - last < SMART_ROUTE_COOLDOWN_SECONDS:
            raise ControlError("Smart routing is in its 15-minute route-change cooldown.")
        saved = self.route_state()
        routes = {saved.get(mac, {}).get("route", "AUTO") for mac in group["members"]}
        if len(routes) != 1:
            raise ControlError("Group members have mixed saved routes; smart routing stopped.")
        if next(iter(routes)) == route:
            return {"applied": False, "group": group["name"], "route": route,
                    "detail": "The group already prefers this WAN."}
        with self._router_write_lock:
            router_state = self.router.snapshot()
            if router_state.get("paused_until", 0) > time.time():
                return {"applied": False, "group": group["name"], "route": route,
                        "detail": "Router checks are paused; Smart WAN will retry after they resume."}
            sqlite.record_group_smart_action(self.db_path, group_id, int(now))
            preview = self.preview_group(group_id, route, SMART_ROUTE_ACTOR, 0)
            try:
                return self.apply_group(preview["token"])
            except Exception:
                with self._lock:
                    self._pending_groups.pop(preview["token"], None)
                raise

    def preview_group(self, group_id: int, route: str, actor: str,
                      expiry_seconds: int = 0) -> dict:
        """Prepare a one-shot group action after checking every member is independently routable."""
        if not self.state()["enabled"]:
            raise ControlError("Router controls are locked; no group route preview is available.")
        if isinstance(group_id, bool) or not isinstance(group_id, int):
            raise ControlError("Choose a valid device group.")
        group = next((g for g in sqlite.device_groups(self.db_path) if g["id"] == group_id), None)
        if not group:
            raise ControlError("This device group no longer exists.")
        if not group["members"]:
            raise ControlError("Add at least one device before changing a group route.")
        route = str(route or "").upper()
        if route not in ROUTE_OPTIONS:
            raise ControlError("Choose Auto, WAN1, or WAN2.")
        if (isinstance(expiry_seconds, bool) or not isinstance(expiry_seconds, int)
                or expiry_seconds not in ROUTE_EXPIRY_OPTIONS):
            raise ControlError("Choose Until changed, 1 hour, 6 hours, 24 hours, or 7 days.")
        if route == "AUTO":
            expiry_seconds = 0
        devices = []
        labels = sqlite.device_labels(self.db_path)
        routes = self.route_state()
        raw = self.router.snap.raw if isinstance(self.router.snap.raw, dict) else {}
        for mac in group["members"]:
            if self.is_local_device(mac):
                raise ControlError("The NetPulse Pi is a group member; remove it before steering this group.")
            reservation, ip = self._cached_device(mac)
            saved = routes.get(mac, {})
            saved_route = saved.get("route", "AUTO")
            observed = observed_netpulse_route(raw, mac)
            if observed["route"] is None:
                raise ControlError("The ER605's current device route could not be read; wait for a fresh router check before reviewing this group.")
            checked_at = observed.get("checked_at")
            policy_age = age_seconds(checked_at, time.time())
            if policy_age is None or policy_age > MAX_ROUTER_AGE_SECONDS:
                raise ControlError("The ER605's current device route is stale; wait for a fresh router check before reviewing this group.")
            devices.append({"mac": mac, "ip": ip, "name": labels.get(mac) or
                            str(reservation.get("note") or "Home device"),
                            "current": observed["route"], "saved_current": saved_route,
                            "current_expires_at": (saved.get("expires_at")
                                                    if saved_route == observed["route"]
                                                    and saved_route in ("WAN1", "WAN2") else None)})
        now = time.time()
        token = secrets.token_urlsafe(24)
        with self._lock:
            self._pending_groups = {k: v for k, v in self._pending_groups.items() if v["expires"] > now}
            self._pending_groups[token] = {"group_id": group_id, "group_name": group["name"],
                "group_updated_at": group["updated_at"], "members": devices, "route": route,
                "smart_routing_enabled": group["smart_routing_enabled"],
                "actor": actor, "expiry_seconds": expiry_seconds, "expires": now + PREVIEW_SECONDS}
        return {"token": token, "expires_in": PREVIEW_SECONDS, "group": group["name"],
                "route": route, "expiry_label": ROUTE_EXPIRY_OPTIONS[expiry_seconds], "members": devices,
                "effect": (f"Apply {route} to all {len(devices)} listed devices. Each device keeps its own ER605 policy rule. "
                           "These rules remain on the ER605 if the Pi is offline. Priority mode uses the router's own WAN online detection; "
                           "if the ER605 reports the selected WAN offline, that rule stops applying. "
                           + ("NetPulse must be running at the timed expiry to return devices to Auto; if the Pi is offline then, "
                              "the rules remain until NetPulse returns." if expiry_seconds else
                              "The preferences stay on the ER605 until changed."))}

    def apply_group(self, token: str) -> dict:
        with self._router_write_lock:
            return self._apply_group_locked(token)

    def _apply_group_locked(self, token: str) -> dict:
        """Apply one group change; if any member fails, restore prior member preferences in reverse order."""
        with self._lock:
            pending = self._pending_groups.pop(str(token or ""), None)
        if not pending or pending["expires"] <= time.time():
            raise ControlError("This group preview expired or was already used. Review it again.")
        self._refresh_transaction_uptime()
        group = next((g for g in sqlite.device_groups(self.db_path) if g["id"] == pending["group_id"]), None)
        def group_is_unchanged():
            current = next((g for g in sqlite.device_groups(self.db_path)
                            if g["id"] == pending["group_id"]), None)
            return bool(current and current["name"] == pending["group_name"]
                        and current["updated_at"] == pending["group_updated_at"]
                        and (pending["actor"] != SMART_ROUTE_ACTOR
                             or current["smart_routing_enabled"])
                        and current["members"] == [d["mac"] for d in pending["members"]])

        if not group_is_unchanged():
            raise ControlError("Group name or membership changed after review; create a fresh preview.")
        if pending["actor"] != SMART_ROUTE_ACTOR:
            # A manual choice always takes precedence over future automatic steering.
            sqlite.set_group_smart_routing(self.db_path, group["id"], False)
        prepared = []
        for device in pending["members"]:
            preview = self.preview(device["mac"], pending["route"], pending["actor"],
                                   pending["expiry_seconds"])
            with self._lock:
                self._pending.pop(preview["token"], None)
            if (preview["ip"] != device["ip"] or preview["observed_current"] != device["current"]
                    or preview["saved_current"] != device["saved_current"]):
                raise ControlError("A group member changed after review; nothing was applied. Review the group again.")
            prepared.append(device)
        applied = []
        applying = None
        try:
            for device in prepared:
                self._refresh_transaction_uptime()
                if not group_is_unchanged():
                    raise ControlError("Group changed during apply; restoring completed member changes.")
                preview = self.preview(device["mac"], pending["route"], pending["actor"],
                                       pending["expiry_seconds"])
                if (preview["ip"] != device["ip"] or preview["observed_current"] != device["current"]
                        or preview["saved_current"] != device["saved_current"]):
                    with self._lock:
                        self._pending.pop(preview["token"], None)
                    raise ControlError("A group member changed after review; review the group again.")
                applying = device
                self.apply(preview["token"])
                applied.append(device)
                applying = None
            if not group_is_unchanged():
                raise ControlError("Group changed during apply; restoring completed member changes.")
        except Exception as exc:
            rollback_errors = []
            failed_member_restored = False
            if applying is not None:
                raw = self.router.snap.raw if isinstance(self.router.snap.raw, dict) else {}
                checked_at = raw.get("policy_routes_checked_at")
                observed = observed_netpulse_route(raw, applying["mac"])
                try:
                    snapshot_fresh = (checked_at is not None
                                      and 0 <= time.time() - float(checked_at) <= MAX_ROUTER_AGE_SECONDS)
                except (TypeError, ValueError, OverflowError):
                    snapshot_fresh = False
                route = observed.get("route") if snapshot_fresh else None
                if snapshot_fresh and route == applying["current"]:
                    failed_member_restored = True
                elif snapshot_fresh and route in ROUTE_OPTIONS:
                    # The single-device apply attempted its own rollback, but its fresh
                    # read-back still shows another known route. Make one safe second attempt
                    # through the same confirmed, read-back-verified per-device workflow.
                    try:
                        self._refresh_transaction_uptime()
                        rollback = self.preview(applying["mac"], applying["current"], pending["actor"], 0)
                        self.apply(rollback["token"])
                        raw = self.router.snap.raw if isinstance(self.router.snap.raw, dict) else {}
                        checked_at = raw.get("policy_routes_checked_at")
                        observed = observed_netpulse_route(raw, applying["mac"])
                        try:
                            snapshot_fresh = (checked_at is not None
                                              and 0 <= time.time() - float(checked_at) <= MAX_ROUTER_AGE_SECONDS)
                        except (TypeError, ValueError, OverflowError):
                            snapshot_fresh = False
                        failed_member_restored = (snapshot_fresh
                                                  and observed.get("route") == applying["current"])
                    except Exception:
                        log.exception("group rollback retry failed for %s", applying["mac"])
                if not failed_member_restored:
                    route = observed.get("route") if snapshot_fresh else None
                    rollback_errors.append(
                        f"{applying['mac']}: failed member was not restored to its prior route "
                        f"(observed {route or 'unknown'})")
            for device in reversed(applied):
                try:
                    self._refresh_transaction_uptime()
                    rollback = self.preview(device["mac"], device["current"], pending["actor"], 0)
                    self.apply(rollback["token"])
                except Exception as rollback_exc:
                    rollback_errors.append(f"{device['mac']}: {type(rollback_exc).__name__}")
            suffix = (" Rollback failed for " + ", ".join(rollback_errors) + "; inspect device routes immediately."
                      if rollback_errors else
                      " The failed member and previously changed members were restored and verified."
                      if applying is not None else
                      " Previously changed members were restored and verified.")
            message = f"Group change stopped at a member error ({type(exc).__name__}).{suffix}"
            try:
                sqlite.log_device_group_action(self.db_path, int(time.time()), group["id"], group["name"],
                    pending["actor"], pending["route"], "failed", len(pending["members"]), message)
            except Exception:
                log.exception("could not write group route audit for %s", group["name"])
            raise ControlError(message) from exc
        try:
            sqlite.log_device_group_action(self.db_path, int(time.time()), group["id"], group["name"],
                pending["actor"], pending["route"], "applied", len(applied),
                "All member routes were individually read back and verified.")
        except Exception:
            log.exception("could not write group route audit for %s", group["name"])
        return {"applied": True, "group": group["name"], "route": pending["route"],
                "count": len(applied), "detail": "All member routes were individually read back and verified.",
                "expiry_label": ROUTE_EXPIRY_OPTIONS[pending["expiry_seconds"]]}

    @staticmethod
    def local_device_macs() -> set[str]:
        return _local_interface_macs()

    @staticmethod
    def is_local_device(mac: str) -> bool:
        return normalize_mac(mac) in RouterControl.local_device_macs()

    def _reservation(self, clients, reservations, mac: str) -> tuple[dict, str]:
        if self.is_local_device(mac):
            raise ControlError("This is the NetPulse Pi itself; its WAN route is protected.")
        reservations = reservations if isinstance(reservations, list) else []
        clients = clients if isinstance(clients, list) else []
        matches = [r for r in reservations if isinstance(r, dict)
                   and normalize_mac(r.get("mac", r.get("macaddr", ""))) == normalize_mac(mac)
                   and str(r.get("enable", "1")).lower() not in ("0", "false", "off")]
        if len(matches) != 1:
            raise ControlError("This device needs one enabled DHCP reservation before it can be pinned.")
        row = matches[0]
        ip = str(row.get("ip", row.get("ipaddr", "")) or "")
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            raise ControlError("The router's reservation does not contain a valid IPv4 address.") from None
        if address.version != 4:
            raise ControlError("ER605 device route controls require an IPv4 reservation.")
        if not address.is_private or str(address) == self.client.host:
            raise ControlError("The reserved address is not a usable private device address.")
        enabled_ips = [str(r.get("ip", r.get("ipaddr", "")) or "") for r in reservations
                       if isinstance(r, dict) and str(r.get("enable", "1")).lower() not in ("0", "false", "off")]
        if enabled_ips.count(ip) != 1:
            raise ControlError("The reserved IP is assigned to more than one router reservation.")
        active = [c for c in clients if isinstance(c, dict)
                  and normalize_mac(c.get("macaddr", c.get("mac", ""))) == normalize_mac(mac)]
        if active and any(str(c.get("ipaddr", c.get("ip", ""))) != ip for c in active):
            raise ControlError("The active lease differs from its reservation; wait for the device to renew it.")
        return row, ip

    def _assert_not_paused(self, mac: str) -> None:
        if normalize_mac(mac) in blocked_macs(self.db_path):
            raise ControlError("This device has an Internet pause or unresolved pause change; resume it before changing its route or reservation.")

    def _cached_device(self, mac: str) -> tuple[dict, str]:
        self._assert_not_paused(mac)
        snap = self.router.snap
        max_age = max(300, self.router.poll_seconds * 2)
        age = age_seconds(snap.checked_at, time.time())
        if age is None or age > max_age:
            raise ControlError("The router device list is stale; wait for its next refresh.")
        raw = snap.raw if isinstance(snap.raw, dict) else {}
        return self._reservation(raw.get("clients"), raw.get("reservations"), mac)

    @staticmethod
    def _client_mac(row: dict) -> str:
        return normalize_mac(row.get("macaddr", row.get("mac", "")))

    @staticmethod
    def _client_ip(row: dict) -> str:
        return str(row.get("ipaddr", row.get("ip", "")) or "")

    def _reservation_candidate(self, clients, reservations, lan_rows, dhcp_settings, mac: str,
                               requested_name: str = "") -> tuple[dict, str, str]:
        self._assert_not_paused(mac)
        if self.is_local_device(mac):
            raise ControlError("This is the NetPulse Pi itself; it cannot be changed by this workflow.")
        clients = clients if isinstance(clients, list) else []
        reservations = reservations if isinstance(reservations, list) else []
        client_rows = [r for r in clients if isinstance(r, dict) and self._client_mac(r) == mac]
        if len(client_rows) != 1:
            raise ControlError("Select one currently connected device from the router's device list.")
        client = client_rows[0]
        matching_mac = [r for r in reservations if isinstance(r, dict)
                        and normalize_mac(r.get("mac", r.get("macaddr", ""))) == normalize_mac(mac)]
        if matching_mac:
            raise ControlError("A DHCP reservation already exists for this device; refresh the device list.")
        ip = self._client_ip(client)
        try:
            address = ipaddress.ip_address(ip)
            lan_row = next(r for r in (lan_rows or []) if isinstance(r, dict) and r.get("name") == "IP_LAN")
            network = ipaddress.ip_network(str(lan_row.get("scope")), strict=False)
            if isinstance(dhcp_settings, list):
                dhcp_settings = dhcp_settings[0] if len(dhcp_settings) == 1 else None
            start = ipaddress.ip_address(dhcp_settings["ipaddr_start"])
            end = ipaddress.ip_address(dhcp_settings["ipaddr_end"])
        except (ValueError, KeyError, TypeError, StopIteration):
            raise ControlError("Could not safely read the LAN and DHCP pool; no reservation can be prepared.") from None
        if (not isinstance(address, ipaddress.IPv4Address)
                or not isinstance(network, ipaddress.IPv4Network)
                or not isinstance(start, ipaddress.IPv4Address)
                or not isinstance(end, ipaddress.IPv4Address)):
            raise ControlError("Could not safely read an IPv4 LAN and DHCP pool; no reservation can be prepared.")
        if (start > end or start not in network or end not in network
                or start in (network.network_address, network.broadcast_address)
                or end in (network.network_address, network.broadcast_address)):
            raise ControlError("Could not safely read an IPv4 LAN and DHCP pool; no reservation can be prepared.")
        if address not in network or address in (network.network_address, network.broadcast_address):
            raise ControlError("This device's current IP is not a usable address in the ER605 LAN.")
        if not (start <= address <= end):
            raise ControlError("This device's current IP is outside the DHCP pool; keep its current router setup unchanged.")
        if any(isinstance(r, dict) and str(r.get("ip", r.get("ipaddr", ""))) == ip for r in reservations):
            raise ControlError("This IP is already present in the router reservation table; refresh or inspect it in Omada.")
        if any(isinstance(r, dict) and self._client_ip(r) == ip and self._client_mac(r) != mac
               for r in clients):
            raise ControlError("The current IP is also reported for another device; no reservation was prepared.")
        name = str(requested_name or client.get("name") or "Home device").strip()
        if (not name or len(name) > 48 or any(ord(c) < 32 for c in name)):
            raise ControlError("Use a device name from 1 to 48 characters without control characters.")
        return client, ip, name

    def preview_reservation(self, mac: str, name: str = "", actor: str = "dashboard") -> dict:
        if not self.state()["enabled"]:
            raise ControlError("Router controls are locked; no reservation preview is available.")
        mac = normalize_mac(mac)
        if not MAC_RE.fullmatch(mac):
            raise ControlError("Choose a listed device with a valid MAC address.")
        snap = self.router.snap
        max_age = max(300, self.router.poll_seconds * 2)
        age = age_seconds(snap.checked_at, time.time())
        if age is None or age > max_age:
            raise ControlError("The router device list is stale; wait for its next refresh.")
        raw = snap.raw if isinstance(snap.raw, dict) else {}
        friendly = sqlite.device_labels(self.db_path).get(mac, "")
        client, ip, device_name = self._reservation_candidate(raw.get("clients"), raw.get("reservations"),
            raw.get("lan_scopes"), raw.get("dhcp_settings"), mac, name or friendly)
        token = secrets.token_urlsafe(24)
        now = time.time()
        with self._lock:
            self._pending_reservations = {k: v for k, v in self._pending_reservations.items()
                                          if v["expires"] > now}
            self._pending_reservations[token] = {"mac": mac, "ip": ip, "name": device_name,
                                                 "actor": actor, "expires": now + PREVIEW_SECONDS}
        return {"token": token, "expires_in": PREVIEW_SECONDS, "mac": mac, "ip": ip,
                "device": device_name, "lease": str(client.get("leasetime") or ""),
                "reservation": f"NetPulse: {device_name}",
                "effect": "Keeps this device on automatic DHCP and asks the ER605 to give this MAC its current IP. "
                          "It may renew its lease once. IP-MAC binding stays off. No WAN route is changed yet."}

    def apply_reservation(self, token: str) -> dict:
        with self._router_write_lock:
            return self._apply_reservation_locked(token)

    def _apply_reservation_locked(self, token: str) -> dict:
        with self._lock:
            pending = self._pending_reservations.pop(str(token or ""), None)
        if not pending or pending["expires"] <= time.time():
            raise ControlError("This reservation preview expired or was already used. Create a new preview.")
        if not self.state()["enabled"]:
            raise ControlError("Router controls were locked before confirmation; no change was made.")
        mac, ip, name, actor = pending["mac"], pending["ip"], pending["name"], pending["actor"]
        self._assert_not_paused(mac)
        note = f"NetPulse: {name}"
        try:
            with self.client.session() as c:
                live_balance = _balance_enabled(c.get("balance", "balance_basic"))
                if live_balance is not True:
                    raise ControlError("ER605 load balancing is not confirmed on by a fresh read; no change was made.")
                client, actual_ip, actual_name = self._reservation_candidate(c.get("dhcps", "client"),
                    c.get("dhcps", "reservation"), c.get("ipgroup", "ipscope_list"),
                    c.get("dhcps", "lan"), mac, name)
                if actual_ip != ip or actual_name != name:
                    raise ControlError("Device lease or name changed after preview; review a fresh reservation preview.")
                if not self.state()["enabled"]:
                    raise ControlError("Router controls were locked during confirmation; no change was made.")
                row = self.client.add_dhcp_reservation(c.get("dhcps", "reservation") or [], {
                    "ip": ip, "mac": mac, "note": note, "enable": "on", "bind": "0", "interface": "LAN1",
                })
                latest = c.get("dhcps", "reservation") or []
                snapshot = dict(self.router.snap.raw or {})
                snapshot["reservations"] = sanitize(latest)
                self.router.snap.raw = snapshot
                self.router.snap.checked_at = time.time()
        except Exception as exc:
            sqlite.log_device_reservation(self.db_path, int(time.time()), actor, mac, ip, "create", "failed",
                                           type(exc).__name__)
            raise
        sqlite.log_device_reservation(self.db_path, int(time.time()), actor, mac, ip, "create", "applied",
                                       "DHCP reservation verified; IP-MAC binding off")
        return {"applied": True, "mac": mac, "ip": ip, "device": name,
                "reservation_id": str(row.get("id", "")), "detail": "Reservation verified; IP-MAC binding is off. "
                "Use Review change to choose Auto, WAN1, or WAN2 separately."}

    def preview_group_reservations(self, group_id: int, actor: str = "dashboard") -> dict:
        """Prepare one reviewed batch for missing DHCP reservations in a device group."""
        if not self.state()["enabled"]:
            raise ControlError("Router controls are locked; no group reservation preview is available.")
        if isinstance(group_id, bool) or not isinstance(group_id, int):
            raise ControlError("Choose a valid device group.")
        group = next((g for g in sqlite.device_groups(self.db_path) if g["id"] == group_id), None)
        if not group:
            raise ControlError("This device group no longer exists.")
        if not group["members"]:
            raise ControlError("Add at least one device before reserving a group.")
        snap = self.router.snap
        max_age = max(300, self.router.poll_seconds * 2)
        age = age_seconds(snap.checked_at, time.time())
        if age is None or age > max_age:
            raise ControlError("The ER605 device list is stale; wait for its next refresh before reviewing group reservations.")
        raw = snap.raw if isinstance(snap.raw, dict) else {}
        reservations = raw.get("reservations")
        reservations = reservations if isinstance(reservations, list) else []
        clients = raw.get("clients")
        clients = clients if isinstance(clients, list) else []
        labels = sqlite.device_labels(self.db_path)
        reviewed, new_reservations = [], []
        for mac in group["members"]:
            name = labels.get(mac) or ""
            display_name = name or "Home device"
            if self.is_local_device(mac):
                reviewed.append({"mac": mac, "ip": "", "name": display_name,
                                 "status": "protected · NetPulse Pi cannot be reserved"})
                continue
            matches = [r for r in reservations if isinstance(r, dict)
                       and normalize_mac(r.get("mac", r.get("macaddr", ""))) == mac]
            enabled = [r for r in matches
                       if str(r.get("enable", "1")).lower() not in ("0", "false", "off")]
            if matches:
                if len(matches) != 1 or len(enabled) != 1:
                    reviewed.append({"mac": mac, "ip": "", "name": display_name,
                                     "status": "needs attention · disabled or duplicate reservation in Omada"})
                    continue
                try:
                    reservation, ip = self._reservation(clients, reservations, mac)
                except ControlError as exc:
                    reviewed.append({"mac": mac, "ip": "", "name": display_name,
                                     "status": f"needs attention · {exc}"})
                    continue
                reviewed.append({"mac": mac, "ip": ip,
                                 "name": labels.get(mac) or str(reservation.get("note") or "Home device"),
                                 "status": "already reserved"})
                continue

            active = [r for r in clients if isinstance(r, dict) and self._client_mac(r) == mac]
            if not active:
                reviewed.append({"mac": mac, "ip": "", "name": display_name,
                                 "status": "not currently listed in the ER605 DHCP clients"})
                continue
            if len(active) != 1:
                reviewed.append({"mac": mac, "ip": "", "name": display_name,
                                 "status": "needs attention · ER605 reports multiple active leases"})
                continue
            try:
                preview = self.preview_reservation(mac, name, actor)
            except ControlError as exc:
                reviewed.append({"mac": mac, "ip": "", "name": display_name,
                                 "status": f"needs attention · {exc}"})
                continue
            item = {"mac": mac, "ip": preview["ip"], "name": preview["device"],
                    "status": "will be reserved", "effect": preview["effect"]}
            reviewed.append(item)
            new_reservations.append({**item, "token": preview["token"]})

        now = time.time()
        token = secrets.token_urlsafe(24) if new_reservations else ""
        if new_reservations:
            with self._lock:
                self._pending_group_reservations = {
                    key: value for key, value in self._pending_group_reservations.items()
                    if value["expires"] > now
                }
                self._pending_group_reservations[token] = {
                    "group_id": group_id, "group_name": group["name"],
                    "group_updated_at": group["updated_at"],
                    "members": list(group["members"]), "items": new_reservations,
                    "actor": actor, "expires": now + PREVIEW_SECONDS,
                }
        skipped = sum(1 for member in reviewed if member["status"] != "already reserved"
                      and member["status"] != "will be reserved")
        effect = (f"Create DHCP reservations for {len(new_reservations)} currently listed unreserved devices. "
                  f"{skipped} member(s) need attention or must appear in the ER605 DHCP client list first. "
                  "Each selected device stays on automatic DHCP; the ER605 may renew its lease once. "
                  "IP-MAC binding stays off. Existing reservations and WAN routes are not changed." if new_reservations else
                  f"No router changes are needed. {sum(1 for m in reviewed if m['status'] == 'already reserved')} member(s) "
                  f"are already reserved; {skipped} member(s) need attention or must appear in the ER605 DHCP client list first.")
        return {"token": token, "expires_in": PREVIEW_SECONDS if token else 0,
                "group": group["name"], "members": reviewed,
                "count": len(new_reservations),
                "skipped": skipped, "effect": effect}

    def apply_group_reservations(self, token: str) -> dict:
        with self._router_write_lock:
            return self._apply_group_reservations_locked(token)

    def _apply_group_reservations_locked(self, token: str) -> dict:
        with self._lock:
            pending = self._pending_group_reservations.pop(str(token or ""), None)
        def discard_remaining(start: int = 0) -> None:
            if not pending:
                return
            with self._lock:
                for item in pending["items"][start:]:
                    self._pending_reservations.pop(item["token"], None)

        if not pending:
            raise ControlError("This group reservation review expired or was already used. Review it again.")
        if pending["expires"] <= time.time():
            discard_remaining()
            raise ControlError("This group reservation review expired or was already used. Review it again.")
        try:
            self._refresh_transaction_uptime()
        except ControlError:
            discard_remaining()
            raise

        def unchanged() -> bool:
            current = next((g for g in sqlite.device_groups(self.db_path)
                            if g["id"] == pending["group_id"]), None)
            return bool(current and current["name"] == pending["group_name"]
                        and current["updated_at"] == pending["group_updated_at"]
                        and current["members"] == pending["members"])

        if not unchanged():
            discard_remaining(0)
            raise ControlError("Group name or membership changed after review; create a fresh reservation review.")

        # The outer group review is the owner's confirmation. Discard the one-device
        # child tokens from that preview and mint each internal token immediately before
        # its write so later members cannot expire during a long verified batch.
        discard_remaining()

        completed = []

        def completed_summary() -> str:
            if not completed:
                return ""
            values = [f"{row['device']} at {row['ip']}" for row in completed[:8]]
            if len(completed) > len(values):
                values.append(f"and {len(completed) - len(values)} more")
            return " Completed and verified: " + ", ".join(values) + "."

        for index, item in enumerate(pending["items"]):
            try:
                self._refresh_transaction_uptime()
                if not unchanged():
                    discard_remaining(index)
                    raise ControlError("group membership changed")
                fresh = self.preview_reservation(item["mac"], "", pending["actor"])
                if (fresh["ip"] != item["ip"] or fresh["device"] != item["name"]):
                    with self._lock:
                        self._pending_reservations.pop(fresh["token"], None)
                    discard_remaining(index)
                    raise ControlError("reviewed device lease or name changed")
                completed.append(self.apply_reservation(fresh["token"]))
            except Exception as exc:
                discard_remaining(index + 1)
                raise ControlError(f"Stopped after {len(completed)} of {len(pending['items'])} new reservations "
                                   f"({type(exc).__name__})." + completed_summary() +
                                   " Completed reservations remain active; refresh the group "
                                   "to see current router state before retrying.") from exc
        if not unchanged():
            raise ControlError(f"All {len(completed)} reservations were created, but group membership changed during apply. "
                               + completed_summary() + "The reservations remain active; refresh the group.")
        return {"applied": True, "group": pending["group_name"], "count": len(completed),
                "devices": [{"name": row["device"], "ip": row["ip"], "mac": row["mac"]}
                            for row in completed],
                "detail": "Each DHCP reservation was individually read back and verified. "
                          "No WAN routes were changed."}

    def preview(self, mac: str, route: str, actor: str, expiry_seconds: int = 0) -> dict:
        if not self.state()["enabled"]:
            raise ControlError("Router controls are locked. The local kill switch is active or controls are disabled.")
        mac = normalize_mac(mac)
        route = str(route or "").upper()
        if not MAC_RE.fullmatch(mac) or route not in ROUTE_OPTIONS:
            raise ControlError("Choose a listed device and Auto, WAN1, or WAN2.")
        if (isinstance(expiry_seconds, bool) or not isinstance(expiry_seconds, int)
                or expiry_seconds not in ROUTE_EXPIRY_OPTIONS):
            raise ControlError("Choose Until changed, 1 hour, 6 hours, 24 hours, or 7 days.")
        if route == "AUTO":
            expiry_seconds = 0
        reservation, ip = self._cached_device(mac)
        saved = self.route_state().get(mac, {})
        saved_current = saved.get("route", "AUTO")
        raw = self.router.snap.raw if isinstance(self.router.snap.raw, dict) else {}
        observed = observed_netpulse_route(raw, mac)
        if observed["route"] is None:
            raise ControlError("The ER605's current device route could not be read; wait for a fresh router check before reviewing this change.")
        current = observed["route"]
        checked_at = observed.get("checked_at")
        policy_age = age_seconds(checked_at, time.time())
        if policy_age is None or policy_age > MAX_ROUTER_AGE_SECONDS:
            raise ControlError("The ER605's current device route is stale; wait for a fresh router check before reviewing this change.")
        token = secrets.token_urlsafe(24)
        now = time.time()
        with self._lock:
            self._pending = {k: v for k, v in self._pending.items() if v["expires"] > now}
            self._pending[token] = {"mac": mac, "ip": ip, "route": route, "actor": actor,
                                    "current": saved_current, "observed_current": current,
                                    "expiry_seconds": expiry_seconds,
                                    "expires": now + PREVIEW_SECONDS}
        device_name = str(reservation.get("note") or "device")[:48]
        expiry_label = ROUTE_EXPIRY_OPTIONS[expiry_seconds]
        if route == "AUTO":
            effect = "Return this device to the ER605's normal load balancing."
        else:
            expiry_note = ("NetPulse must be running at the timed expiry to return this device to Auto; "
                           "if the Pi is offline then, the rule remains until NetPulse returns."
                           if expiry_seconds else "This preference stays on the ER605 until changed.")
            effect = (f"Prefer {route} for this device. This rule is saved on the ER605 and remains there if the Pi is offline. "
                      "Priority mode uses the ER605's own WAN online detection; if the ER605 reports the selected WAN offline, the rule stops applying. "
                      f"This preference will {('remain until changed' if expiry_seconds == 0 else 'return to Auto after ' + expiry_label)}. "
                      f"{expiry_note}")
        drift_note = (f" NetPulse saved preference: {saved_current}; ER605 currently reports: {current}."
                      if saved_current != current else "")
        return {"token": token, "expires_in": PREVIEW_SECONDS, "mac": mac, "ip": ip,
                "device": device_name, "current": current, "observed_current": current,
                "saved_current": saved_current,
                "route": route, "effect": effect + drift_note,
                "expiry_seconds": expiry_seconds, "expiry_label": expiry_label,
                "route_expires_at": int(now + expiry_seconds) if expiry_seconds else None}

    @staticmethod
    def _fields(row: dict, names: tuple[str, ...]) -> dict:
        return {key: row[key] for key in names if key in row and row[key] is not None}

    def _assert_enabled(self) -> None:
        if not self.state()["enabled"]:
            raise ControlError("Router controls were locked; no further changes will be made.")

    def _refresh_transaction_uptime(self) -> None:
        refresh = getattr(self.router, "refresh_uptime", None)
        if not callable(refresh) or not refresh():
            raise ControlError("A fresh ER605 uptime could not be confirmed; no further router changes were made.")
        max_age = max(MAX_ROUTER_AGE_SECONDS, self.router.poll_seconds * 2)
        status_age = age_seconds(self.router.snap.checked_at, time.time())
        if status_age is None or status_age >= max(0, max_age - 60):
            refresh_status = getattr(self.router, "refresh_control_status", None)
            if not callable(refresh_status) or not refresh_status():
                raise ControlError("A fresh authenticated ER605 status could not be confirmed; no further router changes were made.")
        status = self.state()
        if not status["enabled"]:
            reason = status.get("reason") or "readiness could not be confirmed"
            raise ControlError(f"Router controls were locked; no further router changes will be made. {reason}")

    def _update(self, module: str, form: str, rows: list, name: str, fields: tuple[str, ...], patch: dict) -> dict:
        found = [(i, r) for i, r in enumerate(rows) if isinstance(r, dict) and r.get("name") == name]
        if len(found) != 1:
            raise RouterError("NetPulse router object is missing or ambiguous")
        index, record = found[0]
        old = self._fields(record, fields)
        new = dict(old)
        new.update(patch)
        try:
            self._assert_enabled()
            self.client.set_row(module, form, index, f"key-{index}", old, new)
            check = next((r for r in (self.client.get(module, form) or [])
                          if isinstance(r, dict) and r.get("name") == name), None)
            if not check or any(check.get(k) != v for k, v in patch.items()):
                raise RouterError("NetPulse router object did not match the requested read-back")
            return check
        except Exception:
            # A timeout/read-back mismatch can happen after the router accepted the set.
            rows_now = self.client.get(module, form) or []
            current = [(i, r) for i, r in enumerate(rows_now)
                       if isinstance(r, dict) and r.get("name") == name]
            if len(current) == 1:
                ix, row = current[0]
                restore_old = self._fields(row, fields)
                if restore_old != old:
                    self.client.set_row(module, form, ix, f"key-{ix}", restore_old, old)
                    restored = next((r for r in (self.client.get(module, form) or [])
                                     if isinstance(r, dict) and r.get("name") == name), None)
                    if not restored or self._fields(restored, fields) != old:
                        raise RouterError("Failed to restore the previous NetPulse router rule")
            raise

    def apply(self, token: str) -> dict:
        with self._router_write_lock:
            return self._apply_one(token)

    def _apply_one(self, token: str) -> dict:
        with self._lock:
            pending = self._pending.pop(str(token or ""), None)
        if not pending or pending["expires"] <= time.time():
            raise ControlError("This preview expired or was already used. Create a new preview.")
        if not self.state()["enabled"]:
            raise ControlError("Router controls were locked before confirmation; nothing was changed.")

        mac, target, ip, actor = pending["mac"], pending["route"], pending["ip"], pending["actor"]
        self._assert_not_paused(mac)
        if actor != SMART_ROUTE_ACTOR:
            # A manual single-device change overrides the policy of any containing group.
            sqlite.disable_group_smart_routing_for_member(self.db_path, mac)
        current_route = self.route_state().get(mac, {}).get("route", "AUTO")
        if current_route != pending["current"]:
            raise ControlError("The saved device route changed after preview; review a fresh preview.")
        route_expires_at = None
        hexmac = mac.replace("-", "")
        ip_name, group_name, route_name = f"NP_I_{hexmac}", f"NP_G_{hexmac}", f"NP_R_{hexmac}"
        old_route = self.route_state().get(mac, {}).get("route", "AUTO")
        created: list[tuple[str, str, str]] = []
        updated_route_before: dict | None = None
        observed_policy_routes = None
        failure_policy_routes = None
        try:
            with self.client.session() as c:
                clients = c.get("dhcps", "client")
                reservations = c.get("dhcps", "reservation")
                live_balance = _balance_enabled(c.get("balance", "balance_basic"))
                if live_balance is not True:
                    raise ControlError("ER605 load balancing is not confirmed on by a fresh read; no route was changed.")
                _, actual_ip = self._reservation(clients, reservations, mac)
                if actual_ip != ip:
                    raise ControlError("The device reservation changed after preview; review a fresh preview.")
                routes = c.get("policy_route", "policy_route") or []
                observed_now = observed_netpulse_route({"policy_routes": routes}, mac)["route"]
                if observed_now != pending["observed_current"]:
                    raise ControlError("The ER605 device route changed after review; create a fresh preview.")
                route_rows = [(i, r) for i, r in enumerate(routes) if isinstance(r, dict)
                              and r.get("name") == route_name]
                if len(route_rows) > 1:
                    raise ControlError("Multiple NetPulse route rules exist for this device; manual repair is needed.")
                if target == "AUTO":
                    if route_rows and route_rows[0][1].get("state") != "off":
                        updated_route_before = self._fields(route_rows[0][1], ROUTE_FIELDS)
                        self._update("policy_route", "policy_route", routes, route_name, ROUTE_FIELDS,
                                     {"state": "off"})
                    detail = "Normal ER605 load balancing restored."
                else:
                    ip_rows = c.get("ipgroup", "ipscope_reservation") or []
                    lan_rows = c.get("ipgroup", "ipscope_list") or []
                    lan = next((r.get("scope") for r in lan_rows if isinstance(r, dict)
                                and r.get("name") == "IP_LAN"), None)
                    try:
                        lan_net = ipaddress.ip_network(str(lan), strict=False)
                    except ValueError:
                        raise ControlError("Could not confirm the ER605 LAN network; route controls stopped.") from None
                    if ipaddress.ip_address(ip) not in lan_net:
                        raise ControlError("The reserved device IP is outside the ER605 LAN network.")
                    entry = next((r for r in ip_rows if isinstance(r, dict) and r.get("name") == ip_name), None)
                    if entry and entry.get("scope") != f"{ip}-{ip}":
                        raise ControlError("A NetPulse IP entry conflicts with this device reservation.")
                    if not entry:
                        self._assert_enabled()
                        created.append(("ipgroup", "ipscope_reservation", ip_name))
                        entry = c.add_row("ipgroup", "ipscope_reservation", ip_rows, {
                            "name": ip_name, "type": "range", "flag": "user", "scope": f"{ip}-{ip}",
                            "scope_start": ip, "scope_end": ip, "comment": "NetPulse",
                        })

                    group_rows = c.get("ipgroup", "ipgroup_reservation") or []
                    group = next((r for r in group_rows if isinstance(r, dict) and r.get("name") == group_name), None)
                    if group and group.get("rule_scope") != [ip_name]:
                        raise ControlError("A NetPulse device group conflicts with its address entry.")
                    if not group:
                        self._assert_enabled()
                        created.append(("ipgroup", "ipgroup_reservation", group_name))
                        group = c.add_row("ipgroup", "ipgroup_reservation", group_rows, {
                            "name": group_name, "rule_scope": [ip_name], "comment": "", "flag": "user",
                        })

                    first = target
                    interfaces = first
                    if route_rows:
                        route = route_rows[0][1]
                        if route.get("src_ipgroup") != group_name or route.get("dst_ipgroup") != "IPGROUP_ANY":
                            raise ControlError("A NetPulse route conflicts with this device group.")
                        # Keep enough of the old NP_ rule to restore it if a later
                        # verification or database write fails after the set succeeded.
                        updated_route_before = self._fields(route, ROUTE_FIELDS)
                        current = c.get("policy_route", "policy_route") or []
                        route = self._update("policy_route", "policy_route", current, route_name, ROUTE_FIELDS,
                                             {"interfaces": interfaces, "mode": "Priority", "state": "on"})
                    else:
                        self._assert_enabled()
                        indices = [int(r["index"]) for r in routes
                                   if isinstance(r, dict) and str(r.get("index", "")).isdigit()]
                        rule_index = max(indices, default=0) + 1
                        if rule_index > 64:
                            raise ControlError("The ER605 policy route table is full (64 rules).")
                        created.append(("policy_route", "policy_route", route_name))
                        route = c.add_row("policy_route", "policy_route", routes, {
                            "name": route_name, "service_type": "ALL", "src_ipgroup": group_name,
                            "dst_ipgroup": "IPGROUP_ANY", "interfaces": interfaces, "timeobj": "Any",
                            "mode": "Priority", "comment": "NetPulse", "state": "on",
                            "index": rule_index, "src": "ipgroup", "dst": "ipgroup",
                        })
                    if (route.get("interfaces") != interfaces or route.get("mode") != "Priority"
                            or route.get("state") != "on" or route.get("src_ipgroup") != group_name):
                        raise RouterError("The router did not verify the selected WAN preference.")
                    detail = (f"{first} preferred. When the router reports it offline, the pin stops applying "
                              "and normal router routing resumes.")
                    if pending["expiry_seconds"]:
                        detail += (f" Returns to Auto after {ROUTE_EXPIRY_OPTIONS[pending['expiry_seconds']].lower()} while NetPulse is running; "
                                   "if the Pi is offline then, the saved rule remains until NetPulse returns.")
                    else:
                        detail += " Stays until changed."
                observed_policy_routes = c.get("policy_route", "policy_route") or []
            applied_at = time.time()
            snapshot = dict(self.router.snap.raw or {})
            snapshot["policy_routes"] = sanitize(observed_policy_routes)
            snapshot["policy_routes_checked_at"] = applied_at
            self.router.snap.raw = snapshot
            expiry_seconds = pending["expiry_seconds"]
            route_expires_at = int(applied_at + expiry_seconds) if expiry_seconds else None
            expires_monotonic = time.monotonic() + expiry_seconds if expiry_seconds else None
            sqlite.set_device_route(self.db_path, mac, ip, target, int(applied_at), actor,
                                    old_route, "applied", detail, route_expires_at,
                                    expires_monotonic, self._boot_id)
            self._expiry_retry_after.pop(mac, None)
            self._expiry_audited.discard(mac)
        except Exception as exc:
            # Restore an existing route before removing dependencies created during
            # this request. Otherwise a failed read-back could leave a live rule
            # pointing at a group that cleanup then deletes.
            try:
                with self.client.session() as c:
                    if updated_route_before is not None:
                        try:
                            current = c.get("policy_route", "policy_route") or []
                            current_row = next((r for r in current if isinstance(r, dict)
                                                and r.get("name") == route_name), None)
                            if current_row is not None:
                                current_fields = self._fields(current_row, ROUTE_FIELDS)
                                if current_fields != updated_route_before:
                                    ix = next(i for i, r in enumerate(current)
                                              if isinstance(r, dict) and r.get("name") == route_name)
                                    c.set_row("policy_route", "policy_route", ix, f"key-{ix}",
                                              current_fields, updated_route_before)
                                    restored = next((r for r in (c.get("policy_route", "policy_route") or [])
                                                     if isinstance(r, dict) and r.get("name") == route_name), None)
                                    if not restored or self._fields(restored, ROUTE_FIELDS) != updated_route_before:
                                        raise RouterError("Failed to restore the previous NetPulse route")
                        except Exception:
                            log.exception("router control route rollback failed for %s", route_name)
                            # Keep dependencies in place if restoring the route failed.
                            created = []
                    for module, form, name in reversed(created):
                        try:
                            if any(isinstance(row, dict) and row.get("name") == name
                                   for row in (c.get(module, form) or [])):
                                c.delete_row(module, form, name)
                        except Exception:
                            log.exception("router control cleanup failed for %s", name)
                    failure_policy_routes = c.get("policy_route", "policy_route") or []
            except Exception:
                log.exception("router control cleanup session failed")
            snapshot = dict(self.router.snap.raw or {})
            snapshot["policy_routes"] = sanitize(failure_policy_routes)
            snapshot["policy_routes_checked_at"] = time.time() if failure_policy_routes is not None else None
            self.router.snap.raw = snapshot
            sqlite.set_device_route(self.db_path, mac, ip, target, int(time.time()), actor,
                                    old_route, "failed", type(exc).__name__)
            raise

        return {"applied": True, "mac": mac, "ip": ip, "route": target, "detail": detail,
                "route_expires_at": route_expires_at,
                "expiry_label": ROUTE_EXPIRY_OPTIONS[pending["expiry_seconds"]]}

    def expire_due_routes(self, now: float | None = None,
                          monotonic_now: float | None = None) -> int:
        with self._router_write_lock:
            return self._expire_due_routes_locked(now, monotonic_now)

    def _expire_due_routes_locked(self, now: float | None = None,
                                  monotonic_now: float | None = None) -> int:
        """Return confirmed timed WAN pins to Auto after fresh router checks.

        Expiry comes only from a user-confirmed route preview. Stale router state,
        reboot settling, the kill switch, a changed policy row, or an API error
        leaves the route untouched and retries after a short backoff.
        """
        now = time.time() if now is None else now
        monotonic_now = time.monotonic() if monotonic_now is None else monotonic_now
        if not self._expiry_lock.acquire(blocking=False):
            return 0
        completed = 0
        try:
            if not self.state()["enabled"]:
                return 0
            for saved in sqlite.due_device_routes(self.db_path, int(now), monotonic_now, self._boot_id):
                mac = saved["mac"]
                if normalize_mac(mac) in blocked_macs(self.db_path):
                    # Keep the paused target's objects stable; expiry retries after verified resume.
                    continue
                if self._expiry_retry_after.get(mac, 0) > now:
                    continue
                if self.is_local_device(mac):
                    self._expiry_retry_after[mac] = now + 300
                    log.error("route expiry refused for local NetPulse MAC %s", mac)
                    continue
                current = self.route_state().get(mac)
                if (not current or current.get("route") != saved["route"]
                        or current.get("expires_at") != saved["expires_at"]):
                    continue
                route_name = f"NP_R_{mac.replace('-', '')}"
                group_name = f"NP_G_{mac.replace('-', '')}"
                try:
                    self._assert_enabled()
                    with self.client.session() as c:
                        if _balance_enabled(c.get("balance", "balance_basic")) is not True:
                            raise ControlError("live load balancing is not confirmed")
                        routes = c.get("policy_route", "policy_route") or []
                        matches = [(i, r) for i, r in enumerate(routes) if isinstance(r, dict)
                                   and r.get("name") == route_name]
                        if len(matches) > 1:
                            raise ControlError("multiple NetPulse rules are present")
                        if matches:
                            _, row = matches[0]
                            if (row.get("src_ipgroup") != group_name or row.get("dst_ipgroup") != "IPGROUP_ANY"
                                    or row.get("mode") != "Priority"):
                                raise ControlError("policy row no longer matches the saved NetPulse preference")
                            if row.get("state") != "off":
                                if row.get("interfaces") != saved["route"]:
                                    raise ControlError("policy WAN differs from the saved preference; refusing overwrite")
                                self._update("policy_route", "policy_route", routes, route_name, ROUTE_FIELDS,
                                             {"state": "off"})
                    detail = "Timed preference expired; normal ER605 load balancing restored."
                    sqlite.set_device_route(self.db_path, mac, saved["ip"], "AUTO", int(now),
                                            "system expiry", saved["route"], "applied", detail)
                    self._expiry_retry_after.pop(mac, None)
                    self._expiry_audited.discard(mac)
                    completed += 1
                except Exception:  # noqa: BLE001 - keep the pin and retry; never claim failback succeeded
                    self._expiry_retry_after[mac] = now + 300
                    log.exception("timed route expiry could not be verified for %s; will retry", mac)
                    if mac not in self._expiry_audited:
                        self._expiry_audited.add(mac)
                        failure = {"mac": mac, "ip": saved["ip"], "route": saved["route"]}
                        with self._expiry_queue_lock:
                            self._expiry_failures.append(failure)
                        try:
                            sqlite.set_device_route(
                                self.db_path, mac, saved["ip"], "AUTO", int(now), "system expiry",
                                saved["route"], "failed",
                                "Timed preference expired, but NetPulse could not verify return to Auto. "
                                "The prior pin may still affect this device; a retry is scheduled.")
                        except Exception:  # noqa: BLE001 - audit failure cannot interrupt retries
                            log.exception("could not audit timed route expiry failure for %s", mac)
            return completed
        finally:
            self._expiry_lock.release()
