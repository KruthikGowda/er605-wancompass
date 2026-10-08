"""Tiny read-only dashboard + JSON API on the standard-library HTTP server.

Runs in a background thread. Live status comes from an in-memory snapshot
the monitor loop publishes; history comes from read-only SQLite connections.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import re
import sqlite3
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from netpulse.storage import sqlite
from netpulse.web import report
from netpulse.router.er605 import RouterError
from netpulse.router.control import (ControlError, observed_netpulse_route,
                                     summarize_group_routes)
from netpulse.devices.identity import display_name as display_device_name, normalize_mac
from netpulse.probes.presence import (MAX_CLIENT_ROWS_TO_SCAN,
                                      per_device_scan_interval_seconds)
from netpulse.decision.review import summarize as summarize_decision_review
from netpulse.decision.best_wan import recommend_group as recommend_group_wan
from netpulse.decision.throughput import (MAX_SPEED_SAMPLE_AGE_SECONDS,
                                          compare_recent_samples, latest_recent_success)
from netpulse.freshness import age_seconds

log = logging.getLogger(__name__)
INDEX = Path(__file__).with_name("static") / "index.html"
MAX_POINTS = 720
AUTH_FAILURE_LIMIT = 8
AUTH_FAILURE_WINDOW_SECONDS = 300


class StatusBoard:
    def __init__(self):
        self._lock = threading.Lock()
        self._snapshot: dict = {"wans": [], "updated": None}
        self._extra: dict = {}

    def publish(self, snapshot: dict) -> None:
        with self._lock:
            self._snapshot = snapshot

    def get(self) -> dict:
        with self._lock:
            return self._snapshot

    def set_extra(self, key: str, value) -> None:
        with self._lock:
            self._extra[key] = value

    def get_extra(self, key: str):
        with self._lock:
            return self._extra.get(key)


def _read_auth_file(path: str | None):
    if not path or not Path(path).is_file():
        return None
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return data["username"], bytes.fromhex(data["salt"]), bytes.fromhex(data["digest"]), int(data["iterations"])
    except (OSError, ValueError, KeyError, TypeError):
        raise RuntimeError(f"invalid dashboard auth file {path}") from None


def _password_matches(header: str | None, auth) -> bool:
    if not header or not header.startswith("Basic "):
        return False
    try:
        decoded = base64.b64decode(header[6:], validate=True).decode("utf-8")
        username, password = decoded.split(":", 1)
        expected_user, salt, digest, iterations = auth
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
        return hmac.compare_digest(username, expected_user) and hmac.compare_digest(actual, digest)
    except (ValueError, UnicodeDecodeError):
        return False


class _AuthRateLimiter:
    """Bound repeated password hashing per client address without storing credentials."""

    def __init__(self, limit: int = AUTH_FAILURE_LIMIT, window: int = AUTH_FAILURE_WINDOW_SECONDS):
        self.limit, self.window = limit, window
        self._failures: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def retry_after(self, address: str, now: float | None = None) -> int:
        now = time.monotonic() if now is None else now
        with self._lock:
            attempts = self._failures.get(address)
            if not attempts:
                return 0
            while attempts and now - attempts[0] >= self.window:
                attempts.popleft()
            if not attempts:
                self._failures.pop(address, None)
                return 0
            if len(attempts) < self.limit:
                return 0
            return max(1, int(attempts[0] + self.window - now + 0.999))

    def failed(self, address: str, now: float | None = None) -> None:
        now = time.monotonic() if now is None else now
        with self._lock:
            attempts = self._failures.get(address)
            if attempts is None:
                if len(self._failures) >= 512:
                    oldest = min(self._failures, key=lambda key: self._failures[key][-1])
                    self._failures.pop(oldest, None)
                attempts = self._failures[address] = deque()
            while attempts and now - attempts[0] >= self.window:
                attempts.popleft()
            attempts.append(now)

    def succeeded(self, address: str) -> None:
        with self._lock:
            self._failures.pop(address, None)


def make_handler(board: StatusBoard, db_path: str, auth_file: str | None = None):
    auth = _read_auth_file(auth_file)
    auth_limiter = _AuthRateLimiter()

    class Handler(BaseHTTPRequestHandler):
        def _authorized(self) -> bool:
            if auth is None:
                return True
            address = str(self.client_address[0])
            retry_after = auth_limiter.retry_after(address)
            if retry_after:
                self.send_response(429)
                self.send_header("Retry-After", str(retry_after))
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return False
            if _password_matches(self.headers.get("Authorization"), auth):
                auth_limiter.succeeded(address)
                return True
            auth_limiter.failed(address)
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="NetPulse", charset="UTF-8"')
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return False

        def do_GET(self):
            if not self._authorized():
                return
            url = urlparse(self.path)
            q = parse_qs(url.query)
            try:
                if url.path in ("/", "/index.html"):
                    self._send(200, INDEX.read_bytes(), "text/html; charset=utf-8")
                elif url.path == "/api/status":
                    self._json(board.get())
                elif url.path == "/api/history":
                    hours = min(max(float(q.get("hours", ["24"])[0]), 1), 24 * 400)
                    since = int(time.time() - hours * 3600)
                    bucket = max(60, int(hours * 3600 / MAX_POINTS) // 60 * 60)
                    target = q.get("target", [""])[0]
                    points = (sqlite.target_history(db_path, since, bucket, target) if target
                              else sqlite.history(db_path, since, bucket))
                    self._json({
                        "hours": hours,
                        "bucket": bucket,
                        "target": target,
                        "points": points,
                        "state_minutes": sqlite.state_minutes(db_path, since),
                    })
                elif url.path == "/api/speedtests":
                    mon = board.get_extra("speedtest")
                    days = min(max(float(q.get("days", ["30"])[0]), 1), 400)
                    since = int(time.time() - days * 86400)
                    self._json({
                        "running": bool(mon and mon.tester.running),
                        "results": sqlite.speedtests(db_path, since),
                        "usual": mon.usual_speeds() if mon else {},
                        "plans": {n: w.plan_mbps for n, w in mon.labels.items()} if mon else {},
                        "data_usage": (
                            mon.speedtest_data_usage()
                            if mon and callable(getattr(mon, "speedtest_data_usage", None))
                            else None
                        ),
                    })
                elif url.path in ("/report", "/api/report.csv"):
                    mon = board.get_extra("speedtest")
                    days = min(max(float(q.get("days", ["30"])[0]), 1), 400)
                    labels = {n: w.label or n for n, w in mon.labels.items()} if mon else {}
                    plans = {n: w.plan_mbps for n, w in mon.labels.items()} if mon else {}
                    selected_wan = q.get("wan", [None])[0]
                    if selected_wan is not None and selected_wan not in labels:
                        self._send(400, b"invalid WAN filter", "text/plain; charset=utf-8")
                        return
                    rep = report.build(db_path, labels, plans, days, selected_wan)
                    if url.path == "/report":
                        self._send(200, report.to_html(rep).encode(), "text/html; charset=utf-8")
                    else:
                        name = f"netpulse-report-{time.strftime('%Y%m%d')}.csv"
                        self._send(200, report.to_csv(rep, db_path, labels).encode(), "text/csv; charset=utf-8",
                                   {"Content-Disposition": f'attachment; filename="{name}"'})
                elif url.path == "/api/router":
                    body = {"router": board.get().get("router")}
                    if q.get("raw", ["0"])[0] == "1":
                        body["raw"] = board.get_extra("router_raw")  # sanitized: no credentials
                    self._json(body)
                elif url.path == "/api/control":
                    control = board.get_extra("router_control")
                    self._json(control.state() if control else {"enabled": False, "reason": "Router controls are not configured."})
                elif url.path == "/api/device-groups":
                    self._json({"groups": sqlite.device_groups(db_path)})
                elif url.path == "/api/devices/paused":
                    control = board.get_extra("pause_control")
                    records = control.records() if control else []
                    raw_state = control.state() if control else {
                        "enabled": False, "configured": False}
                    enabled = bool(raw_state.get("enabled"))
                    configured = bool(raw_state.get("configured"))
                    public_state = {
                        "enabled": enabled,
                        "configured": configured,
                        "cleanup_enabled": bool(raw_state.get("cleanup_enabled")),
                        "reason": ("" if enabled else
                                   "Internet pause has not been enabled. Awaiting WAN2 and recovery validation."
                                   if not configured else
                                   "Internet pause is temporarily unavailable; router safety checks need attention."),
                    }
                    safe_records = [{key: record.get(key) for key in
                                     ("mac", "ip", "label", "group_id", "status", "expires_at")}
                                    for record in records if isinstance(record, dict)]
                    self._json({"state": public_state,
                        "records": safe_records})
                elif url.path == "/api/system":
                    health = board.get_extra("system_health")
                    if isinstance(health, dict):
                        health = dict(health)
                        try:
                            max_age = float(health["max_age_seconds"])
                            age = age_seconds(health["checked_at"], time.time())
                            health["age_seconds"] = round(age, 1) if age is not None else None
                            health["stale"] = age is None or age > max_age
                        except (KeyError, TypeError, ValueError):
                            health["age_seconds"] = None
                            health["stale"] = True
                    self._json({"enabled": health is not None, "health": health})
                elif url.path == "/api/devices":
                    status_snapshot = board.get()
                    now = time.time()
                    router = status_snapshot.get("router")
                    raw = board.get_extra("router_raw") or {}
                    clients = raw.get("clients") if isinstance(raw, dict) else None
                    reservations = raw.get("reservations") if isinstance(raw, dict) else None
                    devices = []
                    names = sqlite.device_labels(db_path)
                    history = sqlite.device_history(db_path)
                    history_now = time.time()
                    for sample in history.values():
                        if not isinstance(sample, dict):
                            continue
                        for field in ("first_seen", "last_seen"):
                            timestamp = sample.get(field)
                            if timestamp is not None and age_seconds(timestamp, history_now) is None:
                                sample[field] = None
                    saved_routes = sqlite.device_routes(db_path)
                    groups = sqlite.device_groups(db_path)
                    speed_rows = sqlite.speedtests(db_path,
                                                   int(now - MAX_SPEED_SAMPLE_AGE_SECONDS),
                                                   int(now) + 1)
                    recent_speeds = latest_recent_success(speed_rows, now)
                    recent_speed_comparison = compare_recent_samples(recent_speeds)
                    presence_by_mac = board.get_extra("device_presence") or {}
                    group_by_mac = {mac: g["name"] for g in groups for mac in g["members"]}
                    for group in groups:
                        member_settings = {(saved_routes.get(mac, {}).get("route", "AUTO"),
                                            saved_routes.get(mac, {}).get("expires_at")
                                            if saved_routes.get(mac, {}).get("route", "AUTO") in ("WAN1", "WAN2")
                                            else None)
                                           for mac in group["members"]}
                        member_routes = {route for route, _ in member_settings}
                        group["route"] = next(iter(member_routes)) if len(member_routes) == 1 else "MIXED"
                        group["expiry_mixed"] = (len(member_routes) == 1 and
                                                  len({expiry for _, expiry in member_settings}) > 1)
                        group["suggested_wan"] = recommend_group_wan(
                            status_snapshot.get("wans"), status_snapshot.get("updated"), now,
                            group["route"] if group["route"] in ("WAN1", "WAN2") else "AUTO",
                            recent_speed_comparison)
                        group["monitor_advice"] = status_snapshot.get(
                            "group_recommendations", {}).get(group["id"])
                    control = board.get_extra("router_control")

                    def route_observation(mac: str, saved: dict) -> dict:
                        observed = observed_netpulse_route(raw, mac)
                        actual = observed["route"]
                        saved_route = saved.get("route", "AUTO")
                        route_max_age = (router.get("links_max_age_seconds", 1200)
                                         if isinstance(router, dict) else 1200)
                        checked_at = observed["checked_at"]
                        checked_age = age_seconds(checked_at, time.time())
                        return {"np_rule_route": actual or "UNKNOWN",
                                "np_rule_drift": None if actual is None else actual != saved_route,
                                "np_rule_checked_at": (None if checked_at is not None and checked_age is None
                                                        else checked_at),
                                "np_rule_stale": (None if checked_at is None else
                                                  checked_age is None or checked_age > route_max_age)}

                    by_mac = {}
                    if isinstance(clients, list):
                        for item in clients:
                            if not isinstance(item, dict):
                                continue
                            mac = item.get("macaddr", item.get("mac", ""))
                            ip = item.get("ipaddr", item.get("ip", ""))
                            mac = normalize_mac(mac)
                            if not mac or mac in by_mac:
                                continue
                            device = {
                                "name": display_device_name(item.get("name"), mac),
                                "label": names.get(mac, ""),
                                "ip": str(ip or ""),
                                "mac": mac,
                                "lease": str(item.get("leasetime") or ""),
                                # ER605's DHCP client table is a lease list, not a
                                # real-time reachability signal.
                                "listed": True,
                                "lan_presence": presence_by_mac.get(mac, {
                                    "state": "unknown", "ip": str(ip or ""),
                                    "checked_at": None, "last_reply_at": None, "misses": 0,
                                }),
                                "first_seen": history.get(mac, {}).get("first_seen"),
                                "last_seen": history.get(mac, {}).get("last_seen"),
                                "reserved": str(item.get("bind", "0")).lower() in ("1", "true")
                                           or str(item.get("leasetime", "")).lower() == "permanent",
                                "protected": bool(control and control.is_local_device(mac)),
                                "group": group_by_mac.get(mac, ""),
                                "route": saved_routes.get(mac, {}).get("route", "AUTO"),
                                "route_expires_at": saved_routes.get(mac, {}).get("expires_at"),
                                **route_observation(mac, saved_routes.get(mac, {})),
                            }
                            devices.append(device)
                            if mac:
                                by_mac[mac] = device
                    if isinstance(reservations, list):
                        for item in reservations:
                            if not isinstance(item, dict):
                                continue
                            mac = normalize_mac(item.get("mac", item.get("macaddr", "")))
                            if not mac:
                                continue
                            enabled = str(item.get("enable", "1")).lower() not in ("0", "false", "off")
                            current = by_mac.get(mac)
                            if current is not None:
                                current["reserved"] = enabled
                                if item.get("note"):
                                    current["name"] = str(item["note"])
                                continue
                            if enabled:
                                saved = saved_routes.get(mac, {})
                                devices.append({
                                    "name": display_device_name(item.get("note"), mac),
                                    "label": names.get(mac, ""),
                                    "ip": str(item.get("ip", item.get("ipaddr", "")) or ""),
                                    "mac": mac,
                                    "lease": "",
                                    "listed": False,
                                    "lan_presence": presence_by_mac.get(mac, {
                                        "state": "unknown", "ip": str(item.get("ip", item.get("ipaddr", "")) or ""),
                                        "checked_at": None, "last_reply_at": None, "misses": 0,
                                    }),
                                    "first_seen": history.get(mac, {}).get("first_seen"),
                                    "last_seen": history.get(mac, {}).get("last_seen"),
                                    "reserved": True,
                                    "protected": bool(control and control.is_local_device(mac)),
                                    "group": group_by_mac.get(mac, ""),
                                    "route": saved.get("route", "AUTO"),
                                    "route_expires_at": saved.get("expires_at"),
                                    **route_observation(mac, saved),
                                })
                    presence_client_count = len(clients) if isinstance(clients, list) else None
                    configured_presence_interval = (board.get_extra("device_presence_interval_seconds") or 60)
                    presence_cycle_seconds = per_device_scan_interval_seconds(
                        configured_presence_interval, presence_client_count) \
                        if presence_client_count is not None else None
                    presence_inventory_supported = (
                        None if presence_client_count is None else
                        0 <= presence_client_count <= MAX_CLIENT_ROWS_TO_SCAN)
                    device_by_mac = {device["mac"]: device for device in devices if device.get("mac")}
                    for group in groups:
                        ready_members = [device_by_mac.get(mac) for mac in group["members"]]
                        group["reserved_count"] = sum(bool(device and device["reserved"])
                                                       for device in ready_members)
                        group["blocked_count"] = sum(bool(not device or not device["reserved"]
                                                           or device["protected"])
                                                      for device in ready_members)
                        route_max_age = (router.get("links_max_age_seconds", 1200)
                                         if isinstance(router, dict) else 1200)
                        group.update(summarize_group_routes(
                            raw, group["members"], saved_routes, time.time(), route_max_age))
                    inventory_checked = router.get("checked_at") if isinstance(router, dict) else None
                    inventory_max_age = (router.get("links_max_age_seconds", 1200)
                                         if isinstance(router, dict) else 1200)
                    inventory_scan_interval = max(60, inventory_max_age / 2)
                    inventory_age = (age_seconds(inventory_checked, time.time())
                                     if inventory_checked is not None else None)
                    inventory_stale = (None if inventory_checked is None else
                                       inventory_age is None or inventory_age > inventory_max_age)
                    syslog = board.get_extra("router_syslog")
                    if not isinstance(syslog, dict):
                        syslog = {"enabled": False, "listening": False,
                                  "accepted_allocations": 0, "duplicates_suppressed": 0,
                                  "device_events": 0, "known_renewals_suppressed": 0,
                                  "last_allocation_at": None}
                    self._json({"configured": router is not None, "ready": isinstance(clients, list),
                                "updated": router.get("checked_at") if isinstance(router, dict) else None,
                                "inventory_stale": inventory_stale,
                                "inventory_age_seconds": inventory_age,
                                "scan_interval_seconds": inventory_scan_interval,
                                "missing_confirmation_scans": sqlite.DEVICE_OFFLINE_AFTER_SCANS,
                                "syslog": syslog,
                                "presence_enabled": bool(
                                    getattr(board.get_extra("device_presence_settings"), "enabled",
                                            board.get_extra("device_presence_enabled"))),
                                "presence_available": bool(
                                    getattr(board.get_extra("device_presence_settings"), "available", False)),
                                "presence_probe_interval_seconds": board.get_extra(
                                    "device_presence_interval_seconds") or 60,
                                "presence_probe_cycle_seconds": presence_cycle_seconds,
                                "presence_inventory_supported": presence_inventory_supported,
                                "presence_confirm_misses": board.get_extra("device_presence_confirm_misses") or 3,
                                "control": control.state() if control else {"enabled": False},
                                "groups": groups,
                                "recent_speeds": recent_speeds,
                                "recent_speed_comparison": recent_speed_comparison,
                                "group_history": sqlite.device_group_history(db_path, 20),
                                "devices": devices,
                                "route_history": sqlite.router_control_history(db_path, 20)})
                elif url.path == "/api/events":
                    limit = min(int(q.get("limit", ["50"])[0]), 500)
                    self._json(sqlite.recent_events(db_path, limit))
                elif url.path == "/api/decisions":
                    days = int(q.get("days", ["7"])[0])
                    if not 1 <= days <= 30:
                        raise ValueError("days must be from 1 to 30")
                    review = summarize_decision_review(db_path, days, recommendation_limit=10)
                    review["omitted_recommendations"] = max(
                        0, review["total"] - len(review["recommendations"]))
                    self._json(review)
                else:
                    self._send(404, b"not found", "text/plain")
            except ValueError:
                self._send(400, b"bad request", "text/plain")
            except Exception:  # noqa: BLE001
                log.exception("web request failed: %s", self.path)
                self._send(500, b"internal error", "text/plain")

        def do_POST(self):
            if not self._authorized():
                return
            url = urlparse(self.path)
            # Only accept actions from the dashboard itself, not from other websites (CSRF).
            origin = self.headers.get("Origin")
            if origin and urlparse(origin).netloc != self.headers.get("Host"):
                self._send(403, b"cross-site request refused", "text/plain")
                return
            try:
                if url.path == "/api/router/pause":
                    if not origin or urlparse(origin).netloc != self.headers.get("Host"):
                        self._send(403, b"router pause requires a same-origin request", "text/plain")
                        return
                    try:
                        length = int(self.headers.get("Content-Length", "0"))
                    except ValueError:
                        self._send(400, b"bad request", "text/plain")
                        return
                    if length < 1 or length > 1024:
                        self._send(413, b"invalid request size", "text/plain")
                        return
                    try:
                        body = json.loads(self.rfile.read(length))
                    except (ValueError, UnicodeDecodeError):
                        self._send(400, b"bad request", "text/plain")
                        return
                    seconds = body.get("seconds") if isinstance(body, dict) else None
                    if isinstance(seconds, bool) or not isinstance(seconds, int) or seconds != 1800:
                        self._send(400, b"seconds must be 1800", "text/plain")
                        return
                    router_watch = board.get_extra("router_watch")
                    if not router_watch:
                        self._json({"error": "Router monitoring is unavailable."}, 503)
                        return
                    router_watch.pause(seconds)
                    paused_until = router_watch.snapshot().get("paused_until")
                    self._json({"paused_until": paused_until, "seconds": seconds})
                elif url.path == "/api/router/resume":
                    if not origin or urlparse(origin).netloc != self.headers.get("Host"):
                        self._send(403, b"router resume requires a same-origin request", "text/plain")
                        return
                    try:
                        length = int(self.headers.get("Content-Length", "0"))
                    except ValueError:
                        self._send(400, b"bad request", "text/plain")
                        return
                    if length < 1 or length > 1024:
                        self._send(413, b"invalid request size", "text/plain")
                        return
                    try:
                        body = json.loads(self.rfile.read(length))
                    except (ValueError, UnicodeDecodeError):
                        self._send(400, b"bad request", "text/plain")
                        return
                    if not isinstance(body, dict) or body.get("confirmed") is not True:
                        self._send(400, b"explicit confirmation required", "text/plain")
                        return
                    router_watch = board.get_extra("router_watch")
                    if not router_watch:
                        self._json({"error": "Router monitoring is unavailable."}, 503)
                        return
                    router_watch.resume()
                    self._json({"paused_until": 0})
                elif url.path == "/api/router/firmware/accept":
                    if not origin or urlparse(origin).netloc != self.headers.get("Host"):
                        self._send(403, b"firmware review requires a same-origin request", "text/plain")
                        return
                    try:
                        length = int(self.headers.get("Content-Length", "0"))
                    except ValueError:
                        self._send(400, b"bad request", "text/plain")
                        return
                    if length < 1 or length > 1024:
                        self._send(413, b"invalid request size", "text/plain")
                        return
                    try:
                        body = json.loads(self.rfile.read(length))
                    except (ValueError, UnicodeDecodeError):
                        self._send(400, b"bad request", "text/plain")
                        return
                    if not isinstance(body, dict) or body.get("confirmed") is not True:
                        self._send(400, b"explicit firmware review confirmation required", "text/plain")
                        return
                    control = board.get_extra("router_control")
                    if not control:
                        self._json({"error": "Router controls are unavailable."}, 503)
                        return
                    try:
                        self._json(control.accept_firmware(body.get("firmware_version"), True))
                    except ControlError as exc:
                        self._json({"error": str(exc)}, 409)
                elif url.path == "/api/devices/presence":
                    if not origin or urlparse(origin).netloc != self.headers.get("Host"):
                        self._send(403, b"LAN presence settings require a same-origin request", "text/plain")
                        return
                    try:
                        length = int(self.headers.get("Content-Length", "0"))
                    except ValueError:
                        self._send(400, b"bad request", "text/plain")
                        return
                    if length < 1 or length > 1024:
                        self._send(413, b"invalid request size", "text/plain")
                        return
                    try:
                        body = json.loads(self.rfile.read(length))
                    except (ValueError, UnicodeDecodeError):
                        self._send(400, b"bad request", "text/plain")
                        return
                    settings = board.get_extra("device_presence_settings")
                    if not settings:
                        self._json({"error": "LAN presence settings are not ready."}, 503)
                        return
                    enabled = body.get("enabled") if isinstance(body, dict) else None
                    if not isinstance(enabled, bool):
                        self._send(400, b"enabled must be true or false", "text/plain")
                        return
                    try:
                        enabled = settings.set_enabled(enabled)
                    except ValueError as exc:
                        self._json({"error": str(exc)}, 409)
                        return
                    board.set_extra("device_presence_enabled", enabled)
                    self._json({"enabled": enabled})
                elif url.path in ("/api/devices/route/preview", "/api/devices/route/apply",
                                "/api/devices/reservation/preview", "/api/devices/reservation/apply",
                                "/api/device-groups/route/preview", "/api/device-groups/route/apply",
                                "/api/device-groups/smart-routing",
                                "/api/device-groups/reservations/preview", "/api/device-groups/reservations/apply",
                                "/api/device-groups/save", "/api/device-groups/delete"):
                    if not origin or urlparse(origin).netloc != self.headers.get("Host"):
                        self._send(403, b"device controls require a same-origin request", "text/plain")
                        return
                    try:
                        length = int(self.headers.get("Content-Length", "0"))
                    except ValueError:
                        self._send(400, b"bad request", "text/plain")
                        return
                    if length < 1 or length > 16384:
                        self._send(413, b"invalid request size", "text/plain")
                        return
                    try:
                        body = json.loads(self.rfile.read(length))
                    except (ValueError, UnicodeDecodeError):
                        self._send(400, b"bad request", "text/plain")
                        return
                    control = board.get_extra("router_control")
                    needs_control = url.path not in ("/api/device-groups/save", "/api/device-groups/delete")
                    if needs_control and not control:
                        self._json({"error": "Router control is not configured."}, 503)
                        return
                    try:
                        reservation_action = "/reservation/" in url.path
                        if url.path == "/api/device-groups/save":
                            if not isinstance(body, dict):
                                raise ValueError("Invalid group request.")
                            name = body.get("name")
                            members = body.get("members")
                            group_id = body.get("id")
                            if (not isinstance(name, str) or not name.strip() or len(name.strip()) > 40
                                    or any(ord(ch) < 32 for ch in name)):
                                raise ValueError("Group name must be 1 to 40 characters.")
                            if (not isinstance(members, list) or len(members) > 128
                                    or any(not isinstance(mac, str) or not normalize_mac(mac) for mac in members)):
                                raise ValueError("Choose up to 128 devices with valid MAC addresses.")
                            normalized = [normalize_mac(m) for m in members]
                            if len(set(normalized)) != len(normalized):
                                raise ValueError("A device can appear only once in a group.")
                            if group_id is not None and (isinstance(group_id, bool) or not isinstance(group_id, int)):
                                raise ValueError("Invalid group id.")
                            result = sqlite.save_device_group(db_path, name.strip(), normalized,
                                                             int(time.time()), group_id)
                        elif url.path == "/api/device-groups/smart-routing":
                            if (not isinstance(body, dict)
                                    or isinstance(body.get("id"), bool)
                                    or not isinstance(body.get("id"), int)
                                    or not isinstance(body.get("enabled"), bool)):
                                raise ValueError("Choose a group and set smart routing on or off.")
                            result = control.set_group_smart_routing(
                                body["id"], body["enabled"], "dashboard")
                        elif url.path == "/api/device-groups/delete":
                            group_id = body.get("id") if isinstance(body, dict) else None
                            if isinstance(group_id, bool) or not isinstance(group_id, int):
                                raise ValueError("Invalid group id.")
                            result = {"deleted": sqlite.delete_device_group(db_path, group_id)}
                        elif url.path.endswith("/preview"):
                            if not control:
                                raise ValueError("Router control is not configured.")
                            if not isinstance(body, dict):
                                raise ValueError("Invalid preview request.")
                            if url.path == "/api/device-groups/reservations/preview":
                                result = control.preview_group_reservations(body.get("id"), "dashboard group")
                            elif url.path.startswith("/api/device-groups/"):
                                result = control.preview_group(body.get("id"), body.get("route"), "dashboard",
                                                               body.get("expiry_seconds", 0))
                            else:
                                result = (control.preview_reservation(body.get("mac"), body.get("name", ""), "dashboard")
                                          if reservation_action else
                                          control.preview(body.get("mac"), body.get("route"), "dashboard",
                                                          body.get("expiry_seconds", 0)))
                        else:
                            if not control:
                                raise ValueError("Router control is not configured.")
                            token = body.get("token") if isinstance(body, dict) else None
                            if not isinstance(token, str) or len(token) > 100:
                                raise ValueError("Invalid confirmation token.")
                            result = (control.apply_group_reservations(token)
                                      if url.path == "/api/device-groups/reservations/apply" else
                                      control.apply_group(token) if url.path.startswith("/api/device-groups/") else
                                      control.apply_reservation(token) if reservation_action else control.apply(token))
                    except ControlError as e:
                        self._json({"error": str(e)}, 409)
                        return
                    except (ValueError, sqlite3.IntegrityError) as e:
                        if isinstance(e, sqlite3.IntegrityError):
                            e = ValueError("That group name is already in use, or a device already belongs to another group.")
                        self._json({"error": str(e)}, 409)
                        return
                    except RouterError as e:
                        self._json({"error": str(e)}, 502)
                        return
                    self._json(result, 200)
                elif url.path in ("/api/devices/pause/preview", "/api/device-groups/pause/preview",
                                  "/api/devices/pause/apply"):
                    if not origin or urlparse(origin).netloc != self.headers.get("Host"):
                        self._send(403, b"Internet controls require a same-origin request", "text/plain")
                        return
                    try:
                        length = int(self.headers.get("Content-Length", "0"))
                    except ValueError:
                        self._send(400, b"bad request", "text/plain")
                        return
                    if length < 1 or length > 16384:
                        self._send(413, b"invalid request size", "text/plain")
                        return
                    try:
                        body = json.loads(self.rfile.read(length))
                    except (ValueError, UnicodeDecodeError):
                        self._send(400, b"bad request", "text/plain")
                        return
                    pause = board.get_extra("pause_control")
                    if not pause:
                        self._json({"error": "Internet pause controls are not configured."}, 503)
                        return
                    if not isinstance(body, dict):
                        self._json({"error": "Invalid Internet control request."}, 400)
                        return
                    try:
                        if url.path == "/api/devices/pause/apply":
                            token = body.get("token")
                            if not isinstance(token, str) or len(token) > 100:
                                raise ValueError("Invalid confirmation token.")
                            if body.get("confirmed") is not True:
                                raise ValueError("Explicit confirmation is required.")
                            result = pause.apply(token, actor="dashboard owner")
                        else:
                            action = body.get("action")
                            if action not in ("pause", "resume"):
                                raise ValueError("Choose pause or resume.")
                            duration = body.get("duration_seconds", 3600)
                            if (isinstance(duration, bool) or not isinstance(duration, int)
                                    or duration not in (0, 900, 3600, 21600)):
                                raise ValueError("Choose a supported pause duration.")
                            remote_ip = self.client_address[0] if self.client_address else None
                            if url.path == "/api/devices/pause/preview":
                                mac = body.get("mac")
                                if not isinstance(mac, str) or not normalize_mac(mac):
                                    raise ValueError("Choose a valid device MAC address.")
                                result = pause.preview(normalize_mac(mac), action=action,
                                                       actor="dashboard owner", duration_seconds=duration,
                                                       management_ip=remote_ip)
                            else:
                                group_id = body.get("id")
                                if isinstance(group_id, bool) or not isinstance(group_id, int):
                                    raise ValueError("Choose a valid device group.")
                                result = pause.preview_group(group_id, action=action,
                                                             actor="dashboard owner", duration_seconds=duration,
                                                             management_ip=remote_ip)
                    except ControlError as exc:
                        self._json({"error": str(exc)}, 409)
                        return
                    except (ValueError, RouterError) as exc:
                        self._json({"error": str(exc)}, 409 if isinstance(exc, ValueError) else 502)
                        return
                    self._json(result, 200)
                elif url.path == "/api/devices/label":
                    try:
                        length = int(self.headers.get("Content-Length", "0"))
                    except ValueError:
                        self._send(400, b"bad request", "text/plain")
                        return
                    if length < 1 or length > 4096:
                        self._send(413, b"invalid request size", "text/plain")
                        return
                    try:
                        body = json.loads(self.rfile.read(length))
                    except (ValueError, UnicodeDecodeError):
                        self._send(400, b"bad request", "text/plain")
                        return
                    mac = normalize_mac(body.get("mac", "")) if isinstance(body, dict) else ""
                    label = body.get("label") if isinstance(body, dict) else None
                    if not mac:
                        self._send(400, b"invalid device MAC", "text/plain")
                        return
                    if not isinstance(label, str) or len(label.strip()) > 48 or any(ord(c) < 32 for c in label):
                        self._send(400, b"invalid device label", "text/plain")
                        return
                    sqlite.set_device_label(db_path, mac, label.strip())
                    self._json({"saved": True})
                elif url.path == "/api/speedtest":
                    mon = board.get_extra("speedtest")
                    if not mon:
                        self._json({"started": False, "reason": "Not ready yet."}, 503)
                        return
                    start = getattr(mon, "start_speedtest", None)
                    why = (start("manual") if callable(start)
                           else mon.tester.try_start("manual"))
                    self._json({"started": why is None, "reason": why}, 202 if why is None else 429)
                else:
                    self._send(404, b"not found", "text/plain")
            except Exception:  # noqa: BLE001
                log.exception("web POST failed: %s", self.path)
                self._send(500, b"internal error", "text/plain")

        def _json(self, obj, code: int = 200) -> None:
            self._send(code, json.dumps(obj).encode(), "application/json")

        def _send(self, code: int, body: bytes, ctype: str, extra_headers: dict | None = None) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Security-Policy", "frame-ancestors 'none'")
            self.send_header("Referrer-Policy", "no-referrer")
            for k, v in (extra_headers or {}).items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):  # keep journald quiet
            pass

    return Handler


def start(host: str, port: int, board: StatusBoard, db_path: str,
          auth_file: str | None = None) -> ThreadingHTTPServer:
    auth = _read_auth_file(auth_file)
    if host not in ("127.0.0.1", "::1", "localhost") and auth is None:
        raise RuntimeError("dashboard auth is required when listening beyond loopback; run tools/web_setup.py")
    server = ThreadingHTTPServer((host, port), make_handler(board, db_path, auth_file))
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, name="web", daemon=True).start()
    log.info("dashboard on http://%s:%d/", host, port)
    return server
