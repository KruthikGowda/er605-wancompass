#!/usr/bin/env python3
"""Serve a synthetic, read-only NetPulse dashboard preview on loopback only.

This helper serves the repository's current dashboard and local fixture APIs. It
does not load NetPulse configuration, credentials, a router client, or Telegram.
Every HTTP mutation is rejected.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]
INDEX = ROOT / "netpulse" / "web" / "static" / "index.html"
DEMO_BANNER = (
    '<div role="status" aria-label="Local demo preview" '
    'style="position:relative;padding:8px 14px;text-align:center;'
    'background:#7c2d12;color:#fff;font:700 14px system-ui;box-shadow:0 2px 8px #0004">'
    'DEMO · LOCAL PREVIEW · synthetic data · read only</div>'
)


def fixture_data(now: float | None = None) -> dict[str, dict]:
    """Return dashboard-shaped synthetic data without reading host configuration."""
    now = time.time() if now is None else float(now)
    macs = [f"02-00-00-00-00-{n:02X}" for n in range(1, 9)]
    names = ["Demo Work laptop", "Demo living room TV", "Demo camera", "Demo phone",
             "Demo printer", "Demo tablet", "Demo speaker", "Demo console"]
    devices = []
    for i, (mac, name) in enumerate(zip(macs, names, strict=True), 1):
        devices.append({
            "mac": mac, "name": name, "label": name, "ip": f"192.0.2.{10 + i}",
            "listed": True, "reserved": True, "protected": False,
            "first_seen": now - 30 * 86400, "last_seen": now - i * 300,
            "lease": "3h 12m", "group": "Example Work Group",
            "route": "AUTO", "route_expires_at": None, "np_rule_route": "AUTO",
            "np_rule_checked_at": now - 60, "np_rule_stale": False, "np_rule_drift": False,
            "lan_presence": {"state": "replying", "checked_at": now - 30,
                             "last_reply_at": now - 45, "misses": 0},
        })
    wans = [
        {"name": "WAN1", "label": "Demo Fiber", "state": "HEALTHY", "state_since": now - 7200,
         "score": 96.4, "loss_pct": 0.0, "rtt_ms": 12.8, "jitter_ms": 1.4,
         "availability_pct": 100.0, "rtt_ratio": 1.0, "why": [], "errors": [],
         "connectivity": None,
         "targets": [{"target": ip, "rtt_ms": value, "loss_pct": 0.0}
                     for ip, value in zip(("1.1.1.1", "8.8.8.8", "9.9.9.9"), (12.8, 14.1, 11.4), strict=True)]},
        {"name": "WAN2", "label": "Demo Backup", "state": "OFFLINE", "state_since": now - 420,
         "score": 0.0, "loss_pct": 100.0, "rtt_ms": None, "jitter_ms": None,
         "availability_pct": 0.0, "rtt_ratio": None, "why": ["No probe target replied"], "errors": [],
         "connectivity": None,
         "targets": [{"target": ip, "rtt_ms": None, "loss_pct": 100.0}
                     for ip in ("1.1.1.1", "8.8.8.8", "9.9.9.9")]},
    ]
    status = {
        "version": "demo", "mode": "monitor", "updated": now,
        "targets": ["1.1.1.1", "8.8.8.8", "9.9.9.9"], "muted_until": 0,
        "headline": {"level": "DEGRADED", "text": "Demo Fiber is healthy; Demo Backup is down"},
        "alert_policy": {"telegram_enabled": False, "device_activity_notifications": False,
                         "quiet_start": "23:00", "quiet_end": "07:00",
                         "suppressed_since_start": {"mute": 0, "quiet_hours": 0, "rate_limited": 0}},
        "decision": None, "wans": wans,
        "router": {"ok": True, "model": "ER605 · synthetic", "firmware_version": "demo fixture",
                   "checked_at": now - 90, "next_check": now + 510,
                   "links_max_age_seconds": 1200, "links": {
                       "WAN1": {"up": True, "interface_up": True, "ip": "192.0.2.2"},
                       "WAN2": {"up": False, "interface_up": True, "ip": "192.0.2.3"}},
                   "clients": 8, "control": {"enabled": True,
                                                "reason": "Demo controls shown for layout review; all writes are denied."}},
    }
    groups = [{
        "id": 1, "name": "Example Work Group", "members": macs, "reserved_count": 8,
        "blocked_count": 0, "route": "AUTO", "expiry_mixed": False,
        "suggested_wan": {"wan": "WAN1", "reason": "healthy-link probe latency", "rtt_ms": 12.8,
                          "loss_pct": 0.0},
        "monitor_advice": None, "route_readback": "matches", "route_drift_count": 0,
        "route_unknown_count": 0, "smart_routing_enabled": False, "smart_last_action_at": None,
    }]
    paused = [{
        "mac": macs[1], "ip": "192.0.2.12", "label": names[1], "group_id": 1,
        "status": "paused", "expires_at": now + 3600,
    }, {
        "mac": macs[2], "ip": "192.0.2.13", "label": names[2], "group_id": 1,
        "status": "error", "expires_at": now + 900,
    }]
    devices_payload = {
        "configured": True, "ready": True, "updated": now - 90,
        "inventory_stale": False, "inventory_age_seconds": 90, "scan_interval_seconds": 600,
        "missing_confirmation_scans": 3, "syslog": {"enabled": False},
        "presence_enabled": True, "presence_available": True,
        "presence_probe_interval_seconds": 60, "presence_probe_cycle_seconds": 60,
        "presence_inventory_supported": True, "presence_confirm_misses": 3,
        "control": {"enabled": True, "reason": "Demo controls shown for layout review; all writes are denied."},
        "groups": groups, "recent_speeds": {}, "recent_speed_comparison": None,
        "group_history": [], "devices": devices, "route_history": [],
    }
    return {
        "/api/status": status,
        "/api/devices": devices_payload,
        "/api/devices/paused": {"state": {"enabled": True, "configured": True,
                                                "cleanup_enabled": True,
                                                "reason": "Synthetic demo controls; router changes are disabled."},
                                 "records": paused},
        "/api/control": {"enabled": True, "reason": "Demo controls shown for layout review; all writes are denied."},
        "/api/device-groups": {"groups": groups},
        "/api/system": {"enabled": True, "health": {
            "stale": False, "age_seconds": 30, "disk_free_pct": 62.0,
            "disk_low": False, "memory_available_pct": 48.0, "memory_available_mb": 1760,
            "temperature_c": 48.2, "load_per_core": 0.12,
            "undervoltage": False, "undervoltage_occurred": False,
            "backup": {"enabled": False}, "acl_recovery": {"status": "unavailable"},
        }},
        "/api/history": {"hours": 1, "bucket": 60, "target": "", "points": [], "state_minutes": []},
        "/api/events": [],
        "/api/decisions": {"total": 0, "recommendations": [], "omitted_recommendations": 0},
        "/api/speedtests": {"running": False, "results": [], "usual": {},
                             "plans": {"WAN1": 500, "WAN2": 100},
                             "data_usage": {"budget_enabled": False, "used_mb": 0, "next_run_mb": 0}},
        "/api/router": {"router": status["router"]},
    }


class PreviewServer:
    """Context-managed loopback server and temporary, unused demo SQLite file."""

    def __init__(self, port: int = 0):
        self._temporary = TemporaryDirectory(prefix="netpulse-dashboard-demo-")
        self.db_path = Path(self._temporary.name) / "demo.sqlite3"
        db = sqlite3.connect(self.db_path)
        try:
            db.execute("CREATE TABLE preview_marker (created_at INTEGER NOT NULL)")
            db.execute("INSERT INTO preview_marker VALUES (?)", (int(time.time()),))
            db.commit()
        finally:
            db.close()
        self.fixture = fixture_data()
        self._html = INDEX.read_text(encoding="utf-8").replace(
            "<body>", "<body>" + DEMO_BANNER, 1).encode("utf-8")
        owner = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, _format, *_args):
                return

            def _send(self, code: int, body: bytes, content_type: str):
                self.send_response(code)
                self.send_header("Content-Type", content_type)
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                path = urlparse(self.path).path
                if path in ("/", "/index.html"):
                    self._send(200, owner._html, "text/html; charset=utf-8")
                    return
                if path == "/api/report.csv":
                    self._send(200, b"timestamp,wan,state\nDemo,WAN1,HEALTHY\n",
                               "text/csv; charset=utf-8")
                    return
                if path in owner.fixture:
                    body = json.dumps(owner.fixture[path], separators=(",", ":")).encode("utf-8")
                    self._send(200, body, "application/json; charset=utf-8")
                    return
                if path == "/report":
                    self._send(200, "<!doctype html><title>Local demo report</title><p>DEMO · synthetic data</p>".encode("utf-8"),
                               "text/html; charset=utf-8")
                    return
                self._send(404, b"not found", "text/plain; charset=utf-8")

            def _deny_write(self):
                body = json.dumps({"error": "Local demo only; no device or router change was made."}).encode("utf-8")
                self._send(503, body, "application/json; charset=utf-8")

            def do_POST(self):
                path = urlparse(self.path).path
                if path not in ("/api/devices/pause/preview", "/api/device-groups/pause/preview"):
                    self._deny_write()
                    return
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    if length < 1 or length > 16384:
                        raise ValueError
                    body = json.loads(self.rfile.read(length))
                    if not isinstance(body, dict) or body.get("action") not in ("pause", "resume"):
                        raise ValueError
                except (ValueError, UnicodeDecodeError):
                    self._send(400, b"invalid read-only preview request", "text/plain; charset=utf-8")
                    return
                action = body["action"]
                duration_seconds = body.get("duration_seconds", 3600)
                duration_names = {0: "Until resumed", 900: "15 minutes", 3600: "1 hour", 21600: "6 hours"}
                if (isinstance(duration_seconds, bool) or not isinstance(duration_seconds, int)
                        or duration_seconds not in duration_names):
                    self._send(400, b"invalid demo duration", "text/plain; charset=utf-8")
                    return
                if path == "/api/devices/pause/preview":
                    mac = body.get("mac")
                    device = next((d for d in owner.fixture["/api/devices"]["devices"]
                                   if d["mac"] == mac), None)
                    if not device:
                        self._send(400, b"unknown demo device", "text/plain; charset=utf-8")
                        return
                    preview = {"token": "demo-read-only", "action": action,
                               "device": device["label"], "mac": device["mac"], "ip": device["ip"],
                               "members": [{"mac": device["mac"], "name": device["label"], "ip": device["ip"]}],
                               "duration_seconds": duration_seconds,
                               "expiry_label": duration_names[duration_seconds] if action == "pause" else "Resume now",
                               "count": 1, "effect": "DEMO ONLY. No router change will occur."}
                else:
                    group_id = body.get("id")
                    group = next((g for g in owner.fixture["/api/devices"]["groups"]
                                  if not isinstance(group_id, bool) and isinstance(group_id, int)
                                  and g["id"] == group_id), None)
                    if not group:
                        self._send(400, b"unknown demo group", "text/plain; charset=utf-8")
                        return
                    devices = {d["mac"]: d for d in owner.fixture["/api/devices"]["devices"]}
                    target_macs = group["members"]
                    if action == "resume":
                        saved = {r["mac"] for r in owner.fixture["/api/devices/paused"]["records"]}
                        target_macs = [mac for mac in target_macs if mac in saved]
                    members = [{"mac": mac, "name": devices[mac]["label"], "ip": devices[mac]["ip"]}
                               for mac in target_macs]
                    preview = {"token": "demo-read-only", "action": action,
                               "group": group["name"], "members": members,
                               "duration_seconds": duration_seconds,
                               "expiry_label": duration_names[duration_seconds] if action == "pause" else "Resume now",
                               "count": len(members), "effect": "DEMO ONLY. No router change will occur."}
                self._send(200, json.dumps(preview, separators=(",", ":")).encode("utf-8"),
                           "application/json; charset=utf-8")

            do_PUT = _deny_write
            do_PATCH = _deny_write
            do_DELETE = _deny_write

        self.server = ThreadingHTTPServer(("127.0.0.1", int(port)), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       name="netpulse-dashboard-preview", daemon=True)
        self.thread.start()

    @property
    def url(self) -> str:
        host, port = self.server.server_address[:2]
        return f"http://{host}:{port}/"

    def close(self):
        if getattr(self, "server", None):
            self.server.shutdown()
            self.server.server_close()
            self.thread.join(timeout=3)
            self.server = None
        if getattr(self, "_temporary", None):
            self._temporary.cleanup()
            self._temporary = None

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=0,
                        help="loopback port (0 chooses an ephemeral port; default: 0)")
    args = parser.parse_args(argv)
    if not 0 <= args.port <= 65535:
        parser.error("port must be from 0 to 65535")
    preview = PreviewServer(args.port)
    print(f"Local demo dashboard: {preview.url}", flush=True)
    try:
        while preview.thread.is_alive():
            preview.thread.join(timeout=1)
    except KeyboardInterrupt:
        pass
    finally:
        preview.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
