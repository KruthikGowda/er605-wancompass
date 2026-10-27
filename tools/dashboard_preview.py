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
from urllib.parse import parse_qs, urlparse


ROOT = Path(__file__).resolve().parents[1]
CAP_PRESETS = {f"bandwidth_wan2_{rate}m": rate for rate in (2, 5, 10, 25, 50)}
CAP_PRESETS["bandwidth_wan2_remove"] = None
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
            "listed": True, "reserved": i != 4, "protected": False,
            "first_seen": now - 30 * 86400, "last_seen": now - i * 300,
            "lease": "3h 12m", "group": "Example Work Group",
            "route": "WAN1_ONLY" if i == 1 else "WAN2_ONLY" if i == 2 else "AUTO",
            "route_expires_at": None,
            "np_rule_route": "WAN1_ONLY" if i == 1 else "WAN2_ONLY" if i == 2 else "AUTO",
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
        "id": 1, "name": "Example Work Group", "members": macs, "reserved_count": 7,
        "blocked_count": 1, "route": "MIXED", "expiry_mixed": False,
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
    traffic_devices = [{
        "mac": device["mac"], "ip": device["ip"],
        "available": i != 7, "stale": i == 7,
        "rx_mbps": round(0.08 * i, 3) if i != 7 else 0.56,
        "tx_mbps": round(0.025 * i, 3) if i != 7 else 0.175,
        "reason": "" if i != 7 else "Router refresh is temporarily unavailable.",
    } for i, device in enumerate(devices, 1)]
    traffic = {
        "enabled": True, "available": True, "sampled_at": now - 2,
        "sample_seconds": 2.0, "age_seconds": 1.2,
        "source": "ER605 router RX/TX per-IP byte-counter deltas",
        "reason": "", "devices": traffic_devices,
    }
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
        "/api/devices/traffic": traffic,
        "/api/actions": {"control": {"enabled": True,
                                            "reason": "DEMO ONLY. Synthetic controls; no router changes are made."},
                          "actions": [
                              {"id": "auto", "label": "Auto balance", "enabled": True},
                              {"id": "prefer_wan1", "label": "Prefer Demo Fiber", "enabled": True},
                              {"id": "prefer_wan2", "label": "Prefer Demo Backup", "enabled": True},
                              {"id": "pause", "label": "Pause Internet", "enabled": True},
                              {"id": "resume", "label": "Resume Internet", "enabled": True},
                              {"id": "only_wan1", "label": "Only Demo Fiber · no fallback", "enabled": True},
                              {"id": "only_wan2", "label": "Only Demo Backup · no fallback", "enabled": True},
                          ],
                          "bandwidth_options": [
                              {"id": action, "label": f"WAN 2 · {rate} Mbps per device" if rate else "Remove WAN 2 limits",
                               "enabled": True} for action, rate in CAP_PRESETS.items()],
                          "bandwidth_caps": []},
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


def action_preview_fixture(payload: object, fixture: dict[str, dict]) -> dict:
    """Build a synthetic combined-action preview using fixture identities only."""
    if not isinstance(payload, dict):
        raise ValueError("Request must be a JSON object.")
    action = payload.get("action")
    if not isinstance(action, str) or action not in {
            "auto", "prefer_wan1", "prefer_wan2", "pause", "resume", "only_wan1", "only_wan2", *CAP_PRESETS}:
        raise ValueError("Choose a supported demo action.")
    has_macs, has_group = "macs" in payload, "group_id" in payload
    if has_macs == has_group:
        raise ValueError("Choose devices or one device group.")

    duration_seconds = payload.get("duration_seconds", 3600 if action == "pause" else 0)
    if isinstance(duration_seconds, bool) or not isinstance(duration_seconds, int):
        raise ValueError("Choose a valid demo duration.")
    if action in CAP_PRESETS:
        allowed_durations = {0}
    elif action in ("pause", "resume"):
        allowed_durations = {0, 900, 3600, 21600}
    else:
        allowed_durations = {0, 3600, 21600, 86400, 604800}
    if duration_seconds not in allowed_durations:
        raise ValueError("Choose a valid demo duration.")
    if action == "resume":
        duration_seconds = 0

    devices_payload = fixture["/api/devices"]
    devices_by_mac = {device["mac"]: device for device in devices_payload["devices"]
                      if not device.get("protected")}
    if has_group:
        group_id = payload.get("group_id")
        if isinstance(group_id, bool) or not isinstance(group_id, int):
            raise ValueError("Choose a valid demo group.")
        group = next((item for item in devices_payload["groups"] if item["id"] == group_id), None)
        if not group:
            raise ValueError("Unknown demo group.")
        selected_macs = list(group["members"])
    else:
        group = None
        selected_macs = payload.get("macs")
        if (not isinstance(selected_macs, list) or not 1 <= len(selected_macs) <= 128
                or any(not isinstance(mac, str) or mac not in devices_by_mac for mac in selected_macs)
                or len(set(selected_macs)) != len(selected_macs)):
            raise ValueError("Select known demo devices only.")

    paused = {record["mac"]: record for record in fixture["/api/devices/paused"]["records"]
              if record.get("status") != "resumed"}
    if action == "resume":
        selected_macs = [mac for mac in selected_macs if mac in paused]
        if not selected_macs:
            raise ValueError("No selected demo device has a saved pause to resume.")
    elif action == "pause" and any(mac in paused for mac in selected_macs):
        raise ValueError("A selected demo device already has a saved pause; review resume instead.")

    if any(mac not in devices_by_mac for mac in selected_macs):
        raise ValueError("The demo group contains an unavailable device.")
    route_values = {"auto": "AUTO", "prefer_wan1": "WAN1", "prefer_wan2": "WAN2",
                    "only_wan1": "WAN1_ONLY", "only_wan2": "WAN2_ONLY"}
    wan_names = {"WAN1": "Demo Fiber", "WAN2": "Demo Backup"}
    targets = []
    for mac in selected_macs:
        device = devices_by_mac[mac]
        current = device.get("route", "AUTO")
        if action == "resume":
            current = "Paused (IPv4)"
        targets.append({
            "mac": mac,
            "ip": device["ip"],
            "name": device["label"],
            "current": current,
            "saved_current": current,
            "reservation_needed": not bool(device.get("reserved")),
        })

    reservation_count = sum(target["reservation_needed"] for target in targets)
    if action in CAP_PRESETS:
        rate = CAP_PRESETS[action]
        effect = (f"DEMO ONLY. Limit each selected device on WAN2 to {rate} Mbps download and upload. "
                  "Other WANs are not limited. No router change will occur." if rate else
                  "DEMO ONLY. Remove the selected WAN2 bandwidth limits. No router change will occur.")
    elif action == "pause":
        duration_name = {0: "until resumed", 900: "15 minutes", 3600: "1 hour", 21600: "6 hours"}[duration_seconds]
        effect = (f"DEMO ONLY. Pause the IPv4 Internet path for {duration_name}; IPv6 and LAN protection are not validated. "
                  "No router change will occur.")
    elif action == "resume":
        effect = "DEMO ONLY. Review removal of saved IPv4 Internet pause state. No router change will occur."
    elif action.startswith("only_"):
        wan = "WAN1" if action.endswith("wan1") else "WAN2"
        effect = (f"DEMO ONLY. Use only {wan_names[wan]}; no WAN fallback is configured and the device may lose Internet "
                  "when that WAN is offline. No router change will occur.")
    elif action == "auto":
        effect = "DEMO ONLY. Return selected devices to normal ER605 load balancing. No router change will occur."
    else:
        wan = "WAN1" if action.endswith("wan1") else "WAN2"
        effect = (f"DEMO ONLY. Prefer {wan_names[wan]}; the router's WAN online detection remains available for fallback. "
                  "No router change will occur.")

    result = {
        "token": "demo-read-only",
        "action": action,
        "members": targets,
        "count": len(targets),
        "reservation_count": reservation_count,
        "duration_seconds": duration_seconds,
        "effect": effect,
    }
    if action in route_values:
        result["route"] = route_values[action]
        result["expiry_label"] = "Until changed" if not duration_seconds else str(duration_seconds)
    if group:
        result["group"] = group["name"]
    else:
        result["target"] = targets[0]["name"] if len(targets) == 1 else f"{len(targets)} selected devices"
    return result


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
                parsed = urlparse(self.path)
                path = parsed.path
                if path in ("/", "/index.html"):
                    html = INDEX.read_text(encoding="utf-8").replace("<body>", "<body>" + DEMO_BANNER, 1)
                    self._send(200, html.encode("utf-8"), "text/html; charset=utf-8")
                    return
                if path == "/api/report.csv":
                    self._send(200, b"timestamp,wan,state\nDemo,WAN1,HEALTHY\n",
                               "text/csv; charset=utf-8")
                    return
                if path == "/api/devices/traffic":
                    query = parse_qs(parsed.query)
                    has_group = "group_id" in query
                    has_macs = "mac" in query
                    if has_group == has_macs:
                        self._send(400, b'{"error":"Choose devices or one group."}',
                                   "application/json; charset=utf-8")
                        return
                    devices = owner.fixture["/api/devices"]["devices"]
                    if has_group:
                        group_ids = query.get("group_id", [])
                        if len(group_ids) != 1 or not group_ids[0].isdigit():
                            self._send(400, b'{"error":"Choose a valid demo group."}',
                                       "application/json; charset=utf-8")
                            return
                        group_id = int(group_ids[0])
                        group = next((item for item in owner.fixture["/api/devices"]["groups"]
                                      if item["id"] == group_id), None)
                        if group is None:
                            self._send(400, b'{"error":"Unknown demo group."}',
                                       "application/json; charset=utf-8")
                            return
                        selected = list(group["members"])
                    else:
                        values = query.get("mac", [])
                        if len(values) != 1:
                            self._send(400, b'{"error":"Choose demo devices."}',
                                       "application/json; charset=utf-8")
                            return
                        selected = [part.strip().replace(":", "-").upper()
                                    for part in values[0].split(",") if part.strip()]
                        known = {device["mac"] for device in devices if not device.get("protected")}
                        if (not 1 <= len(selected) <= 128 or len(set(selected)) != len(selected)
                                or any(mac not in known for mac in selected)):
                            self._send(400, b'{"error":"Choose known demo devices only."}',
                                       "application/json; charset=utf-8")
                            return
                    by_mac = {item["mac"]: item for item in owner.fixture["/api/devices/traffic"]["devices"]}
                    rows = [by_mac[mac] for mac in selected if mac in by_mac]
                    base = owner.fixture["/api/devices/traffic"]
                    result = {key: value for key, value in base.items() if key != "devices"}
                    result["devices"] = rows
                    result["available"] = any(item["available"] for item in rows)
                    if not result["available"]:
                        result["reason"] = "No selected demo device has a current traffic sample."
                    self._send(200, json.dumps(result, separators=(",", ":")).encode("utf-8"),
                               "application/json; charset=utf-8")
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
                if path == "/api/actions/preview":
                    try:
                        length = int(self.headers.get("Content-Length", "0"))
                        if length < 1 or length > 16384:
                            raise ValueError("Request size is invalid.")
                        body = json.loads(self.rfile.read(length))
                    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
                        payload = json.dumps({"error": "Invalid read-only demo preview request."}).encode("utf-8")
                        self._send(400, payload, "application/json; charset=utf-8")
                        return
                    try:
                        preview = action_preview_fixture(body, owner.fixture)
                    except (ValueError, TypeError, KeyError) as exc:
                        payload = json.dumps({"error": str(exc)}).encode("utf-8")
                        self._send(400, payload, "application/json; charset=utf-8")
                        return
                    self._send(200, json.dumps(preview, separators=(",", ":")).encode("utf-8"),
                               "application/json; charset=utf-8")
                    return
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
