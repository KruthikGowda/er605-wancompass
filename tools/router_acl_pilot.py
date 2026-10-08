#!/usr/bin/env python3
"""Bounded one-device ER605 IPv4 LAN-to-WAN ACL pilot.

The pilot is deliberately separate from household controls. It uses one existing DHCP
reservation, refuses any pre-existing ACL rules, makes no route changes, and removes its
own temporary ACL row in a finally block, with a separate Pi process armed to clean up if
the runner exits unexpectedly. `--apply` requires the selected phone to pass a live IPv4
Internet and Pi LAN baseline before the app service is stopped and the exact ACL row is added.
"""

from __future__ import annotations

import argparse
import hmac
import ipaddress
import json
import math
import os
import re
import secrets
import sys
import subprocess
import stat
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
import socket

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from netpulse.devices.identity import MAC_RE, normalize_mac
from netpulse.router.er605 import (ACL_PILOT_STATES, ER605Client, RouterError,
                                   acl_pilot_effective_match)
from netpulse.router.control import RouterControl
from netpulse.router.watch import RouterWatch
from netpulse.storage import sqlite as storage_sqlite
from tools.router_firewall_discover import summarize_acl_order
from netpulse.config import load, load_router_credentials


CONFIG = "/etc/netpulse/config.toml"
REVIEWED_DEVICES_FILE = Path("/etc/netpulse/acl-pilot-devices.json")
MAX_REVIEWED_DEVICES_BYTES = 65536
EXPECTED_ROUTE = "WAN1"
EXPECTED_MODE = "Priority"
PILOT_FIRMWARE = "2.3.3 Build 20251029 Rel.18054"
ACL_FORM = ("access_ctl", "acl_inner")
ACL_STATE_VALUES: tuple[str, ...] = ACL_PILOT_STATES
MAX_PILOT_SECONDS = 180
DEFAULT_PILOT_SECONDS = 90
MAX_WATCHDOG_SECONDS = 600
MAX_WATCHDOG_RECORD_BYTES = 8192
PROBE_PATH = "/probe/"
IPIFY_IPV4 = "https://api4.ipify.org?format=json"
NAME_RE = re.compile(r"NP_TEST_P_[A-F0-9]{32}\Z")


class PilotError(ValueError):
    """The live endpoint pilot cannot continue safely."""


def exact_mac(value: object) -> str | None:
    value = str(value or "").strip().upper().replace(":", "-")
    return value if MAC_RE.fullmatch(value) else None


def _unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise PilotError("Reviewed-device file contains duplicate keys.")
        result[key] = value
    return result


def load_reviewed_devices(path: Path = REVIEWED_DEVICES_FILE) -> dict[str, str]:
    """Load explicit private MAC-to-IPv4 approvals without exposing file contents."""
    try:
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise PilotError("Reviewed-device file must be a regular private file.")
        _validate_root_private_metadata(info, 0o600, "Reviewed-device file")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(fd)
            if (not stat.S_ISREG(opened.st_mode)
                    or getattr(info, "st_ino", None) != getattr(opened, "st_ino", None)
                    or getattr(info, "st_dev", None) != getattr(opened, "st_dev", None)):
                raise PilotError("Reviewed-device file changed while it was being opened.")
            _validate_root_private_metadata(opened, 0o600, "Reviewed-device file")
            chunks = bytearray()
            while len(chunks) <= MAX_REVIEWED_DEVICES_BYTES:
                part = os.read(fd, min(4096, MAX_REVIEWED_DEVICES_BYTES + 1 - len(chunks)))
                if not part:
                    break
                chunks.extend(part)
            if len(chunks) > MAX_REVIEWED_DEVICES_BYTES:
                raise PilotError("Reviewed-device file exceeds its size limit.")
        finally:
            os.close(fd)
        value = json.loads(chunks.decode("utf-8"), object_pairs_hook=_unique_json_object)
    except PilotError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise PilotError("Reviewed-device file is missing or invalid; no device is eligible.") from None
    if not isinstance(value, dict) or not value:
        raise PilotError("Reviewed-device file must contain at least one explicit approval.")
    approved = {}
    private_ranges = (ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("172.16.0.0/12"),
                      ipaddress.ip_network("192.168.0.0/16"))
    for mac, address in value.items():
        canonical_mac = exact_mac(mac)
        try:
            ip = ipaddress.IPv4Address(address)
        except (ipaddress.AddressValueError, TypeError):
            raise PilotError("Reviewed-device file contains an invalid approval; no device is eligible.") from None
        if (canonical_mac != mac or not isinstance(address, str) or str(ip) != address
                or not any(ip in network for network in private_ranges)):
            raise PilotError("Reviewed-device file contains an invalid approval; no device is eligible.")
        approved[canonical_mac] = str(ip)
    return approved


def resolve_candidate(selector: str, clients) -> tuple[str, str, str]:
    """Resolve a unique exact lease by IP, MAC, or exact case-insensitive name."""
    selector = str(selector or "").strip()
    rows = clients if isinstance(clients, list) else []
    try:
        ip = str(ipaddress.ip_address(selector))
        matches = [r for r in rows if isinstance(r, dict)
                   and str(r.get("ipaddr", r.get("ip", ""))) == ip]
    except ValueError:
        mac = exact_mac(selector)
        if mac:
            matches = [r for r in rows if isinstance(r, dict)
                       and exact_mac(r.get("macaddr", r.get("mac"))) == mac]
        else:
            matches = [r for r in rows if isinstance(r, dict)
                       and str(r.get("name", "")).strip().casefold() == selector.casefold()]
    if len(matches) != 1:
        raise PilotError("The selector must identify exactly one current ER605 lease.")
    row = matches[0]
    ip = str(ipaddress.ip_address(str(row.get("ipaddr", row.get("ip", "")))))
    mac = exact_mac(row.get("macaddr", row.get("mac")))
    name = str(row.get("name", "")).strip()
    if not mac or not ipaddress.ip_address(ip).is_private:
        raise PilotError("The lease is not a private IPv4 client with a valid MAC.")
    return name, mac, ip


def _named(rows, name: str) -> list[dict]:
    return [row for row in rows if isinstance(row, dict) and row.get("name") == name] \
        if isinstance(rows, list) else []


def validate_empty_acl(response) -> None:
    """Require a uniquely readable, explicitly empty ACL response."""
    summary = summarize_acl_order(response)
    if not summary.get("readable") or summary.get("count") != 0:
        raise PilotError("The ACL snapshot is unreadable, ambiguous, or has existing rules.")


def validate_preflight(*, selector: str, expected_mac: str, expected_ip: str,
                       clients, reservations, ip_entries, ip_groups, policy_routes,
                       acl_response, controls_enabled: bool, kill_switch_active: bool,
                       firmware_version: str | None, accepted_firmware: str | None,
                       pending_firmware: str | None, status_checked_at: float | None,
                       uptime: int | None, uptime_at: float | None, now: float,
                       pi_addresses=()) -> dict:
    """Validate all exact live facts required before the endpoint is invited to probe."""
    name, mac, ip = resolve_candidate(selector, clients)
    expected_mac = exact_mac(expected_mac)
    if mac != expected_mac or ip != str(ipaddress.IPv4Address(expected_ip)):
        raise PilotError("The live lease does not match the reviewed phone MAC/IP.")
    if any(str(address) == ip for address in pi_addresses):
        raise PilotError("The selected endpoint address belongs to the Pi.")
    reservations_match = [row for row in reservations if isinstance(row, dict)
                         and exact_mac(row.get("mac", row.get("macaddr"))) == mac
                         and str(row.get("ip", row.get("ipaddr", ""))) == ip
                         and str(row.get("enable", "")).strip().lower() in ("1", "on", "true", "enabled")] \
        if isinstance(reservations, list) else []
    if len(reservations_match) != 1:
        raise PilotError("The selected lease must have exactly one matching enabled DHCP reservation.")

    suffix = mac.replace("-", "")
    entry_name, group_name, route_name = (f"NP_I_{suffix}", f"NP_G_{suffix}", f"NP_R_{suffix}")
    entries, groups, routes = (_named(ip_entries, entry_name), _named(ip_groups, group_name),
                                _named(policy_routes, route_name))
    if len(entries) != 1 or entries[0].get("scope") != f"{ip}-{ip}":
        raise PilotError("The existing NetPulse address object is missing or does not match the exact /32.")
    if len(groups) != 1 or groups[0].get("rule_scope") != [entry_name]:
        raise PilotError("The existing NetPulse device group is missing or ambiguous.")
    if len(routes) != 1:
        raise PilotError("The selected device must have exactly one existing NetPulse route row.")
    route = routes[0]
    if (route.get("state") != "on" or route.get("interfaces") != EXPECTED_ROUTE
            or route.get("mode") != EXPECTED_MODE or route.get("src_ipgroup") != group_name
            or route.get("dst_ipgroup") != "IPGROUP_ANY"):
        raise PilotError("The selected device must already have its verified WAN1 Priority route; no route changes are made.")

    validate_empty_acl(acl_response)
    if not controls_enabled or kill_switch_active:
        raise PilotError("Manual router controls must be enabled and the local kill switch must be off.")
    if (firmware_version != PILOT_FIRMWARE or accepted_firmware != PILOT_FIRMWARE
            or firmware_version != accepted_firmware
            or pending_firmware):
        raise PilotError("The current router firmware must match the explicitly accepted version with no pending review.")
    if (status_checked_at is None or now < status_checked_at or now - status_checked_at > 300
            or uptime_at is None or now < uptime_at or now - uptime_at > 120
            or uptime is None or uptime < 300):
        raise PilotError("Fresh authenticated router status and settled uptime are required.")
    return {"device": name[:64], "mac_suffix": mac[-8:], "ip_last_octet": ip.rsplit(".", 1)[1],
            "route": EXPECTED_ROUTE, "mode": EXPECTED_MODE, "acl_rule_count": 0,
            "firmware_version": firmware_version}


def new_rule_name() -> str:
    return "NP_TEST_P_" + secrets.token_hex(16).upper()


def build_acl_row(mac: str, name: str, states: tuple[str, ...] | None = None) -> dict:
    """Build only the one-device IPv4 Block/ALL/LAN→WAN shape.

    The authenticated 2.3.3 Build 20251029 page confirms the four lowercase values
    and serializes this multi-select as an array.
    """
    mac = exact_mac(mac)
    if not mac or not NAME_RE.fullmatch(name):
        raise PilotError("Invalid temporary ACL identity.")
    if states is None:
        states = ACL_STATE_VALUES
    if states is None:
        raise PilotError("Exact ER605 ACL connection-state values are not yet verified; writes are disabled.")
    if not isinstance(states, tuple) or len(states) != 4 or any(not isinstance(v, str) or not v for v in states):
        raise PilotError("Four verified ACL connection-state values are required.")
    if states != ACL_STATE_VALUES:
        raise PilotError("ACL connection-state values must exactly match the verified firmware values.")
    return {"name": name, "policy": "DROP", "service": "ALL", "iptype": "ipv4",
            "zone": "LAN", "is_src": "ipgroup", "src": f"NP_G_{mac.replace('-', '')}",
            "is_dst": "ipgroup", "dest": "IPGROUP_ANY", "time": "Any", "states": list(states),
            "position": "", "flag": "1", "user": "1"}


class EndpointProbe:
    """Short-lived Pi LAN page that proves phone-originated IPv4 and LAN heartbeat."""

    def __init__(self, bind_host: str, candidate_ip: str, ttl_seconds: int = 480):
        if not ipaddress.IPv4Address(bind_host).is_private:
            raise PilotError("The probe server must bind to the Pi's private IPv4 LAN address.")
        self.candidate_ip = str(ipaddress.IPv4Address(candidate_ip))
        self.token = secrets.token_urlsafe(24)
        self.expires_at = time.time() + min(max(int(ttl_seconds), 60), 600)
        self.phase = "baseline"
        self.reports: dict[str, dict] = {}
        self._condition = threading.Condition()
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def setup(self):
                super().setup()
                self.connection.settimeout(3)

            def log_message(self, _format, *args):
                return

            def _authorized(self, parsed):
                tokens = parse_qs(parsed.query).get("t", [])
                return (self.client_address[0] == owner.candidate_ip
                        and len(tokens) == 1
                        and hmac.compare_digest(tokens[0], owner.token)
                        and time.time() < owner.expires_at)

            def _send(self, status, body, content_type):
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                parsed = urlsplit(self.path)
                if not self._authorized(parsed):
                    self._send(404, b"not found", "text/plain; charset=utf-8")
                    return
                if parsed.path == PROBE_PATH:
                    body = _probe_html(owner.token).encode("utf-8")
                    self._send(200, body, "text/html; charset=utf-8")
                elif parsed.path == "/state":
                    with owner._condition:
                        payload = json.dumps({"phase": owner.phase,
                                              "expires_in": max(0, int(owner.expires_at - time.time()))})
                    self._send(200, payload.encode(), "application/json")
                else:
                    self._send(404, b"not found", "text/plain; charset=utf-8")

            def do_POST(self):
                parsed = urlsplit(self.path)
                if parsed.path != "/report" or not self._authorized(parsed):
                    self._send(404, b"not found", "text/plain; charset=utf-8")
                    return
                if self.headers.get("Origin") != f"http://{bind_host}:{owner.server.server_address[1]}":
                    self._send(403, b"forbidden", "text/plain; charset=utf-8")
                    return
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    if length < 2 or length > 512:
                        raise ValueError
                    data = json.loads(self.rfile.read(length))
                    if not isinstance(data, dict):
                        raise ValueError
                except (TypeError, ValueError, json.JSONDecodeError):
                    self._send(400, b"bad request", "text/plain; charset=utf-8")
                    return
                with owner._condition:
                    if (data.get("phase") != owner.phase
                            or type(data.get("internet_ipv4_ok")) is not bool
                            or data.get("lan_ok") is not True or owner.phase in owner.reports):
                        self._send(409, b"unexpected report", "text/plain; charset=utf-8")
                        return
                    owner.reports[owner.phase] = {"internet_ipv4_ok": data["internet_ipv4_ok"],
                                                  "lan_ok": True}
                    owner._condition.notify_all()
                self._send(204, b"", "text/plain")

            def do_OPTIONS(self):
                self._send(405, b"method not allowed", "text/plain; charset=utf-8")

        self.server = ThreadingHTTPServer((bind_host, 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self) -> str:
        return f"http://{self.server.server_address[0]}:{self.server.server_address[1]}{PROBE_PATH}?t={self.token}"

    def set_phase(self, phase: str) -> None:
        if phase not in ("blocked", "recovery"):
            raise ValueError("invalid probe phase")
        with self._condition:
            self.phase = phase
            self._condition.notify_all()

    def wait_report(self, phase: str, timeout: float) -> dict:
        deadline = min(time.time() + max(0.0, timeout), self.expires_at)
        with self._condition:
            while phase not in self.reports and time.time() < deadline:
                self._condition.wait(min(1.0, deadline - time.time()))
            if phase not in self.reports:
                raise TimeoutError(f"No {phase} phone probe report arrived before timeout.")
            return dict(self.reports[phase])

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


def _probe_html(token: str) -> str:
# CORS fetch uses the explicit IPv4-only ipify endpoint; same-origin POST proves
# the LAN heartbeat still reaches the Pi when the public probe is blocked.
    return f'''<!doctype html><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetPulse temporary connection check</title>
<h1>NetPulse temporary connection check</h1><p id="state">Checking…</p>
<p>Keep this page open on Wi-Fi with mobile data and VPN off. It sends only pass/fail to the Pi.</p>
<script>
const token={json.dumps(token)}, stateUrl="/state?t="+encodeURIComponent(token), reportUrl="/report?t="+encodeURIComponent(token);
let phase="", sent=false, timer=null, generation=0;
function validIPv4(value) {{ const parts=String(value||"").split(".");
  return parts.length===4 && parts.every(x=>/^\\d{{1,3}}$/.test(x) && Number(x)>=0 && Number(x)<=255); }}
function report(ok, expectedPhase, expectedGeneration) {{
  if(sent || phase!==expectedPhase || generation!==expectedGeneration) return; sent=true; clearTimeout(timer);
  const controller=new AbortController(), abort=setTimeout(()=>controller.abort(),5000);
  fetch(reportUrl,{{method:"POST",headers:{{"Content-Type":"application/json"}},
    body:JSON.stringify({{phase:expectedPhase,internet_ipv4_ok:ok,lan_ok:true}}),signal:controller.signal}}).then(response=>{{
      if(!response.ok) throw new Error("report rejected");
      document.getElementById("state").textContent=expectedPhase+": result received; waiting for next check";
    }}).catch(()=>{{document.getElementById("state").textContent="Pi heartbeat failed";}}).finally(()=>clearTimeout(abort));
}}
async function probe() {{ sent=false;
  const expectedPhase=phase, expectedGeneration=++generation, controller=new AbortController();
  timer=setTimeout(()=>{{controller.abort();report(false,expectedPhase,expectedGeneration);}},10000);
  try {{ const response=await fetch({json.dumps(IPIFY_IPV4)}+"&n="+Date.now(),{{mode:"cors",cache:"no-store",signal:controller.signal}});
    if(!response.ok) throw new Error("probe failed"); const data=await response.json();
    report(Boolean(data && validIPv4(data.ip)),expectedPhase,expectedGeneration);
  }} catch (_) {{ report(false,expectedPhase,expectedGeneration); }}
}}
async function poll() {{ try {{ const s=await (await fetch(stateUrl,{{cache:"no-store"}})).json();
  if(s.phase!==phase) {{ phase=s.phase; generation++; sent=false; clearTimeout(timer); document.getElementById("state").textContent=phase+": checking IPv4 Internet and Pi LAN"; probe(); }}
  if(s.expires_in<=0) {{ document.getElementById("state").textContent="This temporary check expired"; return; }}
}} catch (_) {{ document.getElementById("state").textContent="Pi LAN heartbeat unavailable"; }}
setTimeout(poll,1000); }} poll();
</script>'''


def run_callback_transaction(client, acl_response, row: dict, probe: EndpointProbe,
                             wait_seconds: int = DEFAULT_PILOT_SECONDS,
                             baseline_report: dict | None = None,
                             cleanup_record: Path | None = None) -> dict:
    """Testable bounded add → observed block → delete → observed recovery transaction.

    The callback hook is the phone's actual browser result in live mode; fake callbacks
    keep tests isolated. This function never changes WAN routes or DHCP state.
    """
    if wait_seconds < 15 or wait_seconds > MAX_PILOT_SECONDS:
        raise PilotError("Pilot wait must be 15 to 180 seconds.")
    validate_empty_acl(acl_response)
    baseline = baseline_report if baseline_report is not None else probe.wait_report("baseline", wait_seconds)
    if baseline != {"internet_ipv4_ok": True, "lan_ok": True}:
        raise PilotError("The exact endpoint must pass both baseline IPv4 Internet and Pi LAN checks before any ACL write.")
    rows = client.read_acl_pilot_rows()
    if rows:
        raise PilotError("Fresh ACL read no longer shows an empty list; no rule was added.")
    attempted = False
    block_error = None
    try:
        attempted = True
        client.add_acl_pilot_rule(rows, row)
        probe.set_phase("blocked")
        blocked = probe.wait_report("blocked", wait_seconds)
        if blocked != {"internet_ipv4_ok": False, "lan_ok": True}:
            block_error = PilotError("The endpoint did not show IPv4 Internet blocked with Pi LAN still reachable.")
    except Exception as exc:
        block_error = exc
    finally:
        if attempted:
            current = client.read_acl_pilot_rows()
            matches = [item for item in current if isinstance(item, dict)
                       and item.get("name") == row["name"]
                       and acl_pilot_effective_match(item, row)]
            if len(matches) == 1:
                client.delete_acl_pilot_rule(row["name"], row)
            elif any(isinstance(item, dict) and item.get("name") == row["name"] for item in current):
                raise PilotError("Temporary ACL row is ambiguous; automatic cleanup could not proceed.")
    probe.set_phase("recovery")
    recovered = probe.wait_report("recovery", wait_seconds)
    if recovered != {"internet_ipv4_ok": True, "lan_ok": True}:
        raise PilotError("IPv4 Internet did not recover after the temporary ACL row was removed.")
    if not attempted or block_error:
        raise block_error or PilotError("ACL pilot rule was not applied.")
    return {"baseline_ipv4": True, "blocked_ipv4": True,
            "lan_reachable_during_block": True, "recovered_ipv4": True,
            "acl_rule_removed": True}


def _cleanup_record_path() -> Path:
    return Path("/var/lib/netpulse/router-acl-pilot/watchdog.json")


def _write_cleanup_record(path: Path, config_path: str, row: dict, seconds: int,
                          restart_service: bool = False) -> None:
    if not _reviewed_row(row):
        raise PilotError("Refusing to arm cleanup for a nonpilot ACL row.")
    if config_path != CONFIG:
        raise PilotError("The watchdog may use only /etc/netpulse/config.toml.")
    if isinstance(seconds, bool) or not isinstance(seconds, int) or not 1 <= seconds <= MAX_WATCHDOG_SECONDS:
        raise PilotError("Watchdog deadline must be between 1 and 600 seconds.")
    if type(restart_service) is not bool:
        raise PilotError("Watchdog service-restoration flag must be boolean.")
    try:
        parent_info = path.parent.lstat()
    except FileNotFoundError:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        parent_info = path.parent.lstat()
    if stat.S_ISLNK(parent_info.st_mode) or not stat.S_ISDIR(parent_info.st_mode):
        raise PilotError("Watchdog directory must be a real directory.")
    if os.name == "posix" and parent_info.st_uid != 0:
        raise PilotError("Watchdog directory must be root-owned.")
    os.chmod(path.parent, 0o700)
    _validate_watchdog_directory(path.parent, path.parent.lstat())
    payload = json.dumps({"config": config_path, "row": row,
                          "deadline": time.time() + seconds, "owner_pid": os.getpid(),
                          "restart_service": bool(restart_service)}, separators=(",", ":")).encode()
    if len(payload) > MAX_WATCHDOG_RECORD_BYTES:
        raise PilotError("Watchdog record exceeds its size limit.")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            _validate_watchdog_file(path, os.fstat(stream.fileno()))
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        if os.name == "posix":
            dir_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
    except Exception:
        path.unlink(missing_ok=True)
        raise


def _remove_cleanup_record(path: Path | None) -> None:
    if path is not None:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass


def _local_address(router_host: str) -> str:
    address = router_host.rsplit(":", 1)[0] if router_host.count(":") == 1 else router_host
    try:
        socket.inet_aton(address)
        ip = address
    except OSError:
        info = socket.getaddrinfo(address, 443, socket.AF_INET, socket.SOCK_DGRAM)
        ip = info[0][4][0]
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect((ip, 443))
        local = sock.getsockname()[0]
    if not ipaddress.IPv4Address(local).is_private:
        raise PilotError("Could not identify a private Pi LAN address for the phone heartbeat.")
    return local


def _reviewed_row(row) -> bool:
    if not isinstance(row, dict) or not NAME_RE.fullmatch(str(row.get("name", ""))):
        return False
    source = row.get("src")
    prefix = "NP_G_"
    if not isinstance(source, str) or not source.startswith(prefix):
        return False
    mac_hex = source[len(prefix):]
    if not re.fullmatch(r"[0-9A-F]{12}", mac_hex):
        return False
    mac = "-".join(mac_hex[index:index + 2] for index in range(0, 12, 2))
    try:
        return row == build_acl_row(mac, row["name"])
    except PilotError:
        return False


def _validate_watchdog_directory(path: Path, info) -> None:
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise PilotError("Watchdog directory must be a real directory.")
    _validate_root_private_metadata(info, 0o700, "Watchdog directory")


def _validate_watchdog_file(path: Path, info) -> None:
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise PilotError("Watchdog record must be a regular file, not a symlink.")
    _validate_root_private_metadata(info, 0o600, "Watchdog record")
    if info.st_size > MAX_WATCHDOG_RECORD_BYTES:
        raise PilotError("Watchdog record exceeds its size limit.")


def _validate_root_private_metadata(info, mode: int, label: str) -> None:
    if os.name == "posix" and (getattr(info, "st_uid", None) != 0
                                or info.st_mode & 0o777 != mode):
        raise PilotError(f"{label} must be root-owned with mode {mode:04o}.")


def _validate_cleanup_payload(record: object, now: float | None = None,
                              allow_future_deadline: bool = False) -> dict:
    keys = {"config", "row", "deadline", "owner_pid", "restart_service"}
    if not isinstance(record, dict) or set(record) != keys:
        raise PilotError("Watchdog record has unknown or missing fields.")
    deadline, owner_pid = record["deadline"], record["owner_pid"]
    if (record["config"] != CONFIG
            or isinstance(deadline, bool) or not isinstance(deadline, (int, float))
            or not math.isfinite(float(deadline)) or deadline < 0
            or (not allow_future_deadline
                and float(deadline) > (time.time() if now is None else now) + MAX_WATCHDOG_SECONDS)
            or isinstance(owner_pid, bool) or not isinstance(owner_pid, int) or owner_pid < 1
            or type(record["restart_service"]) is not bool
            or not _reviewed_row(record["row"])):
        raise PilotError("Watchdog record is invalid or outside its reviewed limits.")
    return record


def _read_cleanup_record(path: Path, *, allow_future_deadline: bool = False) -> dict | None:
    """Read one root-private record without following symlinks or accepting oversized data."""
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    _validate_watchdog_directory(path.parent, path.parent.lstat())
    _validate_watchdog_file(path, info)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        _validate_watchdog_file(path, opened)
        if (getattr(info, "st_ino", None) != getattr(opened, "st_ino", None)
                or getattr(info, "st_dev", None) != getattr(opened, "st_dev", None)):
            raise PilotError("Watchdog record changed while it was being opened.")
        chunks = bytearray()
        while len(chunks) <= MAX_WATCHDOG_RECORD_BYTES:
            part = os.read(fd, min(4096, MAX_WATCHDOG_RECORD_BYTES + 1 - len(chunks)))
            if not part:
                break
            chunks.extend(part)
        if len(chunks) > MAX_WATCHDOG_RECORD_BYTES:
            raise PilotError("Watchdog record exceeds its size limit.")
    finally:
        os.close(fd)
    try:
        record = json.loads(chunks.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise PilotError("Watchdog record is not valid UTF-8 JSON.") from None
    return _validate_cleanup_payload(record, allow_future_deadline=allow_future_deadline)


def _write_watchdog_failure(path: Path, exc: Exception) -> None:
    """Write a small root-only marker only inside a verified private watchdog directory."""
    try:
        _validate_watchdog_directory(path.parent, path.parent.lstat())
        failed = path.with_suffix(".failed")
        fd = os.open(failed, os.O_WRONLY | os.O_CREAT | os.O_TRUNC
                     | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as stream:
            stream.write(type(exc).__name__[:80])
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(failed, 0o600)
    except (OSError, PilotError):
        pass


def _watchdog(path: Path, *, boot_recovery: bool = False, now_fn=None,
              sleep_fn=None, pid_alive_fn=None, client_factory=None) -> int:
    """Clean one reviewed ACL row; boot recovery skips owner waits and service starts."""
    now_fn = time.time if now_fn is None else now_fn
    sleep_fn = time.sleep if sleep_fn is None else sleep_fn
    pid_alive_fn = _pid_alive if pid_alive_fn is None else pid_alive_fn
    client_factory = ER605Client if client_factory is None else client_factory
    record = None
    restart_service = False
    try:
        record = _read_cleanup_record(path, allow_future_deadline=boot_recovery)
        if record is None:
            return 0
        row = record["row"]
        deadline = float(record["deadline"])
        owner_pid = record["owner_pid"]
        restart_service = record["restart_service"]
        config_path = record["config"]
        if not boot_recovery:
            while path.exists() and now_fn() < deadline and pid_alive_fn(owner_pid):
                sleep_fn(min(2.0, max(0.1, deadline - now_fn())))
        if not path.exists():
            if not boot_recovery and restart_service and not _service_active():
                _start_service()
            return 0
        cfg = load(config_path)
        credentials = load_router_credentials(cfg.router.credentials_file)
        client = client_factory(cfg.router.host, credentials.username, credentials.password,
                                credentials.cert_sha256)
        with client.session() as router:
            rows = router.read_acl_pilot_rows()
            matches = [item for item in rows if isinstance(item, dict) and item.get("name") == row["name"]]
            if not matches:
                path.unlink(missing_ok=True)
            elif len(matches) != 1 or not acl_pilot_effective_match(matches[0], row):
                raise PilotError("watchdog found a changed/ambiguous ACL row; manual review is required")
            else:
                router.delete_acl_pilot_rule(row["name"], matches[0])
        if restart_service and not boot_recovery:
            _start_service()
        path.unlink(missing_ok=True)
        return 0
    except Exception as exc:
        if not boot_recovery:
            restart_service = bool(record and record.get("restart_service"))
        if not boot_recovery and restart_service:
            try:
                _start_service()
            except Exception as service_exc:
                exc = PilotError(f"cleanup failed ({type(exc).__name__}); service restart failed ({type(service_exc).__name__})")
        _write_watchdog_failure(path, exc)
        return 2


def recover_acl_on_boot(path: Path | None = None, **kwargs) -> int:
    """Boot-time recovery API; no owner wait and never starts netpulse.service."""
    return _watchdog(_cleanup_record_path() if path is None else Path(path),
                     boot_recovery=True, **kwargs)


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _start_watchdog(path: Path, config_path: str, row: dict, seconds: int,
                    restart_service: bool):
    _write_cleanup_record(path, config_path, row, seconds, restart_service)
    process = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--watchdog", str(path)],
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, close_fds=True, start_new_session=True)
    time.sleep(0.15)
    if process.poll() is not None:
        _remove_cleanup_record(path)
        raise PilotError("Independent Pi cleanup watchdog did not start; no ACL row was written.")


def _service_active() -> bool:
    result = subprocess.run(["systemctl", "is-active", "--quiet", "netpulse.service"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
    return result.returncode == 0


def _stop_service() -> None:
    result = subprocess.run(["systemctl", "stop", "netpulse.service"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
    if result.returncode != 0 or _service_active():
        raise PilotError("Could not confirm netpulse.service stopped before the router pilot.")


def _start_service() -> None:
    result = subprocess.run(["systemctl", "start", "netpulse.service"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
    if result.returncode != 0 or not _service_active():
        raise PilotError("Could not confirm netpulse.service restarted after the router pilot.")


def _validate_no_near_expiries(db_path: str, now: float, seconds: int) -> None:
    routes = storage_sqlite.device_routes(db_path)
    window_end = now + seconds + 120
    near = [item for item in routes.values() if item.get("expires_at") is not None
            and int(item["expires_at"]) <= window_end]
    if near:
        raise PilotError("A saved timed route is due during the pilot window; wait until it has expired and returned to Auto.")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=CONFIG, help="NetPulse TOML config (default: /etc/netpulse/config.toml)")
    parser.add_argument("--device",
                        help="exact lease name, MAC, or current IPv4 from the private reviewed-device file")
    parser.add_argument("--duration", type=int, default=DEFAULT_PILOT_SECONDS,
                        help="maximum endpoint observation time in seconds (15–180)")
    parser.add_argument("--apply", action="store_true", help="request the bounded live ACL pilot after preflight")
    parser.add_argument("--watchdog", help=argparse.SUPPRESS)
    parser.add_argument("--recover-on-boot", action="store_true",
                        help="remove a pending reviewed ACL pilot row before NetPulse starts")
    args = parser.parse_args(argv)
    if args.recover_on_boot and args.watchdog:
        parser.error("--recover-on-boot and --watchdog cannot be combined")
    if args.recover_on_boot:
        return recover_acl_on_boot()
    if args.watchdog:
        return _watchdog(Path(args.watchdog))
    if not args.device:
        parser.error("--device is required for a pilot run")
    if os.name != "posix" or os.geteuid() != 0:
        print("Run on the Pi with sudo so protected configuration and device inventory are readable.", file=sys.stderr)
        return 2
    if args.duration < 15 or args.duration > MAX_PILOT_SECONDS:
        parser.error("--duration must be 15 to 180 seconds")
    try:
        cfg = load(args.config)
        if not cfg.router.enabled:
            raise PilotError("ER605 monitoring is disabled in config.")
        if not cfg.router.controls_enabled:
            raise PilotError("Owner-enabled router controls are required.")
        if Path(cfg.router.kill_switch).exists():
            raise PilotError("The local router-control kill switch is active.")
        credentials = load_router_credentials(cfg.router.credentials_file)
        client = ER605Client(cfg.router.host, credentials.username, credentials.password,
                             credentials.cert_sha256)
        router = RouterWatch(client, {w.name: w.label for w in cfg.wans}, cfg.router.poll_minutes)
        router.tick(time.time(), advance_during_wait=True)
        control = RouterControl(router, cfg.db_path, cfg.router.controls_enabled, cfg.router.kill_switch)
        control_state = control.state()
        if not control_state.get("enabled"):
            raise PilotError("NetPulse manual controls are not ready: " + str(control_state.get("reason", "unknown state")))
        with client.session() as c:
            acl = c.get_response(*ACL_FORM)
            ip_entries = c.get("ipgroup", "ipscope_reservation")
            ip_groups = c.get("ipgroup", "ipgroup_reservation")
            routes = c.get("policy_route", "policy_route")
        raw = router.snap.raw
        pi_ip = _local_address(cfg.router.host)
        _name, target_mac, target_ip = resolve_candidate(args.device, raw.get("clients"))
        if load_reviewed_devices().get(target_mac) != target_ip:
            raise PilotError("This phone MAC/IP is not in the reviewed pilot allowlist.")
        facts = dict(selector=args.device, expected_mac=target_mac, expected_ip=target_ip,
                     clients=raw.get("clients"), reservations=raw.get("reservations"),
                     ip_entries=ip_entries, ip_groups=ip_groups, policy_routes=routes,
                     acl_response=acl, controls_enabled=control_state["enabled"],
                     kill_switch_active=control_state["kill_switch"],
                     firmware_version=control_state.get("firmware_version"),
                     accepted_firmware=control_state.get("accepted_firmware_version"),
                     pending_firmware=control_state.get("firmware_review_version") if control_state.get("firmware_review_required") else None,
                     status_checked_at=router.snap.checked_at, uptime=router.snap.uptime,
                     uptime_at=router.snap.uptime_at, now=time.time(), pi_addresses=[pi_ip])
        summary = validate_preflight(**facts)
        print(f"Preflight passed for {summary['device']} · MAC …{summary['mac_suffix']} · IPv4 …{summary['ip_last_octet']}; WAN1 Priority; ACL empty.")
        if args.apply:
            watchdog_record = _cleanup_record_path()
            watchdog_seconds = min(600, max(90, args.duration * 3 + 60))
            probe = EndpointProbe(pi_ip, target_ip, ttl_seconds=watchdog_seconds)
            service_was_active = False
            rule_absent = False
            row = None
            try:
                print(f"On the selected phone, open {probe.url} on home Wi-Fi with mobile data/VPN off.", flush=True)
                print("Waiting for the phone's successful IPv4 Internet and Pi LAN baseline.", flush=True)
                baseline = probe.wait_report("baseline", args.duration)
                if baseline != {"internet_ipv4_ok": True, "lan_ok": True}:
                    raise PilotError("Phone IPv4 Internet baseline failed; the ACL was not changed.")
                row = build_acl_row(target_mac, new_rule_name())
                _validate_no_near_expiries(cfg.db_path, time.time(), watchdog_seconds)
                service_was_active = _service_active()
                _start_watchdog(watchdog_record, args.config, row, watchdog_seconds, service_was_active)
                if service_was_active:
                    _stop_service()

                # The phone waited on the page while the app was running. Refresh all
                # authenticated state after stopping the app, immediately before adding.
                fresh_router = RouterWatch(client, {w.name: w.label for w in cfg.wans}, cfg.router.poll_minutes)
                fresh_router.tick(time.time(), advance_during_wait=True)
                fresh_control = RouterControl(fresh_router, cfg.db_path, cfg.router.controls_enabled,
                                              cfg.router.kill_switch)
                fresh_state = fresh_control.state()
                if not fresh_state.get("enabled"):
                    raise PilotError("Fresh manual-control readiness failed before the ACL write.")
                with client.session() as fresh_client:
                    fresh_acl = fresh_client.get_response(*ACL_FORM)
                    fresh_entries = fresh_client.get("ipgroup", "ipscope_reservation")
                    fresh_groups = fresh_client.get("ipgroup", "ipgroup_reservation")
                    fresh_routes = fresh_client.get("policy_route", "policy_route")
                fresh_raw = fresh_router.snap.raw
                fresh_facts = dict(selector=args.device, expected_mac=target_mac,
                                   expected_ip=target_ip, clients=fresh_raw.get("clients"),
                                   reservations=fresh_raw.get("reservations"), ip_entries=fresh_entries,
                                   ip_groups=fresh_groups, policy_routes=fresh_routes,
                                   acl_response=fresh_acl, controls_enabled=fresh_state["enabled"],
                                   kill_switch_active=fresh_state["kill_switch"],
                                   firmware_version=fresh_state.get("firmware_version"),
                                   accepted_firmware=fresh_state.get("accepted_firmware_version"),
                                   pending_firmware=(fresh_state.get("firmware_review_version")
                                                     if fresh_state.get("firmware_review_required") else None),
                                   status_checked_at=fresh_router.snap.checked_at,
                                   uptime=fresh_router.snap.uptime, uptime_at=fresh_router.snap.uptime_at,
                                   now=time.time(), pi_addresses=[pi_ip])
                validate_preflight(**fresh_facts)
                _validate_no_near_expiries(cfg.db_path, time.time(), watchdog_seconds)
                with client.session() as pilot_client:
                    result = run_callback_transaction(pilot_client, fresh_acl, row, probe, args.duration,
                                                      baseline_report=baseline, cleanup_record=watchdog_record)
                rule_absent = True
                print("Pilot passed: IPv4 Internet blocked while Pi LAN stayed reachable, then recovered after ACL removal.")
                print(json.dumps(result, sort_keys=True))
            finally:
                probe.close()
                if service_was_active and watchdog_record.exists():
                    _start_service()
                if rule_absent:
                    _remove_cleanup_record(watchdog_record)
        else:
            print("Read-only preflight candidate only. No router settings were changed.")
        return 0
    except (OSError, ValueError, RouterError, subprocess.SubprocessError) as exc:
        reason = str(exc) if isinstance(exc, PilotError) else type(exc).__name__
        print(f"Pilot stopped: {reason}. Check the temporary-rule cleanup/watchdog record before another run.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
