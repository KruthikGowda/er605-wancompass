"""Periodic read-only view of the ER605: reboots, WAN status/IP changes, load, clients.

- Every minute: unauthenticated uptime (reboot detection). Never disturbs anyone's login.
- Every `poll_minutes`: one short login → read a few pages → logout.
- Pausable ("I'm using Omada") because each login kicks the web UI session.
- Failed logins back off hard (30 min, doubling to 6 h) to avoid the router's lockout.

`tick()` is blocking and runs in a worker thread. It returns events for the main loop.
"""

from __future__ import annotations

import ipaddress
import logging
import threading
import time
from dataclasses import dataclass, field

from netpulse.router.er605 import ER605Client, RouterAuthError, RouterError, sanitize

log = logging.getLogger(__name__)

AUTH_BACKOFF_START = 1800
AUTH_BACKOFF_MAX = 6 * 3600
UNREACHABLE_AFTER = 3  # consecutive failed uptime checks before we say the router is unreachable


@dataclass
class RouterEvent:
    kind: str          # "router"
    wan: str | None
    message: str       # stored in the event log
    alert: str | None  # Telegram text, or None for log-only
    critical: bool = False


@dataclass
class WanLink:
    up: bool | None = None
    interface_up: bool | None = None
    ip: str | None = None
    gateway: str | None = None
    dns_servers: tuple[str, ...] = ()


def _find(entries, wan: str) -> dict | None:
    """Pick the entry describing this WAN from a list, matching common ER605 name fields."""
    for e in entries or []:
        if not isinstance(e, dict):
            continue
        names = {str(e.get(k, "")).upper() for k in ("interface", "t_name", "name", "t_label", "iface")}
        if wan.upper() in names or (wan.upper() == "WAN2" and "WAN/LAN2" in names):
            return e
    return None


def _first(d: dict, *keys):
    for k in keys:
        v = d.get(k)
        if v not in (None, "", "0.0.0.0", "---"):
            return v
    return None


def _version_fields(value) -> dict[str, str]:
    """Extract only the two observed version strings from firmware/upgrade."""
    if not isinstance(value, dict):
        return {}
    result = value.get("result", value)
    if not isinstance(result, dict):
        return {}
    fields = {}
    for key in ("hardware_version", "firmware_version"):
        candidate = result.get(key)
        if (isinstance(candidate, str) and candidate.strip()
                and len(candidate) <= 128 and candidate.isprintable()):
            fields[key] = candidate.strip()
    return fields


def _reported_bool(value) -> bool | None:
    """Parse only documented boolean-like spellings from the ER605 status form."""
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in ("1", "true", "up", "online", "connected"):
        return True
    if text in ("0", "false", "down", "offline", "disconnected"):
        return False
    return None


def parse_links(online, status2, wans: list[str]) -> dict[str, WanLink]:
    """Combine router-reported WAN status and interface/status2 flags and addresses.

    The online/online result is not proof of physical carrier or end-to-end Internet access.
    Keep it separate from the status2 interface flag and NetPulse's own WAN probes.
    """
    online_list = online if isinstance(online, list) else (online or {}).get("online", [])
    s2 = status2 or {}
    s2_list = s2.get("normal", []) if isinstance(s2, dict) else s2
    links = {}
    for wan in wans:
        link = WanLink()
        o = _find(online_list, wan)
        if o is not None:
            state = str(o.get("state", o.get("status", ""))).lower()
            link.up = state in ("up", "online", "connected", "1", "true") if state else None
        s = _find(s2_list, wan)
        if s is not None:
            link.interface_up = _reported_bool(s.get("t_isup"))
            link.ip = _first(s, "ipaddr", "t_ipaddr", "ip", "wan_ip", "ipv4")
            link.gateway = _first(s, "gateway", "t_gateway", "gw", "wan_gateway")
            dns_servers = []
            for key in ("dns1", "dns2"):
                value = s.get(key)
                try:
                    address = ipaddress.IPv4Address(str(value))
                except (ipaddress.AddressValueError, TypeError):
                    continue
                if (not address.is_multicast and not address.is_loopback
                        and not address.is_link_local and not address.is_reserved
                        and not address.is_unspecified and str(address) not in dns_servers):
                    dns_servers.append(str(address))
            link.dns_servers = tuple(dns_servers)
            if link.up is None:
                st = str(s.get("t_linkstatus", s.get("status", ""))).lower()
                link.up = ("up" in st or "connected" in st) if st else None
        links[wan] = link
    return links


@dataclass
class RouterSnapshot:
    ok: bool = False
    model: str | None = None
    hardware_version: str | None = None
    firmware_version: str | None = None
    uptime: int | None = None
    checked_at: float | None = None      # last successful full check
    uptime_at: float | None = None
    cpu_pct: float | None = None
    mem_pct: float | None = None
    clients: int | None = None
    links: dict = field(default_factory=dict)
    raw: dict = field(default_factory=dict)  # sanitized, for debugging via /api/router?raw=1
    error: str | None = None
    paused_until: float = 0.0
    next_check: float = 0.0


class RouterWatch:
    def __init__(self, client: ER605Client, wans: dict[str, str], poll_minutes: float = 10):
        self.client = client
        self.wans = wans                     # name -> label
        self.poll_seconds = max(60, poll_minutes * 60)
        self.snap = RouterSnapshot()
        self._lock = threading.Lock()
        self._uptime_lock = threading.Lock()
        # Standalone ER605 permits one authenticated web session. Serialize full monitor reads
        # with NetPulse control transactions so one NetPulse login cannot invalidate another.
        self.api_lock = threading.RLock()
        self._next_full = 0.0                # first full check on the first tick
        self._paused_until = 0.0
        self._auth_failures = 0
        self._login_blocked_until = 0.0
        self._unreachable = 0
        self._reported_unreachable = False
        self._uptime_mono: float | None = None
        self._deferred_router_events: list[RouterEvent] = []

    # --- controls (thread-safe) ---

    def pause(self, seconds: float) -> None:
        # Wait for any active authenticated check, then pause before another can start.
        # This makes the pause response a reliable point to open the Omada UI afterward.
        with self.api_lock:
            with self._lock:
                self._paused_until = time.time() + seconds

    def resume(self) -> None:
        with self.api_lock:
            with self._lock:
                self._paused_until = 0.0
                self._next_full = 0.0

    def snapshot(self) -> dict:
        s = self.snap
        now = time.time()
        with self._lock:
            paused = self._paused_until if self._paused_until > now else 0.0
        next_check = (None if self._unreachable else
                      max(self._next_full, self._login_blocked_until, paused))
        return {
            "ok": s.ok, "model": s.model, "uptime": s.uptime, "uptime_at": s.uptime_at,
            "hardware_version": s.hardware_version, "firmware_version": s.firmware_version,
            "checked_at": s.checked_at, "cpu_pct": s.cpu_pct, "mem_pct": s.mem_pct,
            "clients": s.clients, "error": s.error, "paused_until": paused,
            "next_check": next_check,
            "links_max_age_seconds": self.poll_seconds * 2,
            # Keep WAN resolver addresses internal; they are used only for source-bound
            # outage diagnosis and are not part of the router API snapshot.
            "links": {w: {"up": l.up, "interface_up": l.interface_up,
                          "ip": l.ip, "gateway": l.gateway}
                      for w, l in s.links.items()},
        }

    def label(self, wan: str) -> str:
        return self.wans.get(wan) or wan

    # --- work ---

    def tick(self, now: float, mono: float | None = None, *,
             advance_during_wait: bool = False) -> list[RouterEvent]:
        """now: wall clock (for display). mono: monotonic seconds, used to measure real elapsed time,
        so the Pi's clock jumping when it syncs can't look like a router restart."""
        events: list[RouterEvent] = []
        tick_mono = time.monotonic()
        def effective_now() -> float:
            elapsed = max(0.0, time.monotonic() - tick_mono)
            return float(now) + elapsed if advance_during_wait else float(now)

        with self._lock:
            events.extend(self._deferred_router_events)
            self._deferred_router_events.clear()
        with self._uptime_lock:
            check_now = effective_now()
            elapsed = max(0.0, time.monotonic() - tick_mono)
            check_mono = (time.monotonic() if mono is None else
                          mono + (elapsed if advance_during_wait else 0.0))
            self._check_uptime(check_now, check_mono, events)
        with self._lock:
            paused = self._paused_until > check_now
        if check_now >= self._next_full and not paused and check_now >= self._login_blocked_until and self._unreachable == 0:
            with self.api_lock:
                full_now = effective_now()
                with self._lock:
                    paused = self._paused_until > full_now
                if not paused and full_now >= self._next_full and full_now >= self._login_blocked_until and self._unreachable == 0:
                    self._next_full = full_now + self.poll_seconds
                    self._full_check(full_now, events)
        return events

    def refresh_uptime(self, now: float | None = None, mono: float | None = None) -> bool:
        """Refresh only unauthenticated uptime during a serialized router write transaction.

        Events are deferred to the next normal ``tick`` so restart and reachability notices
        still pass through the main watch event handler.
        """
        events: list[RouterEvent] = []
        with self._uptime_lock:
            now = time.time() if now is None else now
            mono = time.monotonic() if mono is None else mono
            fresh = self._check_uptime(now, mono, events)
            if events:
                with self._lock:
                    self._deferred_router_events.extend(events)
        return fresh

    def refresh_control_status(self, now: float | None = None) -> bool:
        """Refresh authenticated control inputs during a long serialized write batch."""
        events: list[RouterEvent] = []
        with self.api_lock:
            now = time.time() if now is None else now
            with self._lock:
                if self._paused_until > now or self._login_blocked_until > now:
                    return False
            fresh = self._full_check(now, events)
            if events:
                with self._lock:
                    self._deferred_router_events.extend(events)
            if fresh:
                self._next_full = max(self._next_full, now + self.poll_seconds)
        return fresh

    def _check_uptime(self, now: float, mono: float, events: list[RouterEvent]) -> bool:
        try:
            info = self.client.public_info()
        except RouterError as e:
            self._unreachable += 1
            self.snap.ok = False
            self.snap.error = str(e)
            self.snap.uptime_at = None
            if self._unreachable >= UNREACHABLE_AFTER and not self._reported_unreachable:
                self._reported_unreachable = True
                events.append(RouterEvent("router", None, f"Router not reachable: {e}",
                                          "🔴 Can't reach the ER605 router from the Pi", critical=True))
            return False
        except (AttributeError, KeyError, TypeError, ValueError):
            self.snap.ok = False
            self.snap.error = "router returned invalid uptime response"
            self.snap.uptime_at = None
            return False
        raw_uptime = info.get("uptime") if isinstance(info, dict) else None
        try:
            if isinstance(raw_uptime, bool):
                raise ValueError
            uptime = int(raw_uptime)
            if uptime < 0 or (isinstance(raw_uptime, float) and not raw_uptime.is_integer()):
                raise ValueError
        except (TypeError, ValueError, OverflowError):
            self.snap.ok = False
            self.snap.error = "router returned invalid uptime"
            self.snap.uptime_at = None
            return False
        if self._reported_unreachable:
            events.append(RouterEvent("router", None, "Router reachable again",
                                      "🟢 ER605 router is reachable again", critical=True))
        self._unreachable = 0
        self._reported_unreachable = False
        prev, prev_mono = self.snap.uptime, self._uptime_mono
        self._uptime_mono = mono
        # Restarted if the router's uptime is well short of what real elapsed time predicts.
        if prev is not None and prev_mono is not None and uptime + 120 < prev + (mono - prev_mono):
            events.append(RouterEvent("router", None, f"Router restarted (uptime {uptime}s)",
                                      f"🔄 The ER605 router restarted about {max(1, uptime // 60)} min ago",
                                      critical=True))
            # Authenticated status (including firmware and load balancing) belongs to
            # the previous boot. Require a fresh full check before controls can unlock.
            self.snap.checked_at = None
        self.snap.uptime, self.snap.uptime_at = uptime, now
        self.snap.model = info.get("model")
        self.snap.ok = True
        if self.snap.error and "login" not in (self.snap.error or ""):
            self.snap.error = None
        return True

    def _full_check(self, now: float, events: list[RouterEvent]) -> bool:
        try:
            with self.client.session() as c:
                raw = {
                    "online": c.get("online", "online"),
                    "status2": c.get("interface", "status2"),
                    "usage": c.get("sys_status", "all_usage"),
                    "clients": c.get("dhcps", "client", {}),
                    "reservations": c.get("dhcps", "reservation", {}),
                }
                # Exact read observed on the authenticated System Status page for
                # ER605 v2.30 / firmware 2.3.3 Build 20251029. Keep only version strings.
                try:
                    raw["firmware_info"] = _version_fields(c.get("firmware", "upgrade"))
                except RouterError:
                    raw["firmware_info"] = {}
                    log.warning("router firmware version is unavailable")
                # Needed for the reservation preview's in-LAN and DHCP-pool guard.
                for key, module, form in (("lan_scopes", "ipgroup", "ipscope_list"),
                                          ("dhcp_settings", "dhcps", "lan")):
                    try:
                        raw[key] = c.get(module, form)
                    except RouterError:
                        raw[key] = None
                        log.warning("router %s/%s settings are unavailable", module, form)
                # Control readiness is optional; an unknown firmware form must not break monitoring.
                for form in ("balance_global", "balance_basic"):
                    try:
                        raw[form] = c.get("balance", form)
                    except RouterError:
                        raw[form] = None
                        log.warning("router %s status is unavailable", form)
                # The policy route form is read-only here and lets the dashboard detect
                # edits made outside NetPulse. Failure is informational, never a monitor failure.
                try:
                    raw["policy_routes"] = c.get("policy_route", "policy_route")
                    raw["policy_routes_checked_at"] = now
                except RouterError:
                    raw["policy_routes"] = None
                    raw["policy_routes_checked_at"] = None
                    log.warning("router policy route state is unavailable")
        except RouterAuthError as e:
            self._auth_failures += 1
            wait = min(AUTH_BACKOFF_START * 2 ** (self._auth_failures - 1), AUTH_BACKOFF_MAX)
            self._login_blocked_until = now + wait
            self.snap.error = f"login failed, next try in {wait // 60} min"
            log.warning("router login rejected; not retrying for %d min", wait // 60)
            events.append(RouterEvent(
                "router", None, f"Router login failed ({e})",
                "⚠️ NetPulse couldn't log in to the ER605 (password changed?).\n"
                f"Router checks paused for {wait // 60} min. Fix: sudo python3 tools/router_setup.py",
                critical=False))
            return False
        except RouterError as e:
            self.snap.error = str(e)
            log.warning("router check failed: %s", e)
            return False

        self._auth_failures = 0
        self.snap.raw = sanitize(raw)
        firmware = raw.get("firmware_info")
        self.snap.hardware_version = (firmware.get("hardware_version")
                                      if isinstance(firmware, dict) else None)
        self.snap.firmware_version = (firmware.get("firmware_version")
                                      if isinstance(firmware, dict) else None)
        self.snap.checked_at = now
        self.snap.error = None
        usage = raw.get("usage") or {}
        self.snap.cpu_pct = _pct(usage, "cpu")
        self.snap.mem_pct = _pct(usage, "mem")
        clients = raw.get("clients")
        self.snap.clients = len(clients) if isinstance(clients, list) else None

        links = parse_links(raw.get("online"), raw.get("status2"), list(self.wans))
        for wan, link in links.items():
            old = self.snap.links.get(wan)
            if old is None:
                continue
            name = self.label(wan)
            if old.up is not None and link.up is not None and old.up != link.up:
                if link.up:
                    events.append(RouterEvent("router", wan,
                                              f"{name}: ER605-reported WAN status changed to Online",
                                              f"🟢 Router: {name} WAN status is Online", critical=True))
                else:
                    events.append(RouterEvent("router", wan,
                                              f"{name}: ER605-reported WAN status changed to Offline",
                                              f"🔴 Router: {name} WAN status is Offline", critical=True))
            if old.ip and link.ip and old.ip != link.ip:
                events.append(RouterEvent("router", wan, f"{name}: WAN IP changed {old.ip} -> {link.ip}",
                                          f"🔁 {name} reconnected (new WAN IP {link.ip})"))
        self.snap.links = links
        return True


def _pct(usage: dict, what: str) -> float | None:
    """all_usage shapes vary by firmware: try a few, return 0-100 or None."""
    if not isinstance(usage, dict):
        return None
    for k in (f"{what}_usage", what, f"{what}_rate", f"{what}usage"):
        v = usage.get(k)
        if isinstance(v, dict):
            # ER605 2.3.3: cpu_usage = {"core1": 3, "core2": 4, ...}, mem_usage = {"mem": 30}
            v = [x for x in v.values() if isinstance(x, (int, float)) or str(x).replace(".", "", 1).isdigit()]
        if isinstance(v, list) and v:
            nums = [float(x) for x in v if str(x).replace(".", "", 1).isdigit()]
            if nums:
                return round(sum(nums) / len(nums), 1)
        try:
            if v is not None:
                return float(str(v).rstrip("%"))
        except ValueError:
            pass
    return None
