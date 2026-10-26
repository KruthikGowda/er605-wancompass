"""Read-only per-IP ER605 RX/TX byte-rate samples bound to fresh DHCP identities."""
from __future__ import annotations

import ipaddress
import math
import re
import threading
import time

from netpulse.devices.identity import MAC_RE, normalize_mac
from netpulse.router.er605 import RouterAuthError

MAX_ROWS = 8192
MAX_SELECTED = 128
MAX_EXACT_COUNTER = 2**53
TRAFFIC_CACHE_SECONDS = 15.0
TRAFFIC_SAMPLE_SECONDS = 2.0


class TrafficError(ValueError):
    """Selected device input cannot be read safely."""


class DeviceTraffic:
    """Measure read-only router receive/transmit rates by IPv4 for selected MACs."""

    def __init__(self, watch, clock=time.time, sleep=time.sleep, monotonic=time.monotonic,
                 sample_seconds=TRAFFIC_SAMPLE_SECONDS,
                 cache_seconds=TRAFFIC_CACHE_SECONDS):
        self.watch = watch
        self.clock = clock
        self.sleep = sleep
        self.monotonic = monotonic
        self.sample_seconds = float(sample_seconds)
        self.cache_seconds = float(cache_seconds)
        if (not math.isfinite(self.sample_seconds) or self.sample_seconds <= 0
                or not math.isfinite(self.cache_seconds) or self.cache_seconds <= 0):
            raise ValueError("Traffic sample and cache intervals must be finite and positive.")
        self._lock = threading.RLock()
        self._cache = None
        self._retry_after = 0.0
        self._retry_reason = ""

    def read(self, macs: list[str]) -> dict:
        selected = self._selected(macs)
        with self._lock:
            guard = self._watch_guard()
            if guard:
                return self._stale_result(selected, guard)
            try:
                with self.watch.api_lock:
                    guard = self._watch_guard()
                    if guard:
                        return self._stale_result(selected, guard)
                    with self.watch.client.session() as client:
                        clients_before = client.get("dhcps", "client")
                        before, duplicate_macs, duplicate_ips = self._client_map(clients_before)
                        status = self._status(client.get("ipstats", "setting"))
                        if status is False:
                            self._cache = None
                            return self._unavailable(selected, "ER605 per-IP statistics are disabled.", enabled=False)
                        if status is None:
                            return self._stale_result(selected, "ER605 per-IP statistics status is unavailable.", enabled=None)

                        initial = self._selection_identity(selected, before, duplicate_macs, duplicate_ips)
                        if (initial and self._cache_fresh()
                                and all(self._cache["identities"].get(mac) == ip
                                        for mac, ip in initial.items())
                                and all(ip in self._cache["rates"] for ip in initial.values())):
                            clients_after = client.get("dhcps", "client")
                            after, after_duplicate_macs, after_duplicate_ips = self._client_map(clients_after)
                            final = self._selection_identity(selected, after, after_duplicate_macs,
                                                             after_duplicate_ips)
                            if final == initial:
                                return self._cached_result(selected, initial, enabled=True)
                            self._cache = None
                            return self._unavailable(selected,
                                "A selected device's DHCP identity changed during the traffic check.", enabled=True)

                        if not initial:
                            self._cache = None
                            return self._unavailable(selected,
                                "Selected device MACs are not uniquely bound to current IPv4 leases.", enabled=True)

                        first_raw = client.get("ipstats", "list")
                        first = self._counter_map(first_raw)
                        before_mono = self.monotonic()
                        self.sleep(self.sample_seconds)
                        second_raw = client.get("ipstats", "list")
                        second = self._counter_map(second_raw)
                        after_mono = self.monotonic()
                        clients_after = client.get("dhcps", "client")
                        after, after_duplicate_macs, after_duplicate_ips = self._client_map(clients_after)
                        final = self._selection_identity(selected, after, after_duplicate_macs,
                                                         after_duplicate_ips)
                        if initial != final:
                            self._cache = None
                            return self._unavailable(selected,
                                "A selected device's DHCP identity changed during the traffic check.", enabled=True)

                        elapsed = after_mono - before_mono
                        rates, problems = self._rates(first, second, elapsed)
                        sampled_at = self.clock()
                        self._cache = {"rates": rates, "identities": dict(before),
                                       "sampled_at": sampled_at, "sample_mono": after_mono,
                                       "sample_seconds": elapsed, "problems": problems}
                        return self._sample_result(selected, initial, enabled=True)
            except Exception as exc:
                # Router errors can contain private addresses, request data, or authentication details.
                delay = 1800 if isinstance(exc, RouterAuthError) else 15
                self._retry_after = max(self._retry_after, self.clock() + delay)
                self._retry_reason = ("ER605 authentication is in backoff; wait for its normal router check."
                                      if isinstance(exc, RouterAuthError) else
                                      "Could not read fresh per-device traffic from the ER605; retry shortly.")
                return self._stale_result(selected, self._retry_reason)

    @staticmethod
    def _selected(macs):
        if not isinstance(macs, (list, tuple)) or not macs or len(macs) > MAX_SELECTED:
            raise TrafficError(f"Select between 1 and {MAX_SELECTED} devices.")
        normalized = [normalize_mac(mac) for mac in macs]
        if any(not MAC_RE.fullmatch(mac) for mac in normalized) or len(set(normalized)) != len(normalized):
            raise TrafficError("Select unique, valid device MAC addresses.")
        return normalized

    def _watch_guard(self):
        now = self.clock()
        if self._retry_after > now:
            return self._retry_reason or "Per-device traffic is temporarily unavailable; retry shortly."
        if getattr(self.watch, "client", None) is None or not hasattr(self.watch, "api_lock"):
            return "Router traffic controls are unavailable."
        if getattr(self.watch, "_login_blocked_until", 0) > now:
            return "ER605 authentication is in backoff; wait for its normal router check."
        if getattr(self.watch, "_paused_until", 0) > now:
            return "ER605 checks are paused; traffic data is unavailable."
        if getattr(self.watch, "_unreachable", 0):
            return "ER605 is unreachable; wait for its normal router check."
        snap = getattr(self.watch, "snap", None)
        if getattr(snap, "ok", True) is False:
            return "ER605 status is not ready; wait for its normal router check."
        checked_at = getattr(snap, "checked_at", None)
        try:
            age = now - float(checked_at)
        except (TypeError, ValueError, OverflowError):
            return "ER605 inventory is not fresh; wait for its normal router check."
        max_age = max(120, float(getattr(self.watch, "poll_seconds", 0)) * 2)
        if not math.isfinite(age) or age < 0 or age > max_age:
            return "ER605 inventory is stale; wait for its normal router check."
        error = str(getattr(snap, "error", "") or "").casefold()
        if "login" in error or "auth" in error:
            return "ER605 authentication is unavailable; wait for its normal router check."
        return ""

    @staticmethod
    def _status(value):
        if not isinstance(value, dict) or "status" not in value:
            return None
        status = value.get("status")
        if isinstance(status, bool):
            return status
        text = str(status).strip().casefold()
        if text in ("1", "on", "enabled", "true"):
            return True
        if text in ("0", "off", "disabled", "false"):
            return False
        return None

    @staticmethod
    def _client_map(rows):
        if not isinstance(rows, list):
            raise ValueError("Invalid DHCP client list")
        mac_counts, ip_counts, pairs = {}, {}, []
        for row in rows:
            if not isinstance(row, dict):
                continue
            mac = normalize_mac(row.get("macaddr", row.get("mac", "")))
            if not mac:
                continue
            try:
                ip = str(ipaddress.IPv4Address(str(row.get("ipaddr", row.get("ip", "")))))
            except (ipaddress.AddressValueError, TypeError):
                mac_counts[mac] = mac_counts.get(mac, 0) + 1
                pairs.append((mac, None))
                continue
            mac_counts[mac] = mac_counts.get(mac, 0) + 1
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
            pairs.append((mac, ip))
        mapping, duplicate_macs, duplicate_ips = {}, set(), set()
        for mac, ip in pairs:
            if mac_counts[mac] != 1:
                duplicate_macs.add(mac)
            elif ip is None:
                duplicate_macs.add(mac)
            elif ip_counts[ip] != 1:
                duplicate_ips.add(ip)
            else:
                mapping[mac] = ip
        return mapping, duplicate_macs, duplicate_ips

    @staticmethod
    def _selection_identity(selected, mapping, duplicate_macs, duplicate_ips):
        result = {}
        for mac in selected:
            ip = mapping.get(mac)
            if ip and mac not in duplicate_macs and ip not in duplicate_ips:
                result[mac] = ip
        return result

    @staticmethod
    def _counter_value(value):
        if isinstance(value, bool):
            return None
        if isinstance(value, int):
            return value if 0 <= value <= MAX_EXACT_COUNTER else None
        if isinstance(value, float):
            if math.isfinite(value) and value.is_integer() and 0 <= value <= MAX_EXACT_COUNTER:
                return int(value)
            return None
        if isinstance(value, str) and re.fullmatch(r"\d{1,16}", value.strip()):
            parsed = int(value.strip())
            return parsed if parsed <= MAX_EXACT_COUNTER else None
        return None

    @classmethod
    def _counter_map(cls, rows):
        if not isinstance(rows, list) or len(rows) > MAX_ROWS:
            raise ValueError("Invalid or oversized IP statistics list")
        counters, invalid, duplicates = {}, set(), set()
        for row in rows:
            if not isinstance(row, dict):
                raise ValueError("Invalid IP statistics row")
            address = row.get("addr")
            try:
                ip = str(ipaddress.IPv4Address(str(address)))
            except (ipaddress.AddressValueError, TypeError):
                raise ValueError("Invalid IP statistics address") from None
            if not isinstance(address, str) or address != ip:
                raise ValueError("IP statistics address is not canonical IPv4")
            if ip in counters or ip in invalid:
                duplicates.add(ip)
                counters.pop(ip, None)
                invalid.add(ip)
                continue
            rx = cls._counter_value(row.get("rx_bytes"))
            tx = cls._counter_value(row.get("tx_bytes"))
            if rx is None or tx is None:
                invalid.add(ip)
                continue
            counters[ip] = (rx, tx)
        for ip in duplicates:
            counters.pop(ip, None)
        return counters, invalid | duplicates

    @staticmethod
    def _rates(first, second, elapsed):
        if not math.isfinite(elapsed) or elapsed <= 0:
            raise ValueError("Invalid traffic sample interval")
        first_rows, first_invalid = first
        second_rows, second_invalid = second
        rates, problems = {}, set(first_invalid) | set(second_invalid)
        for ip in first_rows.keys() & second_rows.keys():
            rx1, tx1 = first_rows[ip]
            rx2, tx2 = second_rows[ip]
            if rx2 < rx1 or tx2 < tx1:
                problems.add(ip)
                continue
            rx_mbps = (rx2 - rx1) * 8 / elapsed / 1_000_000
            tx_mbps = (tx2 - tx1) * 8 / elapsed / 1_000_000
            if not math.isfinite(rx_mbps) or not math.isfinite(tx_mbps):
                problems.add(ip)
                continue
            rates[ip] = {"rx_mbps": round(rx_mbps, 3), "tx_mbps": round(tx_mbps, 3)}
        return rates, problems

    def _cache_fresh(self):
        return bool(self._cache and 0 <= self.monotonic() - self._cache["sample_mono"] <= self.cache_seconds)

    def _sample_result(self, selected, identities, enabled):
        cache = self._cache
        age = max(0.0, self.monotonic() - cache["sample_mono"])
        devices = []
        for mac in selected:
            ip = identities.get(mac)
            rates = cache["rates"].get(ip) if ip else None
            invalid = ip is None or ip in cache["problems"] or rates is None
            reason = ("Device MAC and IPv4 address are not uniquely present in the current DHCP list."
                      if ip is None else
                      "ER605 returned missing, duplicate, reset, or invalid counters for this IP."
                      if invalid else "")
            devices.append({"mac": mac, "ip": ip, "available": not invalid,
                            "rx_mbps": rates["rx_mbps"] if rates and not invalid else None,
                            "tx_mbps": rates["tx_mbps"] if rates and not invalid else None,
                            "stale": False, "reason": reason})
        available = any(item["available"] for item in devices)
        return {"enabled": enabled, "available": available, "devices": devices,
                "sampled_at": cache["sampled_at"], "sample_seconds": cache["sample_seconds"],
                "age_seconds": round(age, 3),
                "source": "ER605 router RX/TX per-IP byte-counter deltas",
                "reason": "" if available else "No selected device has a valid traffic sample."}

    def _cached_result(self, selected, identities, enabled):
        return self._sample_result(selected, identities, enabled)

    def _unavailable(self, selected, reason, enabled=None):
        return {"enabled": enabled, "available": False,
                "devices": [{"mac": mac, "ip": None, "available": False,
                             "rx_mbps": None, "tx_mbps": None, "stale": False,
                             "reason": reason} for mac in selected],
                "sampled_at": None, "sample_seconds": None, "age_seconds": None,
                "source": "ER605 router RX/TX per-IP byte-counter deltas", "reason": reason}

    def _stale_result(self, selected, reason, enabled=None):
        cache = self._cache
        age = None
        if cache:
            age = max(0.0, self.monotonic() - cache["sample_mono"])
        devices = []
        for mac in selected:
            ip = cache["identities"].get(mac) if cache else None
            rates = cache["rates"].get(ip) if cache and ip else None
            devices.append({"mac": mac, "ip": ip, "available": False,
                            "rx_mbps": rates["rx_mbps"] if rates else None,
                            "tx_mbps": rates["tx_mbps"] if rates else None,
                            "stale": bool(rates), "reason": reason})
        return {"enabled": enabled, "available": False, "devices": devices,
                "sampled_at": cache["sampled_at"] if cache else None,
                "sample_seconds": cache["sample_seconds"] if cache else None,
                "age_seconds": round(age, 3) if age is not None else None,
                "source": "ER605 router RX/TX per-IP byte-counter deltas", "reason": reason}
