"""Interpret local ping results without claiming that silence means a device is offline."""

from __future__ import annotations

import threading
from collections import OrderedDict
from math import ceil

from netpulse.storage.sqlite import KeyValueFile

MAX_TRACKED_DEVICES = 512


class PresenceSettings:
    """Persist the owner's optional LAN-ping choice without editing TOML or touching the router."""

    KEY = "lan_presence_probes_enabled"

    def __init__(self, db_path: str, available: bool, default_enabled: bool = False):
        self.available = bool(available)
        self._store = KeyValueFile(db_path)
        stored = self._store.get(self.KEY)
        self._enabled = stored == "1" if stored in ("0", "1") else bool(default_enabled)
        self._lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        with self._lock:
            return self.available and self._enabled

    def set_enabled(self, enabled: bool) -> bool:
        if not isinstance(enabled, bool):
            raise ValueError("Enabled must be true or false.")
        if enabled and not self.available:
            raise ValueError("Router monitoring is unavailable; LAN ping hints cannot be enabled.")
        with self._lock:
            self._store.set(self.KEY, "1" if enabled else "0")
            self._enabled = enabled
        return self.enabled


class PresenceTracker:
    def __init__(self, confirm_misses: int = 3, confirm_replies: int = 2,
                 probe_interval_seconds: int = 60):
        self.confirm_misses = max(2, min(int(confirm_misses), 10))
        self.confirm_replies = max(1, min(int(confirm_replies), 5))
        self.probe_interval_seconds = max(1, int(probe_interval_seconds))
        self.recovery_max_gap = max(30, int(self.probe_interval_seconds * 2.5))
        self._states: OrderedDict[str, dict] = OrderedDict()

    def observe(self, results: dict[str, dict], scan_rounds: int = 1) -> list[tuple[str, str, str]]:
        """Apply a scan; return (mac, transition, ip) for confirmed state changes."""
        if isinstance(scan_rounds, bool) or not isinstance(scan_rounds, int):
            scan_rounds = 1
        scan_rounds = max(1, min(scan_rounds, 4))
        recovery_max_gap = max(self.recovery_max_gap,
                               int(ceil(self.probe_interval_seconds * 2.5 * scan_rounds)))
        transitions = []
        for mac, result in results.items():
            if not isinstance(result, dict):
                # Probe failures do not count as device silence.
                continue
            if result.get("response") not in (True, False):
                current = self._states.get(mac)
                if current and current["state"] == "no_reply":
                    current["recovery_replies"] = 0
                continue
            ip = str(result.get("ip") or "")
            checked_at = result.get("checked_at")
            current = self._states.get(mac)
            if current is None or current["ip"] != ip:
                self._states.pop(mac, None)
                while len(self._states) >= MAX_TRACKED_DEVICES:
                    self._states.popitem(last=False)
                current = {"ip": ip, "state": "unknown", "misses": 0,
                           "checked_at": None, "last_reply_at": None,
                           "recovery_replies": 0}
                self._states[mac] = current
            else:
                self._states.move_to_end(mac)
            previous_checked_at = current.get("checked_at")
            if (current["state"] == "no_reply" and current["recovery_replies"]
                    and isinstance(checked_at, (int, float))
                    and isinstance(previous_checked_at, (int, float))
                    and checked_at - previous_checked_at > recovery_max_gap):
                current["recovery_replies"] = 0
            current["checked_at"] = checked_at
            if result["response"]:
                if current["state"] == "no_reply":
                    current["recovery_replies"] += 1
                    if current["recovery_replies"] < self.confirm_replies:
                        continue
                    transitions.append((mac, "reply_restored", ip))
                current["state"] = "replying"
                current["misses"] = 0
                current["recovery_replies"] = 0
                current["last_reply_at"] = checked_at
            elif current["state"] == "replying":
                current["misses"] += 1
                if current["misses"] >= self.confirm_misses:
                    current["state"] = "no_reply"
                    current["recovery_replies"] = 0
                    transitions.append((mac, "no_reply", ip))
            elif current["state"] == "no_reply":
                current["misses"] += 1
                current["recovery_replies"] = 0
        return transitions

    def snapshot(self) -> dict[str, dict]:
        return {mac: dict(state) for mac, state in self._states.items()}
