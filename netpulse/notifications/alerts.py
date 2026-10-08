"""Alert policy: quiet hours, mute, and per-key rate limiting.

Critical alerts (a connection went down / came back) always go through.
Everything else respects quiet hours and mute, and is rate-limited by alert key.
Router DHCP lease changes held during quiet hours remain in the event log and are summarized
in the next daily digest; other held alerts are not replayed.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from typing import Protocol

from netpulse.config import TelegramConfig, parse_hhmm
from netpulse.notifications.base import DEVICE_NOTICE_CATEGORY, Notifier

log = logging.getLogger(__name__)

RATE_LIMIT_SECONDS = 300
PERSISTED_RATE_LIMITS_KEY = "alert_rate_limits_v1"
PERSISTED_RATE_LIMIT_TTL_SECONDS = 7 * 24 * 60 * 60
MAX_PERSISTED_RATE_LIMITS = 1024


class RateLimitStore(Protocol):
    def get(self, key: str) -> str | None: ...
    def set(self, key: str, value: str) -> None: ...


def in_quiet_hours(minute_of_day: int, start: int, end: int) -> bool:
    if start == end:
        return False
    if start < end:
        return start <= minute_of_day < end
    return minute_of_day >= start or minute_of_day < end  # wraps midnight


class Alerter:
    def __init__(self, notifier: Notifier, cfg: TelegramConfig,
                 rate_limit_store: RateLimitStore | None = None):
        self.notifier = notifier
        self.quiet = (parse_hhmm(cfg.quiet_start), parse_hhmm(cfg.quiet_end))
        self._muted_until = 0.0
        self._last_sent: dict[str, float] = {}
        self._lock = threading.Lock()
        self._rate_lock = threading.Lock()
        self._rate_limit_store = rate_limit_store
        self._persistent_last_sent: dict[str, float] = {}
        self._persistent_store_failed = False
        self._suppression_lock = threading.Lock()
        self._suppressed = {"mute": 0, "quiet_hours": 0, "rate_limited": 0}
        self._category_suppressed = {
            DEVICE_NOTICE_CATEGORY: {"mute": 0, "quiet_hours": 0, "rate_limited": 0}
        }
        if rate_limit_store:
            try:
                raw = rate_limit_store.get(PERSISTED_RATE_LIMITS_KEY)
                values = json.loads(raw) if raw else {}
                if isinstance(values, dict):
                    for key, value in values.items():
                        if (isinstance(key, str) and isinstance(value, (int, float))
                                and value > 0):
                            self._persistent_last_sent[key] = float(value)
            except Exception:  # noqa: BLE001 - notification must survive a bad cooldown cache
                self._persistent_store_failed = True
                log.warning("persistent alert rate limits could not be loaded")

    def mute(self, seconds: float) -> None:
        with self._lock:
            self._muted_until = time.time() + seconds

    def unmute(self) -> None:
        with self._lock:
            self._muted_until = 0.0

    def muted_until(self) -> float:
        with self._lock:
            return self._muted_until if self._muted_until > time.time() else 0.0

    def suppression_counts(self) -> dict[str, int]:
        """Return process-lifetime, privacy-safe counts of non-critical alert suppression."""
        with self._suppression_lock:
            return dict(self._suppressed)

    def category_suppression_counts(self, category: str) -> dict[str, int]:
        """Return counts for a fixed, identity-free alert category."""
        with self._suppression_lock:
            return dict(self._category_suppressed.get(category, {}))

    def _count_suppressed(self, reason: str, category: str | None = None) -> None:
        with self._suppression_lock:
            self._suppressed[reason] += 1
            if category in self._category_suppressed:
                self._category_suppressed[category][reason] += 1

    def alert(self, text: str, key: str, critical: bool = False, now: float | None = None,
              rate_limit_seconds: float = RATE_LIMIT_SECONDS,
              persist_rate_limit: bool = False,
              delivery_category: str | None = None) -> bool:
        """Send unless suppressed. Returns True if sent."""
        now = now or time.time()
        if not critical:
            if self.muted_until():
                self._count_suppressed("mute", delivery_category)
                log.info("non-critical alert held by mute policy")
                return False
            lt = time.localtime(now)
            if in_quiet_hours(lt.tm_hour * 60 + lt.tm_min, *self.quiet):
                self._count_suppressed("quiet_hours", delivery_category)
                log.info("non-critical alert held by quiet-hours policy")
                return False
            with self._rate_lock:
                last_sent = self._last_sent.get(key, 0.0)
                if persist_rate_limit:
                    last_sent = max(last_sent, self._persistent_last_sent.get(key, 0.0))
                if now - last_sent < max(0.0, float(rate_limit_seconds)):
                    self._count_suppressed("rate_limited", delivery_category)
                    category = (delivery_category if delivery_category in self._category_suppressed
                                else "other")
                    log.info("alert rate-limited (category=%s)", category)
                    return False
                self._last_sent[key] = now
                if persist_rate_limit and self._rate_limit_store:
                    self._remember_persistent(key, now)
        else:
            with self._rate_lock:
                self._last_sent[key] = now
        categorized = getattr(self.notifier, "send_categorized", None)
        if delivery_category in self._category_suppressed and callable(categorized):
            categorized(text, delivery_category)
        else:
            self.notifier.send(text)
        return True

    def _remember_persistent(self, key: str, now: float) -> None:
        """Persist a bounded set of opted-in cooldowns; storage failure never blocks alerts."""
        if not self._rate_limit_store or self._persistent_store_failed:
            return
        self._persistent_last_sent = {
            k: ts for k, ts in self._persistent_last_sent.items()
            if now - ts <= PERSISTED_RATE_LIMIT_TTL_SECONDS
        }
        self._persistent_last_sent[key] = now
        if len(self._persistent_last_sent) > MAX_PERSISTED_RATE_LIMITS:
            oldest = sorted(self._persistent_last_sent.items(), key=lambda item: item[1])
            self._persistent_last_sent = dict(oldest[-MAX_PERSISTED_RATE_LIMITS:])
        try:
            self._rate_limit_store.set(
                PERSISTED_RATE_LIMITS_KEY,
                json.dumps(self._persistent_last_sent, separators=(",", ":")),
            )
        except Exception:  # noqa: BLE001 - notification must survive a storage error
            self._persistent_store_failed = True
            log.warning("persistent alert rate limits could not be saved")
