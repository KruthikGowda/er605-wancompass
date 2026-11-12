"""Bounded, replaceable alert outbox; menu replies use the ordinary queue."""
import json
import logging
import threading
import time
import uuid

log = logging.getLogger(__name__)


class AlertOutbox:
    KEY = "telegram_alert_outbox_v1"

    def __init__(self, store):
        self.store = store
        self.lock = threading.RLock()
        self.rows = {}
        self.persistence_ok = bool(store)
        try:
            rows = json.loads(store.get(self.KEY) or "{}") if store else {}
            if isinstance(rows, dict):
                for key, row in list(rows.items())[:100]:
                    if (isinstance(row, dict) and isinstance(row.get("text"), str)
                            and isinstance(row.get("targets"), list)
                            and all(isinstance(x, str) for x in row["targets"])
                            and isinstance(row.get("created"), (int, float))
                            and isinstance(row.get("next"), (int, float))
                            and isinstance(row.get("attempts"), int) and isinstance(row.get("version"), str)):
                        self.rows[key] = row
        except Exception:
            self.persistence_ok = False
            log.warning("Telegram durable alert queue could not be loaded")

    def _save(self):
        try:
            if self.store is None:
                return
            self.store.set(self.KEY, json.dumps(self.rows))
            self.persistence_ok = True
        except Exception:
            self.persistence_ok = False
            log.warning("Telegram durable alert queue could not be saved")

    def enqueue(self, key, text, targets, critical, now=None):
        now = time.time() if now is None else now
        with self.lock:
            if key not in self.rows and len(self.rows) >= 100:
                return False
            self.rows[key] = {"version": uuid.uuid4().hex, "text": text, "targets": list(targets),
                              "critical": bool(critical), "created": now, "next": now, "attempts": 0}
            self._save()
            return True

    def due(self, allowed, now=None):
        now = time.time() if now is None else now
        with self.lock:
            changed = False
            for key, row in list(self.rows.items()):
                targets = [target for target in row["targets"] if target in allowed]
                if not targets or now - row["created"] >= 86400 or row["created"] > now + 300:
                    del self.rows[key]
                    changed = True
                elif targets != row["targets"]:
                    row["targets"] = targets
                    changed = True
            if changed:
                self._save()
            rows = [(key, row) for key, row in self.rows.items() if row["next"] <= now]
            rows.sort(key=lambda item: (not item[1].get("critical"), item[1]["created"]))
            if not rows:
                return None
            key, row = rows[0]
            return key, {**row, "targets": list(row["targets"])}

    def result(self, key, version, recipient, ok, now=None, retry_after=0):
        now = time.time() if now is None else now
        with self.lock:
            row = self.rows.get(key)
            if not row or row["version"] != version:
                return
            if ok:
                row["targets"] = [target for target in row["targets"] if target != recipient]
                if not row["targets"]:
                    del self.rows[key]
            else:
                row["attempts"] += 1
                row["next"] = now + max(min(3600, retry_after), min(300, 5 * 2 ** min(row["attempts"], 6)))
                # Rotate failed recipients so one unreachable chat cannot block the others.
                row["targets"] = [t for t in row["targets"] if t != recipient] + [recipient]
            self._save()

    def stats(self):
        with self.lock:
            return {"durable_pending": len(self.rows), "durable_store_ok": self.persistence_ok,
                    "oldest_pending_age_seconds": max((max(0, time.time() - r["created"])
                                                       for r in self.rows.values()), default=0)}
