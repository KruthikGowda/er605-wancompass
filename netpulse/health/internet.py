"""Confirmed Internet incidents, independent of ping quality and routing decisions."""
from __future__ import annotations

import json
import logging

log = logging.getLogger(__name__)


class InternetIncidents:
    def __init__(self, store):
        self.store = store
        self.rows = {}
        self.persistence_ok = True
        try:
            rows = json.loads(store.get("internet_incidents_v1") or "{}")
            if isinstance(rows, dict):
                self.rows = {name: row for name, row in rows.items() if isinstance(row, dict)
                             and isinstance(row.get("last"), (int, float))
                             and isinstance(row.get("count"), int)
                             and isinstance(row.get("since"), (int, float))}
        except Exception as exc:
            self.persistence_ok = False
            log.warning("Internet incident state unavailable (%s)", type(exc).__name__)

    def save(self):
        try:
            self.store.set("internet_incidents_v1", json.dumps(self.rows))
            self.persistence_ok = True
        except Exception as exc:
            self.persistence_ok = False
            log.warning("Internet incident state could not be saved (%s)", type(exc).__name__)

    def observe(self, wan, state, checked_at):
        family = ("ONLINE" if state == "ONLINE" else "PARTIAL" if state == "PARTIAL"
                  else "MONITOR_ERROR" if state == "MONITOR_ERROR" else "UNUSABLE")
        row = self.rows.setdefault(wan, {"last": 0, "family": "", "count": 0,
                                         "announced": "", "since": checked_at})
        if checked_at <= row["last"]:
            return None
        contiguous = checked_at - row["last"] <= 180
        if row.get("family") == family and contiguous:
            row["count"] += 1
        else:
            row.update(family=family, count=1, since=checked_at)
        row["last"] = checked_at
        self.save()
        threshold = 3 if family == "PARTIAL" else 2
        if row["count"] < threshold:
            return None
        announced = row.get("announced", "")
        if (family == "ONLINE" and announced) or (family != "ONLINE" and family != announced):
            return {"family": family, "state": state, "since": row["since"],
                    "recovered": family == "ONLINE"}
        return None

    def acknowledge(self, wan, event):
        self.rows[wan]["announced"] = "" if event["recovered"] else event["family"]
        self.save()
