"""Read-only summaries of dry-run WAN recommendations."""

from __future__ import annotations

from contextlib import closing
from datetime import datetime
import re
import sqlite3
import time
from pathlib import Path

MAX_DAYS = 90
MAX_RECOMMENDATION_DETAILS = 100
MAX_METRIC_AGE_SECONDS = 120
FOLLOW_UP_HORIZONS_SECONDS = (300, 900)
FOLLOW_UP_TOLERANCE_SECONDS = 90
SWITCH_RE = re.compile(r"^WOULD SWITCH .*?\((WAN[1-9][0-9]*)\) -> .*?\((WAN[1-9][0-9]*)\):")


def _latest_metric(db: sqlite3.Connection, wan: str,
                   decision_ts: int) -> tuple[int, str, float | None] | None:
    row = db.execute(
        "SELECT ts, state, score FROM wan_minute WHERE wan = ? AND ts <= ? ORDER BY ts DESC LIMIT 1",
        (wan, decision_ts),
    ).fetchone()
    if not row or decision_ts - int(row[0]) > MAX_METRIC_AGE_SECONDS:
        return None
    score = None if row[2] is None else round(float(row[2]), 1)
    return int(row[0]), str(row[1]), score


def _metric_near(db: sqlite3.Connection, wan: str, target_ts: int,
                 report_end: int) -> tuple[int, str, float | None] | None:
    """Return a bounded sample near a follow-up time; never use data past the report end."""
    row = db.execute(
        """SELECT ts, state, score FROM wan_minute
           WHERE wan = ? AND ts BETWEEN ? AND ? AND ts <= ?
           ORDER BY ABS(ts - ?) ASC, ts DESC LIMIT 1""",
        (wan, target_ts - FOLLOW_UP_TOLERANCE_SECONDS,
         target_ts + FOLLOW_UP_TOLERANCE_SECONDS, report_end, target_ts),
    ).fetchone()
    if not row:
        return None
    score = None if row[2] is None else round(float(row[2]), 1)
    return int(row[0]), str(row[1]), score


def _follow_up(db: sqlite3.Connection, source: str | None, target: str | None,
               decision_ts: int, horizon: int, report_end: int) -> dict | None:
    if not source or not target:
        return None
    source_sample = _metric_near(db, source, decision_ts + horizon, report_end)
    target_sample = _metric_near(db, target, decision_ts + horizon, report_end)
    if not source_sample or not target_sample:
        return None
    source_ts, source_state, source_score = source_sample
    target_ts, target_state, target_score = target_sample
    delta = (None if source_score is None or target_score is None
             else round(target_score - source_score, 1))
    return {
        "after_seconds": horizon,
        "source_state": source_state,
        "source_score": source_score,
        "target_state": target_state,
        "target_score": target_score,
        "target_minus_source_score": delta,
        "sample_offset_seconds": max(abs(source_ts - decision_ts - horizon),
                                      abs(target_ts - decision_ts - horizon)),
    }


def summarize(db_path: str, days: int = 7, now: float | None = None,
              recommendation_limit: int | None = None) -> dict:
    """Read sanitized recommendation context from SQLite in read-only mode."""
    if isinstance(days, bool) or not isinstance(days, int) or not 1 <= days <= MAX_DAYS:
        raise ValueError(f"days must be an integer from 1 to {MAX_DAYS}")
    if recommendation_limit is not None and (
            isinstance(recommendation_limit, bool)
            or not isinstance(recommendation_limit, int)
            or not 1 <= recommendation_limit <= MAX_RECOMMENDATION_DETAILS):
        raise ValueError(f"recommendation_limit must be from 1 to {MAX_RECOMMENDATION_DETAILS}")
    end = int(time.time() if now is None else now)
    start = end - days * 86400
    uri = Path(db_path).resolve().as_uri() + "?mode=ro"
    with closing(sqlite3.connect(uri, uri=True, timeout=5)) as db:
        db.execute("PRAGMA query_only=ON")
        total = int(db.execute(
            "SELECT COUNT(*) FROM events WHERE kind = ? AND ts >= ? AND ts < ?",
            ("decision", start, end),
        ).fetchone()[0])
        timestamps = db.execute(
            "SELECT ts FROM events WHERE kind = ? AND ts >= ? AND ts < ? ORDER BY ts",
            ("decision", start, end),
        ).fetchall()
        if recommendation_limit is None:
            rows = db.execute(
                "SELECT ts, wan, message FROM events WHERE kind = ? AND ts >= ? AND ts < ? ORDER BY ts",
                ("decision", start, end),
            ).fetchall()
        else:
            rows = db.execute(
                """SELECT ts, wan, message FROM events WHERE kind = ? AND ts >= ? AND ts < ?
                   ORDER BY ts DESC, id DESC LIMIT ?""",
                ("decision", start, end, recommendation_limit),
            ).fetchall()[::-1]
        recommendations = []
        for timestamp, target, message in rows:
            timestamp = int(timestamp)
            match = SWITCH_RE.match(str(message))
            source_wan = match.group(1) if match else None
            message_target = match.group(2) if match else None
            target_wan = message_target if message_target and message_target == target else None
            source_metric = _latest_metric(db, source_wan, timestamp) if source_wan else None
            target_metric = _latest_metric(db, target_wan, timestamp) if target_wan else None
            message_text = str(message)
            if "OFFLINE, failing over to" in message_text:
                kind = "outage failover"
            elif match and " advantage " in message_text:
                kind = "sustained quality advantage"
            else:
                kind = "trigger unavailable"
            recommendations.append({
                "ts": timestamp,
                "source": source_wan,
                "target": target_wan,
                "kind": kind,
                "source_state": source_metric[1] if source_metric else None,
                "source_score": source_metric[2] if source_metric else None,
                "target_state": target_metric[1] if target_metric else None,
                "target_score": target_metric[2] if target_metric else None,
                "metrics_age_seconds": (max(timestamp - source_metric[0], timestamp - target_metric[0])
                                         if source_metric and target_metric else None),
                "follow_up": [
                    _follow_up(db, source_wan, target_wan, timestamp, horizon, end)
                    for horizon in FOLLOW_UP_HORIZONS_SECONDS
                ],
            })

    daily = {}
    for (timestamp,) in timestamps:
        day = datetime.fromtimestamp(int(timestamp)).date().isoformat()
        daily[day] = daily.get(day, 0) + 1
    return {"days": days, "start": start, "end": end, "total": total,
            "daily": daily, "recommendations": recommendations}
