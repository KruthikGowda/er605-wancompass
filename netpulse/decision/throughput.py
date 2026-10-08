"""Fresh, read-only throughput evidence for WAN comparisons."""

from __future__ import annotations

import math
from collections.abc import Mapping

from netpulse.freshness import age_seconds

MAX_SPEED_SAMPLE_AGE_SECONDS = 24 * 60 * 60


def _finite_number(value, *, positive: bool = False) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    result = float(value)
    if not math.isfinite(result) or result < 0 or (positive and result <= 0):
        return None
    return result


def latest_recent_success(rows, now: float,
                         max_age_seconds: int = MAX_SPEED_SAMPLE_AGE_SECONDS) -> dict[str, dict]:
    """Return each WAN's latest successful speed test while it is at most one day old."""
    if not isinstance(rows, list):
        return {}
    latest: dict[str, tuple[float, dict]] = {}
    for row in rows:
        if not isinstance(row, Mapping) or row.get("error") not in (None, ""):
            continue
        wan, ts = row.get("wan"), row.get("ts")
        age = age_seconds(ts, now)
        down = _finite_number(row.get("down_mbps"), positive=True)
        up = _finite_number(row.get("up_mbps"))
        if (not isinstance(wan, str) or not wan or len(wan) > 32 or age is None
                or age > max_age_seconds or down is None):
            continue
        loaded = _finite_number(row.get("loaded_ms"))
        idle = _finite_number(row.get("idle_ms"))
        sample = {"down_mbps": round(down, 1),
                  "up_mbps": None if up is None else round(up, 1),
                  "loaded_ms": None if loaded is None else round(loaded, 1),
                  "idle_ms": None if idle is None else round(idle, 1),
                  "age_seconds": int(age)}
        if wan not in latest or float(ts) > latest[wan][0]:
            latest[wan] = (float(ts), sample)
    return {wan: sample for wan, (_, sample) in latest.items()}


def compare_recent_samples(samples: Mapping[str, Mapping],
                           max_skew_seconds: int = 15 * 60) -> dict | None:
    """Compare two close-in-time successful tests; do not rank unrelated time windows."""
    if not isinstance(samples, Mapping) or len(samples) != 2:
        return None
    names = sorted(samples)
    first, second = (samples[name] for name in names)
    first_age = _finite_number(first.get("age_seconds")) if isinstance(first, Mapping) else None
    second_age = _finite_number(second.get("age_seconds")) if isinstance(second, Mapping) else None
    if (first_age is None or second_age is None
            or abs(first_age - second_age) > max_skew_seconds):
        return None

    def winner(field: str):
        a, b = _finite_number(first.get(field)), _finite_number(second.get(field))
        if a is None or b is None:
            return None
        if a == b:
            return "tie"
        return names[0] if a > b else names[1]

    def advantage_percent(field: str, winner_name):
        if winner_name in (None, "tie"):
            return None
        a, b = (_finite_number(first.get(field)), _finite_number(second.get(field)))
        denominator = max(a or 0.0, b or 0.0)
        if a is None or b is None or denominator <= 0:
            return None
        return round(abs(a - b) * 100.0 / denominator, 1)

    down_winner, up_winner = winner("down_mbps"), winner("up_mbps")
    return {"wan1": names[0], "wan2": names[1],
            "sample_skew_seconds": int(abs(first_age - second_age)),
            "download_winner": down_winner, "upload_winner": up_winner,
            "download_gap_mbps": (None if down_winner in (None, "tie") else
                                  round(abs(float(first["down_mbps"]) - float(second["down_mbps"])), 1)),
            "upload_gap_mbps": (None if up_winner in (None, "tie") else
                                round(abs(float(first["up_mbps"]) - float(second["up_mbps"])), 1)),
            "download_advantage_pct": advantage_percent("down_mbps", down_winner),
            "upload_advantage_pct": advantage_percent("up_mbps", up_winner)}
