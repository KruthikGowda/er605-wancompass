"""Shared wall-clock freshness checks for externally observed samples."""

from __future__ import annotations

import math


def age_seconds(timestamp, now: float) -> float | None:
    """Return a finite, nonnegative age; future or malformed timestamps are unknown."""
    if isinstance(timestamp, bool):
        return None
    try:
        age = float(now) - float(timestamp)
    except (TypeError, ValueError, OverflowError):
        return None
    return age if math.isfinite(age) and age >= 0 else None
