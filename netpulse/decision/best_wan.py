"""Read-only WAN suggestion prioritizing healthy links and measured latency."""

from __future__ import annotations

import math
from collections.abc import Mapping

from netpulse.freshness import age_seconds

MAX_SAMPLE_AGE_SECONDS = 60
TIE_RTT_MS = 2.0
MIN_SPEED_ADVANTAGE_PERCENT = 15.0
STATE_PRIORITY = {"HEALTHY": 0, "DEGRADED": 1}


def _number(value, minimum: float, maximum: float | None = None) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    result = float(value)
    if not math.isfinite(result) or result < minimum or (maximum is not None and result > maximum):
        return None
    return result


def recommend(wans, updated: float | None, now: float,
              current_wan: str = "AUTO") -> dict | None:
    """Recommend the lowest-latency fresh healthy WAN, with a small tie band.

    This is presentation-only. It does not authorize a route change. Bad, offline,
    unknown, stale, future-dated, and malformed samples cannot be selected.
    """
    age = age_seconds(updated, now)
    if age is None or age > MAX_SAMPLE_AGE_SECONDS or not isinstance(wans, list):
        return None
    candidates = []
    for row in wans:
        if not isinstance(row, Mapping):
            continue
        wan = row.get("name")
        state = str(row.get("state", "")).upper()
        priority = STATE_PRIORITY.get(state)
        rtt = _number(row.get("rtt_ms"), 0)
        loss = _number(row.get("loss_pct"), 0, 100)
        jitter = _number(row.get("jitter_ms"), 0)
        if (not isinstance(wan, str) or not wan or len(wan) > 32 or priority is None
                or rtt is None or loss is None):
            continue
        candidates.append({"wan": wan, "state": state, "state_priority": priority,
                           "rtt_ms": rtt, "loss_pct": loss, "jitter_ms": jitter})
    if not candidates:
        return None
    candidates.sort(key=lambda item: (item["state_priority"], item["rtt_ms"],
                                      item["loss_pct"],
                                      item["jitter_ms"] if item["jitter_ms"] is not None else math.inf,
                                      item["wan"]))
    best = candidates[0]
    # Avoid proposing a device-group move for a tiny RTT difference that is within
    # ordinary probe variation. Retain its current WAN only among equally healthy links.
    current = str(current_wan or "AUTO").upper()
    tied = [item for item in candidates
            if item["state_priority"] == best["state_priority"]
            and item["rtt_ms"] <= best["rtt_ms"] + TIE_RTT_MS]
    selected = next((item for item in tied if item["wan"].upper() == current), best)
    if selected is not best:
        reason = "current WAN retained because RTT difference is within 2 ms"
    elif selected["state"] == "HEALTHY":
        reason = "lower measured RTT among healthy links"
    else:
        reason = "lower measured RTT among degraded links; no healthy link is available"
    return {"wan": selected["wan"], "state": selected["state"],
            "rtt_ms": round(selected["rtt_ms"], 1),
            "loss_pct": round(selected["loss_pct"], 1),
            "jitter_ms": (None if selected["jitter_ms"] is None
                          else round(selected["jitter_ms"], 1)),
            "sample_age_seconds": int(age),
            "reason": reason}


def recommend_group(wans, updated: float | None, now: float,
                    current_wan: str = "AUTO",
                    speed_comparison: Mapping | None = None) -> dict | None:
    """Use comparable two-way throughput only to break a near-equal ping tie.

    The live latency/health recommendation remains primary. Speed tests are useful here only
    when their samples are already confirmed close in time, download and upload favor the same
    WAN, and that WAN has no worse live loss or jitter than the latency candidate. This stays
    read-only and avoids treating old or conflicting active-test results as a universal winner.
    """
    latency = recommend(wans, updated, now, current_wan)
    if not latency or not isinstance(speed_comparison, Mapping):
        return latency
    winner = speed_comparison.get("download_winner")
    if (not isinstance(winner, str) or winner.upper() not in ("WAN1", "WAN2")
            or str(speed_comparison.get("upload_winner", "")).upper() != winner.upper()
            or _number(speed_comparison.get("download_advantage_pct"), 0) is None
            or float(speed_comparison["download_advantage_pct"]) < MIN_SPEED_ADVANTAGE_PERCENT
            or _number(speed_comparison.get("upload_advantage_pct"), 0) is None
            or float(speed_comparison["upload_advantage_pct"]) < MIN_SPEED_ADVANTAGE_PERCENT
            or winner.upper() == str(latency["wan"]).upper()):
        return latency
    rows = {str(row.get("name", "")).upper(): row for row in wans
            if isinstance(row, Mapping)} if isinstance(wans, list) else {}
    alternative = rows.get(winner.upper())
    chosen = rows.get(str(latency["wan"]).upper())
    if not alternative or not chosen:
        return latency
    alt_state, chosen_state = (str(alternative.get("state", "")).upper(),
                               str(chosen.get("state", "")).upper())
    alt_rtt = _number(alternative.get("rtt_ms"), 0)
    chosen_rtt = _number(chosen.get("rtt_ms"), 0)
    alt_loss = _number(alternative.get("loss_pct"), 0, 100)
    chosen_loss = _number(chosen.get("loss_pct"), 0, 100)
    alt_jitter = _number(alternative.get("jitter_ms"), 0)
    chosen_jitter = _number(chosen.get("jitter_ms"), 0)
    if (alt_state != chosen_state or alt_rtt is None or chosen_rtt is None
            or abs(alt_rtt - chosen_rtt) > TIE_RTT_MS
            or alt_loss is None or chosen_loss is None or alt_loss > chosen_loss
            or (alt_jitter is not None and chosen_jitter is not None
                and alt_jitter > chosen_jitter)):
        return latency
    return {"wan": alternative["name"], "state": alt_state,
            "rtt_ms": round(alt_rtt, 1), "loss_pct": round(alt_loss, 1),
            "jitter_ms": None if alt_jitter is None else round(alt_jitter, 1),
            "sample_age_seconds": latency["sample_age_seconds"],
            "reason": "comparable recent throughput wins download and upload by at least 15% and breaks a ping tie within 2 ms"}
