"""Plain-language summaries shared by the dashboard, Telegram digests and weekly report."""

from __future__ import annotations

import re
import time

from netpulse.config import parse_hhmm
from netpulse.notifications.alerts import in_quiet_hours
from netpulse.freshness import age_seconds
from netpulse.probes.connectivity import RESULT_MAX_AGE_SECONDS, result_is_fresh

SERVER_NAMES = {
    "1.1.1.1": "Cloudflare", "1.0.0.1": "Cloudflare",
    "8.8.8.8": "Google", "8.8.4.4": "Google",
    "9.9.9.9": "Quad9", "149.112.112.112": "Quad9",
}
STATE_EMOJI = {"HEALTHY": "🟢", "DEGRADED": "🟡", "BAD": "🟠", "OFFLINE": "🔴", "UNKNOWN": "⚪"}
STATE_WORD = {"DEGRADED": "slow", "BAD": "bad", "OFFLINE": "down"}
SEVERITY = {"UNKNOWN": 0, "HEALTHY": 1, "DEGRADED": 2, "BAD": 3, "OFFLINE": 4}


def server_name(ip: str) -> str:
    return SERVER_NAMES.get(ip, ip)


_REASON_RULES = [
    (re.compile(r"loss (\d+)% >= [\d.]+%"), r"\1% of packets lost"),
    (re.compile(r"RTT (\d+) ms >= [\d.]+ ms"), r"responses take \1 ms"),
    (re.compile(r"RTT ([\d.]+)x baseline"), r"\1× slower than usual"),
    (re.compile(r"jitter (\d+) ms >= [\d.]+ ms"), r"uneven timing (\1 ms)"),
    (re.compile(r"all (\d+) targets failed for (\d+) cycles"), r"no answer from any test server"),
]


def plain_reason(reason: str) -> str:
    """'loss 15% >= 5%' -> '15% of packets lost' (evaluator reasons in household words)."""
    for pattern, words in _REASON_RULES:
        reason = pattern.sub(words, reason)
    return reason


def plain_decision(reason: str, labels: dict[str, str]) -> str:
    """Decision-engine reasons in household words, with ISP names instead of WAN1/WAN2."""
    m = re.match(r"(\w+) OFFLINE, failing over to (\w+)", reason)
    if m:
        return f"{labels.get(m[1], m[1])} is down, so {labels.get(m[2], m[2])} is the better choice right now."
    m = re.match(r"(\w+) advantage \+(\d+) persisted (\d+)s", reason)
    if m:
        return (f"{labels.get(m[1], m[1])} has been clearly better for {int(m[3]) // 60} min "
                f"(quality score {m[2]} points higher).")
    for wan, label in labels.items():
        reason = reason.replace(wan, label)
    return reason


def _label(w: dict) -> str:
    return w.get("label") or w["name"]


def headline(snapshot: dict) -> dict:
    """One line for the top of the dashboard / first line of a status message."""
    wans = snapshot.get("wans") or []
    if not wans or all(w["state"] == "UNKNOWN" for w in wans):
        return {"level": "UNKNOWN", "emoji": "⚪", "text": "Starting up: collecting data"}

    worst = max(wans, key=lambda w: SEVERITY[w["state"]])
    if worst["state"] == "HEALTHY":
        return {"level": "HEALTHY", "emoji": "🟢", "text": "All good: both connections are healthy"}

    problems = [w for w in wans if SEVERITY[w["state"]] >= SEVERITY["DEGRADED"]]
    if len(problems) == len(wans):
        text = "Both connections have problems: " + ", ".join(
            f"{_label(w)} is {STATE_WORD[w['state']]}" for w in problems)
    else:
        text = f"{_label(worst)} is {STATE_WORD[worst['state']]}"
        good = [w for w in wans if w["state"] == "HEALTHY"]
        if good:
            text += f": {' and '.join(_label(w) for w in good)} is fine"
    d = snapshot.get("decision")
    rec = next((_label(w) for w in wans if d and w["name"] == d.get("current")), None)
    if rec:
        text += f". Best for critical devices: {rec}"
    return {"level": worst["state"], "emoji": STATE_EMOJI[worst["state"]], "text": text}


def _fmt(v, digits=0, unit=""):
    return "–" if v is None else f"{v:.{digits}f}{unit}"


def _loss_words(loss) -> str:
    if loss is None:
        return "–"
    if loss < 0.5:
        return "no packet loss"
    return f"{loss:.1f}% packets lost" if loss < 2 else f"{loss:.0f}% packets lost"


def status_text(snapshot: dict) -> str:
    """Short and plain when all is well; adds the 'why' and per-server numbers only for problems."""
    h = headline(snapshot)
    lines = [f"{h['emoji']} {h['text']}", ""]
    for w in snapshot.get("wans", []):
        lines.append(f"{STATE_EMOJI[w['state']]} {_label(w)}: {_fmt(w['rtt_ms'], 0, ' ms')} · {_loss_words(w['loss_pct'])}")
        connectivity = w.get("connectivity")
        if (isinstance(connectivity, dict)
                and result_is_fresh(connectivity.get("checked_at"), time.time())):
            checked_age = age_seconds(connectivity["checked_at"], time.time())

            def reachability(value):
                return "reachable" if value is True else "failed" if value is False else "unknown"

            checks = [f"direct DNS {reachability(connectivity.get('dns_ok'))}",
                      f"HTTPS {reachability(connectivity.get('https_ok'))}"]
            if isinstance(connectivity.get("wan_dns_ok"), bool):
                checks.insert(1, f"ISP DNS {reachability(connectivity['wan_dns_ok'])}")
            icmp_state = str(connectivity.get("icmp_state", "UNKNOWN")).upper()
            if icmp_state not in STATE_EMOJI:
                icmp_state = "UNKNOWN"
            lines.append(f"   DNS/HTTPS ({_age(checked_age)} ago; ICMP {icmp_state.lower()} at sample): "
                         + " · ".join(checks))
        if w["state"] not in ("HEALTHY", "UNKNOWN"):
            if w.get("reasons"):
                lines.append(f"   why: {'; '.join(plain_reason(r) for r in w['reasons'])}")
            servers = " · ".join(f"{server_name(t['target'])} {_fmt(t['rtt_ms'], 0)}" for t in w.get("targets", []))
            if servers:
                lines.append(f"   {servers} ms")
        if w.get("errors"):
            lines.append(f"   ⚠️ {'; '.join(w['errors'])}")
    router = router_line(snapshot.get("router"), wan_labels={w["name"]: _label(w)
                                                             for w in snapshot.get("wans", [])})
    if router:
        lines += ["", router]
    policy_line = alert_policy_line(snapshot)
    if policy_line:
        lines += ["", policy_line]
    updated = snapshot.get("updated")
    if updated:
        lines += ["", f"Updated {time.strftime('%H:%M:%S', time.localtime(updated))}"]
    return "\n".join(lines)


def alert_policy_line(snapshot: dict, now: float | None = None) -> str | None:
    """Explain whether Telegram's non-critical notices are active, muted, or in quiet hours."""
    policy = snapshot.get("alert_policy")
    if not isinstance(policy, dict) or not isinstance(policy.get("telegram_enabled"), bool):
        return None
    if not policy["telegram_enabled"]:
        return "Telegram alerts are disabled."

    def with_suppression_counts(text: str) -> str:
        counts = policy.get("suppressed_since_start")
        if isinstance(counts, dict):
            mute = max(0, int(counts.get("mute", 0) or 0))
            quiet = max(0, int(counts.get("quiet_hours", 0) or 0))
            limited = max(0, int(counts.get("rate_limited", 0) or 0))
            if mute + quiet + limited:
                text += (f" Since NetPulse started: {mute} held by mute, {quiet} by quiet hours, "
                         f"{limited} rate-limited.")
        delivery = policy.get("delivery_since_start")
        if isinstance(delivery, dict):
            accepted = max(0, int(delivery.get("accepted", 0) or 0))
            failed = max(0, int(delivery.get("failed", 0) or 0))
            dropped = max(0, int(delivery.get("queue_dropped", 0) or 0))
            queued = max(0, int(delivery.get("queued", 0) or 0))
            text += (f" Telegram API accepted {accepted} recipient message(s) since service start; "
                     f"{queued} queued, {failed} failed after retries, {dropped} dropped before sending.")
            categories = delivery.get("categories")
            device = categories.get("device_notice") if isinstance(categories, dict) else None
            if isinstance(device, dict):
                device_accepted = max(0, int(device.get("accepted", 0) or 0))
                device_failed = max(0, int(device.get("failed", 0) or 0))
                device_dropped = max(0, int(device.get("queue_dropped", 0) or 0))
                device_queued = max(0, int(device.get("queued", 0) or 0))
                device_held = policy.get("device_notice_suppressed_since_start")
                if not isinstance(device_held, dict):
                    device_held = {}
                held_mute = max(0, int(device_held.get("mute", 0) or 0))
                held_quiet = max(0, int(device_held.get("quiet_hours", 0) or 0))
                held_rate = max(0, int(device_held.get("rate_limited", 0) or 0))
                text += (f" Device notices: {device_accepted} accepted by Telegram, {device_queued} queued, "
                         f"{device_failed} failed after retries, {device_dropped} dropped; "
                         f"{held_mute} muted, {held_quiet} held by quiet hours, {held_rate} rate-limited.")
        return text

    now = time.time() if now is None else float(now)
    muted_until = snapshot.get("muted_until")
    if isinstance(muted_until, (int, float)) and muted_until > now:
        until = time.strftime("%H:%M", time.localtime(muted_until))
        return with_suppression_counts(
            f"Non-critical alerts, including device notices, are muted until {until}; "
            "WAN down/recovery alerts still send.")

    start_text = str(policy.get("quiet_start") or "")
    end_text = str(policy.get("quiet_end") or "")
    try:
        start, end = parse_hhmm(start_text), parse_hhmm(end_text)
    except ValueError:
        return "Alert quiet-hour settings are unavailable."
    if start == end:
        return with_suppression_counts(
            "Non-critical alerts, including device notices, are active; daily quiet hours are off.")
    local = time.localtime(now)
    minute = local.tm_hour * 60 + local.tm_min
    if in_quiet_hours(minute, start, end):
        return with_suppression_counts(
            f"Non-critical alerts, including device notices, are in quiet hours until {end_text}; "
            "WAN down/recovery alerts still send.")
    return with_suppression_counts(
        f"Non-critical alerts, including device notices, are active; quiet hours start at "
        f"{start_text} Pi local time.")


def _age(seconds: float) -> str:
    seconds = max(0, int(seconds))
    if seconds < 90:
        return f"{seconds} s"
    if seconds < 5400:
        return f"{seconds // 60} min"
    if seconds < 2 * 86400:
        return f"{seconds // 3600} h {seconds % 3600 // 60} min"
    return f"{seconds // 86400} d {seconds % 86400 // 3600} h"


def router_line(r: dict | None, now: float | None = None,
                wan_labels: dict[str, str] | None = None) -> str | None:
    """One-line ER605 summary for Telegram status."""
    if not r:
        return None
    now = time.time() if now is None else now
    if not r.get("ok"):
        line = f"🛜 Router: not reachable ({r.get('error') or 'unknown error'})"
    else:
        parts = []
        if r.get("uptime") is not None:
            uptime_at = r.get("uptime_at")
            uptime_age = age_seconds(uptime_at, now) if uptime_at is not None else 0
            if uptime_age is not None:
                up = r["uptime"] + uptime_age
                parts.append(f"up {_age(up)}")
        if r.get("firmware_version"):
            parts.append(f"firmware {r['firmware_version']}")
        if r.get("cpu_pct") is not None:
            parts.append(f"CPU {r['cpu_pct']:.0f}%")
        if r.get("mem_pct") is not None:
            parts.append(f"memory {r['mem_pct']:.0f}%")
        if r.get("clients") is not None:
            parts.append(f"{r['clients']} devices")
        line = "🛜 Router: " + " · ".join(parts)
    links = r.get("links")
    checked_at = r.get("checked_at")
    if isinstance(links, dict) and links:
        labels = wan_labels or {}
        link_age = age_seconds(checked_at, now) if checked_at is not None else None
        max_age = r.get("links_max_age_seconds", 1200)
        freshness = (f"last read {_age(link_age)} ago" if link_age is not None
                     else "stale · read time invalid or in the future")
        if link_age is not None and link_age > max_age:
            freshness = "stale · " + freshness
        reports = []
        for name, state in links.items():
            if not isinstance(state, dict):
                continue
            up = state.get("up")
            word = "Online" if up is True else "Offline" if up is False else "unknown"
            reports.append(f"{labels.get(name, name)} {word}")
        if reports:
            line += f"\n   ER605-reported WAN status ({freshness}): " + " · ".join(reports)
        interface_reports = []
        for name, state in links.items():
            if not isinstance(state, dict) or state.get("interface_up") is None:
                continue
            flag = "up" if state["interface_up"] else "down"
            interface_reports.append(f"{labels.get(name, name)} {flag}")
        if interface_reports:
            line += "\n   ER605 interface flags (not Internet reachability): " + " · ".join(interface_reports)
    checked_at = r.get("checked_at")
    max_age = r.get("links_max_age_seconds", 1200)
    if checked_at is not None:
        age = age_seconds(checked_at, now)
        inventory = (f"📱 Device list: last successful scan {_age(age)} ago"
                     if age is not None else
                     "📱 Device list: stale; scan timestamp is invalid or in the future")
        if age is not None and age > max_age:
            inventory += "; stale"
        if r.get("paused_until"):
            inventory += "; next scan paused"
        elif r.get("next_check") is not None:
            inventory += f"; next check in {_age(max(0, r['next_check'] - now))}"
        elif not r.get("ok"):
            inventory += "; next scan waits for router recovery"
        line += "\n   " + inventory
    elif r.get("next_check") is not None and r.get("next_check") > 0:
        line += f"\n   📱 Device list: no successful scan yet; next check in {_age(max(0, r['next_check'] - now))}"
    if r.get("paused_until"):
        line += f"\n   🛠 checks paused until {time.strftime('%H:%M', time.localtime(r['paused_until']))}"
    elif r.get("error"):
        line += f"\n   ⚠️ {r['error']}"
    control = r.get("control")
    if isinstance(control, dict) and control.get("firmware_review_required"):
        line += f"\n   ⚠️ {control.get('firmware_reason') or 'ER605 firmware needs review; route controls are locked.'}"
    return line


PI_CAP_NOTE = "Speeds above what the Pi can handle (about 220 Mbps) show as about that."


def is_dip(r: dict, usual: float | None, dip_pct: float) -> bool:
    return (not r.get("error") and usual is not None and r.get("down_mbps") is not None
            and r["down_mbps"] < usual * dip_pct / 100)


def speed_line(r: dict, name: str, usual: float | None = None, dip_pct: float = 50) -> str:
    if r.get("error"):
        return f"⚠️ {name}: test failed ({r['error']})"
    parts = [f"⬇ {_fmt(r.get('down_mbps'), 0)} Mbps", f"⬆ {_fmt(r.get('up_mbps'), 0)} Mbps"]
    bloat = r.get("bufferbloat_ms")
    if bloat is None and r.get("loaded_ms") is not None and r.get("idle_ms") is not None:
        bloat = max(0.0, r["loaded_ms"] - r["idle_ms"])
    if bloat is not None:
        parts.append("no extra lag when busy" if bloat < 20 else f"+{bloat:.0f} ms lag when busy")
    line = f"{'📉' if is_dip(r, usual, dip_pct) else '⚡'} {name}: " + " · ".join(parts)
    if usual is not None:
        line += f"\n   usual ⬇ {usual:.0f} Mbps"
    return line


def speed_text(results: list[dict], labels: dict[str, str], usual: dict[str, float | None],
               dip_pct: float = 50, title: str = "⚡ Speed test results") -> str:
    lines = [title, ""]
    for r in results:
        lines.append(speed_line(r, labels.get(r["wan"], r["wan"]), usual.get(r["wan"]), dip_pct))
    lines += ["", PI_CAP_NOTE]
    return "\n".join(lines)


def _duration(minutes: int) -> str:
    if minutes < 60:
        return f"{minutes} min"
    return f"{minutes // 60} h {minutes % 60} min" if minutes % 60 else f"{minutes // 60} h"


def digest_text(summary: dict, labels: dict[str, str], title: str,
                speeds: list[dict] | None = None, device_events: list[dict] | None = None,
                more_device_events: bool = False, device_event_period: str = "last 24 hours") -> str:
    """Format WAN, speed, and concise router lease-change summaries."""
    lines = [title, ""]
    verdicts = []
    for wan, s in summary["wans"].items():
        name = labels.get(wan, wan)
        m = s["minutes"]
        total = sum(m.values()) or 1
        online = 100 * (total - m.get("OFFLINE", 0)) / total
        healthy = 100 * m.get("HEALTHY", 0) / total
        problem_min = m.get("DEGRADED", 0) + m.get("BAD", 0) + m.get("OFFLINE", 0)
        emoji = "🟢" if healthy >= 98 else "🟡" if healthy >= 90 else "🟠" if online >= 95 else "🔴"
        lines.append(f"{emoji} {name} ({wan})")
        lines.append(f"   online {online:.1f}% · healthy {healthy:.1f}%")
        lines.append(f"   typical latency {_fmt(s['rtt_avg'], 0, ' ms')} · avg loss {_fmt(s['loss_avg'], 1, '%')}")
        parts = [f"{label} {_duration(m[state])}" for state, label in
                 (("DEGRADED", "slow"), ("BAD", "bad"), ("OFFLINE", "down")) if m.get(state)]
        if parts:
            lines.append(f"   problems: {', '.join(parts)}")
        if s["outages"]:
            lines.append(f"   went down {s['outages']}×")
        w = s.get("worst_hour")
        if w and (w["loss"] >= 2 or (s["rtt_avg"] and w["rtt"] and w["rtt"] > 2 * s["rtt_avg"])):
            hour = time.strftime("%H:00", time.localtime(w["ts"]))
            lines.append(f"   worst hour {hour}: {_fmt(w['rtt'], 0, ' ms')}, {_fmt(w['loss'], 1, '% loss')}")
        ok = [x["down_mbps"] for x in (speeds or []) if x["wan"] == wan and not x.get("error") and x.get("down_mbps")]
        if ok:
            lines.append(f"   speed tests: ⬇ {min(ok):.0f}–{max(ok):.0f} Mbps ({len(ok)} test{'s' if len(ok) > 1 else ''})")
        lines.append("")
        verdicts.append((problem_min, name))
    if verdicts:
        verdicts.sort()
        best_min, best = verdicts[0]
        if len(verdicts) > 1 and verdicts[-1][0] - best_min >= 15:
            lines.append(f"👉 {best} was the more reliable connection.")
        elif all(v[0] < 15 for v in verdicts):
            lines.append("👉 Both connections behaved well.")
    if device_events:
        lines.extend(["", f"Home-device lease updates ({device_event_period}):"])
        lines.extend(f"   {time.strftime('%H:%M', time.localtime(e['ts']))} · {e['message']}"
                     for e in device_events)
        if more_device_events:
            lines.append("   More lease updates are in the dashboard event history.")
    return "\n".join(lines).rstrip()
