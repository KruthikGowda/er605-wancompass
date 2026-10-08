"""ISP report: a printable page (save as PDF from the browser) and a timestamped CSV export.

Written to be sent to an ISP's support team: plain facts with timestamps.
"""

from __future__ import annotations

import csv
import html
import io
import re
import time
from urllib.parse import urlencode

from netpulse.storage import sqlite


def _t(ts: float, fmt: str = "%d %b %Y %H:%M") -> str:
    return time.strftime(fmt, time.localtime(ts))


def _dur(minutes: float) -> str:
    minutes = int(round(minutes))
    if minutes < 60:
        return f"{minutes} min"
    return f"{minutes // 60} h {minutes % 60} min" if minutes % 60 else f"{minutes // 60} h"


def outages(events: list[dict], wan: str, since: int | None = None,
            previous: dict | None = None) -> list[tuple[float, float | None, bool]]:
    """OFFLINE spans for one WAN; mark a start clipped by the report window explicitly."""
    spans, start, clipped = [], None, False
    if since is not None and isinstance(previous, dict):
        prior = re.search(r"(\w+)\s*->\s*(\w+)", str(previous.get("message", "")))
        if prior and prior.group(2) == "OFFLINE":
            start, clipped = since, True
    for e in events:
        if e["kind"] != "state" or e["wan"] != wan:
            continue
        m = re.search(r"(\w+)\s*->\s*(\w+)", e["message"])
        if not m:
            continue
        before, after = m.groups()
        if after == "OFFLINE" and start is None:
            start, clipped = e["ts"], False
        elif before == "OFFLINE" and start is not None:
            spans.append((start, e["ts"], clipped))
            start, clipped = None, False
    if start is not None:
        spans.append((start, None, clipped))
    return spans


def build(path: str, labels: dict[str, str], plans: dict[str, float], days: float,
          selected_wan: str | None = None) -> dict:
    until = int(time.time())
    since = until - int(days * 86400)
    summ = sqlite.period_summary(path, since, until)
    hours = sqlite.hourly(path, since, until)
    events = sqlite.events_between(path, since, until)
    speeds = sqlite.speedtests(path, since, until)
    wans = []
    for wan, s in summ["wans"].items():
        if selected_wan is not None and wan != selected_wan:
            continue
        m = s["minutes"]
        total = sum(m.values()) or 1
        mine = [h for h in hours if h["wan"] == wan and h["minutes"]]
        worst = sorted(mine, key=lambda h: ((h["loss_pct"] or 0), (h["rtt_ms"] or 0)), reverse=True)[:5]
        ok_speeds = [x for x in speeds if x["wan"] == wan and not x["error"] and x["down_mbps"]]
        wans.append({
            "wan": wan, "label": labels.get(wan, wan), "plan": plans.get(wan) or None,
            "online_pct": 100 * (total - m.get("OFFLINE", 0)) / total,
            "healthy_pct": 100 * m.get("HEALTHY", 0) / total,
            "slow_min": m.get("DEGRADED", 0), "bad_min": m.get("BAD", 0), "down_min": m.get("OFFLINE", 0),
            "rtt_avg": s["rtt_avg"], "loss_avg": s["loss_avg"], "measured_min": total,
            "outages": outages(events, wan, since, sqlite.last_state_event_before(path, wan, since)),
            "worst_hours": [h for h in worst if (h["loss_pct"] or 0) >= 1 or (h["bad_min"] + h["down_min"]) > 0],
            "speeds": ok_speeds,
            "speed_tests": [x for x in speeds if x["wan"] == wan],
        })
    return {"since": since, "until": until, "days": days,
            "selected_wan": selected_wan,
            "selected_label": labels.get(selected_wan, selected_wan) if selected_wan else None,
            "wan_options": [{"wan": wan, "label": label or wan} for wan, label in labels.items()],
            "wans": wans}


def to_html(r: dict) -> str:
    e = html.escape
    parts = []
    days_value = f"{r['days']:g}"
    report_links = [f'<a href="/report?{urlencode({"days": days_value})}">All ISPs</a>']
    for option in r["wan_options"]:
        query = urlencode({"days": days_value, "wan": option["wan"]})
        report_links.append(f'<a href="/report?{query}">{e(option["label"])}</a>')
    csv_query = {"days": f"{r['days']:g}"}
    if r.get("selected_wan"):
        csv_query["wan"] = r["selected_wan"]
    csv_href = "/api/report.csv?" + urlencode(csv_query)
    for w in r["wans"]:
        spd = w["speeds"]
        speed_html = "<p class=muted>No speed tests in this period.</p>"
        if spd:
            downs = [x["down_mbps"] for x in spd]
            speed_html = (f"<p>{len(spd)} speed tests: download {min(downs):.0f}–{max(downs):.0f} Mbps "
                          f"(median {sorted(downs)[len(downs) // 2]:.0f})"
                          + (f", plan {w['plan']:.0f} Mbps" if w["plan"] else "") + ". "
                          "<span class=muted>Measured from a Raspberry Pi, which tops out around 220 Mbps.</span></p>"
                          "<table><tr><th>Time</th><th>Download</th><th>Upload</th><th>Extra lag when busy</th></tr>"
                          + "".join(f"<tr><td>{_t(x['ts'])}</td><td>{x['down_mbps']:.0f} Mbps</td>"
                                    f"<td>{(x['up_mbps'] or 0):.0f} Mbps</td>"
                                    f"<td>{max(0, (x['loaded_ms'] or 0) - (x['idle_ms'] or 0)):.0f} ms</td></tr>"
                                    for x in spd[-30:]) + "</table>")
        out_rows = "".join(
            f"<tr><td>{'before report window' if clipped else _t(a)}</td>"
            f"<td>{_t(b) if b else 'ongoing'}</td>"
            f"<td>{_dur(((b or r['until']) - a) / 60)}</td></tr>"
            for a, b, clipped in w["outages"]) or "<tr><td colspan=3 class=muted>No outages.</td></tr>"
        worst_rows = "".join(
            f"<tr><td>{_t(h['ts'], '%d %b %H:00')}</td><td>{(h['rtt_ms'] or 0):.0f} ms</td>"
            f"<td>{(h['loss_pct'] or 0):.1f}%</td><td>{h['bad_min'] + h['down_min']} min</td></tr>"
            for h in w["worst_hours"]) or "<tr><td colspan=4 class=muted>No bad hours.</td></tr>"
        parts.append(f"""
<section>
  <h2>{e(w['label'])} <small>({e(w['wan'])}{f", {w['plan']:.0f} Mbps plan" if w['plan'] else ""})</small></h2>
  <div class=kpis>
    <div><b>{w['online_pct']:.2f}%</b>online</div>
    <div><b>{w['healthy_pct']:.1f}%</b>healthy</div>
    <div><b>{_dur(w['slow_min'] + w['bad_min'])}</b>slow or bad</div>
    <div><b>{_dur(w['down_min'])}</b>down</div>
    <div><b>{(w['rtt_avg'] or 0):.0f} ms</b>typical latency</div>
    <div><b>{(w['loss_avg'] or 0):.2f}%</b>avg packet loss</div>
  </div>
  <h3>Outages</h3>
  <table><tr><th>Started</th><th>Ended</th><th>Lasted</th></tr>{out_rows}</table>
  <h3>Worst hours</h3>
  <table><tr><th>Hour</th><th>Latency</th><th>Packet loss</th><th>Minutes bad/down</th></tr>{worst_rows}</table>
  <h3>Speed</h3>{speed_html}
</section>""")
    body = "".join(parts) or "<p>No data in this period yet.</p>"
    return f"""<!doctype html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width, initial-scale=1"><title>NetPulse ISP report</title>
<style>
 body {{ font: 14px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; color: #0F2A2E; max-width: 900px; margin: 24px auto; padding: 0 16px; }}
 h1 {{ font-size: 26px; margin: 0; }} h2 {{ margin: 32px 0 8px; border-bottom: 2px solid #127A7E; padding-bottom: 4px; }}
 h2 small {{ font-weight: 400; color: #5B7276; font-size: 14px; }} h3 {{ margin: 18px 0 6px; font-size: 15px; }}
 .muted {{ color: #5B7276; }} table {{ border-collapse: collapse; width: 100%; font-variant-numeric: tabular-nums; }}
 th, td {{ text-align: left; padding: 4px 8px; border-bottom: 1px solid #DCE7E5; }} th {{ font-size: 12px; color: #5B7276; }}
 .kpis {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 8px; }}
 .kpis div {{ background: #EEF4F3; border-radius: 8px; padding: 8px 10px; font-size: 12px; color: #5B7276; }}
 .kpis b {{ display: block; font-size: 18px; color: #0F2A2E; }}
 .bar {{ display: flex; gap: 8px; margin: 12px 0; }} .bar a, .bar button {{ font: inherit; padding: 6px 12px; border-radius: 8px;
   border: 1px solid #DCE7E5; background: #fff; color: #0F2A2E; text-decoration: none; cursor: pointer; }}
 @media print {{ .bar {{ display: none; }} body {{ margin: 0; }} }}
</style></head><body>
<h1>Internet connection report{f" — {e(r['selected_label'])}" if r.get('selected_label') else ""}</h1>
<p class=muted>{_t(r['since'])} to {_t(r['until'])} ({r['days']:g} days). Measured every 10 seconds by NetPulse on a
Raspberry Pi: each connection is tested separately against Cloudflare, Google and Quad9.</p>
<p class=muted>The CSV includes hourly quality, outage spans, and individual speed-test results.</p>
<div class=bar><button onclick="print()">Print / save as PDF</button>
<a href="{e(csv_href)}">Download CSV</a>{''.join(report_links)}
<a href="/report?days=7">7 days</a><a href="/report?days=30">30 days</a><a href="/">Back to dashboard</a></div>
{body}
</body></html>"""


def to_csv(r: dict, path: str, labels: dict[str, str]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["record_type", "timestamp", "end_time", "isp", "wan", "avg_latency_ms",
                "avg_packet_loss_pct", "avg_jitter_ms", "healthy_minutes", "slow_minutes",
                "bad_minutes", "down_minutes", "download_mbps", "upload_mbps",
                "idle_latency_ms", "loaded_latency_ms", "test_status"])

    def safe_text(value) -> str:
        text = str(value or "")
        # Prevent spreadsheet formula execution from configurable labels or stored text.
        if re.match(r"^[\s\x00-\x1f]*[=+@-]", text):
            return "'" + text
        return text

    selected_wans = {wan["wan"] for wan in r["wans"]}
    for h in sqlite.hourly(path, r["since"], r["until"]):
        if h["wan"] not in selected_wans:
            continue
        w.writerow(["hour", _t(h["ts"], "%Y-%m-%dT%H:00%z"), "",
                    safe_text(labels.get(h["wan"], h["wan"])), safe_text(h["wan"]),
                    f"{h['rtt_ms']:.1f}" if h["rtt_ms"] is not None else "",
                    f"{h['loss_pct']:.2f}" if h["loss_pct"] is not None else "",
                    f"{h['jitter_ms']:.1f}" if h["jitter_ms"] is not None else "",
                    h["healthy_min"], h["slow_min"], h["bad_min"], h["down_min"], "", "", "", "", ""])
    for wan in r["wans"]:
        label, code = safe_text(wan["label"]), safe_text(wan["wan"])
        for start, end, clipped in wan["outages"]:
            duration = max(0, int(round(((end or r["until"]) - start) / 60)))
            w.writerow(["outage", "" if clipped else _t(start, "%Y-%m-%dT%H:%M:%S%z"),
                        _t(end, "%Y-%m-%dT%H:%M:%S%z") if end else "", label, code,
                        "", "", "", "", "", "", duration, "", "", "", "",
                        "started_before_window" if clipped else "confirmed" if end else "ongoing"])
        for sample in wan["speed_tests"]:
            w.writerow(["speed_test", _t(sample["ts"], "%Y-%m-%dT%H:%M:%S%z"), "", label, code,
                        "", "", "", "", "", "", "",
                        sample["down_mbps"] if sample["down_mbps"] is not None else "",
                        sample["up_mbps"] if sample["up_mbps"] is not None else "",
                        sample["idle_ms"] if sample["idle_ms"] is not None else "",
                        sample["loaded_ms"] if sample["loaded_ms"] is not None else "",
                        "failed" if sample["error"] else "success"])
    return buf.getvalue()
