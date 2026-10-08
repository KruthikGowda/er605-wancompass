"""Run the full service with simulated probes (no network needed).

Useful for trying the dashboard on a laptop:
    python -m tools.demo            # then open http://localhost:8080/
It backfills 7 days of fake history first, then keeps simulating live cycles.
WAN1 has a bad evening every day; WAN2 is steady but slightly slower.
"""

from __future__ import annotations

import asyncio
import math
import random
import sys
import tempfile
import time
from pathlib import Path

from netpulse import config, main, speedtest
from netpulse.probes.icmp import ProbeResult
from netpulse.storage import sqlite
from netpulse.storage.sqlite import Storage

BASE = {"WAN1": {"1.1.1.1": 22, "8.8.8.8": 7, "9.9.9.9": 30},
        "WAN2": {"1.1.1.1": 34, "8.8.8.8": 16, "9.9.9.9": 41}}
SOURCE = {"192.168.0.201": "WAN1", "192.168.0.202": "WAN2"}


def conditions(wan: str, ts: float) -> tuple[float, float]:
    """(latency multiplier, loss fraction) for a WAN at a given time."""
    hour = time.localtime(ts).tm_hour + time.localtime(ts).tm_min / 60
    if wan == "WAN1" and 20 <= hour < 23:
        return 4 + 2 * math.sin(ts / 300), 0.12
    if wan == "WAN2" and int(ts // 3600) % 37 == 0:
        return 1.3, 0.06
    return 1.0, 0.003


def fake(wan: str, target: str, ts: float, count: int = 5) -> ProbeResult:
    mult, loss = conditions(wan, ts)
    rtts = [BASE[wan][target] * mult * random.uniform(0.9, 1.25) for _ in range(count) if random.random() > loss]
    return ProbeResult(target, count, len(rtts), rtts, ts)


def fake_speed(wan: str, source_ip: str, trigger: str, other_ips: set, ts: float | None = None, **_):
    ts = ts or time.time()
    mult, loss = conditions(wan, ts)
    top = {"WAN1": 95, "WAN2": 110}[wan]
    down = top / (1 + 3 * loss * 10) * random.uniform(0.85, 1.05)
    time.sleep(0 if trigger == "backfill" else 3)
    return speedtest.SpeedResult(wan=wan, ts=ts, trigger=trigger, down_mbps=round(down, 1),
                                 up_mbps=round(down * 0.6, 1), idle_ms=BASE[wan]["1.1.1.1"],
                                 loaded_ms=BASE[wan]["1.1.1.1"] * (1 + mult), public_ip=f"198.51.100.{hash(wan) % 200}",
                                 colo="MAA")


class DemoTester(speedtest.SpeedTester):
    def __init__(self, *a, **k):
        super().__init__(*a, **{**k, "runner": fake_speed})


async def fake_probe(target, source_ip, count, interval, timeout):
    await asyncio.sleep(0.05)
    return fake(SOURCE[source_ip], target, time.time(), count)


def backfill(cfg, days: int) -> None:
    storage = Storage(cfg.db_path)
    rows, target_rows, now = [], [], int(time.time() // 60 * 60)
    for ts in range(now - days * 86400, now, 60):
        for wan in ("WAN1", "WAN2"):
            results = [fake(wan, t, ts) for t in cfg.probe.targets]
            target_rows += [(ts, wan, r.target, r.loss_pct, sorted(r.rtts)[len(r.rtts) // 2] if r.rtts else None, 1.5)
                            for r in results]
            sent = sum(r.sent for r in results)
            recv = sum(r.received for r in results)
            rtts = sorted(x for r in results for x in r.rtts)
            loss = 100 * (sent - recv) / sent
            rtt = rtts[len(rtts) // 2] if rtts else None
            mult, _ = conditions(wan, ts)
            state = "BAD" if loss >= 15 or mult >= 4 else "DEGRADED" if loss >= 5 or mult >= 2.5 else "HEALTHY"
            rows.append((ts, wan, state, max(0, 100 - loss * 3 - (mult - 1) * 12), loss, rtt, random.uniform(1, 4) * mult, 100))
    storage.write_minute(rows, [], [], target_rows)
    storage.close()
    for ts in range(now - days * 86400, now, 6 * 3600):
        for wan in ("WAN1", "WAN2"):
            sqlite.insert_speedtest(cfg.db_path, fake_speed(wan, "", "backfill", set(), ts=ts).to_dict())


def run() -> None:
    raw = config.tomllib.loads(Path("config.example.toml").read_text())
    raw["general"]["db_path"] = str(Path(tempfile.gettempdir()) / "netpulse-demo.db")
    raw["web"]["host"] = "127.0.0.1"
    cfg = config.parse(raw)
    Path(cfg.db_path).unlink(missing_ok=True)
    backfill(cfg, days=int(sys.argv[1]) if len(sys.argv) > 1 else 7)
    main.probe = fake_probe
    main.SpeedTester = DemoTester
    main.logging.basicConfig(level="INFO", format="%(levelname)s %(name)s: %(message)s")
    asyncio.run(main.run_async(cfg))


if __name__ == "__main__":
    run()
