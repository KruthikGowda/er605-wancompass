"""Scenario harness: runs the real NetPulse Monitor on simulated time with scripted ISPs.

Nothing here touches the network. The same `Monitor.cycle()` and `Monitor.every_minute()`
the service uses are driven step by step, so a scenario covering hours runs in seconds.
"""

from __future__ import annotations

import asyncio
import json
import re
import threading
import time
import tomllib
from contextlib import ExitStack
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable
from unittest import mock

from netpulse import config, main
from netpulse.notifications.alerts import Alerter
from netpulse.notifications.base import Notifier
from netpulse.probes.icmp import ProbeResult
from netpulse.speedtest import SpeedResult
from netpulse.storage.sqlite import Storage
from netpulse.web import app as web

ROOT = Path(__file__).resolve().parent.parent
GOLDEN = Path(__file__).resolve().parent / "golden"
SOURCES = {"192.168.0.201": "WAN1", "192.168.0.202": "WAN2"}
BASE_RTT = {"WAN1": {"1.1.1.1": 29.0, "8.8.8.8": 7.0, "9.9.9.9": 3.5},
            "WAN2": {"1.1.1.1": 16.0, "8.8.8.8": 7.0, "9.9.9.9": 4.5}}


def local(hour: int, minute: int = 0, day_offset: int = 0) -> float:
    """Epoch for hh:mm local time on a fixed calendar day (independent of 'today')."""
    return time.mktime((2026, 9, 21 + day_offset, hour, minute, 0, 0, 0, -1))


@dataclass
class Condition:
    """What an ISP looks like at a moment: latency multiplier, packet loss, dead targets."""
    rtt_mult: float = 1.0
    loss: float = 0.0              # fraction of pings lost (0..1)
    down: bool = False             # nothing answers at all
    dead_targets: tuple[str, ...] = ()
    local_error: str = ""          # the Pi itself can't send (e.g. its probe address vanished)


Script = Callable[[float], Condition]


def steady(_t: float) -> Condition:
    return Condition()


class ScriptedNet:
    """Deterministic fake `probe()`: answers according to each WAN's script at the current clock."""

    def __init__(self, clock: "Clock", scripts: dict[str, Script]):
        self.clock = clock
        self.scripts = scripts
        self.calls = 0
        self._loss_debt: dict[tuple[str, str], float] = {}

    async def probe(self, target, source_ip, count, interval, timeout) -> ProbeResult:
        self.calls += 1
        wan = SOURCES[source_ip]
        c = self.scripts.get(wan, steady)(self.clock())
        if c.local_error:
            return ProbeResult(target, count, 0, [], self.clock(), error=c.local_error)
        if c.down or target in c.dead_targets:
            return ProbeResult(target, count, 0, [], self.clock())
        # Carry fractional loss between cycles: 10% of 5 pings loses one ping every other cycle.
        # (round() would give 0 lost, because Python rounds 0.5 to even.)
        key = (wan, target)
        debt = self._loss_debt.get(key, 0.0) + count * c.loss
        lost = min(count, int(debt + 1e-9))
        self._loss_debt[key] = debt - lost
        received = count - lost
        base = BASE_RTT[wan][target] * c.rtt_mult
        # Small fixed wobble, so jitter is realistic but results are repeatable.
        rtts = [round(base + (i % 3) * 0.4, 2) for i in range(received)]
        return ProbeResult(target, count, received, rtts, self.clock())


class Clock:
    def __init__(self, t: float):
        self.t = t

    def __call__(self) -> float:
        return self.t


class Outbox(Notifier):
    """Captures what would be sent to Telegram, with the simulated time it was sent."""

    def __init__(self, clock: Clock):
        self.clock = clock
        self.sent: list[tuple[float, str, str | None]] = []

    def send(self, text: str, chat: str | None = None, markup: dict | None = None) -> None:
        self.sent.append((self.clock(), text, chat))

    def texts(self) -> list[str]:
        return [t for _, t, _ in self.sent]


def fake_speed(wan, source_ip, trigger, other_ips, **_):
    down = {"WAN1": 190.0, "WAN2": 95.0}[wan]
    return SpeedResult(wan=wan, ts=time.time(), trigger=trigger, down_mbps=down, up_mbps=down / 2,
                       idle_ms=20.0, loaded_ms=24.0, public_ip=f"198.51.100.{1 if wan == 'WAN1' else 2}", colo="MAA")


@dataclass
class Scenario:
    tmpdir: str
    start: float
    scripts: dict[str, Script] = field(default_factory=dict)
    overrides: dict = field(default_factory=dict)

    def __post_init__(self):
        raw = tomllib.loads((ROOT / "config.example.toml").read_text(encoding="utf-8"))
        raw["general"]["db_path"] = str(Path(self.tmpdir) / "netpulse.db")
        for section, values in self.overrides.items():
            raw.setdefault(section, {}).update(values)
        self.cfg = config.parse(raw)
        self.clock = Clock(self.start)
        self.net = ScriptedNet(self.clock, self.scripts)
        self.outbox = Outbox(self.clock)
        self.storage = Storage(self.cfg.db_path)
        self.board = web.StatusBoard()
        self.mon = main.Monitor(self.cfg, self.storage, Alerter(self.outbox, self.cfg.telegram), self.board,
                                clock=self.clock, speed_runner=fake_speed)
        self.board.set_extra("speedtest", self.mon)
        self._stack = ExitStack()
        self._stack.enter_context(mock.patch.object(main, "probe", self.net.probe))
        # Mute/quiet-hours checks read the wall clock; make them see simulated time.
        self._stack.enter_context(mock.patch("netpulse.notifications.alerts.time.time", self.clock))
        self._minute = int(self.start // 60 * 60)
        self.evals = {}

    def run(self, seconds: float) -> None:
        """Advance simulated time, doing exactly what the service loop does each 10 s cycle."""
        loop = asyncio.new_event_loop()
        try:
            end = self.clock.t + seconds
            while self.clock.t < end:
                self.evals = loop.run_until_complete(self.mon.cycle())
                now = self.clock.t
                if now >= self._minute + 60:
                    self.mon.every_minute(self._minute, now, self.evals)
                    self._minute = int(now // 60 * 60)
                self.clock.t += self.cfg.interval_seconds
        finally:
            loop.close()

    def state(self, wan: str) -> str:
        return self.evals[wan].state.value

    def close(self) -> None:
        self._stack.close()
        self.storage.close()


# --- golden files ---------------------------------------------------------------------------

def normalize(text: str) -> str:
    """Remove things that legitimately vary between machines (none expected, but be safe)."""
    return re.sub(r"[ \t]+\n", "\n", text).strip() + "\n"


def assert_golden(testcase, name: str, text: str) -> None:
    """Compare against tests/golden/<name>.txt. Set NETPULSE_UPDATE_GOLDEN=1 to (re)write them."""
    import os
    path = GOLDEN / f"{name}.txt"
    actual = normalize(text)
    if os.environ.get("NETPULSE_UPDATE_GOLDEN") == "1" or not path.exists():
        GOLDEN.mkdir(exist_ok=True)
        path.write_text(actual, encoding="utf-8", newline="\n")
        if os.environ.get("NETPULSE_UPDATE_GOLDEN") != "1":
            testcase.fail(f"golden file {path.name} was missing and has been created; review it and rerun")
        return
    expected = path.read_text(encoding="utf-8")
    testcase.assertEqual(expected, actual, f"{name} changed. If intended, rerun with NETPULSE_UPDATE_GOLDEN=1")


# --- fake Telegram Bot API server -----------------------------------------------------------

class FakeTelegram:
    """Just enough of api.telegram.org for TelegramBot: getUpdates long-poll and the send calls."""

    def __init__(self):
        self.calls: list[tuple[str, dict]] = []
        self.fail_sends = False            # answer sendMessage with HTTP 500 (Telegram having a bad day)
        self._updates: list[dict] = []
        self._next_id = 1
        self._cond = threading.Condition()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                method = self.path.rsplit("/", 1)[-1]
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
                if method == "sendMessage" and outer.fail_sends:
                    with outer._cond:
                        outer.calls.append(("sendMessage-failed", body))
                        outer._cond.notify_all()
                    self.send_response(500)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if method == "getUpdates":
                    result = outer._get_updates(body)
                else:
                    with outer._cond:
                        outer.calls.append((method, body))
                        outer._cond.notify_all()
                    result = {"message_id": len(outer.calls)} if method == "sendMessage" else True
                data = json.dumps({"ok": True, "result": result}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *a):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def _get_updates(self, body: dict) -> list[dict]:
        offset = body.get("offset", 0)
        deadline = time.time() + min(1.0, body.get("timeout", 0))
        with self._cond:
            while True:
                ready = [u for u in self._updates if u["update_id"] >= offset]
                if ready or time.time() >= deadline:
                    return ready
                self._cond.wait(0.05)

    def message(self, chat: int, text: str, first_name: str = "Test", username: str | None = None) -> None:
        with self._cond:
            self._updates.append({"update_id": self._next_id, "message": {
                "chat": {"id": chat, "type": "private", "first_name": first_name, "username": username},
                "text": text}})
            self._next_id += 1
            self._cond.notify_all()

    def press(self, chat: int, data: str) -> None:
        with self._cond:
            self._updates.append({"update_id": self._next_id, "callback_query": {
                "id": str(self._next_id), "from": {"id": chat}, "data": data,
                "message": {"message_id": 1, "chat": {"id": chat}}}})
            self._next_id += 1
            self._cond.notify_all()

    def wait_for(self, predicate, timeout: float = 5.0) -> list[tuple[str, dict]]:
        """Block until some recorded call matches; return all calls."""
        deadline = time.time() + timeout
        with self._cond:
            while not any(predicate(m, b) for m, b in self.calls):
                if time.time() >= deadline:
                    raise AssertionError(f"timed out; calls were: {[m for m, _ in self.calls]}")
                self._cond.wait(0.05)
            return list(self.calls)

    def sent_to(self, chat: int) -> list[str]:
        return [b["text"] for m, b in self.calls if m == "sendMessage" and str(b["chat_id"]) == str(chat)]

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
