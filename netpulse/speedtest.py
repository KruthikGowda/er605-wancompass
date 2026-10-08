"""Per-WAN speed tests against Cloudflare's speed servers (speed.cloudflare.com).

Each test is bound to one WAN by using that WAN's probe address as the source IP
(the ER605 policy route pins it). Before measuring, a route check fetches the
public IP seen by Cloudflare; if both WANs show the same IP the test is marked
invalid instead of silently measuring the wrong ISP. If expected ASNs are
configured, the egress IP is also checked with RIPEstat before measuring.

Measures: download and upload (parallel streams, fixed size, time-capped), idle
latency, and latency *while downloading* ("bufferbloat": the lag you feel in calls
and games when the line is busy).

Limits: a Raspberry Pi 3 B+ tops out around 220 Mbps, so results show dips
clearly but can't confirm a full 200/300 Mbps plan.
"""

from __future__ import annotations

import http.client
import json
import logging
import ssl
import statistics
import subprocess
import threading
import time
from dataclasses import asdict, dataclass
from urllib.parse import urlencode

from netpulse.probes.icmp import build_command, parse_ping_output

log = logging.getLogger(__name__)

HOST = "speed.cloudflare.com"
ASN_HOST = "stat.ripe.net"
UA = "Mozilla/5.0 (NetPulse home monitor)"
CHUNK = 64 * 1024


@dataclass
class SpeedResult:
    wan: str
    ts: float
    trigger: str                  # "scheduled" | "manual"
    down_mbps: float | None = None
    up_mbps: float | None = None
    idle_ms: float | None = None
    loaded_ms: float | None = None
    public_ip: str | None = None
    colo: str | None = None
    bytes_down: int = 0
    bytes_up: int = 0
    error: str | None = None

    @property
    def bufferbloat_ms(self) -> float | None:
        if self.idle_ms is None or self.loaded_ms is None:
            return None
        return max(0.0, self.loaded_ms - self.idle_ms)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["bufferbloat_ms"] = self.bufferbloat_ms
        return d


def _conn(source_ip: str, timeout: float) -> http.client.HTTPSConnection:
    return http.client.HTTPSConnection(HOST, timeout=timeout, context=ssl.create_default_context(),
                                       source_address=(source_ip, 0) if source_ip else None)


def trace(source_ip: str, timeout: float = 10) -> dict:
    """Public IP and Cloudflare location as seen through this WAN."""
    c = _conn(source_ip, timeout)
    try:
        c.request("GET", "/cdn-cgi/trace", headers={"User-Agent": UA})
        r = c.getresponse()
        body = r.read().decode(errors="replace")
    finally:
        c.close()
    if r.status != 200:
        raise OSError(f"trace HTTP {r.status}")
    return dict(line.split("=", 1) for line in body.splitlines() if "=" in line)


def origin_asns(public_ip: str, source_ip: str, timeout: float = 8) -> set[str]:
    """Return the routed origin ASN(s) for the observed egress IP using RIPEstat."""
    c = http.client.HTTPSConnection(ASN_HOST, timeout=timeout, context=ssl.create_default_context(),
                                    source_address=(source_ip, 0) if source_ip else None)
    try:
        c.request("GET", "/data/network-info/data.json?" + urlencode({"resource": public_ip}),
                  headers={"User-Agent": UA})
        r = c.getresponse()
        body = r.read()
    finally:
        c.close()
    if r.status != 200:
        raise OSError(f"ASN lookup HTTP {r.status}")
    payload = json.loads(body)
    asns = payload.get("data", {}).get("asns", [])
    if not isinstance(asns, list) or not asns:
        raise OSError("ASN lookup returned no origin")
    return {str(value).upper().removeprefix("AS") for value in asns}


def _transfer(source_ip: str, total_bytes: int, streams: int, deadline_s: float, upload: bool) -> tuple[int, float]:
    """Run `streams` parallel transfers; return (bytes moved, seconds of active transfer)."""
    per = max(CHUNK, total_bytes // streams)
    moved = [0] * streams
    spans: list[tuple[float, float]] = []
    errors: list[str] = []
    lock = threading.Lock()
    stop_at = time.monotonic() + deadline_s

    def worker(i: int) -> None:
        c = _conn(source_ip, timeout=deadline_s + 5)
        try:
            if upload:
                body = b"0" * per
                t0 = time.monotonic()
                c.request("POST", "/__up", body=body, headers={"User-Agent": UA, "Content-Type": "text/plain"})
                c.getresponse().read()
                t1 = time.monotonic()
                moved[i] = per
            else:
                c.request("GET", f"/__down?bytes={per}", headers={"User-Agent": UA})
                r = c.getresponse()
                t0 = time.monotonic()
                while moved[i] < per and time.monotonic() < stop_at:
                    data = r.read(CHUNK)
                    if not data:
                        break
                    moved[i] += len(data)
                t1 = time.monotonic()
            with lock:
                spans.append((t0, t1))
        except OSError as e:
            with lock:
                errors.append(type(e).__name__)
        finally:
            c.close()

    threads = [threading.Thread(target=worker, args=(i,), daemon=True) for i in range(streams)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(deadline_s + 10)
    if not spans:
        raise OSError(f"{'upload' if upload else 'download'} failed ({', '.join(errors) or 'no data'})")
    seconds = max(s[1] for s in spans) - min(s[0] for s in spans)
    return sum(moved), max(seconds, 1e-3)


def _ping_median(source_ip: str, count: int, interval: float = 0.2) -> float | None:
    cmd = build_command("1.1.1.1", source_ip, count, interval, 1)
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=count * interval + 10).stdout
    except (OSError, subprocess.TimeoutExpired):
        return None
    rtts = parse_ping_output(out, "1.1.1.1", count).rtts
    return round(statistics.median(rtts), 1) if rtts else None


def mbps(nbytes: int, seconds: float) -> float:
    return round(nbytes * 8 / seconds / 1e6, 1)


def run_one(wan: str, source_ip: str, trigger: str, other_ips: set[str],
            download_mb: float = 25, upload_mb: float = 10, streams: int = 4, max_seconds: float = 15,
            expected_asns: tuple[str, ...] = ()) -> SpeedResult:
    res = SpeedResult(wan=wan, ts=time.time(), trigger=trigger)
    try:
        t = trace(source_ip)
        res.public_ip, res.colo = t.get("ip"), t.get("colo")
        if res.public_ip and res.public_ip in other_ips:
            res.error = "route check failed: same public IP as the other connection"
            return res
        if expected_asns:
            if not res.public_ip:
                res.error = "route check failed: no public IP returned"
                return res
            try:
                observed = origin_asns(res.public_ip, source_ip)
            except (OSError, ValueError, http.client.HTTPException) as e:
                res.error = f"route check unavailable: {type(e).__name__}"
                return res
            allowed = {value.upper().removeprefix("AS") for value in expected_asns}
            if not observed.intersection(allowed):
                res.error = "route check failed: egress ASN " + ",".join(sorted("AS" + a for a in observed)) + \
                            f" does not match configured ASN for {wan}"
                return res
        res.idle_ms = _ping_median(source_ip, 5)

        # Measure latency while the download runs (bufferbloat).
        loaded: list[float | None] = []
        pinger = threading.Thread(target=lambda: loaded.append(_ping_median(source_ip, 20)), daemon=True)
        pinger.start()
        nbytes, secs = _transfer(source_ip, int(download_mb * 1e6), streams, max_seconds, upload=False)
        pinger.join(15)
        res.bytes_down, res.down_mbps = nbytes, mbps(nbytes, secs)
        res.loaded_ms = loaded[0] if loaded else None

        nbytes, secs = _transfer(source_ip, int(upload_mb * 1e6), max(1, streams // 2), max_seconds, upload=True)
        res.bytes_up, res.up_mbps = nbytes, mbps(nbytes, secs)
    except OSError as e:
        res.error = str(e) or type(e).__name__
    return res


class SpeedTester:
    """Runs one test per WAN, one at a time (never two tests competing for the line)."""

    def __init__(self, wans: list[tuple[str, str]], save, download_mb: float = 25, upload_mb: float = 10,
                 streams: int = 4, min_gap_seconds: float = 300, runner=run_one,
                 expected_asns: dict[str, tuple[str, ...]] | None = None):
        self.wans = wans                  # [(name, source_ip)]
        self.save = save                  # callable(SpeedResult) -> None (thread-safe)
        self.opts = dict(download_mb=download_mb, upload_mb=upload_mb, streams=streams)
        self.expected_asns = expected_asns or {}
        self.min_gap = min_gap_seconds
        self.runner = runner
        self._lock = threading.Lock()
        self._last_start = 0.0
        self.running = False

    def try_start(self, trigger: str, on_done=None) -> str | None:
        """Start a test in the background. Returns None if started, else a reason it didn't."""
        with self._lock:
            if self.running:
                return "A speed test is already running."
            wait = self._last_start + self.min_gap - time.time()
            if wait > 0 and trigger == "manual":
                return f"Please wait {int(wait // 60) + 1} min between speed tests (they use your data)."
            self.running = True
            self._last_start = time.time()
        threading.Thread(target=self._run, args=(trigger, on_done), name="speedtest", daemon=True).start()
        return None

    def run_now(self, trigger: str) -> list[SpeedResult]:
        """Blocking run for all WANs (used by the background thread and tests)."""
        results: list[SpeedResult] = []
        seen_ips: set[str] = set()
        for name, ip in self.wans:
            r = self.runner(name, ip, trigger, set(seen_ips),
                            expected_asns=self.expected_asns.get(name, ()), **self.opts)
            if r.public_ip:
                seen_ips.add(r.public_ip)
            log.info("speed test %s: down %s up %s Mbps, idle %s ms, loaded %s ms%s", name, r.down_mbps,
                     r.up_mbps, r.idle_ms, r.loaded_ms, f" ({r.error})" if r.error else "")
            try:
                self.save(r)
            except Exception:  # noqa: BLE001
                log.exception("saving speed test failed")
            results.append(r)
        return results

    def _run(self, trigger: str, on_done) -> None:
        try:
            results = self.run_now(trigger)
        except Exception:  # noqa: BLE001
            log.exception("speed test crashed")
            results = []
        finally:
            with self._lock:
                self.running = False
        if on_done:
            try:
                on_done(results)
            except Exception:  # noqa: BLE001
                log.exception("speed test callback failed")
