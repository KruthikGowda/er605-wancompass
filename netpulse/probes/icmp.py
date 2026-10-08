"""ICMP probe using the system `ping` (iputils), bound to a source IP.

Binding to a source IP is what makes a probe WAN-specific: the ER605 has a
policy route that sends traffic from that IP out of exactly one WAN.
"""

from __future__ import annotations

import asyncio
import re
import time
from dataclasses import dataclass, field

_REPLY_RE = re.compile(r"icmp_seq=(\d+).*?time=([\d.]+)\s*ms")


@dataclass
class ProbeResult:
    target: str
    sent: int
    received: int
    rtts: list[float] = field(default_factory=list)
    ts: float = 0.0
    error: str = ""

    @property
    def loss_pct(self) -> float:
        return 100.0 if self.sent == 0 else 100.0 * (self.sent - self.received) / self.sent


def parse_ping_output(output: str, target: str, sent: int) -> ProbeResult:
    """Parse per-reply lines of iputils `ping` output.

    Counts unique icmp_seq values so duplicate replies (DUP!) aren't double counted.
    """
    seen: dict[int, float] = {}
    for seq, rtt in _REPLY_RE.findall(output):
        seen.setdefault(int(seq), float(rtt))
    rtts = [seen[s] for s in sorted(seen)]
    return ProbeResult(target=target, sent=sent, received=min(len(rtts), sent), rtts=rtts)


def build_command(target: str, source_ip: str, count: int, interval: float, timeout: float) -> list[str]:
    deadline = max(1, int(count * interval + timeout + 1))
    cmd = ["ping", "-n", "-c", str(count), "-i", str(interval), "-W", str(timeout), "-w", str(deadline)]
    if source_ip:
        cmd += ["-I", source_ip]
    cmd.append(target)
    return cmd


async def probe(target: str, source_ip: str, count: int, interval: float, timeout: float) -> ProbeResult:
    cmd = build_command(target, source_ip, count, interval, timeout)
    ts = time.time()
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        # ping enforces its own deadline (-w); this is a backstop against a hung process.
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=count * interval + timeout + 5)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return ProbeResult(target, count, 0, ts=ts, error="ping timed out")
    except OSError as e:
        return ProbeResult(target, count, 0, ts=ts, error=str(e))

    result = parse_ping_output(stdout.decode(errors="replace"), target, count)
    result.ts = ts
    # Exit code 1 just means "no replies"; 2 means ping itself failed (bad source IP, etc.)
    if proc.returncode == 2:
        result.error = stderr.decode(errors="replace").strip() or "ping error"
    return result
