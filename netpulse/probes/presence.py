"""Bounded LAN reachability probes for DHCP-listed devices.

An echo reply is positive evidence that an endpoint answered from the Pi's LAN.
Missing replies are never treated as proof that a device is offline: many clients
sleep or filter ICMP. The caller owns that interpretation and confirmation policy.
"""

from __future__ import annotations

import asyncio
import ipaddress
import time
from math import ceil

from netpulse.devices.identity import MAC_RE, normalize_mac

PRIVATE_LAN_NETWORKS = tuple(ipaddress.ip_network(value) for value in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
))
MAX_CLIENTS_PER_SCAN = 128
MAX_CLIENT_ROWS_TO_SCAN = 512
MAX_CONCURRENT_PINGS = 16
DEFAULT_TIMEOUT_SECONDS = 1.0


def valid_lan_target(value: str) -> bool:
    """Accept only ordinary IPv4 addresses inside RFC1918 LAN ranges."""
    try:
        address = ipaddress.ip_address(str(value))
    except ValueError:
        return False
    return (isinstance(address, ipaddress.IPv4Address)
            and any(address in network for network in PRIVATE_LAN_NETWORKS)
            and not (address.is_multicast or address.is_loopback or address.is_link_local
                     or address.is_reserved or address.is_unspecified))


def scan_rounds(client_count: int) -> int:
    """Bound the maximum number of configured scans needed to visit an inventory batch set."""
    if isinstance(client_count, bool) or not isinstance(client_count, int):
        return 1
    if client_count <= 0 or client_count > MAX_CLIENT_ROWS_TO_SCAN:
        return 1
    return max(1, ceil(client_count / MAX_CLIENTS_PER_SCAN))


def per_device_scan_interval_seconds(interval_seconds: int, client_count: int) -> int | None:
    """Estimate how often one lease is pinged, accounting for fair batch rotation.

    Return None when the inventory is empty, invalid, or beyond the scanner's explicit cap.
    """
    if (isinstance(interval_seconds, bool) or not isinstance(interval_seconds, int)
            or interval_seconds < 1 or isinstance(client_count, bool)
            or not isinstance(client_count, int) or client_count < 1
            or client_count > MAX_CLIENT_ROWS_TO_SCAN):
        return None
    return interval_seconds * scan_rounds(client_count)


def candidates(clients, exclude_ips=(), limit: int = MAX_CLIENTS_PER_SCAN,
               offset: int = 0) -> list[tuple[str, str]]:
    """Return unambiguous (MAC, IP) candidates from one router DHCP snapshot."""
    limit = max(0, min(int(limit), MAX_CLIENTS_PER_SCAN))
    if limit == 0 or not isinstance(clients, list) or len(clients) > MAX_CLIENT_ROWS_TO_SCAN:
        return []
    excluded = {str(ip) for ip in exclude_ips}
    rows_by_mac: dict[str, set[str]] = {}
    macs_by_ip: dict[str, set[str]] = {}
    valid_rows = []
    for row in clients:
        if not isinstance(row, dict):
            continue
        mac = normalize_mac(row.get("macaddr", row.get("mac", "")))
        ip = str(row.get("ipaddr", row.get("ip", "")) or "")
        if not MAC_RE.fullmatch(mac) or not valid_lan_target(ip) or ip in excluded:
            continue
        rows_by_mac.setdefault(mac, set()).add(ip)
        macs_by_ip.setdefault(ip, set()).add(mac)
        valid_rows.append((mac, ip))

    found = []
    seen = set()
    for mac, ip in valid_rows:
        # A stale/conflicting lease snapshot cannot identify which endpoint answered.
        if len(rows_by_mac[mac]) != 1 or len(macs_by_ip[ip]) != 1 or mac in seen:
            continue
        seen.add(mac)
        found.append((mac, ip))
    found.sort()
    if len(found) <= limit:
        return found
    offset = max(0, int(offset)) % len(found)
    return [found[(offset + index) % len(found)] for index in range(limit)]


async def _ping(ip: str, timeout: float) -> bool | None:
    """True=echo reply, False=valid no-reply result, None=probe unavailable/error."""
    if not valid_lan_target(ip):
        return None
    timeout = max(0.2, min(float(timeout), 3.0))
    wait_seconds = max(1, ceil(timeout))
    deadline_seconds = max(2, wait_seconds + 1)
    cmd = ["ping", "-n", "-c", "1", "-W", str(wait_seconds),
           "-w", str(deadline_seconds), ip]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            await asyncio.wait_for(proc.wait(), timeout=timeout + 2)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return None
    except OSError:
        return None
    if proc.returncode == 0:
        return True
    if proc.returncode == 1:
        return False
    return None


async def scan(clients, now: float | None = None, exclude_ips=(), timeout: float = DEFAULT_TIMEOUT_SECONDS,
               ping=_ping, offset: int = 0) -> dict[str, dict]:
    """Probe one fair batch of at most 128 validated DHCP clients with bounded concurrency."""
    checked_at = time.time() if now is None else float(now)
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_PINGS)
    rows = candidates(clients, exclude_ips, offset=offset)

    async def one(mac: str, ip: str) -> tuple[str, dict]:
        async with semaphore:
            try:
                response = await ping(ip, timeout)
            except Exception:  # malformed OS/network conditions leave reachability unknown
                response = None
            return mac, {"ip": ip, "response": response, "checked_at": checked_at}

    return dict(await asyncio.gather(*(one(mac, ip) for mac, ip in rows)))
