"""Read-only, source-filtered ER605 DHCP allocation syslog support."""

from __future__ import annotations

import ipaddress
import re
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Callable

MAX_DATAGRAM_BYTES = 2048
DEDUP_SECONDS = 900
MAX_DEDUP_ENTRIES = 2048
ALLOCATION = re.compile(
    r"DHCP Server allocated IP address\s+((?:\d{1,3}\.){3}\d{1,3})\s+"
    r"for the \[client:([0-9a-f]{2}(?::[0-9a-f]{2}){5})\]\.\s*$",
    re.IGNORECASE,
)
PRIVATE_V4 = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


@dataclass(frozen=True)
class DhcpAllocation:
    ip: str
    mac: str


def parse_dhcp_allocation(data: bytes) -> DhcpAllocation | None:
    """Parse only the observed ER605 allocation message; never retain its raw payload."""
    if not isinstance(data, bytes) or not data or len(data) > MAX_DATAGRAM_BYTES:
        return None
    try:
        text = data.decode("utf-8").strip()
    except UnicodeDecodeError:
        return None
    match = ALLOCATION.search(text)
    if not match:
        return None
    try:
        address = ipaddress.IPv4Address(match.group(1))
    except ipaddress.AddressValueError:
        return None
    if not any(address in network for network in PRIVATE_V4):
        return None
    octets = bytes.fromhex(match.group(2).replace(":", ""))
    if len(octets) != 6 or octets[0] & 1 or not any(octets):
        return None
    mac = "-".join(f"{part:02X}" for part in octets)
    return DhcpAllocation(str(address), mac)


class RouterSyslogProtocol:
    """Accept bounded allocation records from exactly one configured router address."""

    def __init__(self, router_ip: str, on_allocation: Callable[[DhcpAllocation, float], None],
                 clock: Callable[[], float] = time.time,
                 on_status: Callable[[dict], None] | None = None,
                 monotonic_clock: Callable[[], float] = time.monotonic):
        self.router_ip = str(ipaddress.IPv4Address(router_ip))
        self.on_allocation = on_allocation
        self.clock = clock
        self.monotonic_clock = monotonic_clock
        self.on_status = on_status
        self._seen: OrderedDict[tuple[str, str], float] = OrderedDict()
        self.transport = None
        self.accepted_allocations = 0
        self.duplicates_suppressed = 0
        self.last_allocation_at: float | None = None

    def status(self) -> dict:
        """Return identity-free listener health for the dashboard/API."""
        return {
            "listening": self.transport is not None,
            "accepted_allocations": self.accepted_allocations,
            "duplicates_suppressed": self.duplicates_suppressed,
            "last_allocation_at": self.last_allocation_at,
        }

    def _publish_status(self) -> None:
        if self.on_status is not None:
            self.on_status(self.status())

    def connection_made(self, transport):
        self.transport = transport
        self._publish_status()

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        if len(data) > MAX_DATAGRAM_BYTES or not addr or addr[0] != self.router_ip:
            return
        allocation = parse_dhcp_allocation(data)
        if allocation is None:
            return
        timestamp = self.clock()
        now_mono = self.monotonic_clock()
        expiry = self._seen.get((allocation.mac, allocation.ip), 0.0)
        if expiry > now_mono:
            self.duplicates_suppressed += 1
            self._publish_status()
            return
        self._seen[(allocation.mac, allocation.ip)] = now_mono + DEDUP_SECONDS
        self._seen.move_to_end((allocation.mac, allocation.ip))
        while self._seen and (next(iter(self._seen.values())) <= now_mono
                              or len(self._seen) > MAX_DEDUP_ENTRIES):
            self._seen.popitem(last=False)
        self.accepted_allocations += 1
        self.last_allocation_at = timestamp
        try:
            self.on_allocation(allocation, timestamp)
        finally:
            self._publish_status()

    def error_received(self, exc):
        # A transient ICMP error from a remote syslog sender does not affect monitoring.
        return None

    def connection_lost(self, exc):
        # asyncio calls this when the service closes its UDP transport during shutdown.
        self.transport = None
        self._publish_status()
