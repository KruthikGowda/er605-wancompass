"""Low-rate DNS and HTTPS diagnosis for cycles where every ICMP target fails.

These checks are diagnostic only: they do not override the ICMP health score or WAN decision.
Both sockets bind to the configured source IP, so the ER605 source policy selects that WAN.
"""

from __future__ import annotations

import ipaddress
import os
import socket
import ssl
import struct
import time
from dataclasses import dataclass

from netpulse.freshness import age_seconds

DNS_SERVER = "1.1.1.1"
DNS_NAME = "example.com"
HTTPS_IP = "1.1.1.1"
HTTPS_NAME = "cloudflare-dns.com"
CHECK_INTERVAL_SECONDS = 60
ROUTINE_CHECK_INTERVAL_SECONDS = 120
RESULT_MAX_AGE_SECONDS = 180
CHECK_TIMEOUT_SECONDS = 1.5


def check_interval_seconds(icmp_state: str) -> int:
    """Run faster diagnostics after ICMP outage; sample healthy paths less often."""
    return (CHECK_INTERVAL_SECONDS if str(icmp_state).upper() == "OFFLINE"
            else ROUTINE_CHECK_INTERVAL_SECONDS)


def result_is_fresh(checked_at: float, now: float) -> bool:
    """Reject old, invalid, or future diagnostic timestamps after clock corrections."""
    age = age_seconds(checked_at, now)
    return age is not None and age <= RESULT_MAX_AGE_SECONDS


@dataclass(frozen=True)
class ConnectivityResult:
    checked_at: float
    dns_ok: bool
    https_ok: bool
    diagnosis: str
    wan_dns_ok: bool | None = None
    icmp_state: str = "OFFLINE"

    def as_dict(self) -> dict:
        return {
            "checked_at": self.checked_at,
            "dns_ok": self.dns_ok,
            "https_ok": self.https_ok,
            "wan_dns_ok": self.wan_dns_ok,
            "icmp_state": self.icmp_state,
            "diagnosis": self.diagnosis,
        }


def _dns_ok(source_ip: str, timeout: float, resolver_ip: str = DNS_SERVER) -> bool:
    """Query a numeric resolver directly, without needing local DNS to work first."""
    resolver = ipaddress.IPv4Address(resolver_ip)
    if (resolver.is_multicast or resolver.is_loopback or resolver.is_link_local
            or resolver.is_reserved or resolver.is_unspecified):
        return False
    resolver_ip = str(resolver)
    ident = struct.unpack("!H", os.urandom(2))[0]
    labels = b"".join(bytes((len(label),)) + label.encode("ascii") for label in DNS_NAME.split(".")) + b"\0"
    query = struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0) + labels + struct.pack("!HH", 1, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.bind((source_ip, 0))
        sock.sendto(query, (resolver_ip, 53))
        response, responder = sock.recvfrom(2048)
    if responder != (resolver_ip, 53):
        return False
    if len(response) < 12:
        return False
    resp_id, flags, questions, answers, _, _ = struct.unpack("!HHHHHH", response[:12])
    is_response = bool(flags & 0x8000)
    standard_query = (flags & 0x7800) == 0
    truncated = bool(flags & 0x0200)
    if (resp_id != ident or not is_response or not standard_query or truncated
            or (flags & 0x000F) != 0 or questions != 1 or answers == 0):
        return False
    question_name, question_end = _dns_name(response, 12)
    if question_name != DNS_NAME.lower() or question_end + 4 > len(response):
        return False
    qtype, qclass = struct.unpack("!HH", response[question_end:question_end + 4])
    if qtype != 1 or qclass != 1:
        return False
    return _has_expected_a_answer(response, question_end + 4, answers)


def _has_expected_a_answer(packet: bytes, offset: int, answer_count: int) -> bool:
    """Require a well-formed A answer for the requested name, following CNAMEs."""
    aliases: dict[str, str] = {}
    addresses: set[str] = set()
    cursor = offset
    for _ in range(answer_count):
        owner, owner_end = _dns_name(packet, cursor)
        if owner is None or owner_end + 10 > len(packet):
            return False
        rr_type, rr_class, _ttl, rdlength = struct.unpack(
            "!HHIH", packet[owner_end:owner_end + 10]
        )
        rdata_start = owner_end + 10
        rdata_end = rdata_start + rdlength
        if rdata_end > len(packet):
            return False
        if rr_class == 1 and rr_type == 1 and rdlength == 4:
            addresses.add(owner)
        elif rr_class == 1 and rr_type == 5:
            target, target_end = _dns_name(packet, rdata_start)
            if target is None or target_end != rdata_end:
                return False
            aliases[owner] = target
        cursor = rdata_end

    current = DNS_NAME.lower()
    visited = set()
    for _ in range(len(aliases) + 1):
        if current in addresses:
            return True
        if current in visited or current not in aliases:
            return False
        visited.add(current)
        current = aliases[current]
    return False


def _dns_name(packet: bytes, start: int) -> tuple[str | None, int]:
    """Decode a DNS name with compression pointers and reject malformed/cyclic names."""
    labels = []
    cursor = start
    encoded_end = None
    visited = set()
    for _ in range(128):
        if cursor >= len(packet):
            return None, start
        size = packet[cursor]
        if size & 0xC0 == 0xC0:
            if cursor + 1 >= len(packet):
                return None, start
            pointer = ((size & 0x3F) << 8) | packet[cursor + 1]
            if pointer >= len(packet) or pointer in visited:
                return None, start
            visited.add(pointer)
            if encoded_end is None:
                encoded_end = cursor + 2
            cursor = pointer
            continue
        if size & 0xC0 or size > 63:
            return None, start
        cursor += 1
        if size == 0:
            try:
                return ".".join(labels).lower(), encoded_end if encoded_end is not None else cursor
            except UnicodeDecodeError:
                return None, start
        end = cursor + size
        if end > len(packet):
            return None, start
        try:
            labels.append(packet[cursor:end].decode("ascii"))
        except UnicodeDecodeError:
            return None, start
        cursor = end
    return None, start


def _https_ok(source_ip: str, timeout: float) -> bool:
    """Check a fixed HTTPS endpoint by IP, so the HTTPS check does not depend on DNS."""
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        raw.settimeout(timeout)
        raw.bind((source_ip, 0))
        raw.connect((HTTPS_IP, 443))
        context = ssl.create_default_context()
        with context.wrap_socket(raw, server_hostname=HTTPS_NAME) as tls:
            tls.sendall(
                f"HEAD / HTTP/1.1\r\nHost: {HTTPS_NAME}\r\nConnection: close\r\n\r\n".encode("ascii")
            )
            line = tls.makefile("rb").readline(256).decode("ascii", errors="replace")
            return line.startswith("HTTP/")
    finally:
        raw.close()


def diagnose(source_ip: str, now: float | None = None,
             timeout: float = CHECK_TIMEOUT_SECONDS,
             wan_dns_servers: tuple[str, ...] | list[str] = (),
             icmp_state: str = "OFFLINE") -> ConnectivityResult:
    """Run one tiny DNS query and one TLS/HTTPS request, each failing independently."""
    checked_at = time.time() if now is None else now
    try:
        dns_ok = _dns_ok(source_ip, timeout)
    except (OSError, ValueError):
        dns_ok = False
    try:
        https_ok = _https_ok(source_ip, timeout)
    except (OSError, ssl.SSLError, ValueError):
        https_ok = False

    valid_resolvers = []
    candidates = wan_dns_servers[:2] if isinstance(wan_dns_servers, (tuple, list)) else ()
    for server in candidates:
        try:
            address = ipaddress.IPv4Address(str(server))
        except ipaddress.AddressValueError:
            continue
        if (not address.is_multicast and not address.is_loopback and not address.is_link_local
                and not address.is_reserved and not address.is_unspecified
                and str(address) not in valid_resolvers):
            valid_resolvers.append(str(address))
    wan_dns_ok = None
    if valid_resolvers:
        wan_dns_ok = False
        for server in valid_resolvers:
            try:
                if _dns_ok(source_ip, timeout, server):
                    wan_dns_ok = True
                    break
            except (OSError, ValueError):
                continue

    normalized_state = str(icmp_state).upper()
    if normalized_state not in ("HEALTHY", "DEGRADED", "BAD", "OFFLINE"):
        normalized_state = "OFFLINE"
    icmp_text = ("ICMP probes failed" if normalized_state == "OFFLINE"
                 else f"ICMP probes are {normalized_state.lower()}")
    if normalized_state == "OFFLINE":
        if dns_ok and https_ok:
            text = "ICMP probes failed, but DNS and HTTPS are reachable"
        elif https_ok:
            text = "HTTPS is reachable, but the direct DNS check failed"
        elif dns_ok:
            text = "DNS is reachable, but the HTTPS check failed"
        else:
            text = "ICMP, DNS, and HTTPS checks all failed"
    else:
        if dns_ok and https_ok:
            text = f"{icmp_text}; DNS and HTTPS are reachable"
        elif https_ok:
            text = f"{icmp_text}; HTTPS is reachable, but the direct DNS check failed"
        elif dns_ok:
            text = f"{icmp_text}; DNS is reachable, but the HTTPS check failed"
        else:
            text = f"{icmp_text}; DNS and HTTPS checks both failed"
    if wan_dns_ok is not None:
        text += ("; the WAN-assigned DNS resolver responded" if wan_dns_ok
                 else "; the WAN-assigned DNS resolvers did not respond")
    return ConnectivityResult(checked_at, dns_ok, https_ok, text, wan_dns_ok, normalized_state)
