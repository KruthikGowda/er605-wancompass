"""Source-bound DNS, TLS reachability, and independent expected-response web checks.

These checks are diagnostic only: they do not override the ICMP health score or WAN decision.
Every socket binds to the configured source IP, so the ER605 source policy selects that WAN.
"""

from __future__ import annotations

import ipaddress
import errno
import os
import socket
import ssl
import struct
import time
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor

from netpulse.freshness import age_seconds

DNS_SERVER = "1.1.1.1"
DNS_NAME = "example.com"
HTTPS_IP = "1.1.1.1"
HTTPS_NAME = "cloudflare-dns.com"
CHECK_INTERVAL_SECONDS = 30
ROUTINE_CHECK_INTERVAL_SECONDS = 60
RESULT_MAX_AGE_SECONDS = 180
CHECK_TIMEOUT_SECONDS = 1.5
WEB_ENDPOINTS = (("Cloudflare", "cp.cloudflare.com", "/generate_204"),
                 ("Google", "www.gstatic.com", "/generate_204"))


@dataclass(frozen=True)
class WebCheck:
    provider: str
    ok: bool
    status_code: int | None = None
    error: str = ""
    elapsed_ms: float = 0


def internet_state(result) -> tuple[str, str]:
    checks = result.web_checks
    if not checks:
        return "UNKNOWN", "Waiting for independent web checks"
    if all(check.error == "source_unavailable" for check in checks):
        return "MONITOR_ERROR", "The Pi cannot bind its configured probe address"
    passed = sum(check.ok for check in checks)
    if passed == len(WEB_ENDPOINTS):
        if result.dns_ok:
            return "ONLINE", "Both independent web endpoints and public DNS passed"
        return "PARTIAL", "Both web endpoints respond, but the primary public DNS test failed"
    if passed:
        return "PARTIAL", "One web endpoint passed; the other failed. Internet is partially reachable"
    if not result.dns_ok:
        return "DNS_FAILURE", ("Public DNS failed; direct HTTPS still responds" if result.https_ok
                               else "Public DNS and both web checks failed")
    if any(check.status_code in (200, 301, 302, 303, 307, 308, 511) for check in checks):
        return "RESTRICTED", "Web checks returned an unexpected page or redirect; a portal or restriction is possible"
    return "NO_INTERNET", "DNS responds, but neither independent web check returned the expected response"


def check_interval_seconds(icmp_state: str, application_state: str = "ONLINE") -> int:
    """Run faster diagnostics after ICMP outage; sample healthy paths less often."""
    return (CHECK_INTERVAL_SECONDS if str(icmp_state).upper() == "OFFLINE" or application_state not in ("ONLINE", "UNKNOWN")
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
    web_checks: tuple[WebCheck, ...] = ()

    def as_dict(self) -> dict:
        state, reason = internet_state(self)
        return {
            "checked_at": self.checked_at,
            "dns_ok": self.dns_ok,
            "https_ok": self.https_ok,
            "wan_dns_ok": self.wan_dns_ok,
            "icmp_state": self.icmp_state,
            "diagnosis": self.diagnosis,
            "internet_state": state,
            "internet_reason": reason,
            "web_checks": [check.__dict__ for check in self.web_checks],
        }


def _dns_query(source_ip: str, timeout: float, resolver_ip: str = DNS_SERVER,
               name: str = DNS_NAME) -> tuple[bytes, int, int] | None:
    """Query a numeric resolver directly, without needing local DNS to work first."""
    resolver = ipaddress.IPv4Address(resolver_ip)
    if (resolver.is_multicast or resolver.is_loopback or resolver.is_link_local
            or resolver.is_reserved or resolver.is_unspecified):
        return False
    resolver_ip = str(resolver)
    ident = struct.unpack("!H", os.urandom(2))[0]
    labels = b"".join(bytes((len(label),)) + label.encode("ascii") for label in name.split(".")) + b"\0"
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
    if question_name != name.lower() or question_end + 4 > len(response):
        return False
    qtype, qclass = struct.unpack("!HH", response[question_end:question_end + 4])
    if qtype != 1 or qclass != 1:
        return False
    return response, question_end + 4, answers


def _dns_ok(source_ip: str, timeout: float, resolver_ip: str = DNS_SERVER) -> bool:
    answer = _dns_query(source_ip, timeout, resolver_ip)
    return bool(answer and _has_expected_a_answer(*answer))


def _has_expected_a_answer(packet: bytes, offset: int, answer_count: int) -> bool:
    return bool(_answer_addresses(packet, offset, answer_count, DNS_NAME))


def _answer_addresses(packet: bytes, offset: int, answer_count: int, name: str) -> list[str]:
    """Require a well-formed A answer for the requested name, following CNAMEs."""
    aliases: dict[str, str] = {}
    addresses: dict[str, list[str]] = {}
    cursor = offset
    for _ in range(answer_count):
        owner, owner_end = _dns_name(packet, cursor)
        if owner is None or owner_end + 10 > len(packet):
            return []
        rr_type, rr_class, _ttl, rdlength = struct.unpack(
            "!HHIH", packet[owner_end:owner_end + 10]
        )
        rdata_start = owner_end + 10
        rdata_end = rdata_start + rdlength
        if rdata_end > len(packet):
            return []
        if rr_class == 1 and rr_type == 1 and rdlength == 4:
            addresses.setdefault(owner, []).append(str(ipaddress.IPv4Address(packet[rdata_start:rdata_end])))
        elif rr_class == 1 and rr_type == 5:
            target, target_end = _dns_name(packet, rdata_start)
            if target is None or target_end != rdata_end:
                return []
            aliases[owner] = target
        cursor = rdata_end

    current = name.lower()
    visited = set()
    for _ in range(len(aliases) + 1):
        if current in addresses:
            return addresses[current]
        if current in visited or current not in aliases:
            return []
        visited.add(current)
        current = aliases[current]
    return []


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


def _web_check(source_ip: str, timeout: float, endpoint: tuple[str, str, str]) -> WebCheck:
    """Small GET with source-bound DNS/TLS, a fixed destination, and an absolute deadline."""
    provider, host, path = endpoint
    started = time.monotonic()
    deadline = started + max(1.0, timeout * 4)
    status = None

    def remaining():
        left = deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError()
        return min(timeout, left)

    try:
        addresses, dns_error = [], None
        for resolver in (DNS_SERVER, "8.8.8.8"):
            try:
                answer = _dns_query(source_ip, remaining(), resolver, name=host)
                addresses = _answer_addresses(*answer, host) if answer else []
                addresses = [address for address in addresses if ipaddress.ip_address(address).is_global]
            except OSError as exc:
                if exc.errno == errno.EADDRNOTAVAIL:
                    raise
                dns_error = exc
            if addresses:
                break
        if not addresses:
            if dns_error:
                raise dns_error
            return WebCheck(provider, False, error="dns_failed")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as raw:
            raw.settimeout(remaining())
            raw.bind((source_ip, 0))
            raw.connect((addresses[0], 443))
            raw.settimeout(remaining())
            with ssl.create_default_context().wrap_socket(raw, server_hostname=host) as tls:
                tls.settimeout(remaining())
                tls.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode("ascii"))
                header = b""
                while b"\r\n\r\n" not in header and len(header) <= 8192:
                    tls.settimeout(remaining())
                    block = tls.recv(min(1024, 8193 - len(header)))
                    if not block:
                        break
                    header += block
                if b"\r\n\r\n" not in header or len(header) > 8192:
                    return WebCheck(provider, False, error="invalid_response")
                head, body = header.split(b"\r\n\r\n", 1)
                first = head.split(b"\r\n", 1)[0].split()
                if len(first) >= 2 and first[0] in (b"HTTP/1.0", b"HTTP/1.1") and len(first[1]) == 3 and first[1].isdigit():
                    status = int(first[1])
                fields = [line.partition(b":") for line in head.split(b"\r\n")[1:]]
                lengths = [value.strip() for key, separator, value in fields if key.lower() == b"content-length"]
                valid_headers = all(separator for _, separator, _ in fields) and not any(
                    key.lower() == b"transfer-encoding" for key, _, _ in fields)
                ok = status == 204 and not body and valid_headers and (not lengths or lengths == [b"0"])
                return WebCheck(provider, ok, status, "" if ok else "unexpected_response",
                                round((time.monotonic() - started) * 1000, 1))
    except ssl.SSLError:
        error = "tls_failed"
    except TimeoutError:
        error = "timeout"
    except OSError as exc:
        error = "source_unavailable" if exc.errno == errno.EADDRNOTAVAIL else "connection_failed"
    except ValueError:
        error = "invalid_response"
    return WebCheck(provider, False, status, error, round((time.monotonic() - started) * 1000, 1))


def _web_checks(source_ip: str, timeout: float) -> tuple[WebCheck, ...]:
    with ThreadPoolExecutor(max_workers=2, thread_name_prefix="wan-web") as workers:
        return tuple(workers.map(lambda endpoint: _web_check(source_ip, timeout, endpoint), WEB_ENDPOINTS))


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
    checks = _web_checks(source_ip, timeout)
    return ConnectivityResult(checked_at, dns_ok, https_ok, text, wan_dns_ok, normalized_state, checks)
