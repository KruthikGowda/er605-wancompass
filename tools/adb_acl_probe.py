#!/usr/bin/env python3
"""Report truthful, phone-originated IPv4 and Pi LAN checks to a temporary ACL pilot."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import shlex
import subprocess
import sys
import time
from urllib.parse import parse_qs, urlsplit

IPIFY = "https://api4.ipify.org?format=json"
PHASES = ("baseline", "blocked", "recovery")
TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
HTTP_RE = re.compile(r"(?:^|\n)(\d{3})\s*\Z")
MAC_INPUT_RE = re.compile(r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\Z")


class ProbeError(ValueError):
    pass


def validate_url(value: str) -> tuple[str, int, str, str]:
    """Return (IPv4 host, port, token, base URL) for the exact pilot endpoint shape."""
    try:
        parsed = urlsplit(value)
        host = str(ipaddress.IPv4Address(parsed.hostname or ""))
        port = parsed.port
    except (ValueError, TypeError):
        raise ProbeError("Pilot URL must use a private IPv4 address and valid port.") from None
    private_ranges = (ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("172.16.0.0/12"),
                      ipaddress.ip_network("192.168.0.0/16"))
    ip = ipaddress.IPv4Address(host)
    if (parsed.scheme != "http" or port is None or not 1 <= port <= 65535
            or not any(ip in network for network in private_ranges)
            or parsed.username is not None or parsed.password is not None
            or parsed.fragment or parsed.path != "/probe/"):
        raise ProbeError("Pilot URL must be the private IPv4 /probe/ URL from router_acl_pilot.py.")
    try:
        query = parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True)
    except ValueError:
        raise ProbeError("Pilot URL query is malformed.") from None
    token_values = query.get("t", [])
    if set(query) != {"t"} or len(token_values) != 1 or not TOKEN_RE.fullmatch(token_values[0]):
        raise ProbeError("Pilot URL must contain exactly one valid t token.")
    return host, port, token_values[0], f"http://{host}:{port}"


def adb_shell(serial: str, command: str, timeout: float = 15,
              runner=subprocess.run) -> subprocess.CompletedProcess:
    return runner(["adb", "-s", serial, "shell", command], capture_output=True,
                  text=True, encoding="utf-8", errors="replace", timeout=timeout, check=False)


def _validated_identity(serial: str, phone_mac: str, phone_ip: str) -> tuple[str, str]:
    serial = str(serial or "").strip()
    if not serial or any(char.isspace() for char in serial):
        raise ProbeError("An explicit valid ADB serial is required.")
    if not MAC_INPUT_RE.fullmatch(str(phone_mac or "")):
        raise ProbeError("An explicit valid phone MAC address is required.")
    normalized_mac = re.sub(r"[:-]", "", phone_mac).casefold()
    try:
        address = ipaddress.IPv4Address(phone_ip)
    except (ipaddress.AddressValueError, TypeError):
        raise ProbeError("An explicit private IPv4 phone address is required.") from None
    private_ranges = (ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("172.16.0.0/12"),
                      ipaddress.ip_network("192.168.0.0/16"))
    if not any(address in network for network in private_ranges):
        raise ProbeError("An explicit private IPv4 phone address is required.")
    return normalized_mac, str(address)


def check_phone(serial: str, phone_mac: str, phone_ip: str, runner=subprocess.run) -> None:
    expected_mac, phone_ip = _validated_identity(serial, phone_mac, phone_ip)
    mobile = adb_shell(serial, "settings get global mobile_data", runner=runner)
    if mobile.returncode or mobile.stdout.strip() != "0":
        raise ProbeError("Phone mobile data must already be off; no phone settings were changed.")
    wifi = adb_shell(serial, "dumpsys wifi", runner=runner)
    if wifi.returncode:
        raise ProbeError("Could not verify the phone's current Wi-Fi connection.")
    current_line = any(
        "mwifiinfo" in line.casefold() and "completed" in line.casefold()
        and any(re.sub(r"[:-]", "", candidate).casefold() == expected_mac
                for candidate in re.findall(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f])", line))
        for line in wifi.stdout.splitlines())
    if not current_line:
        raise ProbeError("Phone Wi-Fi must be COMPLETED at the reviewed MAC and IPv4 address.")
    connectivity = adb_shell(serial, "dumpsys connectivity", runner=runner)
    if connectivity.returncode:
        raise ProbeError("Could not verify the phone's active default network.")
    active = re.search(r"Active default network:\s*(\d+)", connectivity.stdout)
    if not active:
        raise ProbeError("Could not identify the phone's active default network.")
    network_id = active.group(1)
    # Android 10 emits each detailed agent on one line. Exclude later request/history
    # sections, which mention VPN even when the active network is ordinary Wi-Fi.
    current = next((line for line in connectivity.stdout.splitlines()
                    if line.lstrip().startswith("NetworkAgentInfo{")
                    and re.search(rf"network\{{\s*{re.escape(network_id)}\s*\}}", line)), "")
    if not current or not re.search(r"\bWIFI\b|TRANSPORT_WIFI", current, re.I) \
            or re.search(r"\bVPN\b|TRANSPORT_VPN", current, re.I) \
            or not re.search(rf"LinkAddresses:.*?(?<![\d.]){re.escape(phone_ip)}/\d{{1,2}}(?![\d.])", current):
        raise ProbeError("Phone's active default network must be Wi-Fi without an active VPN.")


def _curl(serial: str, url: str, *, origin: str | None = None,
          payload: dict | None = None, runner=subprocess.run) -> tuple[int, str, str, int]:
    argv = ["curl", "--ipv4", "--silent", "--show-error", "--connect-timeout", "5", "--max-time", "10",
            "--max-redirs", "0", "--output", "-", "--write-out", "\\n%{http_code}"]
    if origin is not None:
        argv += ["--header", f"Origin: {origin}"]
    if payload is not None:
        argv += ["--header", "Content-Type: application/json", "--data", json.dumps(payload, separators=(",", ":"))]
    argv.append(url)
    result = adb_shell(serial, shlex.join(argv), timeout=20, runner=runner)
    output = result.stdout or ""
    match = HTTP_RE.search(output)
    if not match:
        return 0, output, result.stderr or "", result.returncode
    return int(match.group(1)), output[:match.start()].rstrip("\r\n"), result.stderr or "", result.returncode


def _state(serial: str, base: str, token: str, runner=subprocess.run) -> dict:
    status, body, _err, code = _curl(serial, f"{base}/state?t={token}", runner=runner)
    if code or status != 200:
        raise ProbeError("Phone could not reach the Pi probe state endpoint.")
    try:
        value = json.loads(body)
    except (TypeError, ValueError):
        raise ProbeError("Pi probe returned invalid state data.") from None
    if not isinstance(value, dict) or value.get("phase") not in PHASES:
        raise ProbeError("Pi probe returned an unknown phase.")
    return value


def _internet_ipv4_ok(serial: str, runner=subprocess.run) -> bool:
    url = IPIFY + "&n=" + str(time.time_ns())
    status, body, err, code = _curl(serial, url, runner=runner)
    if code == 60 or "certificate" in err.casefold() or "ssl" in err.casefold():
        raise ProbeError("Verified HTTPS certificate validation failed; no report was sent.")
    if code:
        return False
    if status != 200:
        return False
    try:
        data = json.loads(body)
        address = ipaddress.ip_address(data.get("ip")) if isinstance(data, dict) else None
    except (TypeError, ValueError):
        raise ProbeError("IPv4 Internet endpoint returned an invalid address; no report was sent.") from None
    if not isinstance(address, ipaddress.IPv4Address):
        raise ProbeError("IPv4 Internet endpoint did not return IPv4; no report was sent.")
    return True


def run_probe(url: str, serial: str, phone_mac: str, phone_ip: str, *, runner=subprocess.run,
              timeout_seconds: float = 300, poll_seconds: float = 2,
              sleep=time.sleep, monotonic=time.monotonic) -> dict[str, dict[str, bool]]:
    host, port, token, base = validate_url(url)
    check_phone(serial, phone_mac, phone_ip, runner=runner)
    origin = f"http://{host}:{port}"
    deadline = monotonic() + min(max(timeout_seconds, 1), 300)
    reports: dict[str, dict[str, bool]] = {}
    index = 0
    while index < len(PHASES) and monotonic() < deadline:
        phase = PHASES[index]
        current = _state(serial, base, token, runner=runner)
        if current.get("phase") != phase or current.get("expires_in", 1) <= 0:
            raise ProbeError("Pi phase changed unexpectedly or the temporary probe expired.")
        internet_ok = _internet_ipv4_ok(serial, runner=runner)
        # A phase transition during the external request invalidates that sample; never post it.
        if _state(serial, base, token, runner=runner).get("phase") != phase:
            raise ProbeError("Pi phase changed during the phone test; no stale report was sent.")
        report = {"phase": phase, "internet_ipv4_ok": internet_ok, "lan_ok": True}
        status, _body, _err, code = _curl(serial, f"{base}/report?t={token}", origin=origin,
                                          payload=report, runner=runner)
        if code or status != 204:
            raise ProbeError("Pi rejected the phone's phase report.")
        reports[phase] = {"internet_ipv4_ok": internet_ok, "lan_ok": True}
        index += 1
        if index < len(PHASES):
            while monotonic() < deadline:
                state = _state(serial, base, token, runner=runner)
                if state.get("phase") != phase:
                    if state.get("phase") != PHASES[index]:
                        raise ProbeError("Pi skipped an expected probe phase.")
                    break
                if state.get("expires_in", 1) <= 0:
                    raise ProbeError("The temporary Pi probe expired before the next phase.")
                sleep(min(poll_seconds, max(0, deadline - monotonic())))
            else:
                raise ProbeError("Timed out waiting for the next Pi probe phase.")
    if index != len(PHASES):
        raise ProbeError("Timed out before all phone probe phases were reported.")
    return reports


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True, help="Temporary private /probe/ URL from the Pi")
    parser.add_argument("--serial", required=True, help="ADB serial for the explicitly selected phone")
    parser.add_argument("--phone-mac", required=True, help="Reviewed phone Wi-Fi MAC address")
    parser.add_argument("--phone-ip", required=True, help="Reviewed private IPv4 address of the phone")
    args = parser.parse_args(argv)
    try:
        reports = run_probe(args.url, args.serial, args.phone_mac, args.phone_ip)
    except (ProbeError, OSError, subprocess.SubprocessError) as exc:
        message = str(exc) if isinstance(exc, ProbeError) else type(exc).__name__
        print(f"Phone probe stopped: {message}", file=sys.stderr)
        return 2
    for phase, result in reports.items():
        print(f"{phase}: IPv4 Internet {'ok' if result['internet_ipv4_ok'] else 'unavailable'}; Pi LAN ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
