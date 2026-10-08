"""Read-only per-WAN public egress and origin-ASN discovery.

Run as root so the existing protected NetPulse config can be read:
    sudo python3 tools/wan_asn_discover.py

The tool makes one small Cloudflare trace request and one RIPEstat lookup per WAN.
It never edits the config, changes router settings, or downloads speed-test payloads.
"""

from __future__ import annotations

import argparse
import http.client
import sys
from pathlib import Path

# Running this file by path places tools/, not the repository root, on sys.path.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from netpulse.config import load
from netpulse.speedtest import origin_asns, trace


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="/etc/netpulse/config.toml",
                        help="NetPulse TOML config path (default: %(default)s)")
    args = parser.parse_args(argv)
    cfg = load(args.config)
    failed = False
    observed_by_wan: dict[str, set[str]] = {}
    print("Read-only route identity check; no speed-test data will be downloaded.\n")
    for wan in cfg.wans:
        label = wan.label or wan.name
        if not wan.source_ip:
            print(f"{label} ({wan.name}): source_ip is not configured; skipped.")
            failed = True
            continue
        try:
            public_ip = trace(wan.source_ip).get("ip")
            if not public_ip:
                raise OSError("Cloudflare did not return an egress IP")
            asns = origin_asns(public_ip, wan.source_ip)
        except (OSError, ValueError, http.client.HTTPException) as exc:
            print(f"{label} ({wan.name}): lookup failed ({type(exc).__name__}).")
            failed = True
            continue

        observed_by_wan[wan.name] = asns
        formatted = sorted("AS" + value for value in asns)
        if not formatted:
            print(f"{label} ({wan.name}): egress IP {public_ip}; no origin ASN was returned.")
            failed = True
            continue
        print(f"{label} ({wan.name}): egress IP {public_ip}; origin ASN(s): {', '.join(formatted)}")
        if wan.expected_asns:
            allowed = {value.removeprefix("AS") for value in wan.expected_asns}
            matched = bool(allowed.intersection(asns))
            print("  Configured expected_asns: " + ("match" if matched else "MISMATCH"))
            if not matched:
                failed = True
        else:
            toml_values = ", ".join(f'"{value}"' for value in formatted)
            print(f"  Candidate config: expected_asns = [{toml_values}]")

    names = list(observed_by_wan)
    for i, first in enumerate(names):
        for second in names[i + 1:]:
            if observed_by_wan[first] & observed_by_wan[second]:
                print(f"\nWarning: {first} and {second} share an observed origin ASN; confirm with your ISPs before configuring it.")
    print("\nReview each candidate against the ISP account/service name before adding it to the matching [[wan]] entry.")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
