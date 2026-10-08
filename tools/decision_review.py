#!/usr/bin/env python3
"""Summarize dry-run WAN recommendations without showing event text or device data."""

from __future__ import annotations

import argparse
from datetime import datetime
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from netpulse.decision.review import FOLLOW_UP_HORIZONS_SECONDS, MAX_DAYS, summarize

DEFAULT_DB = "/var/lib/netpulse/netpulse.db"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default=DEFAULT_DB, help="NetPulse SQLite database (default: %(default)s)")
    parser.add_argument("--days", type=int, default=7, help=f"look-back window, 1 to {MAX_DAYS} days (default: 7)")
    args = parser.parse_args(argv)
    try:
        report = summarize(args.db, args.days)
    except (OSError, sqlite3.Error, ValueError) as exc:
        parser.error(f"cannot read decision summary: {exc}")

    start = datetime.fromtimestamp(report["start"]).astimezone().strftime("%Y-%m-%d %H:%M %Z")
    end = datetime.fromtimestamp(report["end"]).astimezone().strftime("%Y-%m-%d %H:%M %Z")
    print(f"Dry-run WAN recommendations · {start} to {end} ({report['days']} days)")
    print(f"Total recommendations: {report['total']}")
    if report["daily"]:
        for day, count in sorted(report["daily"].items()):
            print(f"{day}: {count}")
    else:
        print("No recommendation events were recorded in this window.")
    if report["recommendations"]:
        print("\nRecommendations for manual review (no raw event text):")
        for item in report["recommendations"]:
            when = datetime.fromtimestamp(item["ts"]).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
            route = (f"{item['source']} -> {item['target']}" if item["source"] and item["target"]
                     else "WAN route details unavailable")
            states = "WAN health sample unavailable"
            if item["source_state"] and item["target_state"]:
                states = (f"{item['source']} {item['source_state']}" +
                          (f" ({item['source_score']:.1f})" if item["source_score"] is not None else "") +
                          f"; {item['target']} {item['target_state']}" +
                          (f" ({item['target_score']:.1f})" if item["target_score"] is not None else ""))
                states += f"; sample {item['metrics_age_seconds']}s before recommendation"
            print(f"{when}: {route}; {item['kind']}; {states}")
            for index, follow_up in enumerate(item["follow_up"]):
                horizon = FOLLOW_UP_HORIZONS_SECONDS[index]
                label = f"about {horizon // 60} min later"
                if not follow_up:
                    print(f"  {label}: no paired WAN samples")
                    continue
                comparison = "score unavailable"
                if follow_up["target_minus_source_score"] is not None:
                    delta = follow_up["target_minus_source_score"]
                    comparison = f"{item['target']} minus {item['source']} score {delta:+.1f}"
                print(
                    f"  {label}: {item['source']} {follow_up['source_state']} "
                    f"({follow_up['source_score'] if follow_up['source_score'] is not None else 'n/a'}); "
                    f"{item['target']} {follow_up['target_state']} "
                    f"({follow_up['target_score'] if follow_up['target_score'] is not None else 'n/a'}); "
                    f"{comparison}; samples within {follow_up['sample_offset_seconds']}s of checkpoint"
                )
    print("These later WAN samples are descriptive follow-up, not proof a recommendation was correct "
          "or evidence of routed client traffic.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
