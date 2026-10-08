"""Verify one NetPulse backup can be opened and migrated from a disposable copy."""

from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from netpulse.storage.backup import rehearse_restore


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("backup", help="path to a netpulse-db-*.sqlite3 backup")
    args = parser.parse_args(argv)
    try:
        report = rehearse_restore(args.backup)
    except (OSError, ValueError, sqlite3.DatabaseError) as exc:
        print(f"Restore rehearsal failed: {exc}", file=sys.stderr)
        return 1

    print("Restore rehearsal succeeded on a temporary copy.")
    print("SQLite integrity check passed before and after current storage migrations.")
    print("Rows: " + ", ".join(f"{table}={count}" for table, count in report["tables"].items()))
    print("The source backup and active NetPulse database were not changed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
