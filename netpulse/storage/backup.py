"""Consistent SQLite snapshots with atomic publication and bounded rotation."""

from __future__ import annotations

import os
import sqlite3
import shutil
import tempfile
import time
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from netpulse.freshness import age_seconds

PREFIX = "netpulse-db-"
# These existed in the earliest supported database schema. Newer tables, including kv,
# are created by Storage migrations during the disposable restore rehearsal.
RESTORE_CORE_TABLES = {"wan_minute", "events", "baselines"}
RESTORE_COUNT_TABLES = ("wan_minute", "target_minute", "events", "baselines", "kv", "known_devices",
                        "device_labels", "device_routes", "device_groups")


def status(directory: str, interval_days: int, mount_path: str = "",
           now: float | None = None) -> dict:
    """Summarize backup freshness and destination capacity without exposing its path."""
    if mount_path and not os.path.ismount(mount_path):
        return {"status": "unavailable", "latest_at": None, "age_seconds": None,
                "count": 0, "free_bytes": None}
    root = Path(directory)
    try:
        files = [p for p in root.glob(f"{PREFIX}*.sqlite3") if p.is_file()]
        usage = shutil.disk_usage(root)
        latest = max(files, key=lambda p: p.stat().st_mtime, default=None)
        if latest is None:
            return {"status": "missing", "latest_at": None, "age_seconds": None,
                    "count": 0, "free_bytes": usage.free}
        stamp = latest.stat().st_mtime
        age = age_seconds(stamp, now if now is not None else time.time())
        if age is None:
            return {"status": "stale", "latest_at": stamp, "age_seconds": None,
                    "count": len(files), "free_bytes": usage.free}
        overdue_after = interval_days * 86400 * 1.5
        return {"status": "stale" if age > overdue_after else "ok", "latest_at": stamp,
                "age_seconds": age, "count": len(files), "free_bytes": usage.free}
    except OSError:
        return {"status": "unavailable", "latest_at": None, "age_seconds": None,
                "count": 0, "free_bytes": None}


def create(source: str, directory: str, keep: int = 8, mount_path: str = "",
           now: float | None = None) -> str:
    target_dir = Path(directory)
    if mount_path and not os.path.ismount(mount_path):
        raise OSError(f"backup mount is not available: {mount_path}")
    if keep < 1:
        raise ValueError("keep must be at least 1")
    target_dir.mkdir(mode=0o750, parents=True, exist_ok=True)
    stamp = datetime.fromtimestamp(now if now is not None else datetime.now(timezone.utc).timestamp(),
                                   timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    final = target_dir / f"{PREFIX}{stamp}.sqlite3"
    fd, temporary = tempfile.mkstemp(prefix=".netpulse-backup-", suffix=".tmp", dir=target_dir)
    os.close(fd)
    try:
        with closing(sqlite3.connect(source, timeout=10)) as src, closing(sqlite3.connect(temporary, timeout=10)) as dst:
            src.backup(dst, pages=256, sleep=0.01)
            check = dst.execute("PRAGMA integrity_check").fetchone()
            if not check or check[0] != "ok":
                raise sqlite3.DatabaseError("backup integrity check failed")
            dst.commit()
        os.chmod(temporary, 0o640)
        os.replace(temporary, final)
        # Filesystems such as FAT/SMB may round successive snapshot mtimes to the same tick.
        # The UTC filename retains sub-second creation order and breaks those ties consistently.
        snapshots = sorted(target_dir.glob(f"{PREFIX}*.sqlite3"),
                           key=lambda p: (p.stat().st_mtime_ns, p.name), reverse=True)
        for old in snapshots[keep:]:
            old.unlink()
        return str(final)
    finally:
        Path(temporary).unlink(missing_ok=True)


def rehearse_restore(source: str) -> dict:
    """Open a backup through current storage migrations on a disposable copy, never the live DB."""
    backup_path = Path(source).resolve(strict=True)
    if not backup_path.is_file() or not backup_path.name.startswith(PREFIX) or not backup_path.name.endswith(".sqlite3"):
        raise ValueError("choose a NetPulse SQLite backup file")

    with tempfile.TemporaryDirectory(prefix="netpulse-restore-rehearsal-") as temp_dir:
        restored_path = Path(temp_dir) / "restored.sqlite3"
        shutil.copyfile(backup_path, restored_path)
        with closing(sqlite3.connect(restored_path)) as db:
            integrity = db.execute("PRAGMA integrity_check").fetchone()
            tables = {row[0] for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
        if not integrity or integrity[0] != "ok":
            raise sqlite3.DatabaseError("backup failed SQLite integrity check")
        missing = RESTORE_CORE_TABLES - tables
        if missing:
            raise sqlite3.DatabaseError("backup is missing required NetPulse tables")

        # Storage applies the same additive schema migrations that service startup uses.
        from netpulse.storage.sqlite import Storage

        store = Storage(str(restored_path))
        try:
            counts = {table: store.db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                      for table in RESTORE_COUNT_TABLES}
            final_integrity = store.db.execute("PRAGMA integrity_check").fetchone()
            if not final_integrity or final_integrity[0] != "ok":
                raise sqlite3.DatabaseError("restored database failed SQLite integrity check")
        finally:
            store.close()
        return {"integrity": "ok", "tables": counts}
