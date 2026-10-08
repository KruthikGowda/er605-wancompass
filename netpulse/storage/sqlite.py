"""SQLite storage, written once a minute to keep SD-card wear low.

Only per-minute aggregates are stored; the raw 10 s cycles live in memory.
Measured size: per-ISP minutes ~0.26 MB/day (kept 400 days) plus per-server minutes ~0.83 MB/day
(kept 30 days), so the file levels off around 100-130 MB (tests/test_scale.py holds us to this).
"""

from __future__ import annotations

import sqlite3
import time
from contextlib import closing
from pathlib import Path

from netpulse.health.baseline import Baseline
from netpulse.devices.identity import normalize_mac

RETENTION_DAYS = 400          # per-ISP minutes, events, speed tests (~0.26 MB/day)
TARGET_RETENTION_DAYS = 30    # per-server detail (~0.83 MB/day): the dashboard shows at most a month
DEVICE_OFFLINE_AFTER_SCANS = 3

SCHEMA = """
CREATE TABLE IF NOT EXISTS wan_minute (
    ts INTEGER NOT NULL,
    wan TEXT NOT NULL,
    state TEXT NOT NULL,
    score REAL,
    loss_pct REAL,
    rtt_ms REAL,
    jitter_ms REAL,
    availability_pct REAL,
    PRIMARY KEY (ts, wan)
);
CREATE TABLE IF NOT EXISTS target_minute (
    ts INTEGER NOT NULL,
    wan TEXT NOT NULL,
    target TEXT NOT NULL,
    loss_pct REAL,
    rtt_ms REAL,
    jitter_ms REAL,
    PRIMARY KEY (ts, wan, target)
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    ts INTEGER NOT NULL,
    kind TEXT NOT NULL,
    wan TEXT,
    message TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_ts ON events (ts);
CREATE TABLE IF NOT EXISTS speedtests (
    id INTEGER PRIMARY KEY,
    ts INTEGER NOT NULL,
    wan TEXT NOT NULL,
    trigger TEXT NOT NULL,
    down_mbps REAL,
    up_mbps REAL,
    idle_ms REAL,
    loaded_ms REAL,
    public_ip TEXT,
    colo TEXT,
    bytes_down INTEGER,
    bytes_up INTEGER,
    error TEXT
);
CREATE INDEX IF NOT EXISTS speedtests_ts ON speedtests (ts);
CREATE TABLE IF NOT EXISTS kv (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS baselines (
    wan TEXT NOT NULL,
    target TEXT NOT NULL,
    value REAL NOT NULL,
    samples INTEGER NOT NULL,
    PRIMARY KEY (wan, target)
);
CREATE TABLE IF NOT EXISTS device_labels (
    mac TEXT PRIMARY KEY,
    label TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS known_devices (
    mac TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    ip TEXT NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    listed INTEGER NOT NULL DEFAULT 1,
    missing_scans INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS device_routes (
    mac TEXT PRIMARY KEY,
    ip TEXT NOT NULL,
    route TEXT NOT NULL,
    updated_at INTEGER NOT NULL,
    actor TEXT NOT NULL,
    expires_at INTEGER,
    expires_monotonic REAL,
    boot_id TEXT
);
CREATE TABLE IF NOT EXISTS router_control_audit (
    id INTEGER PRIMARY KEY,
    ts INTEGER NOT NULL,
    actor TEXT NOT NULL,
    mac TEXT NOT NULL,
    ip TEXT NOT NULL,
    old_route TEXT NOT NULL,
    new_route TEXT NOT NULL,
    result TEXT NOT NULL,
    detail TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS router_control_audit_ts ON router_control_audit (ts);
CREATE TABLE IF NOT EXISTS device_groups (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL COLLATE NOCASE UNIQUE,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    smart_routing_enabled INTEGER NOT NULL DEFAULT 0,
    smart_enabled_at INTEGER,
    smart_last_action_at INTEGER
);
CREATE TABLE IF NOT EXISTS device_group_members (
    mac TEXT PRIMARY KEY,
    group_id INTEGER NOT NULL REFERENCES device_groups(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS device_group_members_group ON device_group_members (group_id);
CREATE TABLE IF NOT EXISTS device_group_audit (
    id INTEGER PRIMARY KEY,
    ts INTEGER NOT NULL,
    group_id INTEGER NOT NULL,
    group_name TEXT NOT NULL,
    actor TEXT NOT NULL,
    route TEXT NOT NULL,
    result TEXT NOT NULL,
    member_count INTEGER NOT NULL,
    detail TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS device_group_audit_ts ON device_group_audit (ts);
"""


class Storage:
    def __init__(self, path: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.db = sqlite3.connect(path)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.executescript(SCHEMA)
        columns = {row[1] for row in self.db.execute("PRAGMA table_info(known_devices)")}
        if "listed" not in columns:
            self.db.execute("ALTER TABLE known_devices ADD COLUMN listed INTEGER NOT NULL DEFAULT 1")
        if "missing_scans" not in columns:
            self.db.execute("ALTER TABLE known_devices ADD COLUMN missing_scans INTEGER NOT NULL DEFAULT 0")
        route_columns = {row[1] for row in self.db.execute("PRAGMA table_info(device_routes)")}
        if "expires_at" not in route_columns:
            self.db.execute("ALTER TABLE device_routes ADD COLUMN expires_at INTEGER")
        if "expires_monotonic" not in route_columns:
            self.db.execute("ALTER TABLE device_routes ADD COLUMN expires_monotonic REAL")
        if "boot_id" not in route_columns:
            self.db.execute("ALTER TABLE device_routes ADD COLUMN boot_id TEXT")
        group_columns = {row[1] for row in self.db.execute("PRAGMA table_info(device_groups)")}
        if "smart_routing_enabled" not in group_columns:
            self.db.execute("ALTER TABLE device_groups ADD COLUMN smart_routing_enabled INTEGER NOT NULL DEFAULT 0")
        if "smart_enabled_at" not in group_columns:
            self.db.execute("ALTER TABLE device_groups ADD COLUMN smart_enabled_at INTEGER")
        if "smart_last_action_at" not in group_columns:
            self.db.execute("ALTER TABLE device_groups ADD COLUMN smart_last_action_at INTEGER")
        self.db.commit()

    def write_minute(self, rows: list[tuple], events: list[tuple], baselines, target_rows: list[tuple] = ()) -> None:
        """rows: (ts, wan, state, score, loss, rtt, jitter, availability);
        target_rows: (ts, wan, target, loss, rtt, jitter); events: (ts, kind, wan, message)."""
        with self.db:
            self.db.executemany("INSERT OR REPLACE INTO wan_minute VALUES (?,?,?,?,?,?,?,?)", rows)
            self.db.executemany("INSERT OR REPLACE INTO target_minute VALUES (?,?,?,?,?,?)", target_rows)
            self.db.executemany("INSERT INTO events (ts, kind, wan, message) VALUES (?,?,?,?)", events)
            self.db.executemany(
                "INSERT OR REPLACE INTO baselines VALUES (?,?,?,?)",
                [(w, t, b.value, b.samples) for (w, t), b in baselines],
            )

    def get_value(self, key: str) -> str | None:
        row = self.db.execute("SELECT value FROM kv WHERE key = ?", (key,)).fetchone()
        return row[0] if row else None

    def set_value(self, key: str, value: str) -> None:
        with self.db:
            self.db.execute("INSERT OR REPLACE INTO kv VALUES (?, ?)", (key, value))

    def load_baselines(self) -> dict[tuple[str, str], Baseline]:
        rows = self.db.execute("SELECT wan, target, value, samples FROM baselines")
        return {(w, t): Baseline(v, n) for w, t, v, n in rows}

    def prune(self, now: float | None = None) -> None:
        cutoff = int((now or time.time()) - RETENTION_DAYS * 86400)
        with self.db:
            self.db.execute("DELETE FROM wan_minute WHERE ts < ?", (cutoff,))
            self.db.execute("DELETE FROM target_minute WHERE ts < ?",
                            (int((now or time.time()) - TARGET_RETENTION_DAYS * 86400),))
            self.db.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
            self.db.execute("DELETE FROM speedtests WHERE ts < ?", (cutoff,))

    def close(self) -> None:
        self.db.close()


class KeyValueFile:
    """Tiny thread-safe key/value access with its own short-lived connections (for worker threads)."""

    def __init__(self, path: str):
        self.path = path

    def get(self, key: str) -> str | None:
        with closing(sqlite3.connect(self.path, timeout=10)) as db:
            row = db.execute("SELECT value FROM kv WHERE key = ?", (key,)).fetchone()
        return row[0] if row else None

    def set(self, key: str, value: str) -> None:
        with closing(sqlite3.connect(self.path, timeout=10)) as db:
            with db:
                db.execute("INSERT OR REPLACE INTO kv VALUES (?, ?)", (key, value))


SPEED_COLS = ("ts", "wan", "trigger", "down_mbps", "up_mbps", "idle_ms", "loaded_ms",
              "public_ip", "colo", "bytes_down", "bytes_up", "error")


def insert_speedtest(path: str, r: dict, event: tuple | None = None) -> None:
    """Thread-safe write (own connection): speed tests finish in a worker thread."""
    with closing(sqlite3.connect(path, timeout=10)) as db:
        with db:
            db.execute(f"INSERT INTO speedtests ({', '.join(SPEED_COLS)}) VALUES ({', '.join('?' * len(SPEED_COLS))})",
                       tuple(int(r["ts"]) if c == "ts" else r.get(c) for c in SPEED_COLS))
            if event:
                db.execute("INSERT INTO events (ts, kind, wan, message) VALUES (?,?,?,?)", event)


def device_labels(path: str) -> dict[str, str]:
    with closing(_ro(path)) as db:
        return dict(db.execute("SELECT mac, label FROM device_labels"))


def device_history(path: str) -> dict[str, dict[str, int]]:
    """Return first and most recent valid DHCP scan times for each known MAC."""
    with closing(_ro(path)) as db:
        rows = db.execute("SELECT mac, first_seen, last_seen FROM known_devices")
        return {mac: {"first_seen": first_seen, "last_seen": last_seen}
                for mac, first_seen, last_seen in rows}


def known_device(path: str, mac: str) -> dict | None:
    """Return lease-list state for one normalized MAC without exposing other clients."""
    mac = normalize_mac(mac)
    with closing(_ro(path)) as db:
        row = db.execute("SELECT name, ip, listed FROM known_devices WHERE mac=?", (mac,)).fetchone()
    return {"name": row[0], "ip": row[1], "listed": bool(row[2])} if row else None


def set_device_label(path: str, mac: str, label: str) -> None:
    mac = normalize_mac(mac)
    if not mac:
        raise ValueError("A valid device MAC address is required.")
    with closing(sqlite3.connect(path, timeout=10)) as db:
        with db:
            if label:
                db.execute("INSERT OR REPLACE INTO device_labels VALUES (?, ?)", (mac, label))
            else:
                db.execute("DELETE FROM device_labels WHERE mac = ?", (mac,))


def device_groups(path: str) -> list[dict]:
    """Return named app-level groups and their member MACs, in stable display order."""
    with closing(_ro(path)) as db:
        rows = db.execute("SELECT g.id, g.name, g.created_at, g.updated_at, "
                          "g.smart_routing_enabled, g.smart_enabled_at, g.smart_last_action_at, m.mac "
                          "FROM device_groups g LEFT JOIN device_group_members m ON m.group_id=g.id "
                          "ORDER BY g.name COLLATE NOCASE, m.mac")
        result: dict[int, dict] = {}
        for ident, name, created, updated, smart_enabled, smart_enabled_at, smart_last_action, mac in rows:
            item = result.setdefault(ident, {"id": ident, "name": name, "created_at": created,
                                             "updated_at": updated, "members": [],
                                             "smart_routing_enabled": bool(smart_enabled),
                                             "smart_enabled_at": smart_enabled_at,
                                             "smart_last_action_at": smart_last_action})
            if mac:
                item["members"].append(mac)
        return list(result.values())


def save_device_group(path: str, name: str, members: list[str], now: int,
                      group_id: int | None = None) -> dict:
    """Create/update a group and membership atomically; a device can belong to one group."""
    with closing(sqlite3.connect(path, timeout=10)) as db:
        db.execute("PRAGMA foreign_keys=ON")
        with db:
            if group_id is None:
                cur = db.execute("INSERT INTO device_groups(name, created_at, updated_at) VALUES (?,?,?)",
                                 (name, now, now))
                group_id = cur.lastrowid
            else:
                # A membership edit changes the targets of automatic routing; require a fresh
                # opt-in after the owner reviews the new group membership.
                cur = db.execute("UPDATE device_groups SET name=?, updated_at=?, smart_routing_enabled=0, "
                                 "smart_enabled_at=NULL WHERE id=?", (name, now, group_id))
                if cur.rowcount != 1:
                    raise ValueError("Device group no longer exists.")
            db.execute("DELETE FROM device_group_members WHERE group_id=?", (group_id,))
            db.executemany("INSERT INTO device_group_members(mac, group_id) VALUES (?,?)",
                           [(mac, group_id) for mac in members])
        return next(g for g in device_groups(path) if g["id"] == group_id)


def delete_device_group(path: str, group_id: int) -> bool:
    with closing(sqlite3.connect(path, timeout=10)) as db:
        db.execute("PRAGMA foreign_keys=ON")
        with db:
            cur = db.execute("DELETE FROM device_groups WHERE id=?", (group_id,))
            return cur.rowcount == 1


def set_group_smart_routing(path: str, group_id: int, enabled: bool,
                            now: int | None = None) -> bool:
    """Persist an explicitly opted-in automatic WAN preference for one group."""
    if isinstance(group_id, bool) or not isinstance(group_id, int) or group_id < 1:
        raise ValueError("Invalid device group.")
    if not isinstance(enabled, bool):
        raise ValueError("Smart routing must be enabled or disabled.")
    with closing(sqlite3.connect(path, timeout=10)) as db:
        with db:
            enabled_at = int(time.time() if now is None else now) if enabled else None
            cur = db.execute("UPDATE device_groups SET smart_routing_enabled=?, smart_enabled_at=? WHERE id=?",
                             (int(enabled), enabled_at, group_id))
            return cur.rowcount == 1


def record_group_smart_action(path: str, group_id: int, now: int) -> bool:
    """Persist the last automatic attempt time, whether it succeeded or must cool down."""
    if isinstance(group_id, bool) or not isinstance(group_id, int) or group_id < 1:
        return False
    with closing(sqlite3.connect(path, timeout=10)) as db:
        with db:
            cur = db.execute("UPDATE device_groups SET smart_last_action_at=? WHERE id=?",
                             (int(now), group_id))
            return cur.rowcount == 1


def disable_group_smart_routing_for_member(path: str, mac: str) -> None:
    mac = normalize_mac(mac)
    if not mac:
        return
    with closing(sqlite3.connect(path, timeout=10)) as db:
        with db:
            db.execute("UPDATE device_groups SET smart_routing_enabled=0, smart_enabled_at=NULL WHERE id IN "
                       "(SELECT group_id FROM device_group_members WHERE mac=?)", (mac,))


def log_device_group_action(path: str, ts: int, group_id: int, group_name: str, actor: str,
                            route: str, result: str, member_count: int, detail: str = "") -> None:
    """Persist a transaction-level group audit entry and add it to the home-router event feed."""
    detail = detail[:500]
    with closing(sqlite3.connect(path, timeout=10)) as db:
        with db:
            db.execute("INSERT INTO device_group_audit "
                       "(ts, group_id, group_name, actor, route, result, member_count, detail) "
                       "VALUES (?,?,?,?,?,?,?,?)",
                       (ts, group_id, group_name[:40], actor[:48], route, result, member_count, detail))
            db.execute("INSERT INTO events (ts, kind, wan, message) VALUES (?,?,?,?)",
                       (ts, "router", None,
                        f"Device group {group_name[:40]} → {route}: {result} ({member_count} devices). {detail}"[:500]))


def device_group_history(path: str, limit: int = 20) -> list[dict]:
    limit = max(1, min(int(limit), 100))
    with closing(_ro(path)) as db:
        rows = db.execute("SELECT ts, group_id, group_name, actor, route, result, member_count, detail "
                          "FROM device_group_audit ORDER BY id DESC LIMIT ?", (limit,))
        return [{"ts": ts, "group_id": group_id, "group": name, "actor": actor,
                 "route": route, "result": result, "count": count, "detail": detail}
                for ts, group_id, name, actor, route, result, count, detail in rows]


def device_routes(path: str) -> dict[str, dict]:
    with closing(_ro(path)) as db:
        columns = {row[1] for row in db.execute("PRAGMA table_info(device_routes)")}
        expiry = "expires_at" if "expires_at" in columns else "NULL"
        expiry_mono = "expires_monotonic" if "expires_monotonic" in columns else "NULL"
        boot = "boot_id" if "boot_id" in columns else "NULL"
        rows = db.execute(f"SELECT mac, ip, route, updated_at, actor, {expiry}, {expiry_mono}, {boot} "
                          "FROM device_routes")
        return {mac: {"ip": ip, "route": route, "updated_at": updated_at, "actor": actor,
                      "expires_at": expires_at, "expires_monotonic": expires_monotonic,
                      "boot_id": boot_id}
                for mac, ip, route, updated_at, actor, expires_at, expires_monotonic, boot_id in rows}


def due_device_routes(path: str, now: int | None = None,
                      monotonic_now: float | None = None, boot_id: str | None = None) -> list[dict]:
    """Return expired preferences, preferring monotonic deadlines within the same OS boot."""
    now = int(time.time()) if now is None else int(now)
    with closing(_ro(path)) as db:
        columns = {row[1] for row in db.execute("PRAGMA table_info(device_routes)")}
        if "expires_at" not in columns:
            return []
        expiry_mono = "expires_monotonic" if "expires_monotonic" in columns else "NULL"
        boot = "boot_id" if "boot_id" in columns else "NULL"
        rows = db.execute(f"SELECT mac, ip, route, updated_at, actor, expires_at, {expiry_mono}, {boot} "
                          "FROM device_routes WHERE expires_at IS NOT NULL AND route IN ('WAN1','WAN2') "
                          "ORDER BY expires_at")
        due = []
        for mac, ip, route, updated_at, actor, expires_at, expires_monotonic, saved_boot_id in rows:
            same_boot = bool(boot_id and saved_boot_id and saved_boot_id == boot_id
                             and expires_monotonic is not None and monotonic_now is not None)
            expired = (float(expires_monotonic) <= monotonic_now if same_boot else expires_at <= now)
            if expired:
                due.append({"mac": mac, "ip": ip, "route": route, "updated_at": updated_at,
                            "actor": actor, "expires_at": expires_at,
                            "expires_monotonic": expires_monotonic, "boot_id": saved_boot_id})
        return due


def router_control_history(path: str, limit: int = 20) -> list[dict]:
    """Return recent per-device route actions for the authenticated dashboard."""
    limit = max(1, min(int(limit), 100))
    with closing(_ro(path)) as db:
        rows = db.execute(
            "SELECT ts, actor, mac, ip, old_route, new_route, result, detail "
            "FROM router_control_audit ORDER BY id DESC LIMIT ?", (limit,))
        return [{"ts": ts, "actor": actor, "mac": mac, "ip": ip, "old_route": old,
                 "new_route": new, "result": result, "detail": detail}
                for ts, actor, mac, ip, old, new, result, detail in rows]


def set_device_route(path: str, mac: str, ip: str, route: str, ts: int, actor: str,
                     old_route: str, result: str, detail: str = "",
                     expires_at: int | None = None, expires_monotonic: float | None = None,
                     boot_id: str | None = None) -> None:
    """Persist a verified route choice and append its audit record atomically."""
    with closing(sqlite3.connect(path, timeout=10)) as db:
        with db:
            if result == "applied":
                timed = route in ("WAN1", "WAN2") and expires_at is not None
                db.execute("INSERT OR REPLACE INTO device_routes "
                           "(mac, ip, route, updated_at, actor, expires_at, expires_monotonic, boot_id) "
                           "VALUES (?,?,?,?,?,?,?,?)",
                           (mac, ip, route, ts, actor,
                            expires_at if timed else None,
                            expires_monotonic if timed else None,
                            boot_id if timed else None))
            db.execute("INSERT INTO router_control_audit "
                       "(ts, actor, mac, ip, old_route, new_route, result, detail) "
                       "VALUES (?,?,?,?,?,?,?,?)",
                       (ts, actor, mac, ip, old_route, route, result, detail[:300]))
            db.execute("INSERT INTO events (ts, kind, wan, message) VALUES (?,?,?,?)",
                       (ts, "router", None, f"Device route {mac}: {old_route} → {route} ({result})"))


def log_device_reservation(path: str, ts: int, actor: str, mac: str, ip: str,
                           action: str, result: str, detail: str = "") -> None:
    """Record a reservation change in the existing home-router event stream."""
    message = f"DHCP reservation {action} for {mac} at {ip} ({result}, {actor})"
    if detail:
        message += f": {detail}"
    with closing(sqlite3.connect(path, timeout=10)) as db:
        with db:
            db.execute("INSERT INTO events (ts, kind, wan, message) VALUES (?,?,?,?)",
                       (ts, "router", None, message[:500]))


def log_firmware_review(path: str, ts: int, version: str) -> None:
    """Record the owner-reviewed ER605 firmware baseline without router identifiers."""
    with closing(sqlite3.connect(path, timeout=10)) as db:
        with db:
            db.execute("INSERT INTO events (ts, kind, wan, message) VALUES (?,?,?,?)",
                       (ts, "router", None, f"ER605 firmware version reviewed: {version[:120]}"))


def observe_device_listing(path: str, clients: list, now: int) -> dict[str, list[dict]]:
    """Track valid client scans and report new, returned, and repeatedly missing MACs."""
    if not isinstance(clients, list):
        return {"new": [], "missing": [], "returned": []}
    changes = {"new": [], "missing": [], "returned": []}
    valid = {}
    for item in clients:
        if not isinstance(item, dict):
            continue
        mac = normalize_mac(item.get("macaddr", item.get("mac", "")))
        if mac:
            valid[mac] = item
    # Empty or malformed client responses are not strong enough evidence to mark devices missing.
    if not valid:
        return changes
    with closing(sqlite3.connect(path, timeout=10)) as db:
        with db:
            initialized = db.execute("SELECT value FROM kv WHERE key='device_inventory_initialized'").fetchone()
            for mac, item in valid.items():
                name, ip = str(item.get("name") or "Unknown device"), str(item.get("ipaddr", item.get("ip", "")) or "")
                exists = db.execute("SELECT listed FROM known_devices WHERE mac=?", (mac,)).fetchone()
                if exists:
                    if not exists[0]:
                        changes["returned"].append({"mac": mac, "name": name, "ip": ip})
                    db.execute("UPDATE known_devices SET name=?, ip=?, last_seen=?, listed=1, missing_scans=0 WHERE mac=?",
                               (name, ip, now, mac))
                else:
                    db.execute("INSERT INTO known_devices (mac,name,ip,first_seen,last_seen,listed,missing_scans) "
                               "VALUES (?,?,?,?,?,1,0)", (mac, name, ip, now, now))
                    if initialized:
                        changes["new"].append({"mac": mac, "name": name, "ip": ip})
            known = db.execute("SELECT mac,name,ip,missing_scans FROM known_devices WHERE listed=1").fetchall()
            for mac, name, ip, missing_scans in known:
                if mac in valid:
                    continue
                missing_scans += 1
                if missing_scans >= DEVICE_OFFLINE_AFTER_SCANS:
                    db.execute("UPDATE known_devices SET listed=0, missing_scans=0 WHERE mac=?", (mac,))
                    changes["missing"].append({"mac": mac, "name": name, "ip": ip})
                else:
                    db.execute("UPDATE known_devices SET missing_scans=? WHERE mac=?", (missing_scans, mac))
            if not initialized:
                db.execute("INSERT OR REPLACE INTO kv VALUES ('device_inventory_initialized','1')")
    return changes


def observe_devices(path: str, clients: list, now: int) -> list[dict]:
    """Compatibility helper returning only new devices; use observe_device_listing for transitions."""
    return observe_device_listing(path, clients, now)["new"]


def speedtests(path: str, since: int, until: int | None = None) -> list[dict]:
    with closing(_ro(path)) as db:
        rows = db.execute(
            f"SELECT {', '.join(SPEED_COLS)} FROM speedtests WHERE ts >= ? AND ts < ? ORDER BY ts",
            (since, until or 2**62),
        ).fetchall()
    return [dict(zip(SPEED_COLS, row)) for row in rows]


def usual_download(path: str, wan: str, since: int, min_samples: int = 3) -> float | None:
    """Median download of successful tests: 'what's normal for this ISP' (None until enough tests)."""
    with closing(_ro(path)) as db:
        vals = [v for (v,) in db.execute(
            "SELECT down_mbps FROM speedtests WHERE wan = ? AND ts >= ? AND error IS NULL AND down_mbps IS NOT NULL",
            (wan, since))]
    if len(vals) < min_samples:
        return None
    vals.sort()
    mid = len(vals) // 2
    return vals[mid] if len(vals) % 2 else (vals[mid - 1] + vals[mid]) / 2


# --- read side, used by the web server (separate read-only connections) ---

def _ro(path: str) -> sqlite3.Connection:
    return sqlite3.connect(f"file:{path}?mode=ro", uri=True)


def history(path: str, since: int, bucket: int) -> list[dict]:
    with closing(_ro(path)) as db:
        rows = db.execute(
            """SELECT (ts / ?) * ? AS b, wan, AVG(score), AVG(loss_pct), AVG(rtt_ms), AVG(jitter_ms)
               FROM wan_minute WHERE ts >= ? GROUP BY b, wan ORDER BY b""",
            (bucket, bucket, since),
        ).fetchall()
    return [
        {"ts": b, "wan": w, "score": s, "loss_pct": l, "rtt_ms": r, "jitter_ms": j}
        for b, w, s, l, r, j in rows
    ]


def target_history(path: str, since: int, bucket: int, target: str) -> list[dict]:
    with closing(_ro(path)) as db:
        rows = db.execute(
            """SELECT (ts / ?) * ? AS b, wan, AVG(loss_pct), AVG(rtt_ms), AVG(jitter_ms)
               FROM target_minute WHERE ts >= ? AND target = ? GROUP BY b, wan ORDER BY b""",
            (bucket, bucket, since, target),
        ).fetchall()
    return [
        {"ts": b, "wan": w, "loss_pct": l, "rtt_ms": r, "jitter_ms": j}
        for b, w, l, r, j in rows
    ]


def state_minutes(path: str, since: int) -> dict[str, dict[str, int]]:
    with closing(_ro(path)) as db:
        rows = db.execute(
            "SELECT wan, state, COUNT(*) FROM wan_minute WHERE ts >= ? GROUP BY wan, state", (since,)
        ).fetchall()
    out: dict[str, dict[str, int]] = {}
    for wan, state, n in rows:
        out.setdefault(wan, {})[state] = n
    return out


def period_summary(path: str, since: int, until: int) -> dict:
    """Per-WAN totals for a time range, used by daily and weekly reports."""
    with closing(_ro(path)) as db:
        wans: dict[str, dict] = {}
        for wan, state, n in db.execute(
            "SELECT wan, state, COUNT(*) FROM wan_minute WHERE ts >= ? AND ts < ? GROUP BY wan, state",
            (since, until),
        ):
            wans.setdefault(wan, {"minutes": {}, "outages": 0, "worst_hour": None})["minutes"][state] = n
        for wan, rtt, loss in db.execute(
            "SELECT wan, AVG(rtt_ms), AVG(loss_pct) FROM wan_minute WHERE ts >= ? AND ts < ? GROUP BY wan",
            (since, until),
        ):
            if wan in wans:
                wans[wan].update(rtt_avg=rtt, loss_avg=loss)
        for wan, hour, rtt, loss in db.execute(
            """SELECT wan, (ts / 3600) * 3600 AS h, AVG(rtt_ms), AVG(loss_pct) FROM wan_minute
               WHERE ts >= ? AND ts < ? GROUP BY wan, h""",
            (since, until),
        ):
            if wan not in wans:
                continue
            w = wans[wan]["worst_hour"]
            # Worst = most loss, then highest latency.
            if w is None or ((loss or 0), (rtt or 0)) > (w["loss"], w["rtt"] or 0):
                wans[wan]["worst_hour"] = {"ts": hour, "rtt": rtt, "loss": loss or 0}
        for wan, n in db.execute(
            """SELECT wan, COUNT(*) FROM events WHERE kind = 'state' AND ts >= ? AND ts < ?
               AND message LIKE '%-> OFFLINE%' GROUP BY wan""",
            (since, until),
        ):
            if wan in wans:
                wans[wan]["outages"] = n
    for w in wans.values():
        w.setdefault("rtt_avg", None)
        w.setdefault("loss_avg", None)
    return {"since": since, "until": until, "wans": dict(sorted(wans.items()))}


def hourly(path: str, since: int, until: int) -> list[dict]:
    """Per-WAN, per-hour averages and minutes in each state (for reports / CSV)."""
    with closing(_ro(path)) as db:
        rows = db.execute(
            """SELECT (ts / 3600) * 3600 AS h, wan, AVG(rtt_ms), AVG(loss_pct), AVG(jitter_ms),
                      SUM(state = 'HEALTHY'), SUM(state = 'DEGRADED'), SUM(state = 'BAD'), SUM(state = 'OFFLINE'),
                      COUNT(*)
               FROM wan_minute WHERE ts >= ? AND ts < ? GROUP BY h, wan ORDER BY h, wan""",
            (since, until),
        ).fetchall()
    keys = ("ts", "wan", "rtt_ms", "loss_pct", "jitter_ms", "healthy_min", "slow_min", "bad_min", "down_min", "minutes")
    return [dict(zip(keys, r)) for r in rows]


def events_between(path: str, since: int, until: int, kinds: tuple[str, ...] = ("state", "router", "speedtest")) -> list[dict]:
    with closing(_ro(path)) as db:
        rows = db.execute(
            f"SELECT ts, kind, wan, message FROM events WHERE ts >= ? AND ts < ? AND kind IN ({','.join('?' * len(kinds))})"
            " ORDER BY ts, id", (since, until, *kinds)).fetchall()
    return [{"ts": t, "kind": k, "wan": w, "message": m} for t, k, w, m in rows]


def last_state_event_before(path: str, wan: str, since: int) -> dict | None:
    """Return the last WAN state transition before a report window boundary."""
    with closing(_ro(path)) as db:
        row = db.execute(
            """SELECT ts, kind, wan, message FROM events
               WHERE kind='state' AND wan=? AND ts<? ORDER BY ts DESC, id DESC LIMIT 1""",
            (wan, since),
        ).fetchone()
    return dict(zip(("ts", "kind", "wan", "message"), row)) if row else None


def recent_events(path: str, limit: int) -> list[dict]:
    with closing(_ro(path)) as db:
        rows = db.execute(
            "SELECT ts, kind, wan, message FROM events ORDER BY ts DESC, id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [{"ts": t, "kind": k, "wan": w, "message": m} for t, k, w, m in rows]


def recent_device_lease_events(path: str, since: int, until: int, limit: int = 4) -> tuple[list[dict], bool]:
    """Return recent DHCP lease changes for digests, excluding noisy LAN-ping transitions."""
    limit = max(1, min(int(limit), 20))
    with closing(_ro(path)) as db:
        rows = db.execute(
            """SELECT ts, message FROM events
               WHERE kind='device' AND ts >= ? AND ts < ? AND (
                 message LIKE 'New DHCP lease listed by the ER605:%' OR
                 message LIKE 'DHCP lease no longer listed by the ER605:%' OR
                 message LIKE 'DHCP lease listed again by the ER605:%' OR
                 message LIKE '% DHCP leases are no longer listed by the ER605 after%' OR
                 message LIKE 'ER605 logged a DHCP allocation for:%' OR
                 message LIKE 'ER605 logged a DHCP address change for:%')
               ORDER BY ts DESC, id DESC LIMIT ?""",
            (since, until, limit + 1),
        ).fetchall()
    return ([{"ts": ts, "message": message} for ts, message in rows[:limit]], len(rows) > limit)
