"""Durable intent and audit storage for staged Internet pause controls."""
from __future__ import annotations

import ipaddress
import json
import math
import re
import sqlite3
from contextlib import closing
from pathlib import Path

from netpulse.router.er605 import valid_pause_acl_row

_MAC = re.compile(r"[0-9A-F]{2}(?:-[0-9A-F]{2}){5}\Z")
_STATUSES = {"applying", "paused", "resuming", "error"}
_RECORD_KEYS = {"mac", "ip", "name", "label", "actor", "created_at", "expires_at",
                "expires_monotonic", "boot_id", "status", "rule", "group_id"}
_SECRET = re.compile(r"pass|psk|secret|token|stok|key|user|auth|cookie|pin", re.I)


def _connect(path: str | Path) -> sqlite3.Connection:
    db = sqlite3.connect(str(path), timeout=10)
    db.execute("PRAGMA busy_timeout=10000")
    return db


def _schema(db: sqlite3.Connection) -> None:
    db.executescript("""
    CREATE TABLE IF NOT EXISTS device_pauses (
      mac TEXT PRIMARY KEY, ip TEXT NOT NULL, name TEXT NOT NULL, label TEXT NOT NULL,
      actor TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER,
      expires_monotonic REAL, boot_id TEXT, status TEXT NOT NULL, rule TEXT NOT NULL,
      group_id INTEGER
    );
    CREATE TABLE IF NOT EXISTS pause_actions (
      id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, actor TEXT NOT NULL,
      action TEXT NOT NULL, mac TEXT NOT NULL, result TEXT NOT NULL, detail TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS pause_actions_ts ON pause_actions(ts, id);
    """)


def _validate(record: dict) -> dict:
    if not isinstance(record, dict) or set(record) != _RECORD_KEYS:
        raise ValueError("pause record has invalid fields")
    if not isinstance(record["mac"], str) or not _MAC.fullmatch(record["mac"]):
        raise ValueError("pause MAC must be canonical uppercase dash format")
    try:
        addr = ipaddress.ip_address(record["ip"])
    except (ValueError, TypeError):
        raise ValueError("pause IP must be IPv4") from None
    networks = (ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("172.16.0.0/12"),
                ipaddress.ip_network("192.168.0.0/16"))
    if (addr.version != 4 or not any(addr in network for network in networks)
            or addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_reserved or addr.is_unspecified):
        raise ValueError("pause IP must be ordinary unicast RFC1918 IPv4")
    if not isinstance(record["name"], str) or not isinstance(record["label"], str) or len(record["label"]) > 128:
        raise ValueError("pause name or label is invalid")
    if not isinstance(record["actor"], str) or not record["actor"] or len(record["actor"]) > 128:
        raise ValueError("pause actor is invalid")
    if isinstance(record["created_at"], bool) or not isinstance(record["created_at"], int) or record["created_at"] < 0:
        raise ValueError("created_at must be a nonnegative epoch integer")
    for key in ("expires_at",):
        if record[key] is not None and (isinstance(record[key], bool) or not isinstance(record[key], int)
                                        or record[key] < record["created_at"]):
            raise ValueError("expires_at must be None or an epoch integer at or after created_at")
    mono = record["expires_monotonic"]
    if mono is not None and (isinstance(mono, bool) or not isinstance(mono, (int, float))
                             or not math.isfinite(mono) or mono < 0):
        raise ValueError("expires_monotonic must be finite and nonnegative or None")
    if (mono is None) != (record["boot_id"] is None):
        raise ValueError("boot_id is required only with a monotonic expiry")
    if record["expires_at"] is None and mono is not None:
        raise ValueError("until-resumed pauses cannot contain an expiry clock")
    if record["boot_id"] is not None and (not isinstance(record["boot_id"], str) or not record["boot_id"] or len(record["boot_id"]) > 128):
        raise ValueError("boot_id is invalid")
    if not isinstance(record["status"], str) or record["status"] not in _STATUSES:
        raise ValueError("pause status is invalid")
    if (not valid_pause_acl_row(record["rule"]) or record["rule"]["name"] != record["name"]
            or record["rule"]["src"] != "NP_G_" + record["mac"].replace("-", "")):
        raise ValueError("pause rule is invalid")
    if record["group_id"] is not None and (isinstance(record["group_id"], bool)
                                            or not isinstance(record["group_id"], int) or record["group_id"] < 1):
        raise ValueError("group_id must be a positive integer or None")
    return record


def _record(row) -> dict:
    return _validate({"mac": row[0], "ip": row[1], "name": row[2], "label": row[3], "actor": row[4],
            "created_at": row[5], "expires_at": row[6], "expires_monotonic": row[7], "boot_id": row[8],
            "status": row[9], "rule": json.loads(row[10]), "group_id": row[11]})


class PauseStore:
    def __init__(self, path: str | Path):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with closing(_connect(self.path)) as db:
            _schema(db)
            db.commit()

    def get(self, mac: str) -> dict | None:
        with closing(_connect(self.path)) as db:
            row = db.execute("SELECT mac,ip,name,label,actor,created_at,expires_at,expires_monotonic,boot_id,status,rule,group_id FROM device_pauses WHERE mac=?", (mac,)).fetchone()
        return _record(row) if row else None

    def list(self) -> list[dict]:
        with closing(_connect(self.path)) as db:
            rows = db.execute("SELECT mac,ip,name,label,actor,created_at,expires_at,expires_monotonic,boot_id,status,rule,group_id FROM device_pauses ORDER BY mac").fetchall()
        return [_record(row) for row in rows]

    def put(self, record: dict) -> None:
        r = _validate(record)
        with closing(_connect(self.path)) as db, db:
            db.execute("""INSERT OR REPLACE INTO device_pauses
              (mac,ip,name,label,actor,created_at,expires_at,expires_monotonic,boot_id,status,rule,group_id)
              VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""", (r["mac"], r["ip"], r["name"], r["label"], r["actor"],
              r["created_at"], r["expires_at"], r["expires_monotonic"], r["boot_id"], r["status"],
              json.dumps(r["rule"], sort_keys=True, separators=(",", ":")), r["group_id"]))

    def delete(self, mac: str) -> None:
        if not isinstance(mac, str) or not _MAC.fullmatch(mac):
            raise ValueError("pause MAC must be canonical uppercase dash format")
        with closing(_connect(self.path)) as db, db:
            db.execute("DELETE FROM device_pauses WHERE mac=?", (mac,))

    def audit(self, ts: int, actor: str, action: str, mac: str, result: str, detail: str) -> None:
        if (isinstance(ts, bool) or not isinstance(ts, int) or not all(isinstance(x, str) for x in (actor, action, mac, result, detail))):
            raise ValueError("invalid pause audit fields")
        if len(actor) > 128 or len(action) > 64 or len(mac) > 32 or len(result) > 64:
            raise ValueError("pause audit field too long")
        # Audit detail is diagnostic text only: redact secret-like assignments and cap storage.
        detail = re.sub(r"(?i)(pass(?:word)?|psk|secret|token|stok|auth|cookie)\s*[:=]\s*\S+", r"\1=[redacted]", detail)
        detail = detail[:1000]
        with closing(_connect(self.path)) as db, db:
            db.execute("INSERT INTO pause_actions(ts,actor,action,mac,result,detail) VALUES (?,?,?,?,?,?)",
                       (ts, actor, action, mac, result, detail))

    def audit_tail(self, limit: int = 100) -> list[dict]:
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 0:
            raise ValueError("audit limit must be a nonnegative integer")
        limit = min(limit, 1000)
        with closing(_connect(self.path)) as db:
            rows = db.execute("SELECT ts,actor,action,mac,result,detail FROM pause_actions ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(zip(("ts", "actor", "action", "mac", "result", "detail"), row)) for row in rows]


def blocked_macs(path: str | Path) -> set[str]:
    """Return MACs whose durable pause intent must block routing; absent DB stays absent."""
    path = str(path)
    if not Path(path).exists():
        return set()
    with closing(_connect(path)) as db:
        table = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='device_pauses'").fetchone()
        if not table:
            return set()
        rows = {mac for mac, in db.execute("SELECT mac FROM device_pauses")}
        if any(not isinstance(mac, str) or not _MAC.fullmatch(mac) for mac in rows):
            raise ValueError("invalid saved pause identity; repair is required before route changes")
        return rows
