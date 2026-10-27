"""Durable single-operation intent and verified per-device bandwidth caps."""
from __future__ import annotations

import copy
import ipaddress
import json
import math
import re
import secrets
import sqlite3
from contextlib import closing
from pathlib import Path

from netpulse.devices.identity import MAC_RE, normalize_mac
from netpulse.router.qos import canonical_classification_row, canonical_qos_global, canonical_rate_rule_row

_PHASES = {"prepared", "applying", "settling", "recovering", "error"}
_RECORD_KEYS = {"actor", "created_at", "firmware", "phase", "targets", "global_before",
                "global_after", "rules_before", "classes_before", "engine_setup", "remove",
                "down_kbps", "up_kbps"}
_MAX_BYTES = 128 * 1024
_ID = re.compile(r"[A-Za-z0-9_-]{24,40}\Z")


class BandwidthStoreError(ValueError):
    """Invalid or unavailable durable bandwidth state."""


class BandwidthStoreConflict(BandwidthStoreError):
    """A bandwidth operation is pending or its revision is stale."""


def _connect(path: str | Path) -> sqlite3.Connection:
    db = sqlite3.connect(str(path), timeout=30, isolation_level=None)
    db.execute("PRAGMA busy_timeout=30000")
    return db


def _schema(db: sqlite3.Connection) -> None:
    db.execute("""CREATE TABLE IF NOT EXISTS router_bandwidth_operations (
      id TEXT PRIMARY KEY,
      singleton INTEGER NOT NULL UNIQUE DEFAULT 1 CHECK(singleton=1),
      revision INTEGER NOT NULL CHECK(revision >= 1),
      phase TEXT NOT NULL CHECK(phase IN ('prepared','applying','settling','recovering','error')),
      record_json TEXT NOT NULL,
      schema_version INTEGER NOT NULL CHECK(schema_version=1)
    )""")
    db.execute("""CREATE TABLE IF NOT EXISTS router_bandwidth_caps (
      mac TEXT PRIMARY KEY, ip TEXT NOT NULL, down_kbps INTEGER NOT NULL,
      up_kbps INTEGER NOT NULL, actor TEXT NOT NULL, updated_at REAL NOT NULL
    )""")
    db.execute("""CREATE TABLE IF NOT EXISTS router_bandwidth_audit (
      id INTEGER PRIMARY KEY, ts REAL NOT NULL, actor TEXT NOT NULL,
      operation TEXT NOT NULL, result TEXT NOT NULL, target_count INTEGER NOT NULL
    )""")


def _actor(value: object) -> str:
    if (not isinstance(value, str) or not value or len(value) > 128 or
            any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise BandwidthStoreError("bandwidth actor is invalid")
    return value


def _timestamp(value: object) -> None:
    if (isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0 or
            (isinstance(value, float) and not math.isfinite(value))):
        raise BandwidthStoreError("bandwidth timestamp is invalid")


def _canonical_mac(value: object) -> str:
    if not isinstance(value, str):
        raise BandwidthStoreError("bandwidth MAC is invalid")
    normalized = normalize_mac(value)
    if not normalized or not MAC_RE.fullmatch(normalized):
        raise BandwidthStoreError("bandwidth MAC is invalid")
    return normalized


def _rate(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 100 <= value <= 1_000_000:
        raise BandwidthStoreError("bandwidth rate is invalid")
    return value


def _validate_record(record: object) -> dict:
    if not isinstance(record, dict) or set(record) != _RECORD_KEYS:
        raise BandwidthStoreError("bandwidth operation has invalid fields")
    actor = _actor(record["actor"])
    _timestamp(record["created_at"])
    firmware = record["firmware"]
    if not isinstance(firmware, str) or not firmware or len(firmware) > 128 or any(ord(c) < 32 for c in firmware):
        raise BandwidthStoreError("bandwidth firmware is invalid")
    phase = record["phase"]
    if not isinstance(phase, str) or phase not in _PHASES:
        raise BandwidthStoreError("bandwidth operation phase is invalid")
    if not isinstance(record["engine_setup"], bool) or not isinstance(record["remove"], bool):
        raise BandwidthStoreError("bandwidth operation flags are invalid")
    for key in ("down_kbps", "up_kbps"):
        if record[key] is not None:
            _rate(record[key])
    if record["remove"] != (record["down_kbps"] is None and record["up_kbps"] is None):
        raise BandwidthStoreError("bandwidth operation rates do not match its action")
    if record["global_before"] is not None and canonical_qos_global(record["global_before"]) is None:
        raise BandwidthStoreError("bandwidth global snapshot is invalid")
    if record["global_after"] is not None and canonical_qos_global(record["global_after"]) is None:
        raise BandwidthStoreError("bandwidth global target is invalid")
    rows = record["rules_before"]
    if not isinstance(rows, list) or len(rows) > 128:
        raise BandwidthStoreError("bandwidth rule snapshot is invalid")
    before, seen_names = [], set()
    before_by_name = {}
    for raw in rows:
        row = canonical_rate_rule_row(raw)
        if row is None or row["name"] in seen_names:
            raise BandwidthStoreError("bandwidth rule snapshot is invalid")
        seen_names.add(row["name"])
        before.append(row)
        before_by_name[row["name"]] = row
    classes = record["classes_before"]
    if not isinstance(classes, list) or len(classes) > 128:
        raise BandwidthStoreError("bandwidth classification snapshot is invalid")
    checked_classes, seen_classes = [], set()
    for raw in classes:
        row = canonical_classification_row(raw)
        if row is None or row["id"] in seen_classes:
            raise BandwidthStoreError("bandwidth classification snapshot is invalid")
        seen_classes.add(row["id"])
        checked_classes.append(row)
    targets = record["targets"]
    if not isinstance(targets, list) or not 1 <= len(targets) <= 128:
        raise BandwidthStoreError("bandwidth operation target count is invalid")
    seen_macs = set()
    checked = []
    for target in targets:
        if not isinstance(target, dict) or set(target) != {"mac", "ip", "before_row", "after_row"}:
            raise BandwidthStoreError("bandwidth target has invalid fields")
        mac = _canonical_mac(target["mac"])
        ip = target["ip"]
        if not isinstance(ip, str) or len(ip) > 64 or any(ord(c) < 32 for c in ip):
            raise BandwidthStoreError("bandwidth target IP is invalid")
        try:
            address = ipaddress.ip_address(ip)
            if address.version != 4 or str(address) != ip:
                raise ValueError
        except ValueError:
            raise BandwidthStoreError("bandwidth target IP is invalid") from None
        if mac in seen_macs:
            raise BandwidthStoreError("bandwidth targets must be unique")
        seen_macs.add(mac)
        name, group = "NP_Q_" + mac.replace("-", ""), "NP_G_" + mac.replace("-", "")
        rows_for_target = {}
        for key in ("before_row", "after_row"):
            raw = target[key]
            if raw is None:
                rows_for_target[key] = None
                continue
            row = canonical_rate_rule_row(raw)
            if (row is None or row["name"] != name or row["ip_group"] != group or
                    row["if_pong"] != "WAN2" or row["mode"] != "priv" or
                    row["time"] != "Any" or row["enable"] != "on"):
                raise BandwidthStoreError("bandwidth target rule is not an owned WAN2 cap")
            rows_for_target[key] = row
        if rows_for_target["before_row"] is not None:
            if before_by_name.get(rows_for_target["before_row"]["name"]) != rows_for_target["before_row"]:
                raise BandwidthStoreError("bandwidth target prior row is not in the reviewed snapshot")
        if record["remove"]:
            if rows_for_target["after_row"] is not None:
                raise BandwidthStoreError("removed bandwidth target cannot have an after row")
        elif (rows_for_target["after_row"] is None or
              rows_for_target["after_row"]["rate_max"] != record["up_kbps"] or
              rows_for_target["after_row"]["rate_max_mate"] != record["down_kbps"]):
            raise BandwidthStoreError("bandwidth after row does not match the reviewed rates")
        checked.append({"mac": mac, "ip": ip, **rows_for_target})
    result = {"actor": actor, "created_at": record["created_at"], "firmware": firmware,
              "phase": phase, "targets": checked, "global_before": record["global_before"],
              "global_after": record["global_after"], "rules_before": before,
              "classes_before": checked_classes,
              "engine_setup": record["engine_setup"], "remove": record["remove"],
              "down_kbps": record["down_kbps"], "up_kbps": record["up_kbps"]}
    try:
        encoded = json.dumps(result, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError):
        raise BandwidthStoreError("bandwidth operation is not JSON-compatible") from None
    if len(encoded.encode("utf-8")) > _MAX_BYTES:
        raise BandwidthStoreError("bandwidth operation is too large")
    return copy.deepcopy(result)


def _entry(row) -> dict:
    intent_id, revision, phase, raw, version = row
    if (not isinstance(intent_id, str) or not _ID.fullmatch(intent_id) or
            not isinstance(revision, int) or revision < 1 or version != 1):
        raise BandwidthStoreError("saved bandwidth operation metadata is invalid")
    try:
        record = _validate_record(json.loads(raw))
    except (TypeError, json.JSONDecodeError):
        raise BandwidthStoreError("saved bandwidth operation is invalid") from None
    if record["phase"] != phase:
        raise BandwidthStoreError("saved bandwidth operation phase is inconsistent")
    return {"id": intent_id, "revision": revision, "record": record}


class BandwidthStore:
    """SQLite operation journal and verified current cap state."""

    def __init__(self, db_path: str | Path, clock):
        self.path = str(db_path)
        self.clock = clock
        try:
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
            with closing(_connect(self.path)) as db:
                _schema(db)
        except (OSError, sqlite3.Error):
            raise BandwidthStoreError("bandwidth storage initialization failed") from None

    @staticmethod
    def _id(value: object) -> str:
        if not isinstance(value, str) or not _ID.fullmatch(value):
            raise BandwidthStoreError("bandwidth operation ID is invalid")
        return value

    @staticmethod
    def _revision(value: object) -> None:
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise BandwidthStoreError("bandwidth operation revision is invalid")

    def prepare(self, record: dict) -> str:
        checked = _validate_record(record)
        encoded, ident = json.dumps(checked, sort_keys=True, separators=(",", ":")), secrets.token_urlsafe(24)
        try:
            with closing(_connect(self.path)) as db:
                db.execute("BEGIN IMMEDIATE")
                if db.execute("SELECT 1 FROM router_bandwidth_operations LIMIT 1").fetchone():
                    db.rollback()
                    raise BandwidthStoreConflict("a bandwidth operation is already pending")
                db.execute("INSERT INTO router_bandwidth_operations(id,revision,phase,record_json,schema_version) "
                           "VALUES(?,1,?,?,1)", (ident, checked["phase"], encoded))
                db.commit()
            return ident
        except BandwidthStoreError:
            raise
        except sqlite3.Error:
            raise BandwidthStoreError("bandwidth operation could not be prepared") from None

    def pending(self) -> list[dict]:
        try:
            with closing(_connect(self.path)) as db:
                rows = db.execute("SELECT id,revision,phase,record_json,schema_version "
                                  "FROM router_bandwidth_operations ORDER BY rowid").fetchall()
            return [copy.deepcopy(_entry(row)) for row in rows]
        except BandwidthStoreError:
            raise
        except sqlite3.Error:
            raise BandwidthStoreError("bandwidth operation state could not be read") from None

    def get(self, ident: str) -> dict | None:
        ident = self._id(ident)
        try:
            with closing(_connect(self.path)) as db:
                row = db.execute("SELECT id,revision,phase,record_json,schema_version "
                                 "FROM router_bandwidth_operations WHERE id=?", (ident,)).fetchone()
            return copy.deepcopy(_entry(row)) if row else None
        except BandwidthStoreError:
            raise
        except sqlite3.Error:
            raise BandwidthStoreError("bandwidth operation state could not be read") from None

    def replace(self, ident: str, expected_revision: int, record: dict) -> int:
        ident = self._id(ident)
        self._revision(expected_revision)
        checked = _validate_record(record)
        encoded = json.dumps(checked, sort_keys=True, separators=(",", ":"))
        try:
            with closing(_connect(self.path)) as db:
                db.execute("BEGIN IMMEDIATE")
                cur = db.execute("UPDATE router_bandwidth_operations SET revision=revision+1,phase=?,record_json=? "
                                 "WHERE id=? AND revision=?",
                                 (checked["phase"], encoded, ident, expected_revision))
                if cur.rowcount != 1:
                    db.rollback()
                    raise BandwidthStoreConflict("bandwidth operation revision is stale or missing")
                db.commit()
            return expected_revision + 1
        except BandwidthStoreError:
            raise
        except sqlite3.Error:
            raise BandwidthStoreError("bandwidth operation could not be updated") from None

    def finish(self, ident: str, expected_revision: int) -> None:
        ident = self._id(ident)
        self._revision(expected_revision)
        try:
            with closing(_connect(self.path)) as db:
                db.execute("BEGIN IMMEDIATE")
                row = db.execute("SELECT phase FROM router_bandwidth_operations WHERE id=? AND revision=?",
                                 (ident, expected_revision)).fetchone()
                if not row or row[0] not in {"recovering", "settling"}:
                    db.rollback()
                    raise BandwidthStoreConflict("bandwidth operation is not ready to finish")
                cur = db.execute("DELETE FROM router_bandwidth_operations WHERE id=? AND revision=?",
                                 (ident, expected_revision))
                if cur.rowcount != 1:
                    db.rollback()
                    raise BandwidthStoreConflict("bandwidth operation revision is stale or missing")
                db.commit()
        except BandwidthStoreError:
            raise
        except sqlite3.Error:
            raise BandwidthStoreError("bandwidth operation could not be finished") from None

    def complete(self, ident: str, expected_revision: int, caps: list[dict]) -> None:
        """Atomically persist verified caps and remove their completed intent."""
        ident = self._id(ident)
        self._revision(expected_revision)
        checked = self._validate_caps(caps)
        now = self.clock()
        _timestamp(now)
        try:
            with closing(_connect(self.path)) as db:
                db.execute("BEGIN IMMEDIATE")
                row = db.execute("SELECT phase,record_json,schema_version FROM router_bandwidth_operations "
                                 "WHERE id=? AND revision=?", (ident, expected_revision)).fetchone()
                if not row:
                    db.rollback()
                    raise BandwidthStoreConflict("bandwidth operation revision is stale or missing")
                record = _validate_record(json.loads(row[1]))
                if row[2] != 1 or record["phase"] != row[0]:
                    db.rollback()
                    raise BandwidthStoreError("bandwidth operation metadata is invalid")
                if record["phase"] != "settling":
                    db.rollback()
                    raise BandwidthStoreConflict("bandwidth operation is not ready to commit")
                expected_caps = {target["mac"]: {
                    "ip": target["ip"], "down_kbps": None if record["remove"] else record["down_kbps"],
                    "up_kbps": None if record["remove"] else record["up_kbps"], "actor": record["actor"]}
                    for target in record["targets"]}
                actual_caps = {cap["mac"]: {key: cap[key] for key in ("ip", "down_kbps", "up_kbps", "actor")}
                               for cap in checked}
                if actual_caps != expected_caps:
                    db.rollback()
                    raise BandwidthStoreError("verified cap records do not match the operation")
                for cap in checked:
                    if cap["down_kbps"] is None:
                        db.execute("DELETE FROM router_bandwidth_caps WHERE mac=?", (cap["mac"],))
                    else:
                        db.execute("""INSERT OR REPLACE INTO router_bandwidth_caps
                          (mac,ip,down_kbps,up_kbps,actor,updated_at) VALUES(?,?,?,?,?,?)""",
                          (cap["mac"], cap["ip"], cap["down_kbps"], cap["up_kbps"], cap["actor"], now))
                cur = db.execute("DELETE FROM router_bandwidth_operations WHERE id=? AND revision=?",
                                 (ident, expected_revision))
                if cur.rowcount != 1:
                    db.rollback()
                    raise BandwidthStoreConflict("bandwidth operation revision is stale or missing")
                db.commit()
        except BandwidthStoreError:
            raise
        except (sqlite3.Error, TypeError, ValueError, json.JSONDecodeError):
            raise BandwidthStoreError("verified bandwidth operation could not be committed") from None

    def caps(self) -> dict[str, dict]:
        try:
            with closing(_connect(self.path)) as db:
                rows = db.execute("SELECT mac,ip,down_kbps,up_kbps,actor,updated_at FROM router_bandwidth_caps "
                                  "ORDER BY mac").fetchall()
            result = {}
            for row in rows:
                mac = _canonical_mac(row[0])
                if (mac in result or not isinstance(row[1], str) or not row[1] or
                        isinstance(row[2], bool) or isinstance(row[3], bool) or
                        not isinstance(row[2], int) or not isinstance(row[3], int)):
                    raise BandwidthStoreError("saved bandwidth cap state is invalid")
                try:
                    address = ipaddress.ip_address(row[1])
                except ValueError:
                    raise BandwidthStoreError("saved bandwidth cap state is invalid") from None
                if address.version != 4 or str(address) != row[1]:
                    raise BandwidthStoreError("saved bandwidth cap state is invalid")
                _rate(row[2]); _rate(row[3]); _actor(row[4]); _timestamp(row[5])
                result[mac] = {"mac": mac, "ip": row[1], "down_kbps": row[2], "up_kbps": row[3],
                               "actor": row[4], "updated_at": row[5]}
            return result
        except BandwidthStoreError:
            raise
        except sqlite3.Error:
            raise BandwidthStoreError("verified bandwidth caps could not be read") from None

    def save_caps(self, caps: list[dict]) -> None:
        checked = self._validate_caps(caps)
        now = self.clock()
        _timestamp(now)
        try:
            with closing(_connect(self.path)) as db:
                db.execute("BEGIN IMMEDIATE")
                for cap in checked:
                    if cap["down_kbps"] is None:
                        db.execute("DELETE FROM router_bandwidth_caps WHERE mac=?", (cap["mac"],))
                    else:
                        db.execute("""INSERT OR REPLACE INTO router_bandwidth_caps
                          (mac,ip,down_kbps,up_kbps,actor,updated_at) VALUES(?,?,?,?,?,?)""",
                          (cap["mac"], cap["ip"], cap["down_kbps"], cap["up_kbps"], cap["actor"], now))
                db.commit()
        except sqlite3.Error:
            raise BandwidthStoreError("verified bandwidth caps could not be saved") from None

    @staticmethod
    def _validate_caps(caps: object) -> list[dict]:
        if not isinstance(caps, list) or len(caps) > 128:
            raise BandwidthStoreError("verified bandwidth cap batch is invalid")
        checked, seen = [], set()
        for cap in caps:
            if not isinstance(cap, dict) or set(cap) != {"mac", "ip", "down_kbps", "up_kbps", "actor"}:
                raise BandwidthStoreError("verified bandwidth cap record is invalid")
            mac = _canonical_mac(cap["mac"])
            if mac in seen:
                raise BandwidthStoreError("verified bandwidth cap targets must be unique")
            seen.add(mac)
            if not isinstance(cap["ip"], str) or not cap["ip"] or len(cap["ip"]) > 64:
                raise BandwidthStoreError("verified bandwidth cap IP is invalid")
            try:
                addr = ipaddress.ip_address(cap["ip"])
            except ValueError:
                raise BandwidthStoreError("verified bandwidth cap IP is invalid") from None
            if addr.version != 4 or str(addr) != cap["ip"]:
                raise BandwidthStoreError("verified bandwidth cap IP is invalid")
            down, up = cap["down_kbps"], cap["up_kbps"]
            if (down is None) != (up is None):
                raise BandwidthStoreError("verified bandwidth cap removal fields are invalid")
            if down is not None:
                down, up = _rate(down), _rate(up)
            checked.append({"mac": mac, "ip": cap["ip"], "down_kbps": down,
                            "up_kbps": up, "actor": _actor(cap["actor"])})
        return checked

    def audit(self, actor: str, operation: str, result: str, target_count: int) -> None:
        actor = _actor(actor)
        if (not isinstance(operation, str) or operation not in {"set", "remove", "recover"} or
                not isinstance(result, str) or result not in {"applied", "recovered", "failed"} or
                isinstance(target_count, bool) or not isinstance(target_count, int) or
                not 0 <= target_count <= 128):
            raise BandwidthStoreError("bandwidth audit entry is invalid")
        now = self.clock()
        _timestamp(now)
        try:
            with closing(_connect(self.path)) as db:
                db.execute("BEGIN IMMEDIATE")
                db.execute("INSERT INTO router_bandwidth_audit(ts,actor,operation,result,target_count) "
                           "VALUES(?,?,?,?,?)", (now, actor, operation, result, target_count))
                db.execute("DELETE FROM router_bandwidth_audit WHERE id NOT IN "
                           "(SELECT id FROM router_bandwidth_audit ORDER BY id DESC LIMIT 100)")
                db.commit()
        except sqlite3.Error:
            raise BandwidthStoreError("bandwidth audit entry could not be saved") from None
