"""Crash-safe storage for one unresolved batch of router route intents.

This module stores validated operation snapshots only. It never opens a router
session and does not decide whether a route is safe to apply.
"""
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

_PHASES = {"prepared", "applying", "settling", "recovering", "error"}
_MAC = re.compile(r"[0-9A-F]{2}(?:-[0-9A-F]{2}){5}\Z")
_INTENT_ID = re.compile(r"[A-Za-z0-9_-]{24,40}\Z")
_RECORD_KEYS = {"actor", "created_at", "firmware", "targets", "phase"}
_TARGET_KEYS = {"mac", "ip", "before_saved", "before_row", "after_row"}
_SAVED_KEYS = {"mac", "ip", "route", "updated_at", "actor", "expires_at",
               "expires_monotonic", "boot_id"}
_SAVED_REQUIRED = {"route", "updated_at", "actor", "expires_at", "expires_monotonic", "boot_id"}
_ROUTES = {"AUTO", "WAN1", "WAN2", "WAN1_ONLY", "WAN2_ONLY"}
_ROUTE_FIELDS = {
    ".name", "name", "service_type", "src_ipgroup", "dst_ipgroup", "interfaces", "timeobj",
    "mode", "comment", "state", "index", "src", "dst", "dst_country_group", "dst_domain", "flag",
}
_SECRETISH = re.compile(r"pass|psk|secret|token|stok|key|user|auth|cookie|pin", re.I)
_MAX_RECORD_BYTES = 128 * 1024
_MAX_JSON_DEPTH = 8
_MAX_JSON_NODES = 4096
_MAX_TEXT = 512


class RouteIntentError(ValueError):
    """A route-intent record or operation is invalid."""


class RouteIntentConflict(RouteIntentError):
    """A durable route intent exists already or a compare-and-swap is stale."""


class RouteIntentStorageError(RouteIntentError):
    """A storage operation failed; details are intentionally not exposed."""


def _connect(path: str | Path) -> sqlite3.Connection:
    db = sqlite3.connect(str(path), timeout=30, isolation_level=None)
    db.execute("PRAGMA busy_timeout=30000")
    return db


def _schema(db: sqlite3.Connection) -> None:
    db.execute("""CREATE TABLE IF NOT EXISTS router_route_intents (
      id TEXT PRIMARY KEY,
      singleton INTEGER NOT NULL UNIQUE DEFAULT 1 CHECK (singleton = 1),
      revision INTEGER NOT NULL CHECK (revision >= 1),
      phase TEXT NOT NULL CHECK (phase IN ('prepared','applying','settling','recovering','error')),
      record_json TEXT NOT NULL,
      schema_version INTEGER NOT NULL CHECK (schema_version = 1)
    )""")


def _text(value: object, name: str, limit: int = 128, *, allow_empty: bool = False) -> str:
    if (not isinstance(value, str) or len(value) > limit or
            (not allow_empty and not value.strip()) or
            any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise RouteIntentError(f"{name} is invalid")
    return value


def _timestamp(value: object, name: str, *, nullable: bool = False) -> int | float | None:
    if nullable and value is None:
        return None
    if (isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0 or
            (isinstance(value, float) and not math.isfinite(value))):
        raise RouteIntentError(f"{name} must be finite and nonnegative")
    return value


def _bounded_json(value: object) -> None:
    count = 0

    def visit(node: object, depth: int) -> None:
        nonlocal count
        count += 1
        if count > _MAX_JSON_NODES or depth > _MAX_JSON_DEPTH:
            raise RouteIntentError("route intent data is too complex")
        if node is None or isinstance(node, (str, bool, int)):
            if isinstance(node, str) and (len(node) > _MAX_TEXT or
                                          any(ord(char) < 32 or ord(char) == 127 for char in node)):
                raise RouteIntentError("route intent text is invalid")
            return
        if isinstance(node, float):
            if not math.isfinite(node):
                raise RouteIntentError("route intent numbers must be finite")
            return
        if isinstance(node, list):
            if len(node) > 512:
                raise RouteIntentError("route intent list is too long")
            for item in node:
                visit(item, depth + 1)
            return
        if isinstance(node, dict):
            if len(node) > 128:
                raise RouteIntentError("route intent object is too large")
            for key, item in node.items():
                if (not isinstance(key, str) or not key or len(key) > 128 or
                        any(ord(char) < 32 or ord(char) == 127 for char in key)):
                    raise RouteIntentError("route intent field name is invalid")
                if _SECRETISH.search(key):
                    raise RouteIntentError("route intent contains a forbidden field")
                visit(item, depth + 1)
            return
        raise RouteIntentError("route intent data must be JSON-compatible")

    visit(value, 0)


def _canonical_identity(mac: object, ip: object) -> tuple[str, str]:
    if not isinstance(mac, str) or not _MAC.fullmatch(mac):
        raise RouteIntentError("target MAC must use canonical uppercase dash format")
    if not isinstance(ip, str):
        raise RouteIntentError("target IP must be canonical IPv4")
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        raise RouteIntentError("target IP must be canonical IPv4") from None
    if address.version != 4 or str(address) != ip:
        raise RouteIntentError("target IP must be canonical IPv4")
    return mac, ip


def _validate_saved(value: object, mac: str, ip: str) -> dict | None:
    if value is None:
        return None
    if not isinstance(value, dict) or not _SAVED_REQUIRED <= set(value) or not set(value) <= _SAVED_KEYS:
        raise RouteIntentError("saved route record has invalid fields")
    if not isinstance(value["route"], str) or value["route"] not in _ROUTES:
        raise RouteIntentError("saved route preference is invalid")
    _timestamp(value["updated_at"], "saved route timestamp")
    if not isinstance(value["actor"], str):
        raise RouteIntentError("saved route actor is invalid")
    _text(value["actor"], "saved route actor", 128)
    _timestamp(value["expires_at"], "saved route expiry", nullable=True)
    _timestamp(value["expires_monotonic"], "saved monotonic expiry", nullable=True)
    boot = value["boot_id"]
    _text(boot, "saved boot ID", 128) if boot is not None else None
    if (value["expires_monotonic"] is None) != (boot is None):
        raise RouteIntentError("saved monotonic expiry and boot ID must be paired")
    if "mac" in value and value["mac"] != mac:
        raise RouteIntentError("saved route MAC does not match target")
    if "ip" in value and value["ip"] != ip:
        raise RouteIntentError("saved route IP does not match target")
    result = copy.deepcopy(value)
    if "mac" in result:
        _canonical_identity(result["mac"], ip)
    if "ip" in result:
        _canonical_identity(mac, result["ip"])
    return result


def _validate_row(value: object, mac: str, *, optional: bool) -> dict | None:
    if value is None:
        if optional:
            return None
        raise RouteIntentError("route row is required")
    if not isinstance(value, dict) or not value or not set(value) <= _ROUTE_FIELDS:
        raise RouteIntentError("route row has invalid fields")
    name = f"NP_R_{mac.replace('-', '')}"
    group = f"NP_G_{mac.replace('-', '')}"
    required = {"name", "service_type", "src_ipgroup", "dst_ipgroup", "interfaces", "timeobj",
                "mode", "comment", "state"}
    if not required <= set(value):
        raise RouteIntentError("route row is incomplete")
    if value.get("name") != name or (".name" in value and value[".name"] not in (None, name)):
        raise RouteIntentError("route row name does not match target")
    if (value["service_type"] != "ALL" or value["src_ipgroup"] != group or
            value["dst_ipgroup"] != "IPGROUP_ANY" or
            not isinstance(value["interfaces"], str) or value["interfaces"] not in {"WAN1", "WAN2"} or
            not isinstance(value["mode"], str) or value["mode"] not in {"Priority", "Only"} or
            not isinstance(value["state"], str) or value["state"] not in {"on", "off"} or
            value["timeobj"] != "Any" or value["comment"] != "NetPulse"):
        raise RouteIntentError("route row does not match the NetPulse route policy")
    if any(key in value and value[key] != "ipgroup" for key in ("src", "dst")):
        raise RouteIntentError("route row address type is invalid")
    _bounded_json(value)
    return copy.deepcopy(value)


def _validate_record(record: object) -> dict:
    if not isinstance(record, dict) or set(record) != _RECORD_KEYS:
        raise RouteIntentError("route intent has invalid fields")
    actor = _text(record["actor"], "actor", 128)
    created_at = _timestamp(record["created_at"], "created_at")
    firmware = _text(record["firmware"], "firmware", 128)
    phase = record["phase"]
    if not isinstance(phase, str) or phase not in _PHASES:
        raise RouteIntentError("route intent phase is invalid")
    targets = record["targets"]
    if not isinstance(targets, list) or not 1 <= len(targets) <= 128:
        raise RouteIntentError("route intent must contain 1 to 128 targets")
    seen_macs, seen_ips = set(), set()
    checked = []
    for target in targets:
        if not isinstance(target, dict) or set(target) != _TARGET_KEYS:
            raise RouteIntentError("route target has invalid fields")
        mac, ip = _canonical_identity(target["mac"], target["ip"])
        if mac in seen_macs or ip in seen_ips:
            raise RouteIntentError("route targets must have unique MAC and IP identities")
        seen_macs.add(mac)
        seen_ips.add(ip)
        checked.append({
            "mac": mac,
            "ip": ip,
            "before_saved": _validate_saved(target["before_saved"], mac, ip),
            "before_row": _validate_row(target["before_row"], mac, optional=True),
            "after_row": _validate_row(target["after_row"], mac, optional=True),
        })
    result = {"actor": actor, "created_at": created_at, "firmware": firmware,
              "targets": checked, "phase": phase}
    _bounded_json(result)
    try:
        encoded = json.dumps(result, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError):
        raise RouteIntentError("route intent is not valid JSON") from None
    if len(encoded.encode("utf-8")) > _MAX_RECORD_BYTES:
        raise RouteIntentError("route intent is too large")
    return result


def _entry(row) -> dict:
    intent_id, revision, phase, raw, version = row
    if version != 1 or not isinstance(revision, int) or revision < 1:
        raise RouteIntentError("saved route intent metadata is invalid")
    try:
        record = _validate_record(json.loads(raw))
    except (TypeError, json.JSONDecodeError):
        raise RouteIntentError("saved route intent is invalid") from None
    if record["phase"] != phase:
        raise RouteIntentError("saved route intent phase is inconsistent")
    return {"id": intent_id, "revision": revision, "record": copy.deepcopy(record)}


class RouteIntentStore:
    """Persist one process-independent route operation with revisioned CAS."""

    def __init__(self, db_path: str | Path):
        self.path = str(db_path)
        try:
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
            with closing(_connect(self.path)) as db:
                _schema(db)
        except (OSError, sqlite3.Error):
            raise RouteIntentStorageError("route intent storage initialization failed") from None

    def prepare(self, record: dict) -> str:
        checked = _validate_record(record)
        encoded = json.dumps(checked, sort_keys=True, separators=(",", ":"), allow_nan=False)
        intent_id = secrets.token_urlsafe(24)
        try:
            with closing(_connect(self.path)) as db:
                db.execute("BEGIN IMMEDIATE")
                if db.execute("SELECT 1 FROM router_route_intents LIMIT 1").fetchone():
                    db.rollback()
                    raise RouteIntentConflict("an unresolved route intent already exists")
                db.execute("INSERT INTO router_route_intents(id,revision,phase,record_json,schema_version) "
                           "VALUES(?,1,?,?,1)", (intent_id, checked["phase"], encoded))
                db.commit()
            return intent_id
        except RouteIntentError:
            raise
        except sqlite3.Error:
            raise RouteIntentStorageError("route intent could not be prepared") from None

    def pending(self) -> list[dict]:
        try:
            with closing(_connect(self.path)) as db:
                rows = db.execute("SELECT id,revision,phase,record_json,schema_version "
                                  "FROM router_route_intents ORDER BY rowid").fetchall()
            return [copy.deepcopy(_entry(row)) for row in rows]
        except RouteIntentError:
            raise
        except sqlite3.Error:
            raise RouteIntentStorageError("route intent state could not be read") from None

    def get(self, intent_id: str) -> dict | None:
        ident = self._id(intent_id)
        try:
            with closing(_connect(self.path)) as db:
                row = db.execute("SELECT id,revision,phase,record_json,schema_version "
                                  "FROM router_route_intents WHERE id=?", (ident,)).fetchone()
            return copy.deepcopy(_entry(row)) if row else None
        except RouteIntentError:
            raise
        except sqlite3.Error:
            raise RouteIntentStorageError("route intent state could not be read") from None

    def replace(self, intent_id: str, expected_revision: int, new_record: dict) -> int:
        ident = self._id(intent_id)
        self._revision(expected_revision)
        checked = _validate_record(new_record)
        encoded = json.dumps(checked, sort_keys=True, separators=(",", ":"), allow_nan=False)
        try:
            with closing(_connect(self.path)) as db:
                db.execute("BEGIN IMMEDIATE")
                cursor = db.execute("UPDATE router_route_intents SET revision=revision+1,phase=?,record_json=? "
                                    "WHERE id=? AND revision=?",
                                    (checked["phase"], encoded, ident, expected_revision))
                if cursor.rowcount != 1:
                    db.rollback()
                    raise RouteIntentConflict("route intent revision is stale or missing")
                db.commit()
                return expected_revision + 1
        except RouteIntentError:
            raise
        except sqlite3.Error:
            raise RouteIntentStorageError("route intent could not be replaced") from None

    def finish(self, intent_id: str, expected_revision: int) -> None:
        ident = self._id(intent_id)
        self._revision(expected_revision)
        try:
            with closing(_connect(self.path)) as db:
                db.execute("BEGIN IMMEDIATE")
                cursor = db.execute("DELETE FROM router_route_intents WHERE id=? AND revision=?",
                                    (ident, expected_revision))
                if cursor.rowcount != 1:
                    db.rollback()
                    raise RouteIntentConflict("route intent revision is stale or missing")
                db.commit()
        except RouteIntentError:
            raise
        except sqlite3.Error:
            raise RouteIntentStorageError("route intent could not be finished") from None

    def restore_saved(self, intent_id: str, expected_revision: int) -> None:
        """Restore prior device_routes rows after recovery has verified router state.

        The caller owns router verification and settling. This method changes only
        the local saved-route table and leaves the durable intent unresolved.
        """
        ident = self._id(intent_id)
        self._revision(expected_revision)
        try:
            with closing(_connect(self.path)) as db:
                db.execute("BEGIN IMMEDIATE")
                row = db.execute("SELECT id,revision,phase,record_json,schema_version "
                                 "FROM router_route_intents WHERE id=?", (ident,)).fetchone()
                if not row or row[1] != expected_revision:
                    db.rollback()
                    raise RouteIntentConflict("route intent revision is stale or missing")
                entry = _entry(row)
                if entry["record"]["phase"] not in {"recovering", "error"}:
                    db.rollback()
                    raise RouteIntentError("saved routes can be restored only during recovery")
                columns = {column[1] for column in db.execute("PRAGMA table_info(device_routes)")}
                required = {"mac", "ip", "route", "updated_at", "actor", "expires_at",
                            "expires_monotonic", "boot_id"}
                if not required <= columns:
                    db.rollback()
                    raise RouteIntentStorageError("saved route table is unavailable")

                plans = []
                for target in entry["record"]["targets"]:
                    mac, ip = target["mac"], target["ip"]
                    prior = target["before_saved"]
                    current_row = db.execute(
                        "SELECT ip,route,updated_at,actor,expires_at,expires_monotonic,boot_id "
                        "FROM device_routes WHERE mac=?", (mac,)).fetchone()
                    current = None
                    if current_row:
                        current = dict(zip(("ip", "route", "updated_at", "actor", "expires_at",
                                            "expires_monotonic", "boot_id"), current_row))
                        try:
                            _validate_saved({"mac": mac, **current}, mac, current["ip"])
                        except RouteIntentError:
                            db.rollback()
                            raise RouteIntentError("current saved route state is invalid") from None

                    expected_before = self._saved_row(prior, mac, ip) if prior is not None else None
                    if current == expected_before:
                        plans.append((mac, prior, False))
                        continue

                    operation_actor = entry["record"]["actor"]
                    permitted_routes = {"AUTO", self._row_route(target["after_row"])}
                    if prior is not None:
                        permitted_routes.add(prior["route"])
                    allowed_current = bool(
                        current and current["actor"] == operation_actor and
                        current["route"] in permitted_routes and
                        current["ip"] in {ip, (prior or {}).get("ip", ip)})
                    if current is not None and not allowed_current:
                        db.rollback()
                        raise RouteIntentConflict("saved device route changed outside this recovery")
                    if current is None and prior is None:
                        plans.append((mac, None, False))
                    else:
                        plans.append((mac, prior, True))

                # All targets are checked before any row changes; one transaction
                # rolls back the whole batch if an insert/delete fails.
                for mac, prior, needs_restore in plans:
                    if not needs_restore:
                        continue
                    if prior is None:
                        db.execute("DELETE FROM device_routes WHERE mac=?", (mac,))
                    else:
                        saved = self._saved_row(prior, mac, next(
                            target["ip"] for target in entry["record"]["targets"] if target["mac"] == mac))
                        db.execute("""INSERT OR REPLACE INTO device_routes
                          (mac,ip,route,updated_at,actor,expires_at,expires_monotonic,boot_id)
                          VALUES(?,?,?,?,?,?,?,?)""", (mac, saved["ip"], saved["route"], saved["updated_at"],
                          saved["actor"], saved["expires_at"], saved["expires_monotonic"], saved["boot_id"]))
                db.commit()
        except RouteIntentError:
            raise
        except sqlite3.Error:
            raise RouteIntentStorageError("saved route recovery failed") from None

    @staticmethod
    def _saved_row(saved: dict | None, mac: str, ip: str) -> dict | None:
        if saved is None:
            return None
        return {"ip": saved.get("ip", ip), "route": saved["route"], "updated_at": saved["updated_at"],
                "actor": saved["actor"], "expires_at": saved["expires_at"],
                "expires_monotonic": saved["expires_monotonic"], "boot_id": saved["boot_id"]}

    @staticmethod
    def _row_route(row: dict | None) -> str:
        if row is None or row["state"] == "off":
            return "AUTO"
        if row["mode"] == "Only":
            return row["interfaces"] + "_ONLY"
        return row["interfaces"]

    @staticmethod
    def _id(value: object) -> str:
        if not isinstance(value, str) or not _INTENT_ID.fullmatch(value):
            raise RouteIntentError("route intent ID is invalid")
        return value

    @staticmethod
    def _revision(value: object) -> None:
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise RouteIntentError("route intent revision is invalid")
