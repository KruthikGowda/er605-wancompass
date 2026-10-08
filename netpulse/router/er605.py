"""Read-only client for the TP-Link ER605 (standalone) web API. See docs/er605-api.md.

- HTTPS with the router's self-signed certificate **pinned** by SHA-256 fingerprint
  (verification is not disabled: a different certificate is rejected).
- Login: RSA public key + router uptime from the unauthenticated endpoints, then
  "<password>_<uptime>" encrypted with the router's own zero-padded raw RSA.
- The ER605 allows ONE admin session; a new login silently logs out the previous one
  (including a person in the web UI). So callers use `with client.session():` to log in,
  read, and log out again within a second or two.
- Never logs the password, the stok session token or the sysauth cookie.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import re
import ssl
import threading
from contextlib import contextmanager
from urllib.parse import urlencode

LOGIN_PATH = "/cgi-bin/luci/;stok=/login?form=login"
LOCALE_PATH = "/cgi-bin/luci/;stok=/locale?form=lang"
SECRET_KEY_RE = re.compile(r"pass|psk|secret|token|stok|key|user|auth|cookie|pin", re.I)


class RouterError(Exception):
    """Network/protocol problem talking to the router."""


class RouterAuthError(RouterError):
    """The router rejected the login. Never retry quickly: repeated failures trigger lockout."""


class CertificateMismatch(RouterError):
    """The router presented a different TLS certificate than the pinned one."""


# Verified from the authenticated ER605 v2.30 / firmware 2.3.3 Build 20251029
# Access Control page's `states` multi-select: new, established, related, invalid.
# The UI appends invalid after its three default selected states.
ACL_PILOT_STATES = ("new", "established", "related", "invalid")
ACL_PILOT_NAME_RE = re.compile(r"NP_TEST_P_[A-F0-9]{32}\Z")
ACL_COLLECTION_KEYS = {"rules", "acl", "acl_list", "acl_rules", "entries", "acl_inner"}
ACL_ROW_MARKERS = {"policy", "zone", "iptype", "service", "src", "dest"}
PAUSE_ACL_NAME_RE = re.compile(r"NP_PAUSE_[A-F0-9]{32}\Z")


def valid_pause_acl_row(row: object) -> bool:
    """True only for the exact managed IPv4 LAN DROP row shape used by pause controls."""
    expected_keys = {"name", "policy", "service", "iptype", "zone", "is_src", "src",
                     "is_dst", "dest", "time", "states", "position", "flag", "user"}
    if not isinstance(row, dict) or set(row) != expected_keys:
        return False
    return (PAUSE_ACL_NAME_RE.fullmatch(str(row.get("name", ""))) is not None
            and row.get("policy") == "DROP" and row.get("service") == "ALL"
            and row.get("iptype") == "ipv4" and row.get("zone") == "LAN"
            and row.get("is_src") == "ipgroup" and row.get("is_dst") == "ipgroup"
            and re.fullmatch(r"NP_G_[A-F0-9]{12}", str(row.get("src", ""))) is not None
            and row.get("dest") == "IPGROUP_ANY" and row.get("time") == "Any"
            and isinstance(row.get("states"), list)
            and all(isinstance(item, str) for item in row["states"])
            and len(row["states"]) == 4 and len(set(row["states"])) == 4
            and set(row["states"]) == set(ACL_PILOT_STATES)
            and row.get("position") == "" and row.get("flag") == "1" and row.get("user") == "1")


def canonical_pause_acl_row(observed: object) -> dict | None:
    """Canonicalize a firmware row, tolerating verified display normalization and metadata."""
    if not isinstance(observed, dict):
        return None
    keys = ("name", "policy", "service", "iptype", "zone", "is_src", "src", "is_dst", "dest",
            "time", "states", "position", "flag", "user")
    required = set(keys) - {"position"}
    if (not required.issubset(observed)
            or set(observed) - set(keys) - {"id", "key", "index", ".name"}):
        return None
    row = {key: observed[key] for key in keys if key in observed}
    # Position is an add-form hint, not an effective filtering predicate.
    row["position"] = ""
    if row.get("zone") == ["LAN"]:
        row["zone"] = "LAN"
    if (not isinstance(row.get("states"), list) or not all(isinstance(x, str) for x in row["states"])
            or len(row["states"]) != 4 or len(set(row["states"])) != 4
            or set(row["states"]) != set(ACL_PILOT_STATES)):
        return None
    return row if valid_pause_acl_row(row) else None


def pause_acl_effective_match(observed: dict, expected: dict) -> bool:
    canonical = canonical_pause_acl_row(observed)
    expected_row = expected if valid_pause_acl_row(expected) else canonical_pause_acl_row(expected)
    if canonical is None or expected_row is None:
        return False
    for key, value in expected_row.items():
        actual = canonical.get(key)
        if key == "position":
            continue
        if key == "zone":
            if actual != value and actual != [value]:
                return False
        elif key == "states":
            if (not isinstance(actual, list) or not all(isinstance(item, str) for item in actual)
                    or len(actual) != len(set(actual))
                    or set(actual) != set(value)):
                return False
        elif actual != value:
            return False
    return True


def acl_pilot_effective_match(observed: dict, expected: dict) -> bool:
    if not isinstance(observed, dict):
        return False
    for key, value in expected.items():
        actual = observed.get(key)
        if key == "position":
            # This is an add-form placement hint, not an effective rule predicate.
            # Read-back/delete use the fresh list index; firmware may normalize it.
            continue
        elif key == "zone":
            if actual != value and actual != [value]:
                return False
        elif key == "states":
            if (not isinstance(actual, list) or not all(isinstance(item, str) for item in actual)
                    or len(actual) != len(set(actual)) or set(actual) != set(value)):
                return False
        elif actual != value:
            return False
    return True


def _acl_rows(response, depth: int = 0) -> list[dict]:
    """Extract one unambiguous ACL collection; unknown wrappers fail closed."""
    if depth > 8 or not isinstance(response, dict) or str(response.get("error_code")) != "0":
        raise RouterError("ER605 ACL response is not a verified successful snapshot")
    result = response.get("result")
    if (result == {} and isinstance(response.get("others"), dict)
            and isinstance(response["others"].get("max_rules"), int)
            and not isinstance(response["others"].get("max_rules"), bool)
            and 1 <= response["others"]["max_rules"] <= 4096):
        return []
    found: list[list[dict]] = []

    def visit(value, level: int) -> None:
        if level > 8:
            return
        if isinstance(value, list):
            if not value or (all(isinstance(row, dict) for row in value)
                             and any({str(k).lower() for k in row} & ACL_ROW_MARKERS for row in value)):
                found.append(value)
            for row in value:
                if isinstance(row, (dict, list)):
                    visit(row, level + 1)
        elif isinstance(value, dict):
            for key, child in value.items():
                if (str(key).lower() in ACL_COLLECTION_KEYS and isinstance(child, list)
                        and (not child or all(isinstance(row, dict) for row in child)
                             and any({str(k).lower() for k in row} & ACL_ROW_MARKERS for row in child))):
                    found.append(child)
                if isinstance(child, (dict, list)):
                    visit(child, level + 1)

    visit(result, 0)
    unique = {id(rows): rows for rows in found}
    if len(unique) != 1 or len(next(iter(unique.values()), [])) > 128:
        raise RouterError("ER605 ACL row collection is unknown, ambiguous, or too large")
    return next(iter(unique.values()))


def rsa_encrypt(plaintext: str, modulus_hex: str, exponent_hex: str) -> str:
    """The router's encrypt.js: UTF-8 bytes zero-padded at the END to key size, raw m^e mod n, hex."""
    n, e = int(modulus_hex, 16), int(exponent_hex, 16)
    size = (n.bit_length() + 7) // 8
    data = plaintext.encode()
    if len(data) > size:
        raise ValueError("password too long for the router's key")
    m = int.from_bytes(data + b"\x00" * (size - len(data)), "big")
    return format(pow(m, e, n), "x").rjust(size * 2, "0")


def fingerprint(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest().upper()


def normalize_fingerprint(fp: str) -> str:
    return re.sub(r"[^0-9A-Fa-f]", "", fp).upper()


def sanitize(obj):
    """Drop anything that could be a credential before data is stored or shown."""
    if isinstance(obj, dict):
        return {k: sanitize(v) for k, v in obj.items() if not SECRET_KEY_RE.search(str(k))}
    if isinstance(obj, list):
        return [sanitize(v) for v in obj]
    return obj


class ER605Client:
    def __init__(self, host: str, username: str, password: str, cert_sha256: str, timeout: float = 10):
        self.host = host
        self.username = username
        self._password = password
        self.cert_sha256 = normalize_fingerprint(cert_sha256)
        self.timeout = timeout
        self._stok: str | None = None
        self._cookie: str | None = None
        # A second login invalidates the first session on this firmware. Keep every
        # authenticated read/write transaction together, including dashboard writes.
        self._session_lock = threading.RLock()
        self._ctx = ssl.create_default_context()
        # Self-signed certificate: we check its exact fingerprint instead (see _connect).
        self._ctx.check_hostname = False
        self._ctx.verify_mode = ssl.CERT_NONE

    # --- transport ---

    def _connect(self) -> http.client.HTTPSConnection:
        conn = http.client.HTTPSConnection(self.host, timeout=self.timeout, context=self._ctx)
        try:
            conn.connect()
        except OSError as e:
            raise RouterError(f"cannot connect to router ({type(e).__name__})") from None
        der = conn.sock.getpeercert(binary_form=True)
        if not der or fingerprint(der) != self.cert_sha256:
            conn.close()
            raise CertificateMismatch("router certificate does not match the pinned fingerprint")
        return conn

    def _post(self, path: str, form: dict, referer: str = "/webpages/index.html") -> dict:
        base = f"https://{self.host}"
        headers = {
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "X-Requested-With": "XMLHttpRequest",
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Referer": base + referer,   # the router's CSRF check
            "Origin": base,
        }
        if self._cookie:
            headers["Cookie"] = self._cookie
        conn = self._connect()
        try:
            conn.request("POST", path, urlencode(form), headers)
            resp = conn.getresponse()
            body = resp.read()
            for k, v in resp.getheaders():
                if k.lower() == "set-cookie" and v.startswith("sysauth="):
                    self._cookie = v.split(";", 1)[0]
        except OSError as e:
            raise RouterError(f"request failed ({type(e).__name__})") from None
        finally:
            conn.close()
        if resp.status != 200:
            raise RouterError(f"HTTP {resp.status}")
        try:
            return json.loads(body)
        except ValueError:
            raise RouterError("router returned non-JSON") from None

    # --- unauthenticated ---

    def public_info(self) -> dict:
        """Model and uptime; needs no login, so it never disturbs anyone's session."""
        with self._session_lock:
            r = self._post(LOCALE_PATH, {"operation": "read"}, referer="/webpages/login.html")
            if r.get("error_code") not in ("0", 0):
                raise RouterError(f"public info error {r.get('error_code')}")
            return r["result"]

    # --- session ---

    def login(self) -> None:
        key = self._post(LOGIN_PATH, {"data": json.dumps({"method": "get"})}, referer="/webpages/login.html")
        try:
            n, e = key["result"]["password"]
        except (KeyError, TypeError, ValueError):
            raise RouterError("unexpected key response") from None
        uptime = self.public_info()["uptime"]
        enc = rsa_encrypt(f"{self._password}_{uptime}", n, e)
        r = self._post(LOGIN_PATH, {"data": json.dumps(
            {"method": "login", "params": {"username": self.username, "password": enc}})},
            referer="/webpages/login.html")
        if str(r.get("error_code")) != "0" or not (r.get("result") or {}).get("stok"):
            self._cookie = None
            raise RouterAuthError(f"login rejected (error_code {r.get('error_code')})")
        self._stok = r["result"]["stok"]

    def logout(self) -> None:
        if not self._stok:
            return
        try:
            self._post(f"/cgi-bin/luci/;stok={self._stok}/admin/system?form=logout",
                       {"data": json.dumps({"method": "logout"})})
        except RouterError:
            pass  # session probably already gone
        finally:
            self._stok = None
            self._cookie = None

    @contextmanager
    def session(self):
        with self._session_lock:
            self.login()
            try:
                yield self
            finally:
                self.logout()

    def get(self, module: str, form: str, params: dict | None = None):
        return self.get_response(module, form, params).get("result")

    def get_response(self, module: str, form: str, params: dict | None = None) -> dict:
        """Read an authenticated form while retaining its status/metadata envelope.

        Most callers want only ``result`` through :meth:`get`. Narrow safety tools may
        need ``others`` and ``error_code`` to distinguish a verified empty collection
        from an unknown response shape.
        """
        if not self._stok:
            raise RouterError("not logged in")
        payload = {"method": "get"}
        if params is not None:
            payload["params"] = params
        r = self._post(f"/cgi-bin/luci/;stok={self._stok}/admin/{module}?form={form}",
                       {"data": json.dumps(payload)})
        if str(r.get("error_code")) != "0":
            raise RouterError(f"{module}/{form} error {r.get('error_code')}")
        return r

    def set_row(self, module: str, form: str, index: int, key: str,
                old: dict, new: dict):
        """Edit one existing row on the three firmware-verified control forms.

        Call only inside ``session()``. The caller must read the collection immediately
        before this call, derive the UI row position/key, and retain ``old`` for rollback.
        This intentionally does not expose arbitrary router form writes.
        """
        if not self._stok:
            raise RouterError("not logged in")
        if (module, form) not in {
            ("ipgroup", "ipscope_reservation"),
            ("ipgroup", "ipgroup_reservation"),
            ("policy_route", "policy_route"),
        }:
            raise ValueError("router row-edit form is not allowlisted")
        if not isinstance(index, int) or index < 0 or not re.fullmatch(r"key-\d+", str(key)):
            raise ValueError("invalid router row identity")
        if (not isinstance(old, dict) or not isinstance(new, dict)
                or old.get("name") != new.get("name")
                or not str(old.get("name", "")).startswith("NP_")):
            raise ValueError("router row edits are limited to existing NP_ objects")
        payload = {"method": "set", "params": {"index": index, "key": key, "old": old, "new": new}}
        r = self._post(f"/cgi-bin/luci/;stok={self._stok}/admin/{module}?form={form}",
                       {"data": json.dumps(payload)})
        if str(r.get("error_code")) != "0":
            raise RouterError(f"{module}/{form} set error {r.get('error_code')}")
        return r.get("result")

    def read_acl_pilot_rows(self) -> list[dict]:
        """Read the one firmware-verified ACL collection for the bounded pilot."""
        return _acl_rows(self.get_response("access_ctl", "acl_inner"))

    def add_acl_pilot_rule(self, rows: list, new: dict) -> dict:
        """Add only an exact one-device IPv4 DROP probe row to an empty ACL."""
        if not self._stok:
            raise RouterError("not logged in")
        if not isinstance(rows, list) or rows:
            raise RouterError("ACL pilot requires a fresh, explicitly empty ACL snapshot")
        if not isinstance(new, dict) or not ACL_PILOT_NAME_RE.fullmatch(str(new.get("name", ""))):
            raise ValueError("ACL pilot row name is not an exact temporary identifier")
        expected = {"name", "policy", "service", "iptype", "zone", "is_src", "src",
                    "is_dst", "dest", "time", "states", "position", "flag", "user"}
        if set(new) != expected or any(new.get(k) != v for k, v in {
            "policy": "DROP", "service": "ALL", "iptype": "ipv4", "zone": "LAN",
            "is_src": "ipgroup", "is_dst": "ipgroup", "dest": "IPGROUP_ANY",
            "time": "Any", "states": list(ACL_PILOT_STATES), "position": "", "flag": "1", "user": "1",
        }.items()) or not re.fullmatch(r"NP_G_[A-F0-9]{12}", str(new.get("src", ""))):
            raise ValueError("ACL pilot row does not match the reviewed firmware payload")
        payload = {"method": "add", "params": {
            "index": 0, "key": "add", "old": "add", "new": new,
        }}
        result = self._post(f"/cgi-bin/luci/;stok={self._stok}/admin/access_ctl?form=acl_inner",
                            {"data": json.dumps(payload)})
        if str(result.get("error_code")) != "0":
            raise RouterError("access_ctl/acl_inner add error")
        observed = self.read_acl_pilot_rows()
        if len(observed) != 1 or not acl_pilot_effective_match(observed[0], new):
            raise RouterError("ACL pilot add read-back mismatch")
        return observed[0]

    def delete_acl_pilot_rule(self, name: str, expected_row: dict) -> None:
        """Delete only the exact temporary row created by this pilot."""
        if not self._stok:
            raise RouterError("not logged in")
        if not ACL_PILOT_NAME_RE.fullmatch(str(name)) or not isinstance(expected_row, dict) or expected_row.get("name") != name:
            raise ValueError("ACL pilot cleanup identity is invalid")
        rows = self.read_acl_pilot_rows()
        matches = [(index, row) for index, row in enumerate(rows)
                   if isinstance(row, dict) and row.get("name") == name]
        if len(matches) != 1 or not acl_pilot_effective_match(matches[0][1], expected_row):
            raise RouterError("ACL pilot row is missing, changed, or ambiguous; refusing deletion")
        index, _observed = matches[0]
        preserved = rows[:index] + rows[index + 1:]
        payload = {"method": "delete", "params": {"index": str(index), "key": f"key-{index}"}}
        result = self._post(f"/cgi-bin/luci/;stok={self._stok}/admin/access_ctl?form=acl_inner",
                            {"data": json.dumps(payload)})
        if str(result.get("error_code")) != "0":
            raise RouterError("access_ctl/acl_inner delete error")
        remaining = self.read_acl_pilot_rows()
        if any(isinstance(row, dict) and row.get("name") == name for row in remaining):
            raise RouterError("ACL pilot cleanup read-back failed")
        if remaining != preserved:
            raise RouterError("ACL pilot cleanup changed another ACL row")

    def read_pause_acl_rows(self) -> list[dict]:
        """Read the ACL collection for permanent pause rules using the strict envelope parser."""
        return _acl_rows(self.get_response("access_ctl", "acl_inner"))

    def add_pause_acl_rule(self, rows: list, new: dict) -> dict:
        """Append one managed pause rule while preserving a verified pause-only ACL snapshot.

        Multirow append ordering is staged but not live-verified; callers must keep this
        feature disabled until firmware placement behavior is confirmed.
        """
        if not self._stok:
            raise RouterError("not logged in")
        if not isinstance(rows, list) or len(rows) > 127 or any(canonical_pause_acl_row(r) is None for r in rows):
            raise RouterError("ACL pause add requires only unambiguous managed pause rows")
        if not valid_pause_acl_row(new):
            raise ValueError("ACL pause row does not match the managed payload")
        names = [r["name"] for r in rows]
        if len(names) != len(set(names)) or new["name"] in names:
            raise RouterError("ACL pause rule names are duplicate or already present")
        before = self.read_pause_acl_rows()
        if len(before) != len(rows) or not all(pause_acl_effective_match(a, b) for a, b in zip(before, rows)):
            raise RouterError("ACL pause snapshot changed or contains unmanaged rows; refusing add")
        payload = {"method": "add", "params": {"index": len(rows), "key": "add",
                   "old": "add", "new": new}}
        result = self._post(f"/cgi-bin/luci/;stok={self._stok}/admin/access_ctl?form=acl_inner",
                            {"data": json.dumps(payload)})
        if not isinstance(result, dict) or str(result.get("error_code")) != "0":
            raise RouterError("access_ctl/acl_inner pause add error")
        observed = self.read_pause_acl_rows()
        matches = [(i, row) for i, row in enumerate(observed)
                   if isinstance(row, dict) and row.get("name") == new["name"]]
        if len(matches) != 1 or len(observed) != len(rows) + 1:
            raise RouterError("ACL pause add read-back mismatch")
        i, added = matches[0]
        if i != len(rows) or not pause_acl_effective_match(added, new):
            raise RouterError("ACL pause add placement or read-back mismatch")
        preserved = [row for j, row in enumerate(observed) if j != i]
        if len(preserved) != len(rows) or not all(pause_acl_effective_match(a, b)
                                                  for a, b in zip(preserved, rows)):
            raise RouterError("ACL pause add changed an existing rule or its order")
        return added

    def delete_pause_acl_rule(self, name: str, expected_row: dict) -> None:
        """Delete a unique exact managed pause row at its current row index, then verify preservation."""
        if not self._stok:
            raise RouterError("not logged in")
        if (not isinstance(name, str) or not PAUSE_ACL_NAME_RE.fullmatch(name)
                or not valid_pause_acl_row(expected_row) or expected_row.get("name") != name):
            raise ValueError("ACL pause cleanup identity is invalid")
        rows = self.read_pause_acl_rows()
        matches = [(i, row) for i, row in enumerate(rows)
                   if isinstance(row, dict) and row.get("name") == name]
        if len(matches) != 1 or not pause_acl_effective_match(matches[0][1], expected_row):
            raise RouterError("ACL pause row is missing, changed, or ambiguous; refusing deletion")
        index, _ = matches[0]
        preserved = rows[:index] + rows[index + 1:]
        payload = {"method": "delete", "params": {"index": str(index), "key": f"key-{index}"}}
        result = self._post(f"/cgi-bin/luci/;stok={self._stok}/admin/access_ctl?form=acl_inner",
                            {"data": json.dumps(payload)})
        if not isinstance(result, dict) or str(result.get("error_code")) != "0":
            raise RouterError("access_ctl/acl_inner pause delete error")
        remaining = self.read_pause_acl_rows()
        if any(isinstance(row, dict) and row.get("name") == name for row in remaining):
            raise RouterError("ACL pause cleanup read-back failed")
        if len(remaining) != len(preserved) or not all(pause_acl_effective_match(a, b)
                                                      for a, b in zip(remaining, preserved)):
            raise RouterError("ACL pause cleanup changed another rule or its order")

    def add_row(self, module: str, form: str, rows: list, new: dict) -> dict:
        """Add one NP_-named row and verify it by reading the form back."""
        if not self._stok:
            raise RouterError("not logged in")
        if (module, form) not in {
            ("ipgroup", "ipscope_reservation"),
            ("ipgroup", "ipgroup_reservation"),
            ("policy_route", "policy_route"),
        }:
            raise ValueError("router row-add form is not allowlisted")
        if not isinstance(new, dict) or not str(new.get("name", "")).startswith("NP_"):
            raise ValueError("router row creation is limited to NP_ objects")
        if any(r.get("name") == new["name"] for r in rows if isinstance(r, dict)):
            raise RouterError("NetPulse router object already exists")
        index = len(rows)
        payload = {"method": "add", "params": {
            "index": index, "key": f"key-{index}", "old": "add", "new": new,
        }}
        r = self._post(f"/cgi-bin/luci/;stok={self._stok}/admin/{module}?form={form}",
                       {"data": json.dumps(payload)})
        if str(r.get("error_code")) != "0":
            raise RouterError(f"{module}/{form} add error {r.get('error_code')}")
        matches = [x for x in (self.get(module, form) or [])
                   if isinstance(x, dict) and x.get("name") == new["name"]]
        if len(matches) != 1:
            raise RouterError(f"{module}/{form} add read-back failed")
        return matches[0]

    def delete_row(self, module: str, form: str, name: str) -> None:
        """Delete exactly one NP_ row, resolving its current list position immediately first."""
        if not self._stok:
            raise RouterError("not logged in")
        if (module, form) not in {
            ("ipgroup", "ipscope_reservation"),
            ("ipgroup", "ipgroup_reservation"),
            ("policy_route", "policy_route"),
        }:
            raise ValueError("router row-delete form is not allowlisted")
        if not isinstance(name, str) or not name.startswith("NP_"):
            raise ValueError("router row deletion is limited to NP_ objects")
        rows = self.get(module, form) or []
        matches = [(i, r) for i, r in enumerate(rows)
                   if isinstance(r, dict) and r.get("name") == name]
        if len(matches) != 1:
            raise RouterError("NetPulse router object is missing or ambiguous")
        index, _ = matches[0]
        payload = {"method": "delete", "params": {"index": str(index), "key": f"key-{index}"}}
        r = self._post(f"/cgi-bin/luci/;stok={self._stok}/admin/{module}?form={form}",
                       {"data": json.dumps(payload)})
        if str(r.get("error_code")) != "0":
            raise RouterError(f"{module}/{form} delete error {r.get('error_code')}")
        if any(isinstance(x, dict) and x.get("name") == name for x in (self.get(module, form) or [])):
            raise RouterError(f"{module}/{form} delete read-back failed")

    def add_dhcp_reservation(self, rows: list, new: dict) -> dict:
        """Add one enabled DHCP reservation with IP-MAC binding explicitly off.

        This form was verified on ER605 v2.30: the `key` for add is the current
        list position; delete uses the numeric row id. Do not reuse generic row
        writes here because this form has different key semantics.
        """
        if not self._stok:
            raise RouterError("not logged in")
        if not isinstance(new, dict):
            raise ValueError("invalid DHCP reservation")
        mac = str(new.get("mac", "")).upper()
        ip = str(new.get("ip", ""))
        note = str(new.get("note", ""))
        if (not re.fullmatch(r"[0-9A-F]{2}(?:-[0-9A-F]{2}){5}", mac)
                or not re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", ip)
                or not note.startswith("NetPulse: ") or len(note) > 64
                or new.get("enable") != "on" or str(new.get("bind", "1")) != "0"
                or new.get("interface") != "LAN1"):
            raise ValueError("reservation must be a NetPulse-managed LAN1 entry with binding off")
        if any(isinstance(r, dict) and (str(r.get("mac", "")).upper() == mac or r.get("ip") == ip)
               for r in rows):
            raise RouterError("device MAC or IP already appears in the reservation list")
        index = len(rows)
        payload = {"method": "add", "params": {"index": index, "key": f"key-{index}", "old": "add",
            "new": {"ip": ip, "mac": mac, "note": note, "enable": "on", "bind": "0",
                    "ip_bind": "on", "interface": "LAN1"}}}
        path = f"/cgi-bin/luci/;stok={self._stok}/admin/dhcps?form=reservation"
        result = None
        request_error = None
        try:
            result = self._post(path, {"data": json.dumps(payload)})
        except RouterError as exc:
            request_error = exc
        check_rows = self.get("dhcps", "reservation") or []
        matches = [r for r in check_rows if isinstance(r, dict) and str(r.get("mac", "")).upper() == mac
                   and r.get("ip") == ip and r.get("note") == note]
        if request_error is not None:
            if len(matches) == 1 and str(matches[0].get("bind", "")).lower() in ("0", "false", "off"):
                try:
                    self.delete_dhcp_reservation(str(matches[0].get("id", "")), mac, ip, note)
                except RouterError as cleanup:
                    raise RouterError("reservation add outcome was uncertain and cleanup failed; inspect the "
                                      "NetPulse-managed row in Omada") from cleanup
            raise RouterError("reservation add outcome was uncertain; inspect the ER605 reservation list before retrying") from request_error
        if result is None or str(result.get("error_code")) != "0":
            raise RouterError(f"dhcps/reservation add error {(result or {}).get('error_code')}")
        if len(matches) != 1:
            raise RouterError("DHCP reservation add read-back failed; inspect the router before retrying")
        row = matches[0]
        if (str(row.get("enable", "")).lower() not in ("1", "true", "on")
                or str(row.get("bind", "")).lower() not in ("0", "false", "off")):
            if str(row.get("bind", "")).lower() in ("0", "false", "off"):
                self.delete_dhcp_reservation(str(row.get("id", "")), mac, ip, note)
            raise RouterError("DHCP reservation read-back differs or IP-MAC binding is enabled")
        return row

    def delete_dhcp_reservation(self, row_id: str, mac: str, ip: str, note: str) -> None:
        """Delete only the uniquely matched NetPulse reservation, then verify absence."""
        if not self._stok:
            raise RouterError("not logged in")
        if not str(note).startswith("NetPulse: ") or not str(row_id).isdigit():
            raise ValueError("reservation is not a removable NetPulse-managed entry")
        rows = self.get("dhcps", "reservation") or []
        matches = [(i, r) for i, r in enumerate(rows) if isinstance(r, dict)
                   and str(r.get("id")) == str(row_id) and str(r.get("mac", "")).upper() == mac
                   and str(r.get("ip")) == ip and str(r.get("note")) == note]
        if len(matches) != 1:
            raise RouterError("NetPulse DHCP reservation is missing or ambiguous")
        index, row = matches[0]
        if str(row.get("bind", "")).lower() not in ("0", "false", "off"):
            raise RouterError("IP-MAC binding is enabled for this entry; refusing automated deletion")
        path = f"/cgi-bin/luci/;stok={self._stok}/admin/dhcps?form=reservation"
        result = self._post(path, {"data": json.dumps({"method": "delete", "params": {
            "index": str(index), "key": str(row_id)}})})
        if str(result.get("error_code")) != "0":
            raise RouterError(f"dhcps/reservation delete error {result.get('error_code')}")
        if any(isinstance(r, dict) and str(r.get("id")) == str(row_id)
               and str(r.get("mac", "")).upper() == mac and str(r.get("ip")) == ip
               for r in (self.get("dhcps", "reservation") or [])):
            raise RouterError("DHCP reservation delete read-back failed")
