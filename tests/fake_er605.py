"""A fake TP-Link ER605 (standalone web API) over real HTTPS, for testing ER605Client.

Behaves like firmware 2.3.3 as observed on the real router:
- /login?form=login  {"method":"get"}   -> RSA public key (n, e)
- /locale?form=lang  operation=read      -> model + uptime (no login needed)
- /login?form=login  {"method":"login"} -> password must decrypt to "<password>_<uptime>"
- CSRF check: requests without the web UI's Referer/Origin get HTTP 404
- one admin session at a time: a new login invalidates the previous stok
- /admin/<module>?form=<form> with the right stok + sysauth cookie -> recorded responses
"""

from __future__ import annotations

import json
import random
import re
import secrets
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

FIXTURES = Path(__file__).resolve().parent / "fixtures"
CERT = FIXTURES / "fake-router.pem"


def _is_probable_prime(n: int, rounds: int = 16) -> bool:
    if n < 4:
        return n in (2, 3)
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29):
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d, s = d // 2, s + 1
    rng = random.Random(n)
    for _ in range(rounds):
        x = pow(rng.randrange(2, n - 2), d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _prime(bits: int, rng: random.Random) -> int:
    while True:
        c = rng.getrandbits(bits) | (1 << (bits - 1)) | 1
        if _is_probable_prime(c):
            return c


_KEY_CACHE: dict = {}


def rsa_keypair(bits: int = 512) -> tuple[int, int, int]:
    """(n, e, d). Deterministic and cached. 512-bit keeps the Pi fast; the client handles any size."""
    if bits not in _KEY_CACHE:
        rng, e = random.Random(605), 65537
        while True:
            p, q = _prime(bits // 2, rng), _prime(bits // 2, rng)
            phi = (p - 1) * (q - 1)
            if p != q and phi % e:
                _KEY_CACHE[bits] = (p * q, e, pow(e, -1, phi))
                break
    return _KEY_CACHE[bits]


def load_fixture(name: str = "er605_2.3.3.json") -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


class FakeER605:
    def __init__(self, username="admin", password="correct horse", fixture: dict | None = None):
        self.username, self.password = username, password
        self.fixture = fixture or load_fixture()
        self.n, self.e, self.d = rsa_keypair()
        self.boot = time.time() - 350_000          # "up about 4 days"
        self.stok: str | None = None
        self.cookie: str | None = None
        self.logins = self.failed_logins = self.logouts = 0
        self.requests: list[dict] = []
        self.overrides: dict[str, dict] = {}       # "module/form" -> full response dict
        self.fail_mutation: tuple[str, str, int] | None = None  # key, method, occurrence
        self._mutation_counts: dict[tuple[str, str], int] = {}
        self._lock = threading.Lock()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
                with outer._lock:
                    outer.requests.append({"path": self.path, "headers": dict(self.headers), "body": body})
                    code, payload, cookie = outer._route(self.path, dict(self.headers), parse_qs(body))
                data = json.dumps(payload).encode() if payload is not None else b"<h1>Not Found</h1>"
                self.send_response(code)
                self.send_header("Content-Type", "application/json" if payload is not None else "text/html")
                if cookie:
                    self.send_header("Set-Cookie", f"sysauth={cookie}; path=/; HttpOnly")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *a):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(CERT)
        self.server.socket = ctx.wrap_socket(self.server.socket, server_side=True)
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        self.host = f"127.0.0.1:{self.server.server_address[1]}"

    @property
    def uptime(self) -> int:
        return int(time.time() - self.boot)

    def reboot(self) -> None:
        self.boot = time.time() - 5
        self.stok = self.cookie = None

    # --- routing ---

    def _route(self, path: str, headers: dict, form: dict):
        origin_ok = headers.get("Origin") == f"https://{self.host}"
        referer_ok = headers.get("Referer", "").startswith(f"https://{self.host}/webpages/")
        if not (origin_ok and referer_ok):
            return 404, None, None  # the real router's CSRF guard answers 404
        data = json.loads(form.get("data", ["{}"])[0]) if "data" in form else {}

        if path == "/cgi-bin/luci/;stok=/locale?form=lang":
            loc = json.loads(json.dumps(self.fixture["locale"]))
            loc["result"]["uptime"] = self.uptime
            return 200, loc, None
        if path == "/cgi-bin/luci/;stok=/login?form=login":
            if data.get("method") == "get":
                return 200, {"id": 1, "result": {"password": [format(self.n, "x"), format(self.e, "x")]},
                             "error_code": "0"}, None
            if data.get("method") == "login":
                return self._login(data.get("params", {}))
            return 200, {"id": 1, "error_code": "-1"}, None

        m = re.match(r"^/cgi-bin/luci/;stok=([0-9a-f]*)/admin/(\w+)\?form=(\w+)$", path)
        if not m:
            return 404, None, None
        stok, module, formname = m.groups()
        if not self.stok or stok != self.stok or f"sysauth={self.cookie}" not in headers.get("Cookie", ""):
            return 200, {"id": 1, "error_code": "-40401", "result": {}}, None   # session expired
        if (module, formname) == ("system", "logout"):
            self.stok = self.cookie = None
            self.logouts += 1
            return 200, {"id": 1, "error_code": "0"}, None
        key = f"{module}/{formname}"
        if key in self.overrides:
            return 200, self.overrides[key], None
        if key not in self.fixture:
            return 200, {"id": 1, "error_code": "-1000"}, None
        method = data.get("method")
        if method in {"add", "set", "delete"}:
            # Model only the two firmware-verified write shapes used by NetPulse.
            # This is an isolated in-memory fixture; no live router is involved.
            rows = self.fixture[key]
            params = data.get("params", {})
            mutation_key = (key, method)
            self._mutation_counts[mutation_key] = self._mutation_counts.get(mutation_key, 0) + 1
            if self.fail_mutation == (*mutation_key, self._mutation_counts[mutation_key]):
                return 200, {"id": 1, "error_code": "-1000"}, None
            if not isinstance(rows, list) or not isinstance(params, dict):
                return 200, {"id": 1, "error_code": "-1000"}, None
            try:
                index = int(params.get("index", -1))
            except (TypeError, ValueError):
                return 200, {"id": 1, "error_code": "-1000"}, None
            if method == "add":
                new = params.get("new")
                if (index != len(rows) or params.get("old") != "add"
                        or params.get("key") != f"key-{index}" or not isinstance(new, dict)):
                    return 200, {"id": 1, "error_code": "-1000"}, None
                added = dict(new)
                if key == "dhcps/reservation":
                    ids = [int(r["id"]) for r in rows if isinstance(r, dict)
                           and str(r.get("id", "")).isdigit()]
                    added["id"] = str(max(ids, default=0) + 1)
                    added.setdefault("bind", "0")
                rows.append(added)
            elif method == "set":
                if (index < 0 or index >= len(rows) or params.get("key") != f"key-{index}"
                        or not isinstance(params.get("old"), dict)
                        or not isinstance(params.get("new"), dict)
                        or rows[index] != params["old"]):
                    return 200, {"id": 1, "error_code": "-1000"}, None
                rows[index] = dict(params["new"])
            else:
                if index < 0 or index >= len(rows):
                    return 200, {"id": 1, "error_code": "-1000"}, None
                if key == "dhcps/reservation":
                    if str(rows[index].get("id")) != str(params.get("key")):
                        return 200, {"id": 1, "error_code": "-1000"}, None
                elif params.get("key") != f"key-{index}":
                    return 200, {"id": 1, "error_code": "-1000"}, None
                del rows[index]
            return 200, {"id": 1, "result": params.get("new", {}), "error_code": "0"}, None
        return 200, {"id": 1, "result": self.fixture[key], "error_code": "0"}, None

    def _login(self, params: dict):
        size = (self.n.bit_length() + 7) // 8
        try:
            plain = pow(int(params.get("password", "0"), 16), self.d, self.n).to_bytes(size, "big").rstrip(b"\0").decode()
        except (ValueError, UnicodeDecodeError):
            plain = ""
        pw, _, stamp = plain.rpartition("_")
        fresh = stamp.isdigit() and abs(int(stamp) - self.uptime) <= 5
        if params.get("username") != self.username or pw != self.password or not fresh:
            self.failed_logins += 1
            return 200, {"id": 1, "error_code": "700", "result": {}}, None
        self.logins += 1
        self.stok, self.cookie = secrets.token_hex(16), secrets.token_hex(16)   # kicks any previous session
        return 200, {"id": 1, "result": {"stok": self.stok}, "error_code": "0"}, self.cookie

    def fingerprint(self) -> str:
        import hashlib
        der = ssl.PEM_cert_to_DER_cert(CERT.read_text().split("-----END CERTIFICATE-----")[0] + "-----END CERTIFICATE-----\n")
        return hashlib.sha256(der).hexdigest().upper()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
