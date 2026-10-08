"""Connect NetPulse to your Telegram bot. Run on the Pi from the repo folder:

    sudo python3 tools/telegram_setup.py          # first-time setup
    sudo python3 tools/telegram_setup.py --add    # allow another Telegram account (family, 2nd phone)

1. Asks for the bot token from @BotFather (typed hidden, never printed or logged).
2. Asks you to send your bot any message, and picks up your chat ID from it.
3. Writes token + chat ID into /etc/netpulse/config.toml (keeps its owner and permissions).
4. Sends a test message and restarts NetPulse.
"""

from __future__ import annotations

import getpass
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

CONFIG = "/etc/netpulse/config.toml"
TOKEN_RE = re.compile(r"^\d{5,}:[A-Za-z0-9_-]{30,}$")


def api(token: str, method: str, payload: dict | None = None, timeout: float = 40) -> dict:
    req = urllib.request.Request(
        f"https://api.telegram.org/bot{token}/{method}",
        json.dumps(payload or {}).encode(),
        {"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        return {"ok": False, "error_code": e.code}
    except Exception as e:  # noqa: BLE001 - never print the URL (it contains the token)
        return {"ok": False, "description": type(e).__name__}


def set_keys(text: str, section: str, values: dict[str, str]) -> str:
    """Set key = value lines inside [section] of a TOML file, keeping everything else."""
    lines = text.splitlines()
    try:
        start = next(i for i, l in enumerate(lines) if l.strip() == f"[{section}]")
    except StopIteration:
        lines += ["", f"[{section}]"]
        start = len(lines) - 1
    end = next((i for i in range(start + 1, len(lines)) if lines[i].lstrip().startswith("[")), len(lines))
    pending = dict(values)
    for i in range(start + 1, end):
        m = re.match(r"^\s*([A-Za-z_]+)\s*=", lines[i])
        if m and m.group(1) in pending:
            lines[i] = f"{m.group(1)} = {pending.pop(m.group(1))}"
    for k, v in pending.items():
        lines.insert(start + 1, f"{k} = {v}")
    return "\n".join(lines) + "\n"


def write_preserving(path: str, text: str) -> None:
    st = os.stat(path)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path))
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.chown(tmp, st.st_uid, st.st_gid)
    os.chmod(tmp, st.st_mode & 0o777)
    os.replace(tmp, path)


def wait_for_private_chat(token: str, exclude: set[str], seconds: int = 300) -> dict | None:
    """Skip old updates, then return the first private chat (not in exclude) that messages the bot."""
    old = api(token, "getUpdates", {"timeout": 0})
    offset = max((u["update_id"] for u in old.get("result", [])), default=-1) + 1
    deadline = time.time() + seconds
    while time.time() < deadline:
        res = api(token, "getUpdates", {"offset": offset, "timeout": 25, "allowed_updates": ["message"]})
        for u in res.get("result", []):
            offset = u["update_id"] + 1
            c = (u.get("message") or {}).get("chat") or {}
            if c.get("type") == "private" and str(c.get("id")) not in exclude:
                api(token, "getUpdates", {"offset": offset, "timeout": 0})  # acknowledge
                return c
    return None


def chat_name(chat: dict) -> str:
    name = " ".join(filter(None, [chat.get("first_name"), chat.get("last_name")]))
    user = f"@{chat['username']}" if chat.get("username") else ""
    return " ".join(filter(None, [name, user])) or "?"


def add_account() -> None:
    import tomllib
    with open(CONFIG, "rb") as f:
        tg = tomllib.load(f).get("telegram", {})
    token = tg.get("bot_token", "")
    if not tg.get("enabled") or not token:
        sys.exit("Telegram isn't set up yet. Run: sudo python3 tools/telegram_setup.py")
    existing = [c.strip() for c in str(tg.get("chat_id", "")).split(",") if c.strip()]
    me = api(token, "getMe")
    if not me.get("ok"):
        sys.exit("Can't reach Telegram with the saved token. Check the Pi's internet and retry.")
    username = me["result"]["username"]

    # NetPulse itself is reading the bot's messages; pause it so this script can see the new one.
    print("Pausing NetPulse for a moment (monitoring resumes when this finishes)...")
    subprocess.run(["systemctl", "stop", "netpulse"], check=False)
    try:
        print(f"\nOn the other Telegram account, open https://t.me/{username} and send any message (or tap Start).")
        print("Waiting up to 5 minutes...")
        chat = wait_for_private_chat(token, set(existing))
        if chat is None:
            print("No message from a new account arrived. Nothing was changed.")
            return
        if input(f"\nGot a message from {chat_name(chat)}. Allow this account? [y/N] ").strip().lower() != "y":
            print("Cancelled. Nothing was changed.")
            return
        ids = existing + [str(chat["id"])]
        with open(CONFIG) as f:
            text = f.read()
        write_preserving(CONFIG, set_keys(text, "telegram", {"chat_id": f'"{", ".join(ids)}"'}))
        api(token, "sendMessage", {"chat_id": chat["id"],
                                   "text": "✅ You're connected to NetPulse. Your buttons appear in a moment."})
        print(f"✅ Added. {len(ids)} Telegram accounts can now use the bot and get alerts.")
    finally:
        subprocess.run(["systemctl", "start", "netpulse"], check=False)
        time.sleep(3)
        state = subprocess.run(["systemctl", "is-active", "netpulse"], capture_output=True, text=True).stdout.strip()
        print(f"NetPulse: {state}")


def main() -> None:
    if os.geteuid() != 0:
        sys.exit("Run with sudo: sudo python3 tools/telegram_setup.py")
    if not os.path.exists(CONFIG):
        sys.exit(f"{CONFIG} not found: install NetPulse first (sudo ./scripts/install.sh)")
    if "--add" in sys.argv[1:]:
        add_account()
        return

    print("NetPulse Telegram setup\n")
    print("In Telegram, open @BotFather, send /newbot, pick a name, and copy the token it gives you.")
    token = getpass.getpass("Paste the bot token (hidden): ").strip()
    if not TOKEN_RE.match(token):
        sys.exit("That doesn't look like a bot token (expected something like 123456789:AA...).")

    me = api(token, "getMe")
    if not me.get("ok"):
        sys.exit("Telegram rejected that token, or the Pi can't reach Telegram. Please check and retry.")
    username = me["result"]["username"]
    api(token, "deleteWebhook")
    # Skip anything sent to the bot before now.
    old = api(token, "getUpdates", {"timeout": 0})
    offset = max((u["update_id"] for u in old.get("result", [])), default=-1) + 1

    print(f"\n✅ Token OK: your bot is @{username}")
    print(f"Now open https://t.me/{username} in Telegram, tap Start (or send it any message).")
    print("Waiting up to 5 minutes...")

    deadline = time.time() + 300
    chat = None
    while time.time() < deadline and chat is None:
        res = api(token, "getUpdates", {"offset": offset, "timeout": 25, "allowed_updates": ["message"]})
        for u in res.get("result", []):
            offset = u["update_id"] + 1
            m = u.get("message") or {}
            c = m.get("chat") or {}
            if c.get("type") == "private":
                chat = c
                break
    if chat is None:
        sys.exit("No message received. Run the setup again and message the bot while it waits.")

    who = " ".join(filter(None, [chat.get("first_name"), chat.get("last_name")])) or chat.get("username", "?")
    if input(f"\nGot a message from {who}. Is that you? [y/N] ").strip().lower() != "y":
        sys.exit("Cancelled. Nothing was changed.")

    with open(CONFIG) as f:
        text = f.read()
    text = set_keys(text, "telegram", {"enabled": "true", "bot_token": f'"{token}"',
                                       "chat_id": f'"{chat["id"]}"'})
    write_preserving(CONFIG, text)
    print(f"✅ Saved to {CONFIG}")

    api(token, "sendMessage", {"chat_id": chat["id"],
                               "text": "✅ NetPulse is connected. Restarting now, your buttons appear in a moment."})
    subprocess.run(["systemctl", "restart", "netpulse"], check=False)
    time.sleep(3)
    state = subprocess.run(["systemctl", "is-active", "netpulse"], capture_output=True, text=True).stdout.strip()
    print(f"NetPulse restarted: {state}")
    print("Send 📶 Status in Telegram to try it.")


if __name__ == "__main__":
    main()
