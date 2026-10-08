"""Small display helpers for router-provided device names."""

from __future__ import annotations

import re

MAC_RE = re.compile(r"[0-9A-F]{2}(?:-[0-9A-F]{2}){5}\Z")
_PLACEHOLDERS = {"", "--", "---", "unknown", "unknown device", "none", "n/a"}


def normalize_mac(value: object) -> str:
    """Normalize a router or user MAC to uppercase hyphen-separated form."""
    address = str(value or "").strip().upper().replace(":", "-")
    return address if MAC_RE.fullmatch(address) else ""


def display_name(name, mac: str) -> str:
    """Replace common empty router labels with a stable, recognizable identity."""
    value = str(name or "").strip()
    if value.casefold() not in _PLACEHOLDERS:
        return value[:80]
    address = normalize_mac(mac)
    if address:
        suffix = "-".join(address.split("-")[-3:])
        return f"Unnamed device ({suffix})"
    return "Unnamed device"
