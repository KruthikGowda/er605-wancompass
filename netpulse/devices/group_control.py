"""Owner-reviewed device group membership changes."""
from __future__ import annotations

import copy
import hashlib
import json
import re
import secrets
import sqlite3
import threading
import time

from netpulse.devices.identity import MAC_RE, display_name, normalize_mac
from netpulse.router.control import ControlError
from netpulse.storage import sqlite

TOKEN_SECONDS = 120
MAX_PENDING = 2048
MAX_MEMBERS = 128
GROUP_NAME_RE = re.compile(r"[^\x00-\x1f\x7f]{1,40}\Z")


class GroupControl:
    """Prepare and atomically confirm app-level group membership changes."""

    def __init__(self, db_path: str, eligibility_provider=None):
        self.db_path = db_path
        self.eligibility_provider = eligibility_provider
        self._lock = threading.RLock()
        self._pending: dict[str, dict] = {}

    def preview(self, *, action, actor, group_id=None, macs=None, name=None):
        if not isinstance(actor, str) or not actor.strip():
            raise ControlError("An actor is required for confirmation.")
        action = str(action or "").lower()
        if action not in ("add", "remove", "create", "delete", "rename"):
            raise ControlError("Choose add, remove, create, rename, or delete group membership.")

        group = self._group(group_id) if action in ("add", "remove", "delete", "rename") else None
        if action in ("add", "remove"):
            if name is not None:
                raise ControlError("Choose group membership by selecting an existing group.")
            selected = self._macs(macs)
            if len(group["members"]) > MAX_MEMBERS:
                raise ControlError(f"This group has more than {MAX_MEMBERS} members; remove devices before editing it.")
            if action == "add":
                if set(selected) & set(group["members"]):
                    raise ControlError("Every selected device must be new to this group.")
                self._validate_new_members(selected)
                owners = self._other_group_owners(selected, group["id"])
                if owners:
                    raise ControlError("A selected device already belongs to another group.")
                after = sorted(group["members"] + selected)
                if len(after) > MAX_MEMBERS:
                    raise ControlError(f"A group can have no more than {MAX_MEMBERS} devices.")
                before = list(group["members"])
                added, removed = selected, []
                display_group = group["name"]
            else:
                missing = set(selected) - set(group["members"])
                if missing:
                    raise ControlError("Every selected device must still belong to this group.")
                after = [mac for mac in group["members"] if mac not in set(selected)]
                before = list(group["members"])
                added, removed = [], selected
                display_group = group["name"]
            target_name = group["name"]
        elif action == "create":
            if group_id is not None:
                raise ControlError("A new group cannot include an existing group ID.")
            selected = self._macs(macs)
            group_name = self._name(name)
            self._check_unique_name(group_name)
            self._validate_new_members(selected)
            owners = self._other_group_owners(selected)
            if owners:
                raise ControlError("A selected device already belongs to another group.")
            before, after = [], sorted(selected)
            added, removed = selected, []
            group_snapshot = None
            target_name = group_name
            display_group = group_name
        elif action == "rename":
            if macs is not None:
                raise ControlError("Rename a group by selecting its new name only.")
            group_name = self._name(name)
            self._check_unique_name(group_name, exclude_group_id=group["id"])
            selected = []
            before = list(group["members"])
            after = list(group["members"])
            added, removed = [], []
            target_name = group_name
            display_group = group_name
        else:
            if macs is not None or name is not None:
                raise ControlError("Delete a group by selecting its name only.")
            selected = list(group["members"])
            before, after = list(group["members"]), []
            added, removed = [], list(group["members"])
            target_name = group["name"]
            display_group = group["name"]

        if action != "create":
            group_snapshot = self._snapshot(group)
        details = self._describe_members(before + [mac for mac in after if mac not in before])
        before_details = [details[mac] for mac in before]
        after_details = [details[mac] for mac in after]
        added_details = [details[mac] for mac in added]
        removed_details = [details[mac] for mac in removed]
        effect = self._effect(action, display_group, before, after, group)
        payload = {"action": action, "actor": actor.strip(), "group": group_snapshot,
                   "name": target_name, "selected": list(selected), "before": before,
                   "after": after, "expires": time.time() + TOKEN_SECONDS}
        payload["fingerprint"] = self._fingerprint(payload)
        token = secrets.token_urlsafe(32)
        now = time.time()
        with self._lock:
            self._pending = {key: value for key, value in self._pending.items()
                             if value["expires"] > now}
            if len(self._pending) >= MAX_PENDING:
                raise ControlError("Too many pending group reviews; wait for older reviews to expire.")
            self._pending[token] = payload
        return {"token": token, "expires_in": TOKEN_SECONDS, "action": action,
                "fingerprint": payload["fingerprint"],
                "group_id": group["id"] if group else None, "group": display_group,
                "before_members": before_details, "after_members": after_details,
                "added": added_details, "removed": removed_details,
                "count": len(after), "effect": effect}

    def apply(self, token, actor):
        with self._lock:
            pending = self._pending.pop(str(token or ""), None)
        if not pending or pending["expires"] <= time.time():
            raise ControlError("This group review expired or was already used. Review the change again.")
        if actor != pending["actor"]:
            raise ControlError("The confirmation actor differs from the reviewed actor.")
        if pending["action"] in ("add", "create"):
            self._validate_new_members(pending["selected"])
            owners = self._other_group_owners(pending["selected"],
                                               pending["group"]["id"] if pending["group"] else None)
            if owners:
                raise ControlError("A selected device now belongs to another group; review a fresh change.")
        try:
            action = pending["action"]
            if action == "create":
                result = sqlite.save_device_group(self.db_path, pending["name"], pending["after"],
                                                  int(time.time()))
            elif action == "delete":
                if not sqlite.delete_device_group(self.db_path, pending["group"]["id"],
                                                  expected_snapshot=pending["group"]):
                    raise ControlError("The reviewed group no longer exists.")
                result = {"id": pending["group"]["id"], "name": pending["name"], "members": []}
            else:
                result = sqlite.save_device_group(self.db_path, pending["name"], pending["after"],
                                                  int(time.time()), pending["group"]["id"],
                                                  expected_snapshot=pending["group"],
                                                  preserve_smart_routing=action == "rename")
        except ControlError:
            raise
        except (ValueError, sqlite3.IntegrityError) as exc:
            message = ("The group or membership changed after review; no group change was applied."
                       if "changed after review" in str(exc).casefold() else
                       "A selected device or group name now conflicts with another group; no group change was applied.")
            raise ControlError(message) from exc
        return {"applied": True, "action": pending["action"], "group_id": result["id"],
                "group": result["name"], "members": list(result["members"]),
                "count": len(result["members"]), "fingerprint": pending["fingerprint"], "effect": self._effect(
                    pending["action"], result["name"], pending["before"], pending["after"], pending["group"])}

    @staticmethod
    def _fingerprint(payload):
        value = {key: payload.get(key) for key in
                 ("action", "actor", "group", "name", "selected", "before", "after")}
        canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def _group(self, group_id):
        if isinstance(group_id, bool) or not isinstance(group_id, int):
            raise ControlError("Choose a valid device group.")
        group = next((item for item in sqlite.device_groups(self.db_path) if item["id"] == group_id), None)
        if not group:
            raise ControlError("This device group no longer exists.")
        return group

    @staticmethod
    def _snapshot(group):
        return {key: copy.deepcopy(group[key]) for key in
                ("id", "name", "updated_at", "smart_routing_enabled", "members")}

    @staticmethod
    def _name(value):
        if not isinstance(value, str):
            raise ControlError("Enter a group name between 1 and 40 characters.")
        value = value.strip()
        if not GROUP_NAME_RE.fullmatch(value):
            raise ControlError("Enter a group name between 1 and 40 characters without control characters.")
        return value

    def _check_unique_name(self, name, exclude_group_id=None):
        if any(group["id"] != exclude_group_id and group["name"].casefold() == name.casefold()
               for group in sqlite.device_groups(self.db_path)):
            raise ControlError("A group with that name already exists.")

    @staticmethod
    def _macs(values):
        if not isinstance(values, (list, tuple)) or not values or len(values) > MAX_MEMBERS:
            raise ControlError(f"Select between 1 and {MAX_MEMBERS} devices.")
        normalized = [normalize_mac(value) for value in values]
        if any(not MAC_RE.fullmatch(mac) for mac in normalized) or len(set(normalized)) != len(normalized):
            raise ControlError("Select unique, valid devices.")
        return normalized

    def _inventory(self):
        if not callable(self.eligibility_provider):
            raise ControlError("Current eligible device inventory is unavailable; no membership can be added.")
        try:
            value = self.eligibility_provider()
        except Exception as exc:
            raise ControlError("Current eligible device inventory could not be read.") from exc
        devices = value.get("devices") if isinstance(value, dict) else value
        if not isinstance(devices, (list, tuple)):
            raise ControlError("Current eligible device inventory is unavailable.")
        result = {}
        duplicates = set()
        for item in devices:
            if not isinstance(item, dict):
                continue
            mac = normalize_mac(item.get("mac"))
            if not mac:
                continue
            if mac in result:
                duplicates.add(mac)
            else:
                result[mac] = item
        return result, duplicates

    def _validate_new_members(self, macs):
        inventory, duplicates = self._inventory()
        for mac in macs:
            item = inventory.get(mac)
            if mac in duplicates:
                raise ControlError("A selected device is ambiguous in the current inventory.")
            if not item:
                raise ControlError("A selected device is no longer in the current eligible inventory.")
            if (item.get("protected") or item.get("ambiguous") or item.get("eligible") is False
                    or item.get("listed") is False or item.get("current") is False):
                raise ControlError("A selected device is no longer eligible, protected, or ambiguous and cannot be added to a group.")

    def _other_group_owners(self, macs, group_id=None):
        selected = set(macs)
        return {mac for group in sqlite.device_groups(self.db_path) if group["id"] != group_id
                for mac in group["members"] if mac in selected}

    def _describe_members(self, macs):
        inventory, duplicates = self._inventory_for_display()
        labels = sqlite.device_labels(self.db_path)
        result = {}
        for mac in set(macs):
            known = sqlite.known_device(self.db_path, mac)
            item = inventory.get(mac) if mac not in duplicates else None
            raw_name = (labels.get(mac) or (item or {}).get("name")
                        or (known or {}).get("name") or "Home device")
            result[mac] = {"mac": mac, "name": display_name(raw_name, mac),
                           "ip": str((item or {}).get("ip") or (known or {}).get("ip") or "")}
        return result

    def _inventory_for_display(self):
        if not callable(self.eligibility_provider):
            return {}, set()
        try:
            value = self.eligibility_provider()
        except Exception:
            return {}, set()
        devices = value.get("devices") if isinstance(value, dict) else value
        if not isinstance(devices, (list, tuple)):
            return {}, set()
        result, duplicates = {}, set()
        for item in devices:
            if not isinstance(item, dict):
                continue
            mac = normalize_mac(item.get("mac"))
            if not mac:
                continue
            if mac in result:
                duplicates.add(mac)
            else:
                result[mac] = item
        return result, duplicates

    @staticmethod
    def _effect(action, group_name, before, after, group):
        if action == "create":
            return (f"Create group {group_name} with the listed devices. This only organizes devices; it does not "
                    "change WAN routes or pause/resume state.")
        if action == "rename":
            effect = (f"Rename this group to {group_name}. Its members and their WAN routes and pause/resume state "
                      "stay unchanged.")
            if group and group.get("smart_routing_enabled"):
                effect += " Smart WAN remains enabled for the same members."
            return effect
        if action == "delete":
            return (f"Delete group {group_name}. Device WAN routes and pause/resume state remain unchanged; "
                    "only the group and its membership are removed.")
        if action == "add":
            effect = (f"Add {len(after) - len(before)} listed devices to {group_name}. This does not change WAN routes "
                      "or pause/resume state.")
        else:
            effect = (f"Remove {len(before) - len(after)} listed devices from {group_name}. This does not change WAN routes "
                      "or pause/resume state.")
        if group and group.get("smart_routing_enabled"):
            effect += " Membership changes turn Smart WAN off; review and enable it again if wanted."
        return effect
