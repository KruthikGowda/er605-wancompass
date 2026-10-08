"""Small, non-invasive checks for the Pi disk and Raspberry Pi power throttling flags."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

from netpulse.storage import backup as db_backup

_SYSTEMCTL_RUN = subprocess.run


def _has_systemd_runtime() -> bool:
    return os.name == "posix" and Path("/run/systemd/system").is_dir()


def sample_acl_recovery() -> dict:
    """Read the bounded systemd recovery unit result without changing system state."""
    output = {"status": "unavailable"}
    if not _has_systemd_runtime():
        return output
    command = ["systemctl", "show", "netpulse-acl-recovery.service",
               "--property=LoadState", "--property=Result", "--property=ExecMainStatus",
               "--property=ActiveState"]
    try:
        completed = _SYSTEMCTL_RUN(command, capture_output=True, text=True, encoding="utf-8",
                                   errors="replace", timeout=2, check=False)
    except (OSError, subprocess.SubprocessError):
        return output
    if (completed.returncode != 0 or not isinstance(completed.stdout, str)
            or len(completed.stdout) > 8192):
        return output
    parsed = {}
    required = {"LoadState", "Result", "ExecMainStatus", "ActiveState"}
    for line in completed.stdout.splitlines():
        key, separator, value = line.partition("=")
        if separator and key in required:
            if key in parsed:
                return output
            parsed[key] = value.strip()
    if set(parsed) != required or parsed["LoadState"] != "loaded":
        return output
    valid_active = {"active", "reloading", "inactive", "failed", "activating",
                    "deactivating", "maintenance", "refreshing"}
    valid_results = {"success", "protocol", "timeout", "exit-code", "signal", "core-dump",
                     "watchdog", "start-limit-hit", "resources", "deadlock", "dependency",
                     "skipped", "exec-condition", "condition", "reload-failed", "failure-action"}
    status_text = parsed["ExecMainStatus"]
    if (parsed["ActiveState"] not in valid_active or parsed["Result"] not in valid_results
            or not re.fullmatch(r"\d{1,9}", status_text)):
        return output
    if parsed["ActiveState"] in {"activating", "deactivating", "reloading", "maintenance", "refreshing"}:
        output["status"] = "pending"
    elif parsed["Result"] in {"skipped", "condition", "exec-condition"}:
        return output
    elif (parsed["ActiveState"] == "failed" or parsed["Result"] != "success"
          or int(status_text) != 0):
        output["status"] = "failed"
    else:
        output["status"] = "ok"
    return output


def sample(db_path: str, backup_config=None) -> dict:
    result = {
        "disk_total_bytes": None,
        "disk_free_bytes": None,
        "disk_free_pct": None,
        "disk_check_status": "unavailable",
        "temperature_c": None,
        "load_per_core": None,
        "memory_available_pct": None,
        "memory_available_mb": None,
        "undervoltage": None,
        "undervoltage_occurred": None,
        "arm_frequency_capped": None,
        "arm_frequency_capped_occurred": None,
        "throttled": None,
        "throttled_occurred": None,
        "soft_temp_limit": None,
        "soft_temp_limit_occurred": None,
        "boot_id": None,
        "power_check_status": "tool_missing",
        "acl_recovery": {"status": "unavailable"},
    }
    result["acl_recovery"] = sample_acl_recovery()
    try:
        usage = shutil.disk_usage(Path(db_path).parent)
        result.update(
            disk_total_bytes=usage.total,
            disk_free_bytes=usage.free,
            disk_free_pct=round(100 * usage.free / usage.total, 1) if usage.total else None,
            disk_check_status="available",
        )
    except OSError:
        pass
    try:
        result["boot_id"] = Path("/proc/sys/kernel/random/boot_id").read_text().strip() or None
    except OSError:
        pass
    try:
        load = float(Path("/proc/loadavg").read_text().split()[0])
        cores = os.cpu_count()
        if cores:
            result["load_per_core"] = round(load / cores, 2)
    except (OSError, ValueError, IndexError):
        pass
    try:
        memory = {}
        for line in Path("/proc/meminfo").read_text().splitlines():
            key, separator, rest = line.partition(":")
            if separator and key in ("MemTotal", "MemAvailable"):
                fields = rest.split()
                if fields:
                    memory[key] = int(fields[0])
        total_kb, available_kb = memory.get("MemTotal"), memory.get("MemAvailable")
        if total_kb and available_kb is not None:
            result["memory_available_pct"] = round(100 * available_kb / total_kb, 1)
            result["memory_available_mb"] = round(available_kb / 1024, 1)
    except (OSError, ValueError):
        pass
    executable = shutil.which("vcgencmd")
    if executable:
        try:
            text = subprocess.run([executable, "get_throttled"], check=True, capture_output=True,
                                  text=True, timeout=2).stdout
            match = re.search(r"(?:get_)?throttled=0x([0-9a-f]+)", text, re.IGNORECASE)
            if match:
                result["power_check_status"] = "available"
                flags = int(match.group(1), 16)
                result["undervoltage"] = bool(flags & 0x1)
                result["undervoltage_occurred"] = bool(flags & 0x10000)
                result["arm_frequency_capped"] = bool(flags & 0x2)
                result["arm_frequency_capped_occurred"] = bool(flags & 0x20000)
                result["throttled"] = bool(flags & 0x4)
                result["throttled_occurred"] = bool(flags & 0x40000)
                result["soft_temp_limit"] = bool(flags & 0x8)
                result["soft_temp_limit_occurred"] = bool(flags & 0x80000)
            else:
                result["power_check_status"] = "unexpected_response"
        except (OSError, subprocess.SubprocessError):
            result["power_check_status"] = "command_failed"
        try:
            text = subprocess.run([executable, "measure_temp"], check=True, capture_output=True,
                                  text=True, timeout=2).stdout
            match = re.search(r"\btemp=(-?\d+(?:\.\d+)?)['\"]?C\b", text, re.IGNORECASE)
            if match:
                result["temperature_c"] = float(match.group(1))
        except (OSError, subprocess.SubprocessError, ValueError):
            pass
    if backup_config is not None:
        if backup_config.enabled:
            result["backup"] = {
                "enabled": True,
                **db_backup.status(backup_config.directory, backup_config.interval_days,
                                   backup_config.mount_path),
            }
        else:
            result["backup"] = {"enabled": False}
    return result
