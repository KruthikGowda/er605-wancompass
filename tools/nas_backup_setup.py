#!/usr/bin/env python3
"""Configure NetPulse database backups on a private NAS SMB share.

Run on the Pi with sudo. The NAS password is prompted with terminal echo disabled and
is written only to /etc/netpulse/nas.credentials (mode 0600).
"""

from __future__ import annotations

import getpass
import ipaddress
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from netpulse.config import load  # noqa: E402
from tools.route_expiry_preflight import imminent_route_expiry_count  # noqa: E402
from tools.telegram_setup import set_keys, write_preserving  # noqa: E402

CONFIG = Path("/etc/netpulse/config.toml")
SERVICE_REPO = Path("/opt/netpulse")
FSTAB = Path("/etc/fstab")
CREDENTIALS = Path("/etc/netpulse/nas.credentials")
MOUNT_PATH = Path("/mnt/netpulse-nas")
BACKUP_DIRECTORY = MOUNT_PATH / "netpulse-backups"
DEFAULT_HOST = ""
DEFAULT_SHARE = ""
EXPIRY_WINDOW_SECONDS = 15 * 60
COMMAND_TIMEOUT_SECONDS = 120
SHARE_RE = re.compile(r"^[A-Za-z0-9._$-]{1,80}$")
USERNAME_RE = re.compile(r"^[^\r\n\x00:=]{1,128}$")


@dataclass(frozen=True)
class Paths:
    config: Path = CONFIG
    fstab: Path = FSTAB
    credentials: Path = CREDENTIALS
    mount: Path = MOUNT_PATH
    backup_directory: Path = BACKUP_DIRECTORY


def validate_inputs(host: str, share: str, username: str, password: str) -> tuple[str, str, str, str]:
    """Validate fields used in SMB paths and the credentials file."""
    try:
        address = ipaddress.IPv4Address(host.strip())
    except ipaddress.AddressValueError:
        raise ValueError("NAS host must be a private IPv4 unicast address") from None
    private_ranges = (ipaddress.IPv4Network("10.0.0.0/8"),
                      ipaddress.IPv4Network("172.16.0.0/12"),
                      ipaddress.IPv4Network("192.168.0.0/16"))
    if (not any(address in network for network in private_ranges)
            or address.is_multicast or address.is_unspecified or address.is_loopback
            or address.is_reserved):
        raise ValueError("NAS host must be a private IPv4 unicast address")
    host = str(address)
    share = share.strip()
    if not SHARE_RE.fullmatch(share) or share in (".", ".."):
        raise ValueError("Share name contains unsupported characters")
    if share.casefold() in {"public", "smartware"}:
        raise ValueError("Choose the private NAS share; Public and SmartWare are not accepted")
    username = username.strip()
    if not USERNAME_RE.fullmatch(username):
        raise ValueError("NAS username must be one line and cannot contain ':', '=' or control characters")
    if not isinstance(password, str) or not password or any(c in password for c in "\r\n\x00"):
        raise ValueError("NAS password must be nonempty and contain no line breaks")
    return host, share, username, password


def credential_contents(username: str, password: str) -> bytes:
    if not USERNAME_RE.fullmatch(username) or not password or any(c in password for c in "\r\n\x00"):
        raise ValueError("Invalid SMB credentials")
    return f"username={username}\npassword={password}\n".encode("utf-8")


def fstab_entry(host: str, share: str, mount: Path, credentials: Path,
                uid: int, gid: int) -> str:
    source = f"//{host}/{share}"
    options = ",".join((f"credentials={credentials}", f"uid={uid}", f"gid={gid}",
                        "dir_mode=0750", "file_mode=0640", "nosuid", "nodev", "noexec",
                        "_netdev", "vers=default", "x-systemd.automount",
                        "x-systemd.idle-timeout=600", "nofail"))
    return f"{source} {mount} cifs {options} 0 0"


def add_fstab_entry(text: str, entry: str, mount: Path) -> tuple[str, bool]:
    """Add one entry; reject an existing conflicting source or mountpoint."""
    desired = shlex.split(entry)
    source, target = desired[0], desired[1]
    lines = text.splitlines()
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        fields = shlex.split(stripped, comments=True)
        if len(fields) < 3:
            continue
        if fields[1] == str(mount) or fields[0] == source:
            if fields == desired:
                return text if text.endswith("\n") or not text else text + "\n", False
            raise ValueError("/etc/fstab already has a conflicting NAS source or mountpoint")
    prefix = text if not text or text.endswith("\n") else text + "\n"
    return prefix + entry + "\n", True


def replace_exact_fstab_entry(path: Path, entry: str) -> None:
    lines = path.read_text(encoding="utf-8").splitlines()
    kept = [line for line in lines if line.strip() != entry]
    if len(kept) == len(lines):
        return
    write_preserving(str(path), "\n".join(kept).rstrip("\n") + "\n")


def backup_config_text(text: str, mount: Path, backup_directory: Path) -> str:
    return set_keys(text, "backup", {
        "enabled": "true", "directory": json.dumps(str(backup_directory)),
        "mount_path": json.dumps(str(mount)), "interval_days": "7", "keep": "8",
    })


def _run(command: list[str], *, runner: Callable = subprocess.run, **kwargs):
    """Run argv without a shell; callers should emit only generic errors."""
    return runner(command, check=False, text=True, capture_output=True,
                  timeout=COMMAND_TIMEOUT_SECONDS, **kwargs)


def _service_probe_code(directory: Path) -> str:
    return ("from pathlib import Path\nimport sys\n"
            "root = Path(sys.argv[1])\n"
            "existed = root.exists()\n"
            "root.mkdir(parents=True, exist_ok=True)\n"
            "marker = root / '.netpulse-managed'\n"
            "created = not marker.exists()\n"
            "if created and any(root.iterdir()):\n    raise SystemExit(3)\n"
            "if created:\n    marker.write_text('netpulse-backup-directory-v1\\n')\n"
            "elif marker.read_text() != 'netpulse-backup-directory-v1\\n':\n    raise SystemExit(4)\n"
            "print('NETPULSE_CREATED_BACKUP_MARKER=' + str(int(created)), flush=True)\n"
            "print('NETPULSE_CREATED_BACKUP_DIRECTORY=' + str(int(not existed)), flush=True)\n"
            "p = root / ('.netpulse-probe-' + sys.argv[2])\n"
            "try:\n    p.write_text('ok')\n"
            "finally:\n    p.unlink(missing_ok=True)\n")


def _backup_code(repo: Path) -> str:
    return ("import sys; sys.path.insert(0, sys.argv[1]); "
            "from netpulse.storage.backup import create, rehearse_restore; "
            "p=create(sys.argv[2], sys.argv[3], keep=8, mount_path=sys.argv[4]); "
            "print('NETPULSE_BACKUP_PATH=' + p, flush=True); "
            "r=rehearse_restore(p); "
            "assert r.get('integrity') == 'ok'; print('backup and restore rehearsal passed')")


def _remove_created_backup_code() -> str:
    return ("from pathlib import Path; import sys; p=Path(sys.argv[1]); root=Path(sys.argv[2]); "
            "assert p.parent == root and p.name.startswith('netpulse-db-') and p.name.endswith('.sqlite3'); "
            "p.unlink(missing_ok=True)")


def _remove_created_marker_code() -> str:
    return ("from pathlib import Path\nimport sys\n"
            "root = Path(sys.argv[1])\n"
            "marker = root / '.netpulse-managed'\n"
            "assert marker.read_text() == 'netpulse-backup-directory-v1\\n'\n"
            "marker.unlink()\n"
            "if sys.argv[2] == '1':\n    root.rmdir()\n")


def setup(host: str, share: str, username: str, password: str, *,
          paths: Paths = Paths(), runner: Callable = subprocess.run,
          is_mount: Callable[[Path], bool] = lambda p: os.path.ismount(p),
          is_root: bool = True, repo: Path | None = None,
          service_identity: tuple[int, int] | None = None) -> str:
    """Install credentials/mount, verify a backup as netpulse, then activate config."""
    host, share, username, password = validate_inputs(host, share, username, password)
    if not is_root:
        raise RuntimeError("Run this setup with sudo on the Pi")
    if not paths.config.is_file() or not paths.fstab.is_file():
        raise RuntimeError("NetPulse config or /etc/fstab is missing")
    cfg = load(paths.config)
    if not Path(cfg.db_path).is_file():
        raise RuntimeError("The NetPulse database is missing; run this setup on the Pi")
    runtime_repo = SERVICE_REPO if repo is None else Path(repo)
    if repo is None and not (runtime_repo / "netpulse" / "storage" / "backup.py").is_file():
        raise RuntimeError("Installed NetPulse backup package is missing under /opt/netpulse")
    try:
        if service_identity is None:
            import grp
            import pwd
            service_user = pwd.getpwnam("netpulse")
            service_uid = service_user.pw_uid
            service_gid = service_user.pw_gid
            group_gid = grp.getgrgid(service_gid).gr_gid
        else:
            service_uid, group_gid = service_identity
    except (KeyError, ImportError):
        raise RuntimeError("The netpulse service account is missing") from None
    if any(not shutil.which(command) for command in
           ("smbclient", "mount", "umount", "findmnt", "runuser", "systemctl")):
        raise RuntimeError("Install smbclient, cifs-utils, util-linux, and systemd before continuing")
    service_import = _run(["runuser", "-u", "netpulse", "--", sys.executable, "-B", "-c",
                           "import sys; sys.path.insert(0, sys.argv[1]); "
                           "import netpulse.storage.backup", str(runtime_repo)], runner=runner)
    if service_import.returncode != 0:
        raise RuntimeError("The netpulse service account cannot import the installed backup package")

    # Refuse guest-tree-connect shares entirely. A username/password file must target a
    # share that requires the private NAS account.
    guest = _run(["smbclient", f"//{host}/{share}", "-N", "-c", "quit"], runner=runner)
    if guest.returncode == 0:
        raise RuntimeError("This SMB share accepts guest access; choose a private-account-only share")

    credentials = credential_contents(username, password)
    entry = fstab_entry(host, share, paths.mount, paths.credentials,
                        service_uid, group_gid)
    old_fstab = paths.fstab.read_text(encoding="utf-8")
    new_fstab, fstab_added = add_fstab_entry(old_fstab, entry, paths.mount)
    old_config = paths.config.read_text(encoding="utf-8")
    new_config = backup_config_text(old_config, paths.mount, paths.backup_directory)

    # Validate the exact prospective config using NetPulse's normal parser before touching
    # credentials, fstab, or NAS storage.
    fd, candidate_name = tempfile.mkstemp(prefix="netpulse-nas-config-", suffix=".toml")
    candidate = Path(candidate_name)
    try:
        os.close(fd)
        candidate.write_text(new_config, encoding="utf-8")
        candidate_cfg = load(candidate)
    finally:
        candidate.unlink(missing_ok=True)
    if not candidate_cfg.backup.enabled or candidate_cfg.backup.interval_days != 7 or candidate_cfg.backup.keep != 8:
        raise RuntimeError("Prospective backup settings failed validation")
    imminent = imminent_route_expiry_count(cfg.db_path, window_seconds=EXPIRY_WINDOW_SECONDS)

    credentials_existed = paths.credentials.exists()
    if credentials_existed:
        try:
            existing = paths.credentials.read_bytes()
        except OSError:
            raise RuntimeError("Existing NAS credentials file cannot be read") from None
        if existing != credentials or (paths.credentials.stat().st_mode & 0o777) != 0o600:
            raise RuntimeError("An existing NAS credentials file conflicts; it was left untouched")
        if os.name == "posix" and paths.credentials.stat().st_uid != 0:
            raise RuntimeError("Existing NAS credentials file is not owned by root; it was left untouched")
    mount_created = not paths.mount.exists()
    mount_was_active = is_mount(paths.mount)
    active_mount_verified = False
    if mount_was_active:
        if not credentials_existed or fstab_added:
            raise RuntimeError("NAS mountpoint is active without matching saved setup; inspect it first")
        found = _run(["findmnt", "--noheadings", "--output", "SOURCE,FSTYPE",
                      "--target", str(paths.mount)], runner=runner)
        fields = (found.stdout or "").split()
        if (found.returncode != 0 or len(fields) != 2
                or fields[0].rstrip("/").casefold() != f"//{host}/{share}".casefold()
                or fields[1].casefold() != "cifs"):
            raise RuntimeError("NAS mountpoint is active for an unknown source; it was left untouched")
        active_mount_verified = True
    elif not mount_created and any(paths.mount.iterdir()):
        raise RuntimeError("NAS mountpoint directory is not empty; existing files were left untouched")
    fstab_written = False
    credentials_written = False
    config_written = False
    new_backup: str | None = None
    created_backup_marker = False
    created_backup_directory = False
    backup_result = None
    try:
        paths.mount.mkdir(parents=True, exist_ok=True)
        if not credentials_existed:
            fd = os.open(paths.credentials, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                with os.fdopen(fd, "wb") as out:
                    out.write(credentials)
            except Exception:
                paths.credentials.unlink(missing_ok=True)
                raise
            credentials_written = True
        if fstab_added:
            write_preserving(str(paths.fstab), new_fstab)
            fstab_written = True
            reloaded = _run(["systemctl", "daemon-reload"], runner=runner)
            if reloaded.returncode != 0:
                raise RuntimeError("systemd could not reload the new fstab entry")

        if not active_mount_verified:
            mounted = _run(["mount", str(paths.mount)], runner=runner)
            if mounted.returncode != 0 or not is_mount(paths.mount):
                raise RuntimeError("NAS authentication or mount failed; credentials and router state were not displayed")

        probe = _run(["runuser", "-u", "netpulse", "--", sys.executable, "-c",
                      _service_probe_code(paths.backup_directory),
                      str(paths.backup_directory), uuid.uuid4().hex], runner=runner)
        created_backup_marker = "NETPULSE_CREATED_BACKUP_MARKER=1" in (probe.stdout or "")
        created_backup_directory = "NETPULSE_CREATED_BACKUP_DIRECTORY=1" in (probe.stdout or "")
        if probe.returncode != 0:
            raise RuntimeError("NAS backup directory is not empty/unmanaged or is not writable")
        backup_result = _run(["runuser", "-u", "netpulse", "--", sys.executable, "-c",
                              _backup_code(runtime_repo), str(runtime_repo), cfg.db_path,
                              str(paths.backup_directory), str(paths.mount)], runner=runner)
        for line in (backup_result.stdout or "").splitlines():
            if line.startswith("NETPULSE_BACKUP_PATH="):
                candidate_backup = line.partition("=")[2]
                candidate_path = Path(candidate_backup)
                if (candidate_path.parent == paths.backup_directory
                        and candidate_path.name.startswith("netpulse-db-")
                        and candidate_path.name.endswith(".sqlite3")):
                    new_backup = candidate_backup
                break
        if (backup_result.returncode != 0
                or "backup and restore rehearsal passed" not in (backup_result.stdout or "")):
            raise RuntimeError("Consistent backup or restore rehearsal failed")

        # Recheck immediately before restart: the NAS rehearsal may take long enough for a
        # timed route to enter its protected expiry window.
        imminent = max(imminent, imminent_route_expiry_count(
            cfg.db_path, window_seconds=EXPIRY_WINDOW_SECONDS))

        write_preserving(str(paths.config), new_config)
        config_written = True
        if imminent:
            return ("NAS backup verified and enabled in config. Service restart was deferred because "
                    f"{imminent} timed WAN preference(s) are due or within 15 minutes; restart NetPulse "
                    "after they expire or are reviewed.")
        restarted = _run(["systemctl", "restart", "netpulse"], runner=runner)
        active = _run(["systemctl", "is-active", "--quiet", "netpulse"], runner=runner)
        if restarted.returncode != 0 or active.returncode != 0:
            raise RuntimeError("NetPulse service restart or active-state check failed")
        return "NAS backup verified, enabled, and NetPulse restarted."
    except Exception as original_error:
        rollback_errors: list[str] = []
        safe_to_unmount = not active_mount_verified
        safe_remote_cleanup = True

        def rollback_run(command: list[str]):
            try:
                return _run(command, runner=runner)
            except Exception:
                # Timeouts and runner errors must not prevent later safety cleanup.
                return subprocess.CompletedProcess(command, 1, stdout="", stderr="")

        if config_written:
            try:
                write_preserving(str(paths.config), old_config)
            except Exception:
                rollback_errors.append("previous config could not be restored")
                safe_to_unmount = False
                safe_remote_cleanup = False
            else:
                restored = rollback_run(["systemctl", "restart", "netpulse"])
                restored_active = rollback_run(["systemctl", "is-active", "--quiet", "netpulse"])
                if restored.returncode != 0 or restored_active.returncode != 0:
                    rollback_errors.append("previous NetPulse service could not be confirmed active")
                    safe_to_unmount = False
                    safe_remote_cleanup = False
        if safe_remote_cleanup and is_mount(paths.mount):
            if new_backup:
                cleaned_backup = rollback_run(["runuser", "-u", "netpulse", "--", sys.executable, "-c",
                                                _remove_created_backup_code(), new_backup,
                                                str(paths.backup_directory)])
                if cleaned_backup.returncode != 0:
                    rollback_errors.append("new rehearsal backup could not be removed")
            if created_backup_marker:
                cleaned_marker = rollback_run(["runuser", "-u", "netpulse", "--", sys.executable, "-c",
                                                _remove_created_marker_code(), str(paths.backup_directory),
                                                "1" if created_backup_directory else "0"])
                if cleaned_marker.returncode != 0:
                    rollback_errors.append("new backup-directory marker could not be removed")
        if safe_to_unmount and is_mount(paths.mount):
            unmounted = rollback_run(["umount", str(paths.mount)])
            if unmounted.returncode != 0 or is_mount(paths.mount):
                rollback_errors.append("NAS remains mounted")
                safe_to_unmount = False
        if safe_to_unmount:
            if fstab_written:
                try:
                    replace_exact_fstab_entry(paths.fstab, entry)
                except Exception:
                    rollback_errors.append("new fstab entry could not be removed")
                    safe_to_unmount = False
                if safe_to_unmount:
                    reloaded = rollback_run(["systemctl", "daemon-reload"])
                    if reloaded.returncode != 0:
                        rollback_errors.append("systemd could not reload the rolled-back fstab")
                        safe_to_unmount = False
            if credentials_written and safe_to_unmount:
                try:
                    paths.credentials.unlink(missing_ok=True)
                except OSError:
                    rollback_errors.append("new credentials file could not be removed")
        else:
            try:
                fstab_row_remains = any(
                    line.strip() == entry for line in paths.fstab.read_text(encoding="utf-8").splitlines())
            except OSError:
                fstab_row_remains = False
            rollback_errors.append(
                "fstab entry and root-only credentials were retained for NAS recovery"
                if fstab_row_remains else
                "root-only credentials were retained; systemd mount state needs inspection")
        if not safe_to_unmount and not any("credentials were retained" in e for e in rollback_errors):
            rollback_errors.append("root-only credentials were retained for NAS recovery")
        if mount_created and paths.mount.exists() and not is_mount(paths.mount):
            try:
                paths.mount.rmdir()
            except OSError:
                pass
        if rollback_errors:
            raise RuntimeError("Setup failed; rollback incomplete: " + "; ".join(rollback_errors)) from original_error
        raise


def main() -> int:
    print("Configure a private SMB share for NetPulse backups. No password is printed or logged.")
    if os.geteuid() != 0:
        print("Run this setup with sudo on the Pi.", file=sys.stderr)
        return 1
    host = input("NAS IPv4 address: ").strip()
    share = input("Private share: ").strip()
    username = input("NAS username: ")
    password = getpass.getpass("NAS password: ")
    try:
        validate_inputs(host, share, username, password)
        result = setup(host, share, username, password, is_root=True)
    except Exception as exc:
        # Error strings intentionally do not include credentials or subprocess output.
        print(f"NAS backup setup failed: {exc}", file=sys.stderr)
        return 1
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
