"""Safe, mocked checks for private NAS backup setup."""

from __future__ import annotations

import os
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from netpulse.storage.sqlite import Storage
from tools import nas_backup_setup as nas


CONFIG = '''[[wan]]
name = "WAN1"

[[wan]]
name = "WAN2"

[telegram]
enabled = false
'''


class NASBackupSetupTests(unittest.TestCase):
    def test_production_runtime_repo_defaults_to_installed_opt_path(self):
        self.assertEqual(nas.SERVICE_REPO, Path("/opt/netpulse"))

    def test_input_validation_rejects_public_shares_and_credentials_injection(self):
        self.assertEqual(nas.validate_inputs("10.0.0.20", "private-backups", "nasuser", "secret"),
                         ("10.0.0.20", "private-backups", "nasuser", "secret"))
        for share in ("Public", "SMARTWARE", "../private", "share/name"):
            with self.subTest(share=share), self.assertRaises(ValueError):
                nas.validate_inputs("10.0.0.20", share, "nasuser", "secret")
        for host in ("8.8.8.8", "127.0.0.1", "224.0.0.1", "169.254.1.1"):
            with self.subTest(host=host), self.assertRaisesRegex(ValueError, "private IPv4"):
                nas.validate_inputs(host, "private-backups", "nasuser", "secret")
        for username, password in (("name\npassword=leak", "secret"), ("nasuser", "bad\nvalue")):
            with self.subTest(username=username), self.assertRaises(ValueError):
                nas.validate_inputs("10.0.0.20", "private-backups", username, password)
        self.assertNotIn("secret", nas.credential_contents("nasuser", "secret").decode().splitlines()[0])

    def test_fstab_entry_is_private_modern_and_idempotent(self):
        mount, credentials = Path("/mnt/netpulse-nas"), Path("/etc/netpulse/nas.credentials")
        entry = nas.fstab_entry("10.0.0.20", "private-backups", mount, credentials, 1001, 1001)
        self.assertIn("vers=default", entry)
        self.assertNotIn("vers=1", entry)
        for option in ("nosuid", "nodev", "noexec", "_netdev", "x-systemd.automount",
                       "dir_mode=0750", "file_mode=0640"):
            self.assertIn(option, entry)
        original = "# keep this\nUUID=abc / ext4 defaults 0 1\n"
        updated, added = nas.add_fstab_entry(original, entry, mount)
        self.assertTrue(added)
        self.assertTrue(updated.startswith(original))
        same, added_again = nas.add_fstab_entry(updated, entry, mount)
        self.assertFalse(added_again)
        self.assertEqual(same, updated)
        with self.assertRaisesRegex(ValueError, "conflicting"):
            nas.add_fstab_entry(updated.replace("vers=default", "vers=3.0"), entry, mount)

    def test_backup_config_preserves_unrelated_settings_and_validates(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "candidate.toml"
            updated = nas.backup_config_text(CONFIG, Path("/mnt/netpulse-nas"),
                                             Path("/mnt/netpulse-nas/netpulse-backups"))
            self.assertIn('[telegram]\nenabled = false', updated)
            path.write_text(updated, encoding="utf-8")
            cfg = nas.load(path)
            self.assertTrue(cfg.backup.enabled)
            self.assertEqual(cfg.backup.interval_days, 7)
            self.assertEqual(cfg.backup.keep, 8)
            self.assertEqual(cfg.backup.mount_path, str(Path("/mnt/netpulse-nas")))
            self.assertEqual(cfg.backup.directory, str(Path("/mnt/netpulse-nas/netpulse-backups")))

    def _sandbox(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        cfg = root / "config.toml"
        cfg.write_text(CONFIG, encoding="utf-8")
        db = root / "netpulse.sqlite3"
        store = Storage(str(db))
        store.close()
        # Use a full config with a valid database path for setup's preflight.
        cfg.write_text(CONFIG + f'\n[general]\ndb_path = {json.dumps(str(db))}\n', encoding="utf-8")
        fstab = root / "fstab"
        fstab.write_text("# original fstab row\nUUID=x / ext4 defaults 0 1\n", encoding="utf-8")
        paths = nas.Paths(cfg, fstab, root / "nas.credentials", root / "mnt",
                          root / "mnt" / "netpulse-backups")
        return root, paths, db

    def _patch_platform(self):
        return (
            mock.patch.object(nas.shutil, "which", return_value="/mock/tool"),
            mock.patch.object(nas, "imminent_route_expiry_count", return_value=0),
            mock.patch.object(nas, "write_preserving", side_effect=self._write_without_chown),
        )

    @staticmethod
    def _write_without_chown(path, data):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        prior_mode = path.stat().st_mode & 0o777 if path.exists() else None
        path.write_bytes(data.encode() if isinstance(data, str) else data)
        if prior_mode is not None:
            path.chmod(prior_mode)

    def test_guest_accessible_share_is_refused_before_writes(self):
        _root, paths, _db = self._sandbox()
        fake_run = mock.Mock(return_value=SimpleNamespace(returncode=0, stdout="", stderr=""))
        patches = self._patch_platform()
        with patches[0], patches[1], patches[2]:
            with self.assertRaisesRegex(RuntimeError, "accepts guest access") as raised:
                nas.setup("10.0.0.20", "private-backups", "nasuser", "private-secret",
                          paths=paths, runner=fake_run, is_root=True, service_identity=(1001, 1001),
                          repo=Path("/repo"))
        self.assertNotIn("private-secret", str(raised.exception))
        self.assertFalse(paths.credentials.exists())
        self.assertNotIn("cifs", paths.fstab.read_text(encoding="utf-8"))
        self.assertEqual(fake_run.call_count, 2, "only package import and read-only guest check ran")

    def test_daemon_reload_failure_rolls_back_before_mount_or_config_change(self):
        _root, paths, _db = self._sandbox()
        original_config = paths.config.read_text(encoding="utf-8")
        original_fstab = paths.fstab.read_text(encoding="utf-8")
        calls = []
        reloads = [0]

        def fake_run(command, **_kwargs):
            calls.append(command)
            if command[0] == "smbclient":
                return SimpleNamespace(returncode=1, stdout="", stderr="")
            if command == ["systemctl", "daemon-reload"]:
                reloads[0] += 1
                return SimpleNamespace(returncode=1 if reloads[0] == 1 else 0,
                                       stdout="", stderr="")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        patches = self._patch_platform()
        with patches[0], patches[1], patches[2]:
            with self.assertRaisesRegex(RuntimeError, "could not reload the new fstab"):
                nas.setup("10.0.0.20", "private-backups", "nasuser", "private-secret",
                          paths=paths, runner=fake_run, is_root=True,
                          service_identity=(1001, 1001), repo=Path("/repo"))
        self.assertEqual(paths.config.read_text(encoding="utf-8"), original_config)
        self.assertEqual(paths.fstab.read_text(encoding="utf-8"), original_fstab)
        self.assertFalse(paths.credentials.exists())
        self.assertFalse(paths.mount.exists())
        self.assertFalse(any(command[0] == "mount" for command in calls))
        self.assertEqual(reloads[0], 2, "systemd is reloaded after removing the added fstab row")

    def test_conflicting_credentials_file_is_preserved(self):
        _root, paths, _db = self._sandbox()
        paths.credentials.write_text("username=other\npassword=keep-this\n", encoding="utf-8")
        fake_run = mock.Mock(side_effect=lambda command, **_kwargs: SimpleNamespace(
            returncode=0 if command[0] == "runuser" else 1, stdout="", stderr=""))
        original_credentials = paths.credentials.read_bytes()
        patches = self._patch_platform()
        with patches[0], patches[1], patches[2]:
            with self.assertRaisesRegex(RuntimeError, "credentials file conflicts"):
                nas.setup("10.0.0.20", "private-backups", "nasuser", "private-secret",
                          paths=paths, runner=fake_run, is_root=True,
                          service_identity=(1001, 1001), repo=Path("/repo"))
        self.assertEqual(paths.credentials.read_bytes(), original_credentials)
        self.assertNotIn("cifs", paths.fstab.read_text(encoding="utf-8"))

    def test_mount_failure_cleans_only_created_local_setup_files_and_redacts_secret(self):
        _root, paths, _db = self._sandbox()
        calls = []

        def fake_run(command, **_kwargs):
            calls.append(command)
            result = (1 if command[0] == "smbclient" else
                      0 if command[0] == "runuser" else
                      0 if command == ["systemctl", "daemon-reload"] else 32)
            return SimpleNamespace(returncode=result,
                                   stdout="", stderr="")

        patches = self._patch_platform()
        with patches[0], patches[1], patches[2]:
            with self.assertRaisesRegex(RuntimeError, "mount failed") as raised:
                nas.setup("10.0.0.20", "private-backups", "nasuser", "private-secret",
                          paths=paths, runner=fake_run, is_root=True,
                          service_identity=(1001, 1001), repo=Path("/repo"))
        self.assertNotIn("private-secret", str(raised.exception))
        self.assertFalse(paths.credentials.exists())
        self.assertFalse(paths.mount.exists())
        self.assertNotIn("cifs", paths.fstab.read_text(encoding="utf-8"))
        self.assertEqual([c[0] for c in calls], ["runuser", "smbclient", "systemctl", "mount", "systemctl"])
        self.assertTrue(paths.config.read_text(encoding="utf-8").startswith(CONFIG))

    def test_success_uses_argv_mount_and_rehearses_backup_before_config_activation(self):
        _root, paths, db = self._sandbox()
        service_repo = _root / "opt-netpulse"
        package_file = service_repo / "netpulse" / "storage" / "backup.py"
        package_file.parent.mkdir(parents=True)
        package_file.write_text("# installed package fixture\n", encoding="utf-8")
        calls = []
        mounted = [False]

        def fake_run(command, **_kwargs):
            calls.append(command)
            if command[0] == "mount":
                mounted[0] = True
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            if command[0] == "umount":
                mounted[0] = False
            if command[0] == "smbclient":
                return SimpleNamespace(returncode=1, stdout="", stderr="")
            if command[0] == "runuser" and "NETPULSE_CREATED_BACKUP_MARKER" in command[command.index("-c") + 1]:
                return SimpleNamespace(returncode=0, stdout="NETPULSE_CREATED_BACKUP_MARKER=1\n"
                                       "NETPULSE_CREATED_BACKUP_DIRECTORY=1\n", stderr="")
            if command[0] == "runuser" and "backup and restore rehearsal passed" in command[command.index("-c") + 1]:
                # The rehearsal command must be scheduled before config activation.
                self.assertFalse(paths.config.read_text(encoding="utf-8").find("enabled = true") >= 0)
                args = command[command.index("-c") + 2:]
                self.assertEqual(args[0], str(service_repo))
                self.assertEqual(args[1], str(db))
                self.assertEqual(args[2], str(paths.backup_directory))
                self.assertEqual(args[3], str(paths.mount))
                backup_path = paths.backup_directory / "netpulse-db-20261007T000000.000000Z.sqlite3"
                return SimpleNamespace(returncode=0,
                                       stdout=f"NETPULSE_BACKUP_PATH={backup_path}\nbackup and restore rehearsal passed\n",
                                       stderr="")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        patches = self._patch_platform()
        with patches[0], patches[1], patches[2], mock.patch.object(nas, "SERVICE_REPO", service_repo):
            result = nas.setup("10.0.0.20", "private-backups", "nasuser", "private-secret",
                               paths=paths, runner=fake_run, is_root=True,
                               is_mount=lambda _path: mounted[0],
                               service_identity=(1001, 1001))
        self.assertIn("restarted", result)
        if os.name == "posix":
            self.assertEqual(paths.credentials.stat().st_mode & 0o777, 0o600)
        self.assertEqual(paths.credentials.read_bytes(), b"username=nasuser\npassword=private-secret\n")
        self.assertIn("vers=default", paths.fstab.read_text(encoding="utf-8"))
        cfg = nas.load(paths.config)
        self.assertTrue(cfg.backup.enabled)
        self.assertEqual(cfg.backup.directory, str(paths.backup_directory))
        self.assertIn('[telegram]\nenabled = false', paths.config.read_text(encoding="utf-8"))
        self.assertEqual(calls[-2:], [["systemctl", "restart", "netpulse"],
                                      ["systemctl", "is-active", "--quiet", "netpulse"]])
        self.assertFalse(any("private-secret" in part for call in calls for part in call))
        self.assertNotIn("private-secret", result)

    def test_imminent_timed_route_defers_service_restart(self):
        _root, paths, _db = self._sandbox()
        calls = []
        mounted = [False]

        def fake_run(command, **_kwargs):
            calls.append(command)
            if command[0] == "mount":
                mounted[0] = True
            elif command[0] == "umount":
                mounted[0] = False
            elif command[0] == "smbclient":
                return SimpleNamespace(returncode=1, stdout="", stderr="")
            elif command[0] == "runuser":
                code = command[command.index("-c") + 1]
                if "NETPULSE_CREATED_BACKUP_MARKER" in code:
                    return SimpleNamespace(returncode=0,
                                           stdout="NETPULSE_CREATED_BACKUP_MARKER=1\n"
                                                  "NETPULSE_CREATED_BACKUP_DIRECTORY=1\n", stderr="")
                backup_path = paths.backup_directory / "netpulse-db-20261007T000000.000000Z.sqlite3"
                return SimpleNamespace(returncode=0,
                                       stdout=f"NETPULSE_BACKUP_PATH={backup_path}\n"
                                              "backup and restore rehearsal passed\n", stderr="")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        patches = self._patch_platform()
        with patches[0], mock.patch.object(nas, "imminent_route_expiry_count", return_value=1), patches[2]:
            result = nas.setup("10.0.0.20", "private-backups", "nasuser", "private-secret",
                               paths=paths, runner=fake_run, is_root=True,
                               is_mount=lambda _path: mounted[0], repo=Path("/repo"),
                               service_identity=(1001, 1001))
        self.assertIn("restart was deferred", result)
        self.assertFalse(any(command[:3] == ["systemctl", "restart", "netpulse"] for command in calls))
        self.assertTrue(nas.load(paths.config).backup.enabled)

    def test_matching_active_mount_is_reused_without_mounting_again(self):
        _root, paths, _db = self._sandbox()
        paths.mount.mkdir()
        paths.credentials.write_bytes(b"username=nasuser\npassword=private-secret\n")
        paths.credentials.chmod(0o600)
        entry = nas.fstab_entry("10.0.0.20", "private-backups", paths.mount,
                                paths.credentials, 1001, 1001)
        paths.fstab.write_text("# existing\n" + entry + "\n", encoding="utf-8")
        calls = []

        def fake_run(command, **_kwargs):
            calls.append(command)
            if command[0] == "smbclient":
                return SimpleNamespace(returncode=1, stdout="", stderr="")
            if command[0] == "findmnt":
                return SimpleNamespace(returncode=0,
                                       stdout="//10.0.0.20/private-backups cifs\n", stderr="")
            if command[0] == "runuser":
                code = command[command.index("-c") + 1]
                if "NETPULSE_CREATED_BACKUP_MARKER" in code:
                    return SimpleNamespace(returncode=0, stdout="NETPULSE_CREATED_BACKUP_MARKER=0\n"
                                           "NETPULSE_CREATED_BACKUP_DIRECTORY=0\n", stderr="")
                backup_path = paths.backup_directory / "netpulse-db-20261007T000000.000000Z.sqlite3"
                return SimpleNamespace(returncode=0, stdout=f"NETPULSE_BACKUP_PATH={backup_path}\n"
                                       "backup and restore rehearsal passed\n", stderr="")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        original_stat = Path.stat

        def stat_with_private_credentials(path, *args, **kwargs):
            if path == paths.credentials:
                return SimpleNamespace(st_mode=0o100600, st_uid=0)
            return original_stat(path, *args, **kwargs)

        patches = self._patch_platform()
        with patches[0], patches[1], patches[2], mock.patch.object(Path, "stat", stat_with_private_credentials):
            result = nas.setup("10.0.0.20", "private-backups", "nasuser", "private-secret",
                               paths=paths, runner=fake_run, is_root=True,
                               is_mount=lambda _path: True, service_identity=(1001, 1001),
                               repo=Path("/repo"))
        self.assertIn("restarted", result)
        self.assertTrue(any(command[0] == "findmnt" for command in calls))
        self.assertFalse(any(command[0] == "mount" for command in calls))
        self.assertEqual(paths.fstab.read_text(encoding="utf-8").count("cifs"), 1)

    def test_generated_backup_command_runs_against_disposable_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db = root / "source.sqlite3"
            store = Storage(str(db))
            store.close()
            backups = root / "backups"
            completed = subprocess.run(
                [sys.executable, "-c", nas._backup_code(nas.REPO), str(nas.REPO),
                 str(db), str(backups), ""],
                cwd=nas.REPO, capture_output=True, text=True, timeout=20, check=False)
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertIn("backup and restore rehearsal passed", completed.stdout)
            self.assertTrue(list(backups.glob("netpulse-db-*.sqlite3")))

    def test_restart_failure_restores_config_and_restarts_previous_service(self):
        _root, paths, _db = self._sandbox()
        original_config = paths.config.read_text(encoding="utf-8")
        calls = []
        mounted = [False]
        restart_calls = [0]
        active_calls = [0]

        def fake_run(command, **_kwargs):
            calls.append(command)
            if command[0] == "smbclient":
                return SimpleNamespace(returncode=1, stdout="", stderr="")
            if command[0] == "mount":
                mounted[0] = True
            elif command[0] == "umount":
                mounted[0] = False
            elif command[0] == "runuser":
                code = command[command.index("-c") + 1]
                if "NETPULSE_CREATED_BACKUP_MARKER" in code:
                    return SimpleNamespace(returncode=0, stdout="NETPULSE_CREATED_BACKUP_MARKER=1\n"
                                           "NETPULSE_CREATED_BACKUP_DIRECTORY=1\n", stderr="")
                if "backup and restore rehearsal passed" in code:
                    backup_path = paths.backup_directory / "netpulse-db-20261007T000000.000000Z.sqlite3"
                    return SimpleNamespace(returncode=0, stdout=f"NETPULSE_BACKUP_PATH={backup_path}\n"
                                           "backup and restore rehearsal passed\n", stderr="")
            elif command[:2] == ["systemctl", "restart"]:
                restart_calls[0] += 1
                return SimpleNamespace(returncode=1 if restart_calls[0] == 1 else 0,
                                       stdout="", stderr="")
            elif command[:2] == ["systemctl", "is-active"]:
                active_calls[0] += 1
                return SimpleNamespace(returncode=1 if active_calls[0] == 1 else 0,
                                       stdout="", stderr="")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        patches = self._patch_platform()
        with patches[0], patches[1], patches[2]:
            with self.assertRaisesRegex(RuntimeError, "restart or active-state check failed"):
                nas.setup("10.0.0.20", "private-backups", "nasuser", "private-secret",
                          paths=paths, runner=fake_run, is_root=True,
                          is_mount=lambda _path: mounted[0], service_identity=(1001, 1001),
                          repo=Path("/repo"))
        self.assertEqual(paths.config.read_text(encoding="utf-8"), original_config)
        self.assertEqual(restart_calls[0], 2, "the old configuration is restarted after rollback")
        self.assertEqual(active_calls[0], 2, "the previous service is verified active")
        self.assertFalse(mounted[0])
        self.assertFalse(paths.credentials.exists())
        self.assertNotIn("cifs", paths.fstab.read_text(encoding="utf-8"))

    def test_unmount_failure_retains_mount_credentials_and_fstab_for_recovery(self):
        _root, paths, _db = self._sandbox()
        calls = []
        mounted = [False]

        def fake_run(command, **_kwargs):
            calls.append(command)
            if command[0] == "smbclient":
                return SimpleNamespace(returncode=1, stdout="", stderr="")
            if command[0] == "mount":
                mounted[0] = True
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            if command[0] == "runuser":
                code = command[command.index("-c") + 1]
                if "NETPULSE_CREATED_BACKUP_MARKER" in code:
                    return SimpleNamespace(returncode=0, stdout="NETPULSE_CREATED_BACKUP_MARKER=1\n"
                                           "NETPULSE_CREATED_BACKUP_DIRECTORY=1\n", stderr="")
                if "backup and restore rehearsal passed" in code:
                    backup_path = paths.backup_directory / "netpulse-db-20261007T000000.000000Z.sqlite3"
                    return SimpleNamespace(returncode=1, stdout=f"NETPULSE_BACKUP_PATH={backup_path}\n",
                                           stderr="")
            if command[0] == "umount":
                return SimpleNamespace(returncode=32, stdout="", stderr="busy")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        patches = self._patch_platform()
        with patches[0], patches[1], patches[2]:
            with self.assertRaisesRegex(RuntimeError, "NAS remains mounted.*credentials were retained"):
                nas.setup("10.0.0.20", "private-backups", "nasuser", "private-secret",
                          paths=paths, runner=fake_run, is_root=True,
                          is_mount=lambda _path: mounted[0], service_identity=(1001, 1001),
                          repo=Path("/repo"))
        self.assertTrue(mounted[0])
        self.assertTrue(paths.credentials.exists())
        self.assertIn("private-secret", paths.credentials.read_text(encoding="utf-8"))
        self.assertIn("cifs", paths.fstab.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
