"""The optional helper grants fixed operations, never arbitrary shell execution."""
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tools import privileged_admin as admin, setup_admin_access as setup


class AdminAccess(unittest.TestCase):
    def test_sudo_rule_is_scoped_to_three_exact_commands(self):
        rule = setup.sudo_rule('operator')
        self.assertEqual(rule.count('NOPASSWD:'), 1)
        for action in ('status', 'readiness', 'restart'):
            self.assertIn(f'/usr/local/sbin/wancompass-admin {action}', rule)
        self.assertNotIn('*', rule)
        self.assertNotIn('SETENV', rule)
        self.assertNotIn('/bin/bash', rule)

    def test_user_cannot_inject_a_sudoers_entry(self):
        for user in ('root', '', 'a\nALL ALL=(ALL) ALL', 'a,b', 'a:ALL', '../name', 'a b'):
            with self.subTest(user=user), self.assertRaises(ValueError):
                setup.sudo_rule(user)

    def test_fixed_commands_have_no_user_supplied_arguments(self):
        self.assertEqual(admin.command('restart'), ['/usr/bin/systemctl', 'restart', 'netpulse.service'])
        self.assertEqual(admin.command('status')[:3], ['/usr/bin/systemctl', 'show', 'netpulse.service'])
        with self.assertRaises(ValueError):
            admin.command('restart; sh')

    def test_extra_arguments_are_rejected_before_running_anything(self):
        with patch.object(admin.subprocess, 'run') as run, self.assertRaises(SystemExit):
            admin.main(['restart', '--', '/bin/sh'])
        run.assert_not_called()

    def test_restart_uses_a_clean_environment_and_no_shell(self):
        with (patch.object(admin.os, 'geteuid', return_value=0, create=True),
              patch.object(admin, 'trusted'), patch.object(admin.Path, 'resolve', return_value=Path('/usr/bin/systemctl')),
              patch.object(admin.subprocess, 'run', return_value=SimpleNamespace(returncode=0)) as run):
            self.assertEqual(admin.main(['restart']), 0)
        args, kwargs = run.call_args
        self.assertEqual(args[0], ['/usr/bin/systemctl', 'restart', 'netpulse.service'])
        self.assertNotIn('shell', kwargs)
        self.assertNotIn('PYTHONPATH', kwargs['env'])
        self.assertEqual(kwargs['cwd'], '/')

    def test_validation_failure_keeps_existing_access_file(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'rule'
            target.write_bytes(b'old')
            def invalid(_):
                raise subprocess.CalledProcessError(1, 'visudo')
            with (patch.object(setup, 'protected_directory'), patch.object(setup.os, 'chown', create=True),
                  patch.object(setup.os, 'chmod'),
                  self.assertRaises(subprocess.CalledProcessError)):
                setup.replace_file(target, b'new', 0o440, invalid)
            self.assertEqual(target.read_bytes(), b'old')
            self.assertEqual(list(Path(directory).iterdir()), [target])

    def test_root_dependency_cannot_be_writable_by_the_operator(self):
        path = Path('/opt/netpulse/netpulse/config.py')
        for mode, uid in ((0o100666, 0), (0o100644, 1000), (0o120777, 0)):
            with (patch.object(Path, 'lstat', return_value=SimpleNamespace(st_mode=mode, st_uid=uid)),
                  self.subTest(mode=mode, uid=uid), self.assertRaises(ValueError)):
                admin.trusted(path)


if __name__ == '__main__':
    unittest.main()
