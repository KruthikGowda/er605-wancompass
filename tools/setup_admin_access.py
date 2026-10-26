#!/usr/bin/env python3
"""Install optional password-free status/readiness/restart access for one operator."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


HELPER = Path('/usr/local/sbin/wancompass-admin')
RULE = Path('/etc/sudoers.d/wancompass-admin')


def sudo_rule(user: str) -> str:
    if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', user or '') or user == 'root':
        raise ValueError('Choose one existing non-root Linux operator account.')
    commands = ', '.join(f'{HELPER.as_posix()} {action}' for action in ('status', 'readiness', 'restart'))
    return f'{user} ALL=(root) NOPASSWD: {commands}\n'


def protected_directory(path: Path) -> None:
    for item in (path, *path.parents):
        info = item.lstat()
        if item.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('Installation directories must be protected and root-owned.')


def replace_file(target: Path, content: bytes, mode: int, validator=None) -> None:
    protected_directory(target.parent)
    if target.is_symlink():
        raise ValueError('Refusing a symbolic-link installation target.')
    name = None
    try:
        with tempfile.NamedTemporaryFile(dir=target.parent, delete=False) as stream:
            name = Path(stream.name)
            stream.write(content)
        os.chmod(name, mode)
        os.chown(name, 0, 0)
        if validator:
            validator(name)
        os.replace(name, target)
        name = None
    finally:
        if name:
            name.unlink(missing_ok=True)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--user', default=os.environ.get('SUDO_USER', ''))
    args = parser.parse_args(argv)
    if not hasattr(os, 'geteuid') or os.geteuid() != 0:
        parser.error('Run this setup once with sudo.')
    try:
        import pwd
        content = sudo_rule(args.user)
        if pwd.getpwnam(args.user).pw_uid == 0:
            raise ValueError('The operator cannot have UID 0.')
        visudo = shutil.which('visudo', path='/usr/sbin:/usr/bin:/sbin:/bin')
        if not visudo:
            raise ValueError('visudo is required; no access rule was installed.')
        protected_directory(Path(visudo))
        source = Path(__file__).with_name('privileged_admin.py')
        helper = source.read_bytes()
        compile(helper, str(HELPER), 'exec')
        def validate(path):
            subprocess.run([visudo, '-cf', str(path)], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin'}, timeout=15)
        replace_file(HELPER, helper, 0o755)
        replace_file(RULE, content.encode('utf-8'), 0o440, validate)
    except (OSError, KeyError, ValueError, subprocess.SubprocessError):
        print('Setup failed. Review account, protected paths, and sudoers validation locally.')
        return 1
    print('Installed password-free status, readiness, and NetPulse restart access.')
    print('General shell commands, deployments, and security changes still require sudo authentication.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
