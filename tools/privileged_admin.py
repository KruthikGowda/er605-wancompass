#!/usr/bin/python3 -I
"""Fixed NetPulse administration commands for an optional root-owned sudo helper."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import stat
import subprocess
import sys


INSTALL = Path('/opt/netpulse')
COMMANDS = ('status', 'readiness', 'restart')


def trusted(path: Path) -> None:
    for item in (path, *path.parents):
        info = item.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('An administration dependency is not root-owned and protected.')


def command(action: str) -> list[str]:
    if action == 'status':
        return ['/usr/bin/systemctl', 'show', 'netpulse.service',
                '--property=ActiveState,SubState,MainPID,ExecMainStatus']
    if action == 'restart':
        return ['/usr/bin/systemctl', 'restart', 'netpulse.service']
    if action != 'readiness':
        raise ValueError('Unsupported administration command.')
    script = INSTALL / 'tools/router_control_readiness.py'
    trusted(script)
    package = INSTALL / 'netpulse'
    trusted(package)
    for path in package.rglob('*'):
        if path.is_dir() or path.suffix in ('.py', '.pyc') or path.is_symlink():
            trusted(path)
    bootstrap = (
        "import sys,runpy; sys.path.insert(0,'/opt/netpulse');"
        "sys.argv=['/opt/netpulse/tools/router_control_readiness.py'];"
        "runpy.run_path(sys.argv[0],run_name='__main__')"
    )
    return ['/usr/bin/python3', '-I', '-B', '-c', bootstrap]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=COMMANDS)
    args = parser.parse_args(argv)
    if not hasattr(os, 'geteuid') or os.geteuid() != 0:
        parser.error('Run the installed helper with sudo.')
    os.umask(0o077)
    try:
        invocation = command(args.action)
        trusted(Path(invocation[0]).resolve(strict=True))
        result = subprocess.run(invocation, cwd='/', timeout=120,
                                env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin',
                                     'LANG': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1'},
                                check=False)
        return result.returncode
    except (OSError, ValueError, subprocess.TimeoutExpired):
        print('Administration check failed; no additional action was taken.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
