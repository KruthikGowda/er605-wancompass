#!/usr/bin/env python3
"""Audit tracked release files without printing matched secret or identity values.

This is a release guard, not proof that a repository contains no sensitive data.
An optional private deny file adds deployment-specific strings. Keep that file
outside the repository. History must be reviewed separately or excluded entirely.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess

PATTERNS = {
    "private-key": re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "github-token": re.compile(rb"(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})"),
    "aws-access-key": re.compile(rb"(?:AKIA|ASIA)[A-Z0-9]{16}"),
    "personal-windows-path": re.compile(rb"[A-Za-z]:[\\/]+Users[\\/]+(?!Public\b|EXAMPLE\b)[^\s/\\]+", re.I),
    "personal-home-path": re.compile(rb"/home/(?!EXAMPLE\b|example\b)[A-Za-z0-9_.-]+/"),
}
RUNTIME_SUFFIXES = {".db", ".sqlite", ".sqlite3", ".log", ".auth", ".key", ".p12", ".pfx", ".zip", ".gz"}
RUNTIME_NAMES = {"config.toml", "router.toml", "acl-pilot-devices.json", ".env"}
SYNTHETIC_KEY = "tests/fixtures/fake-router.pem"


def audit(root: Path, files: list[str], denied: list[str] = ()) -> list[dict]:
    findings = []
    root = root.resolve()
    for name in files:
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts:
            findings.append({"file": name, "kind": "unsafe-path"})
            continue
        path = root / relative
        if path.is_symlink() or not path.resolve().is_relative_to(root):
            findings.append({"file": name, "kind": "symlink-or-outside-root"})
            continue
        if not path.is_file():
            findings.append({"file": name, "kind": "missing-file"})
            continue
        if path.suffix.lower() in RUNTIME_SUFFIXES or path.name in RUNTIME_NAMES or path.name.startswith('.env.'):
            findings.append({"file": name, "kind": "runtime-or-private-file"})
        data = path.read_bytes()
        for kind, pattern in PATTERNS.items():
            if kind == "private-key" and relative.as_posix() == SYNTHETIC_KEY:
                continue  # Generated, disposable TLS key for the loopback fake router only.
            if pattern.search(data):
                findings.append({"file": name, "kind": kind})
        folded = data.lower()
        if any(value.encode('utf-8').lower() in folded for value in denied if value):
            findings.append({"file": name, "kind": "private-deny-list"})
    return findings


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--deny-file', type=Path, help='Private UTF-8 file with one deployment identifier per line')
    args = parser.parse_args(argv)
    root = args.root.resolve()
    if args.deny_file and args.deny_file.resolve().is_relative_to(root):
        parser.error('The private deny file must be outside the repository.')
    denied = args.deny_file.read_text(encoding='utf-8').splitlines() if args.deny_file else []
    result = subprocess.run(['git', 'ls-files', '-z'], cwd=root, capture_output=True, check=True)
    files = result.stdout.decode('utf-8').rstrip('\0').split('\0') if result.stdout else []
    findings = audit(root, files, denied)
    print(json.dumps({'files_checked': len(files), 'findings': findings, 'history_checked': False}))
    return int(bool(findings))


if __name__ == '__main__':
    raise SystemExit(main())
