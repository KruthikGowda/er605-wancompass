"""Isolated first-install config selection/validation/copy behavior."""

from __future__ import annotations

import base64
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "scripts" / "install.sh"
BEGIN = "# BEGIN first-install config helpers (kept sourceable for isolated installer tests)."
END = "# END first-install config helpers."


def shell_path(path: Path) -> str:
    value = str(path.resolve())
    if os.name == "nt":
        converted = subprocess.run(["bash", "-c", f"wslpath -a {shlex.quote(value)}"],
                                   text=True, capture_output=True, check=False)
        if converted.returncode:
            raise unittest.SkipTest("Bash/WSL cannot access the temporary test path")
        value = converted.stdout.strip()
    return value


class FirstInstallConfigTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which("bash"):
            raise unittest.SkipTest("Bash is required to exercise installer shell functions")
        source = INSTALLER.read_text(encoding="utf-8")
        start = source.index(BEGIN) + len(BEGIN)
        stop = source.index(END, start)
        cls.helpers = source[start:stop]

    def run_helpers(self, temporary: Path, config_path: Path | str,
                    source_path: Path | None) -> subprocess.CompletedProcess:
        bin_dir = temporary / "fake bin"
        bin_dir.mkdir(exist_ok=True)
        install_stub = bin_dir / "install"
        install_stub.write_text(
            "#!/bin/bash\n"
            "[[ \"$#\" == 8 && \"$1\" == -m && \"$2\" == 640 && \"$3\" == -o "
            "&& \"$4\" == root && \"$5\" == -g && \"$6\" == netpulse ]] || exit 71\n"
            "cp -- \"$7\" \"$8\"\n"
            "chmod \"$2\" \"$8\"\n",
            encoding="utf-8",
            newline="\n",
        )
        executable = subprocess.run(
            ["bash", "-c", f"chmod 755 {shlex.quote(shell_path(install_stub))}"],
            text=True, capture_output=True, check=False,
        )
        if executable.returncode:
            raise unittest.SkipTest("Bash/WSL cannot mark the temporary install stub executable")
        script = "\n".join((
            (f"export NETPULSE_CONFIG_SOURCE={shlex_quote(shell_path(source_path))}"
             if source_path is not None else "unset NETPULSE_CONFIG_SOURCE"),
            f"export PATH={shlex_quote(shell_path(bin_dir))}:/usr/bin:/bin",
            f"REPO={shlex_quote(shell_path(ROOT))}",
            self.helpers,
            f"CONFIG_PATH={shlex_quote(config_path if isinstance(config_path, str) else shell_path(config_path))}",
            "if ! select_and_validate_config_source; then exit 1; fi",
            "if ! install_first_config; then exit 1; fi",
            "if [[ -f \"$CONFIG_PATH\" ]]; then stat -c '%a' \"$CONFIG_PATH\"; base64 -w0 \"$CONFIG_PATH\"; fi",
        ))
        script_path = temporary / "run config helpers.sh"
        script_path.write_text(script, encoding="utf-8", newline="\n")
        return subprocess.run(["bash", shell_path(script_path)], text=True,
                              capture_output=True, check=False)

    def test_valid_custom_config_path_with_spaces_is_validated_and_copied(self):
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            source_path = temporary / "config source" / "first install.toml"
            source_path.parent.mkdir()
            source_path.write_bytes((ROOT / "config.example.toml").read_bytes())
            if os.name == "nt":
                linux_tmp = subprocess.run(["bash", "-c", "mktemp -d /tmp/netpulse-config-test.XXXXXX"],
                                           text=True, capture_output=True, check=True).stdout.strip()
                self.addCleanup(lambda: subprocess.run(
                    ["bash", "-c", f"rm -rf -- {shlex.quote(linux_tmp)}"], check=False,
                    capture_output=True))
                config_path = linux_tmp + "/installed config.toml"
            else:
                config_path = str(temporary / "installed config.toml")
            result = self.run_helpers(temporary, config_path, source_path)
            self.assertEqual(result.returncode, 0, result.stderr)
            output = result.stdout.strip().splitlines()
            self.assertEqual(output[-2], "640")
            self.assertEqual(base64.b64decode(output[-1]), source_path.read_bytes())

    def test_first_config_validation_precedes_installer_mutations(self):
        script = INSTALLER.read_text(encoding="utf-8")
        test_gate = script.index("python3 -m unittest discover")
        validation = script.index("\nselect_and_validate_config_source\n")
        apt = script.index("apt-get install")
        user_create = script.index("useradd --system")
        code_copy = script.index('cp -r "$REPO/netpulse"')
        config_copy = script.index("install_first_config\n", script.index('echo "==> Config ->'))
        self.assertLess(test_gate, validation)
        for mutation in (apt, user_create, code_copy, config_copy):
            self.assertLess(validation, mutation)

    def test_default_source_is_repository_example(self):
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            config_path = temporary / "config.toml"
            result = self.run_helpers(temporary, config_path, None)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(config_path.read_bytes(), (ROOT / "config.example.toml").read_bytes())

    def test_invalid_config_fails_before_copy_and_does_not_print_contents(self):
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            source_path = temporary / "private input.toml"
            source_path.write_text('password = "do-not-print-this"\n[broken\n', encoding="utf-8")
            config_path = temporary / "config.toml"
            result = self.run_helpers(temporary, config_path, source_path)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(config_path.exists())
            self.assertIn("invalid for this NetPulse version", result.stderr)
            self.assertNotIn("do-not-print-this", result.stdout + result.stderr)

    def test_existing_config_ignores_even_a_missing_custom_source(self):
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            source_path = temporary / "does not exist.toml"
            config_path = temporary / "already installed.toml"
            original = b"existing configuration stays byte-for-byte\n"
            config_path.write_bytes(original)
            result = self.run_helpers(temporary, config_path, source_path)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(config_path.read_bytes(), original)

    def test_missing_first_install_source_fails_before_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            source_path = temporary / "missing.toml"
            config_path = temporary / "config.toml"
            result = self.run_helpers(temporary, config_path, source_path)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(config_path.exists())
            self.assertIn("config source is missing", result.stderr)


def shlex_quote(value: str) -> str:
    return shlex.quote(value)


if __name__ == "__main__":
    unittest.main()
