"""Exercise the SNMP counter script without reaching the router or Internet."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = PROJECT_ROOT / "tools" / "snmp_validate_wans.sh"


@unittest.skipUnless(os.name == "posix" and shutil.which("bash"),
                     "SNMP script integration requires a POSIX shell")
class SnmpCommunityScripts(unittest.TestCase):
    def test_community_is_private_for_discovery_and_attribution_scripts(self):
        community = 'fixture "quoted" # community \\ suffix'
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bindir = root / "bin"
            bindir.mkdir()
            capture = root / "capture.log"
            snmpwalk = bindir / "snmpwalk"
            snmpwalk.write_text(
                "#!/bin/sh\n"
                "printf 'ARGS=%s\\n' \"$*\" >> \"$CAPTURE_FILE\"\n"
                "config_dir=\"${SNMPCONFPATH##*:}\"\n"
                "printf 'DIR=%s\\n' \"$config_dir\" >> \"$CAPTURE_FILE\"\n"
                "printf 'DIRMODE=%s\\n' \"$(stat -c %a \"$config_dir\")\" >> \"$CAPTURE_FILE\"\n"
                "config=\"$config_dir/snmp.conf\"\n"
                "printf 'MODE=%s\\n' \"$(stat -c %a \"$config\")\" >> \"$CAPTURE_FILE\"\n"
                "printf 'CONFIG=' >> \"$CAPTURE_FILE\"\n"
                "cat \"$config\" >> \"$CAPTURE_FILE\"\n"
                "oid=\"\"; for arg in \"$@\"; do oid=\"$arg\"; done\n"
                "case \"$oid\" in\n"
                "  .1.3.6.1.2.1.1.1.0) echo '.1.3.6.1.2.1.1.1.0 = STRING: fake router' ;;\n"
                "  .1.3.6.1.2.1.31.1.1.1.1)\n"
                "    echo '.1.3.6.1.2.1.31.1.1.1.1.1042 = STRING: \"default/pe-wan1\"'\n"
                "    echo '.1.3.6.1.2.1.31.1.1.1.1.1077 = STRING: \"default/pe-wan2\"' ;;\n"
                "  .1.3.6.1.2.1.31.1.1.1.6)\n"
                "    echo '.1.3.6.1.2.1.31.1.1.1.6.1042 = Counter64: 100'\n"
                "    echo '.1.3.6.1.2.1.31.1.1.1.6.1077 = Counter64: 200' ;;\n"
                "  .1.3.6.1.2.1.31.1.1.1.10)\n"
                "    echo '.1.3.6.1.2.1.31.1.1.1.10.1042 = Counter64: 300'\n"
                "    echo '.1.3.6.1.2.1.31.1.1.1.10.1077 = Counter64: 400' ;;\n"
                "  *) exit 0 ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            snmpwalk.chmod(0o755)
            curl = bindir / "curl"
            curl.write_text("#!/bin/sh\necho 'mock curl; no network request made'\n", encoding="utf-8")
            curl.chmod(0o755)

            env = os.environ.copy()
            env["PATH"] = f"{bindir}{os.pathsep}{env['PATH']}"
            env["CAPTURE_FILE"] = str(capture)
            results = []
            for script_name in ("snmp_discover.sh", "snmp_validate_wans.sh"):
                result = subprocess.run(
                    ["bash", str(PROJECT_ROOT / "tools" / script_name)],
                    input=f"192.168.0.1\n{community}\n", text=True,
                    capture_output=True, env=env, timeout=30, check=False,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertNotIn(community, result.stdout + result.stderr)
                results.append(result.stdout)

            records = capture.read_text(encoding="utf-8")
            self.assertNotIn("-c ", records)
            argument_lines = [line[5:] for line in records.splitlines() if line.startswith("ARGS=")]
            self.assertTrue(argument_lines)
            self.assertTrue(all(community not in line for line in argument_lines))
            self.assertIn("DIRMODE=700", records)
            self.assertIn("MODE=600", records)
            escaped = community.replace("\\", "\\\\").replace('"', '\\"')
            self.assertIn(f'CONFIG=defCommunity "{escaped}"', records)
            self.assertIn("Discovery complete", results[0])
            self.assertIn("WAN1 via Pi source 192.168.0.201", results[1])
            self.assertIn("WAN2 via Pi source 192.168.0.202", results[1])
            config_dirs = {line[4:] for line in records.splitlines() if line.startswith("DIR=")}
            self.assertEqual(len(config_dirs), 2)
            for config_dir in config_dirs:
                self.assertFalse(Path(config_dir).exists(), "the private SNMP config should be removed")

            real_snmpwalk = shutil.which("snmpwalk")
            if real_snmpwalk:
                parser_dir = root / "real-net-snmp"
                parser_dir.mkdir(mode=0o700)
                parser_conf = parser_dir / "snmp.conf"
                parser_conf.write_text(f' defCommunity "{escaped}"\n'.lstrip(), encoding="utf-8")
                parser_conf.chmod(0o600)
                env["SNMPCONFPATH"] = (
                    f"/etc/snmp:/usr/local/etc/snmp:/usr/local/share/snmp:"
                    f"/usr/local/lib/snmp:{parser_dir}"
                )
                parsed = subprocess.run(
                    [real_snmpwalk, "-v2c", "-t", "1", "-r", "0", "-On", "127.0.0.1",
                     ".1.3.6.1.2.1.1.1.0"], text=True, capture_output=True, env=env,
                    timeout=5, check=False,
                )
                parser_output = parsed.stdout + parsed.stderr
                self.assertNotRegex(parser_output, r"(?i)(unknown token|parse error|bad community|no end quote)")
                self.assertNotIn(community, parser_output)


if __name__ == "__main__":
    unittest.main()
