import json
import subprocess
import unittest
from unittest import mock
from urllib.parse import urlsplit

from tools import adb_acl_probe as probe


URL = "http://192.168.0.10:43210/probe/?t=valid_token-123"
SERIAL = "synthetic-test-device"
PHONE_MAC = "02:11:22:33:44:55"
PHONE_IP = "10.23.45.67"


class URLValidation(unittest.TestCase):
    def test_accepts_private_phone_pilot_url(self):
        self.assertEqual(probe.validate_url(URL),
                         ("192.168.0.10", 43210, "valid_token-123", "http://192.168.0.10:43210"))

    def test_rejects_unsafe_or_ambiguous_urls(self):
        invalid = (
            "https://192.168.0.10:43210/probe/?t=token",
            "http://8.8.8.8:43210/probe/?t=token",
            "http://192.168.0.10/probe/?t=token",
            "http://192.168.0.10:43210/probe/?t=token&t=other",
            "http://192.168.0.10:43210/probe/?t=bad%20token",
            "http://user@192.168.0.10:43210/probe/?t=token",
            "http://192.168.0.10:43210/elsewhere/?t=token",
            "http://192.168.0.10:43210/probe/?t=token#fragment",
        )
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(probe.ProbeError):
                probe.validate_url(value)

    def test_cli_requires_all_phone_identity_inputs(self):
        with self.assertRaises(SystemExit):
            probe.main(["--url", URL])


def completed(stdout="", returncode=0, stderr=""):
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


class PhonePreflight(unittest.TestCase):
    WIFI = ("mWifiInfo SSID: Test, BSSID: aa:bb:cc:dd:ee:ff, MAC: " + PHONE_MAC
            + ", Supplicant state: COMPLETED\n")
    CONNECTIVITY = ("Active default network: 101\nNetworkAgentInfo{ WIFI network{101} "
                    f"LinkAddresses: [{PHONE_IP}/24] Transports: WIFI }}\n"
                    "NetworkAgentInfo [WIFI () - 101]\nHistorical factory transports: VPN\n")

    def test_requires_existing_mobile_data_off_and_reviewed_active_wifi(self):
        def runner(args, **_kwargs):
            command = args[-1]
            if command == "settings get global mobile_data":
                return completed("0\n")
            if command == "dumpsys wifi":
                return completed(self.WIFI)
            if command == "dumpsys connectivity":
                return completed(self.CONNECTIVITY)
            self.fail("unexpected shell command")
        probe.check_phone(SERIAL, PHONE_MAC, PHONE_IP, runner)

    def test_refuses_to_change_or_continue_if_mobile_data_is_on(self):
        calls = []
        def runner(args, **_kwargs):
            calls.append(args[-1])
            return completed("1\n")
        with self.assertRaisesRegex(probe.ProbeError, "mobile data"):
            probe.check_phone(SERIAL, PHONE_MAC, PHONE_IP, runner)
        self.assertEqual(calls, ["settings get global mobile_data"])

    def test_rejects_vpn_as_active_default_even_when_wifi_history_is_present(self):
        def runner(args, **_kwargs):
            command = args[-1]
            if command == "settings get global mobile_data":
                return completed("0")
            if command == "dumpsys wifi":
                return completed(self.WIFI)
            return completed("Active default network: 102\nNetworkAgentInfo [VPN () - 102]\n"
                             f"  LinkAddresses: [{PHONE_IP}/24]\n"
                             "NetworkAgentInfo [WIFI () - 101]\n")
        with self.assertRaisesRegex(probe.ProbeError, "active default network"):
            probe.check_phone(SERIAL, PHONE_MAC, PHONE_IP, runner)

    def test_requires_explicit_valid_phone_identity(self):
        for serial, mac, ip in (("", PHONE_MAC, PHONE_IP), (SERIAL, "not-a-mac", PHONE_IP),
                                (SERIAL, PHONE_MAC, "203.0.113.7")):
            with self.subTest(serial=serial, mac=mac, ip=ip), self.assertRaises(probe.ProbeError):
                probe.check_phone(serial, mac, ip, lambda *_a, **_k: self.fail("ADB must not run"))


class CurlAndPhaseSafety(unittest.TestCase):
    def test_curl_command_uses_phone_shell_with_quoted_json_and_no_follow_redirects(self):
        calls = []
        def runner(args, **kwargs):
            calls.append((args, kwargs))
            return completed("\n204")
        status, body, _err, code = probe._curl(
            "serial", "http://192.168.0.10:43210/report?t=abc", origin="http://192.168.0.10:43210",
            payload={"phase": "blocked", "internet_ipv4_ok": False, "lan_ok": True}, runner=runner)
        self.assertEqual((status, body, code), (204, "", 0))
        self.assertEqual(calls[0][0][:4], ["adb", "-s", "serial", "shell"])
        shell = calls[0][0][-1]
        self.assertIn("--max-redirs 0", shell)
        self.assertIn("--ipv4", shell)
        self.assertIn("Origin:", shell)
        self.assertIn("blocked", shell)
        self.assertNotIn("--insecure", shell)
        self.assertFalse(calls[0][1].get("shell", False))

    def test_rejects_invalid_or_non_ipv4_https_response_and_tls_failure(self):
        responses = [completed('{"ip":"not-an-ip"}\n200'), completed("\n000", 60, "certificate error")]
        for response in responses:
            with self.subTest(response=response), self.assertRaises(probe.ProbeError):
                probe._internet_ipv4_ok("serial", lambda *_a, **_k: response)

    def test_phase_change_during_external_probe_never_posts_stale_sample(self):
        phases = iter(("baseline", "blocked"))
        posted = []
        def fake_curl(serial, url, *, origin=None, payload=None, runner=None):
            path = urlsplit(url).path
            if path == "/state":
                return 200, json.dumps({"phase": next(phases), "expires_in": 100}), "", 0
            if "api4.ipify.org" in url:
                return 200, '{"ip":"203.0.113.8"}', "", 0
            posted.append(payload)
            return 204, "", "", 0
        with mock.patch.object(probe, "_curl", fake_curl), mock.patch.object(probe, "check_phone"):
            with self.assertRaisesRegex(probe.ProbeError, "phase changed during"):
                probe.run_probe(URL, SERIAL, PHONE_MAC, PHONE_IP,
                                runner=lambda *_a, **_k: completed("0"), timeout_seconds=3)
        self.assertEqual(posted, [])


if __name__ == "__main__":
    unittest.main()
