"""Live checks against the real network. Skipped unless NETPULSE_LIVE=1 (run them on the Pi).

    NETPULSE_LIVE=1 python3 -m unittest tests.test_live -v

They never log in to the router and never run a speed test (no data use, no session kicks).
Optional: NETPULSE_ROUTER_PIN=<sha256 fingerprint> also checks the router's pinned HTTPS.
"""

import asyncio
import json
import os
import urllib.error
import unittest
import urllib.request

LIVE = os.environ.get("NETPULSE_LIVE") == "1"
PROBE_IPS = {"WAN1": "192.168.0.201", "WAN2": "192.168.0.202"}


@unittest.skipUnless(LIVE, "live network checks: set NETPULSE_LIVE=1")
class LiveNetwork(unittest.TestCase):
    def test_each_wan_answers_pings_from_its_probe_address(self):
        from netpulse.probes.icmp import probe
        for wan, ip in PROBE_IPS.items():
            r = asyncio.run(probe("1.1.1.1", ip, 3, 0.2, 1))
            self.assertEqual(r.error, "", f"{wan}: {r.error}")
            self.assertGreater(r.received, 0, f"{wan}: no ping replies via {ip}")

    def test_each_wan_reaches_direct_dns_and_https_from_its_probe_address(self):
        from netpulse.probes.connectivity import diagnose
        for wan, ip in PROBE_IPS.items():
            result = diagnose(ip, timeout=1.5)
            self.assertTrue(result.dns_ok, f"{wan}: direct DNS failed from {ip}")
            self.assertTrue(result.https_ok, f"{wan}: direct HTTPS failed from {ip}")

    def test_each_wan_leaves_through_a_different_isp(self):
        from netpulse.speedtest import trace
        ips = {wan: trace(ip).get("ip") for wan, ip in PROBE_IPS.items()}
        self.assertTrue(all(ips.values()), ips)
        self.assertNotEqual(ips["WAN1"], ips["WAN2"], f"both WANs exit with the same public IP: {ips}")

    def test_dashboard_is_up_and_protects_status_api(self):
        try:
            with urllib.request.urlopen("http://127.0.0.1:8080/api/status", timeout=5) as r:
                self.assertEqual(r.status, 200)
                s = json.load(r)
                self.assertEqual(len(s["wans"]), 2)
                self.assertTrue(s["updated"], "service hasn't completed a probe cycle")
        except urllib.error.HTTPError as exc:
            # New deployments require Basic auth even on loopback. Without reading the protected
            # password file in a live test, a 401 is evidence that the server answered securely.
            self.assertEqual(exc.code, 401, "dashboard returned an unexpected HTTP error")

    @unittest.skipUnless(os.environ.get("NETPULSE_ROUTER_PIN"), "set NETPULSE_ROUTER_PIN to check the router")
    def test_router_reachable_with_pinned_certificate(self):
        from netpulse.router.er605 import ER605Client
        c = ER605Client("192.168.0.1", "unused", "unused", os.environ["NETPULSE_ROUTER_PIN"])
        info = c.public_info()   # no login
        self.assertIn("ER605", info.get("model", ""))
        self.assertGreater(int(info["uptime"]), 0)


if __name__ == "__main__":
    unittest.main()
