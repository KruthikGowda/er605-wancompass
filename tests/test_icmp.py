import unittest

from netpulse.probes.icmp import build_command, parse_ping_output

OK = """PING 8.8.8.8 (8.8.8.8) from 192.168.0.201 : 56(84) bytes of data.
64 bytes from 8.8.8.8: icmp_seq=1 ttl=117 time=6.40 ms
64 bytes from 8.8.8.8: icmp_seq=2 ttl=117 time=7.08 ms
64 bytes from 8.8.8.8: icmp_seq=3 ttl=117 time=8.25 ms
64 bytes from 8.8.8.8: icmp_seq=4 ttl=117 time=6.90 ms
64 bytes from 8.8.8.8: icmp_seq=5 ttl=117 time=7.00 ms

--- 8.8.8.8 ping statistics ---
5 packets transmitted, 5 received, 0% packet loss, time 804ms
rtt min/avg/max/mdev = 6.404/7.077/8.251/0.548 ms
"""

PARTIAL = """PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.
64 bytes from 1.1.1.1: icmp_seq=1 ttl=58 time=29.0 ms
64 bytes from 1.1.1.1: icmp_seq=3 ttl=58 time=31.5 ms
64 bytes from 1.1.1.1: icmp_seq=3 ttl=58 time=31.9 ms (DUP!)

--- 1.1.1.1 ping statistics ---
5 packets transmitted, 2 received, +1 duplicates, 60% packet loss, time 820ms
"""

NONE = """PING 9.9.9.9 (9.9.9.9) 56(84) bytes of data.

--- 9.9.9.9 ping statistics ---
5 packets transmitted, 0 received, 100% packet loss, time 4090ms
"""


class ParsePing(unittest.TestCase):
    def test_all_replies(self):
        r = parse_ping_output(OK, "8.8.8.8", 5)
        self.assertEqual(r.received, 5)
        self.assertEqual(r.rtts, [6.40, 7.08, 8.25, 6.90, 7.00])
        self.assertEqual(r.loss_pct, 0)

    def test_partial_loss_ignores_duplicates(self):
        r = parse_ping_output(PARTIAL, "1.1.1.1", 5)
        self.assertEqual(r.received, 2)
        self.assertEqual(r.rtts, [29.0, 31.5])
        self.assertEqual(r.loss_pct, 60)

    def test_total_loss(self):
        r = parse_ping_output(NONE, "9.9.9.9", 5)
        self.assertEqual((r.received, r.rtts, r.loss_pct), (0, [], 100))


class Command(unittest.TestCase):
    def test_binds_source_ip(self):
        cmd = build_command("1.1.1.1", "192.168.0.201", 5, 0.2, 1)
        self.assertEqual(cmd[0], "ping")
        self.assertIn("-I", cmd)
        self.assertEqual(cmd[cmd.index("-I") + 1], "192.168.0.201")
        self.assertEqual(cmd[-1], "1.1.1.1")

    def test_no_source_ip(self):
        self.assertNotIn("-I", build_command("1.1.1.1", "", 5, 0.2, 1))


if __name__ == "__main__":
    unittest.main()
