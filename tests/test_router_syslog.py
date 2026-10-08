import asyncio
import socket
import tempfile
import unittest
from types import SimpleNamespace

from netpulse.router.syslog import RouterSyslogProtocol, parse_dhcp_allocation
from netpulse.notifications.telegram import TelegramBot
from netpulse.storage import sqlite
from tests.harness import FakeTelegram, Scenario, local


MESSAGE = b"DHCP Server allocated IP address 192.168.0.125 for the [client:aa:bb:cc:dd:ee:02]."


class ParseDhcpAllocation(unittest.TestCase):
    def test_parses_router_message_and_syslog_prefixed_message(self):
        expected = ("192.168.0.125", "AA-BB-CC-DD-EE-02")
        self.assertEqual((parse_dhcp_allocation(MESSAGE).ip, parse_dhcp_allocation(MESSAGE).mac), expected)
        prefixed = b"<134>Sep 27 12:00:00 ER605 " + MESSAGE
        parsed = parse_dhcp_allocation(prefixed)
        self.assertEqual((parsed.ip, parsed.mac), expected)

    def test_rejects_non_private_malformed_or_oversized_messages(self):
        cases = [
            b"", b"\xff", b"DHCP Server allocated IP address 8.8.8.8 for the [client:aa:bb:cc:dd:ee:02].",
            b"DHCP Server allocated IP address 999.1.1.1 for the [client:aa:bb:cc:dd:ee:02].",
            b"DHCP Server allocated IP address 192.168.0.125 for the [client:01:bb:cc:dd:ee:02].",
            b"DHCP Server allocated IP address 192.168.0.125 for the [client:00:00:00:00:00:00].",
            MESSAGE + b"x" * 2048,
        ]
        for item in cases:
            with self.subTest(item=item[:80]):
                self.assertIsNone(parse_dhcp_allocation(item))


class SourceFilteredReceiver(unittest.TestCase):
    def test_status_callback_reports_binding_and_identity_free_counts(self):
        statuses = []
        protocol = RouterSyslogProtocol(
            "192.168.0.1", lambda *_: None, clock=lambda: 100.0,
            on_status=statuses.append,
        )
        protocol.connection_made(object())
        protocol.datagram_received(MESSAGE, ("192.168.0.1", 514))
        protocol.connection_lost(None)

        self.assertEqual(statuses[0]["listening"], True)
        self.assertEqual(statuses[-1], {
            "listening": False, "accepted_allocations": 1,
            "duplicates_suppressed": 0, "last_allocation_at": 100.0,
        })
        serialized = str(statuses)
        self.assertNotIn("AA-BB-CC-DD-EE-02", serialized)
        self.assertNotIn("192.168.0.125", serialized)

    def test_exact_source_filter_and_duplicate_suppression_expiry(self):
        now = [100.0]
        received = []
        protocol = RouterSyslogProtocol("192.168.0.1", lambda event, ts: received.append((event, ts)),
                                        clock=lambda: now[0], monotonic_clock=lambda: now[0])
        protocol.datagram_received(MESSAGE, ("192.168.0.2", 514))
        self.assertEqual(received, [])
        protocol.datagram_received(MESSAGE, ("192.168.0.1", 514))
        protocol.datagram_received(MESSAGE, ("192.168.0.1", 514))
        self.assertEqual(len(received), 1)
        self.assertEqual(received[0][1], 100.0)
        self.assertEqual(protocol.status(), {
            "listening": False,
            "accepted_allocations": 1,
            "duplicates_suppressed": 1,
            "last_allocation_at": 100.0,
        })
        now[0] += 901
        protocol.datagram_received(MESSAGE, ("192.168.0.1", 514))
        self.assertEqual(len(received), 2)
        self.assertEqual(protocol.status()["accepted_allocations"], 2)
        self.assertEqual(protocol.status()["last_allocation_at"], 1001.0)

    def test_duplicate_suppression_uses_monotonic_time_when_wall_clock_moves(self):
        wall = [1_000.0]
        mono = [50.0]
        received = []
        protocol = RouterSyslogProtocol(
            "192.168.0.1", lambda event, ts: received.append((event, ts)),
            clock=lambda: wall[0], monotonic_clock=lambda: mono[0],
        )

        protocol.datagram_received(MESSAGE, ("192.168.0.1", 514))
        wall[0] -= 7_200  # NTP or manual clock correction must not extend the dedup window.
        mono[0] += 100
        protocol.datagram_received(MESSAGE, ("192.168.0.1", 514))
        self.assertEqual(len(received), 1)
        self.assertEqual(protocol.status()["duplicates_suppressed"], 1)

        mono[0] += 801
        protocol.datagram_received(MESSAGE, ("192.168.0.1", 514))
        self.assertEqual(len(received), 2)
        self.assertEqual(received[-1][1], wall[0])
        self.assertEqual(protocol.status()["last_allocation_at"], wall[0])

    def test_rejects_non_ipv4_router_address(self):
        with self.assertRaises(ValueError):
            RouterSyslogProtocol("router.local", lambda *_: None)


class UdpReceiverIntegration(unittest.IsolatedAsyncioTestCase):
    async def test_datagram_transport_parses_and_delivers_one_allocation(self):
        received = []
        delivered = asyncio.Event()

        def on_allocation(event, timestamp):
            received.append((event, timestamp))
            delivered.set()

        loop = asyncio.get_running_loop()
        protocol = RouterSyslogProtocol("127.0.0.1", on_allocation)
        transport, _ = await loop.create_datagram_endpoint(
            lambda: protocol,
            local_addr=("127.0.0.1", 0),
        )
        self.addCleanup(transport.close)
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sender.setblocking(False)
        self.addCleanup(sender.close)
        await loop.sock_sendto(sender, MESSAGE, transport.get_extra_info("sockname"))
        await asyncio.wait_for(delivered.wait(), timeout=1)

        self.assertEqual(len(received), 1)
        self.assertTrue(protocol.status()["listening"])
        self.assertEqual((received[0][0].ip, received[0][0].mac),
                         ("192.168.0.125", "AA-BB-CC-DD-EE-02"))
        transport.close()
        await asyncio.sleep(0)
        self.assertIsNone(protocol.transport)
        self.assertFalse(protocol.status()["listening"])

    async def test_udp_allocation_drives_fast_alert_persists_event_and_suppresses_scan_duplicate(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        start = local(12)
        scenario = Scenario(tmp.name, start, overrides={"telegram": {"device_activity_notifications": True}})
        self.addCleanup(scenario.close)
        telegram = FakeTelegram()
        self.addCleanup(telegram.close)
        bot = TelegramBot("test-token", "42", {}, api_base=telegram.base)
        bot.start()
        self.addCleanup(bot.stop)
        scenario.mon.alerter.notifier = bot
        loop = asyncio.get_running_loop()
        delivered = asyncio.Event()

        def on_allocation(allocation, timestamp):
            scenario.mon.on_router_syslog_allocation(allocation, timestamp)
            delivered.set()

        protocol = RouterSyslogProtocol(
            "127.0.0.1", on_allocation, clock=scenario.clock,
        )
        transport, _ = await loop.create_datagram_endpoint(
            lambda: protocol, local_addr=("127.0.0.1", 0),
        )
        self.addCleanup(transport.close)
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(sender.close)
        sender.setblocking(False)
        sender.sendto(MESSAGE, transport.get_extra_info("sockname"))
        await asyncio.wait_for(delivered.wait(), timeout=1)

        deadline = loop.time() + 5
        alert_calls = []
        while loop.time() < deadline:
            with telegram._cond:
                alert_calls = [
                    (method, body) for method, body in telegram.calls
                    if method == "sendMessage"
                    and "ER605 logged a DHCP allocation" in body.get("text", "")
                ]
            accepted = bot.delivery_stats()["categories"]["device_notice"]["accepted"]
            if alert_calls and accepted == 1:
                break
            await asyncio.sleep(0.01)
        alerts = [body["text"] for method, body in alert_calls
                  if method == "sendMessage" and "ER605 logged a DHCP allocation" in body.get("text", "")]
        self.assertEqual(len(alerts), 1)
        self.assertEqual(bot.delivery_stats()["categories"]["device_notice"]["accepted"], 1)
        self.assertEqual(len(scenario.mon.pending_events), 1)
        self.assertEqual(scenario.mon.pending_events[0][1], "device")

        row = {"name": "New sensor", "macaddr": "AA-BB-CC-DD-EE-02",
               "ipaddr": "192.168.0.125"}
        scenario.mon.router = SimpleNamespace(snap=SimpleNamespace(
            raw={"clients": [row]}, checked_at=start + 1,
        ))
        scenario.mon.on_router_events(start + 1, [])
        self.assertEqual(bot._outbox.qsize(), 0)
        self.assertEqual(len(scenario.mon.pending_events), 1)

        scenario.mon.flush_minute(int(start // 60 * 60), {})
        events = sqlite.recent_events(scenario.cfg.db_path, 10)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["kind"], "device")
        self.assertIn("ER605 logged a DHCP allocation", events[0]["message"])

        transport.close()
        await asyncio.sleep(0)

    async def test_udp_known_lease_renewal_does_not_send_a_device_arrival_alert(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        start = local(12)
        scenario = Scenario(tmp.name, start)
        self.addCleanup(scenario.close)
        row = {"name": "Sensor", "macaddr": "AA-BB-CC-DD-EE-02",
               "ipaddr": "192.168.0.125"}
        scenario.mon.router = SimpleNamespace(snap=SimpleNamespace(
            raw={"clients": [row]}, checked_at=start,
        ))
        scenario.mon.on_router_events(start, [])  # establish the known-lease baseline

        loop = asyncio.get_running_loop()
        delivered = asyncio.Event()

        def on_allocation(allocation, timestamp):
            scenario.mon.on_router_syslog_allocation(allocation, timestamp)
            delivered.set()

        protocol = RouterSyslogProtocol(
            "127.0.0.1", on_allocation, clock=scenario.clock,
        )
        transport, _ = await loop.create_datagram_endpoint(
            lambda: protocol, local_addr=("127.0.0.1", 0),
        )
        self.addCleanup(transport.close)
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(sender.close)
        sender.setblocking(False)
        sender.sendto(MESSAGE, transport.get_extra_info("sockname"))
        await asyncio.wait_for(delivered.wait(), timeout=1)

        self.assertEqual(scenario.outbox.texts(), [])
        self.assertEqual(scenario.mon.pending_events, [])
        transport.close()
        await asyncio.sleep(0)


if __name__ == "__main__":
    unittest.main()
