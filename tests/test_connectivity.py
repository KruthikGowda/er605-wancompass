"""Secondary DNS/HTTPS diagnostics are source-bound, isolated, and best-effort."""

from __future__ import annotations

import io
import struct
from types import SimpleNamespace
import unittest
from unittest import mock

from netpulse.main import ConnectivityResult, _fresh_router_dns_servers
from netpulse.probes import connectivity


def dns_reply(query: bytes, *, ident: int | None = None, flags: int = 0x8180,
              questions: int = 1, answers: int = 1, question: bytes | None = None,
              answer: bytes | None = None) -> bytes:
    request_id = struct.unpack("!H", query[:2])[0]
    echoed_question = query[12:] if question is None else question
    answer_record = (b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04"
                     b"\x5d\xb8\xd8\x22") if answer is None and answers else (answer or b"")
    return (struct.pack("!HHHHHH", request_id if ident is None else ident,
                        flags, questions, answers, 0, 0) + echoed_question + answer_record)


class DatagramSocket:
    def __init__(self, response_source=("1.1.1.1", 53), response=None):
        self.response_source = response_source
        self.response = response
        self.sent = None
        self.bound = None
        self.timeout = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def settimeout(self, timeout):
        self.timeout = timeout

    def bind(self, address):
        self.bound = address

    def sendto(self, payload, address):
        self.sent = payload
        self.destination = address

    def recvfrom(self, _size):
        return self.response or dns_reply(self.sent), self.response_source


class StreamSocket:
    def __init__(self):
        self.timeout = None
        self.bound = None
        self.connected = None
        self.closed = False

    def settimeout(self, timeout):
        self.timeout = timeout

    def bind(self, address):
        self.bound = address

    def connect(self, address):
        self.connected = address

    def close(self):
        self.closed = True


class TLSStream:
    def __init__(self, status=b"HTTP/1.1 204 No Content\r\n"):
        self.status = status
        self.sent = []

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def sendall(self, data):
        self.sent.append(data)

    def makefile(self, _mode):
        return io.BytesIO(self.status)


class ConnectivityTests(unittest.TestCase):
    def test_routine_checks_are_spaced_out_and_offline_diagnosis_stays_fast(self):
        self.assertEqual(connectivity.check_interval_seconds("HEALTHY"), 120)
        self.assertEqual(connectivity.check_interval_seconds("DEGRADED"), 120)
        self.assertEqual(connectivity.check_interval_seconds("OFFLINE"), 60)

    def test_only_fresh_router_dns_configuration_is_used(self):
        router = SimpleNamespace(poll_seconds=600, snap=SimpleNamespace(
            checked_at=900.0, links={"WAN1": SimpleNamespace(dns_servers=("8.8.8.8",))}))
        self.assertEqual(_fresh_router_dns_servers(router, "WAN1", 1000.0), ("8.8.8.8",))
        self.assertEqual(_fresh_router_dns_servers(router, "WAN2", 1000.0), ())
        self.assertEqual(_fresh_router_dns_servers(router, "WAN1", 2101.0), ())
        self.assertEqual(_fresh_router_dns_servers(None, "WAN1", 1000.0), ())

    def test_dns_query_is_source_bound_and_accepts_only_valid_resolver_reply(self):
        sock = DatagramSocket()
        with (mock.patch.object(connectivity.socket, "socket", return_value=sock),
              mock.patch.object(connectivity.os, "urandom", return_value=b"\x12\x34")):
            self.assertTrue(connectivity._dns_ok("192.0.2.7", 0.4))
        self.assertEqual(sock.bound, ("192.0.2.7", 0))
        self.assertEqual(sock.destination, (connectivity.DNS_SERVER, 53))
        self.assertEqual(sock.timeout, 0.4)
        self.assertEqual(struct.unpack("!H", sock.sent[:2])[0], 0x1234)

    def test_dns_query_can_check_a_wan_assigned_resolver(self):
        sock = DatagramSocket(response_source=("203.0.113.53", 53))
        with (mock.patch.object(connectivity.socket, "socket", return_value=sock),
              mock.patch.object(connectivity.os, "urandom", return_value=b"\x12\x34")):
            self.assertTrue(connectivity._dns_ok("192.0.2.7", 0.4, "203.0.113.53"))
        self.assertEqual(sock.bound, ("192.0.2.7", 0))
        self.assertEqual(sock.destination, ("203.0.113.53", 53))
        self.assertFalse(connectivity._dns_ok("192.0.2.7", 0.4, "224.0.0.1"))

    def test_dns_rejects_untrusted_or_invalid_responses(self):
        cases = (
            (("192.0.2.1", 53), None),
            (("1.1.1.1", 53000), None),
            (("1.1.1.1", 53), "wrong-id"),
            (("1.1.1.1", 53), "servfail"),
            (("1.1.1.1", 53), "truncated"),
            (("1.1.1.1", 53), "wrong-question-count"),
            (("1.1.1.1", 53), "unsupported-opcode"),
            (("1.1.1.1", 53), "no-answer"),
            (("1.1.1.1", 53), "wrong-question-name"),
            (("1.1.1.1", 53), "wrong-question-type"),
        )
        for source, failure in cases:
            with self.subTest(source=source, failure=failure):
                sock = DatagramSocket(response_source=source)
                if failure == "wrong-id":
                    sock.response = dns_reply(b"\x00\x01", ident=2)
                elif failure == "servfail":
                    sock.response = dns_reply(b"\x00\x01", flags=0x8182)
                elif failure == "truncated":
                    sock.response = dns_reply(b"\x00\x01", flags=0x8380)
                elif failure == "wrong-question-count":
                    sock.response = dns_reply(b"\x00\x01", questions=0)
                elif failure == "unsupported-opcode":
                    sock.response = dns_reply(b"\x00\x01", flags=0x8980)
                elif failure == "no-answer":
                    sock.response = dns_reply(b"\x00\x01", answers=0)
                elif failure == "wrong-question-name":
                    sock.response = dns_reply(
                        b"\x00\x01", question=b"\x07invalid\x03com\0\x00\x01\x00\x01")
                elif failure == "wrong-question-type":
                    sock.response = dns_reply(b"\x00\x01", question=b"\x07example\x03com\0\x00\x1c\x00\x01")
                with (mock.patch.object(connectivity.socket, "socket", return_value=sock),
                      mock.patch.object(connectivity.os, "urandom", return_value=b"\x00\x01")):
                    self.assertFalse(connectivity._dns_ok("192.0.2.7", 0.4))

    def test_dns_requires_well_formed_a_answer_for_queried_name(self):
        bad_answers = (
            b"\x07invalid\x03com\x00\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x5d\xb8\xd8\x22",
            b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x5d\xb8\xd8",
        )
        for answer in bad_answers:
            with self.subTest(answer=answer):
                sock = DatagramSocket()
                sock.response = dns_reply(b"\x00\x01", answer=answer)
                with (mock.patch.object(connectivity.socket, "socket", return_value=sock),
                      mock.patch.object(connectivity.os, "urandom", return_value=b"\x00\x01")):
                    self.assertFalse(connectivity._dns_ok("192.0.2.7", 0.4))

    def test_dns_accepts_a_well_formed_cname_chain_to_an_a_record(self):
        question = (b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1))
        alias = b"\x05alias\x07example\x03net\x00"
        cname = (b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 60, len(alias)) + alias)
        # The A owner points to the alias encoded in the CNAME RDATA (not
        # to its own owner field, which would be a compression loop).
        alias_offset = 12 + len(question) + 2 + 10
        alias_pointer = bytes((0xC0 | (alias_offset >> 8), alias_offset & 0xFF))
        address = alias_pointer + struct.pack("!HHIH", 1, 1, 60, 4) + b"\x5d\xb8\xd8\x22"
        packet = (struct.pack("!HHHHHH", 1, 0x8180, 1, 2, 0, 0)
                  + question + cname + address)
        self.assertTrue(connectivity._has_expected_a_answer(packet, 12 + len(question), 2))

    def test_https_binds_source_and_verifies_hostname(self):
        raw = StreamSocket()
        tls = TLSStream()
        context = mock.Mock()
        context.wrap_socket.return_value = tls
        with (mock.patch.object(connectivity.socket, "socket", return_value=raw),
              mock.patch.object(connectivity.ssl, "create_default_context", return_value=context)):
            self.assertTrue(connectivity._https_ok("192.0.2.8", 0.7))
        self.assertEqual(raw.bound, ("192.0.2.8", 0))
        self.assertEqual(raw.connected, (connectivity.HTTPS_IP, 443))
        self.assertTrue(raw.closed)
        context.wrap_socket.assert_called_once_with(raw, server_hostname=connectivity.HTTPS_NAME)
        self.assertIn(b"Host: cloudflare-dns.com", tls.sent[0])

    def test_diagnosis_reports_all_reachability_combinations(self):
        cases = (
            (True, True, "ICMP probes failed, but DNS and HTTPS are reachable"),
            (False, True, "HTTPS is reachable, but the direct DNS check failed"),
            (True, False, "DNS is reachable, but the HTTPS check failed"),
            (False, False, "ICMP, DNS, and HTTPS checks all failed"),
        )
        for dns_ok, https_ok, expected in cases:
            with self.subTest(dns_ok=dns_ok, https_ok=https_ok), \
                 mock.patch.object(connectivity, "_dns_ok", return_value=dns_ok), \
                 mock.patch.object(connectivity, "_https_ok", return_value=https_ok):
                result = connectivity.diagnose("192.0.2.9", now=123.0, timeout=0.2)
            self.assertEqual(result.as_dict(), {
                "checked_at": 123.0, "dns_ok": dns_ok, "https_ok": https_ok,
                "wan_dns_ok": None, "icmp_state": "OFFLINE", "diagnosis": expected,
            })

    def test_diagnosis_describes_application_checks_when_icmp_is_healthy(self):
        with mock.patch.object(connectivity, "_dns_ok", return_value=False), \
             mock.patch.object(connectivity, "_https_ok", return_value=True):
            result = connectivity.diagnose("192.0.2.9", now=123.0, icmp_state="HEALTHY")
        self.assertEqual(result.icmp_state, "HEALTHY")
        self.assertFalse(result.dns_ok)
        self.assertTrue(result.https_ok)
        self.assertEqual(result.diagnosis,
                         "ICMP probes are healthy; HTTPS is reachable, but the direct DNS check failed")

    def test_dns_failure_does_not_skip_https_diagnosis(self):
        with mock.patch.object(connectivity, "_dns_ok", side_effect=OSError("unavailable")), \
             mock.patch.object(connectivity, "_https_ok", return_value=True) as https:
            result = connectivity.diagnose("192.0.2.9", now=123.0)
        self.assertFalse(result.dns_ok)
        self.assertTrue(result.https_ok)
        https.assert_called_once()

    def test_configured_wan_dns_is_checked_independently_and_falls_back(self):
        calls = []

        def dns(_source, _timeout, resolver=connectivity.DNS_SERVER):
            calls.append(resolver)
            return resolver == "8.8.8.8"

        with mock.patch.object(connectivity, "_dns_ok", side_effect=dns), \
             mock.patch.object(connectivity, "_https_ok", return_value=False):
            result = connectivity.diagnose("192.0.2.7", now=123,
                                            wan_dns_servers=("203.0.113.53", "8.8.8.8"))
        self.assertEqual(calls, [connectivity.DNS_SERVER, "203.0.113.53", "8.8.8.8"])
        self.assertTrue(result.wan_dns_ok)
        self.assertIn("WAN-assigned DNS resolver responded", result.diagnosis)

    def test_missing_wan_dns_configuration_remains_unknown(self):
        with mock.patch.object(connectivity, "_dns_ok", return_value=True), \
             mock.patch.object(connectivity, "_https_ok", return_value=True):
            result = connectivity.diagnose("192.0.2.7", now=123)
        self.assertIsNone(result.wan_dns_ok)


class ConnectivityTelegramAlerts(unittest.TestCase):
    def test_routine_dns_https_warning_requires_three_matching_failures_and_two_recoveries(self):
        import tempfile

        from tests.harness import Scenario, local

        start = local(12)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        scenario = Scenario(tmp.name, start)
        self.addCleanup(scenario.close)

        for index, offset in enumerate((0, 120, 240)):
            result = ConnectivityResult(
                start + offset, False, True,
                "ICMP probes are healthy; HTTPS is reachable, but the direct DNS check failed",
                icmp_state="HEALTHY",
            )
            scenario.mon.on_connectivity_result("WAN1", result, start + offset)
            if index < 2:
                self.assertEqual(scenario.outbox.texts(), [])

        self.assertEqual(len(scenario.outbox.texts()), 1)
        self.assertIn("DNS/HTTPS warning", scenario.outbox.texts()[0])
        self.assertIn("does not change the WAN health score or routing", scenario.outbox.texts()[0])

        for offset in (360, 480):
            scenario.mon.on_connectivity_result("WAN1", ConnectivityResult(
                start + offset, True, True, "ICMP probes are healthy; DNS and HTTPS are reachable",
                icmp_state="HEALTHY",
            ), start + offset)

        self.assertEqual(len(scenario.outbox.texts()), 2)
        self.assertIn("DNS/HTTPS checks recovered", scenario.outbox.texts()[1])

    def test_future_or_invalid_diagnosis_is_not_alerted_or_recorded(self):
        import tempfile

        from tests.harness import Scenario, local

        start = local(12)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        scenario = Scenario(tmp.name, start)
        self.addCleanup(scenario.close)
        result = ConnectivityResult(start + 1, True, True, "future result")

        scenario.mon.on_connectivity_result("WAN1", result, start)

        self.assertEqual(scenario.outbox.texts(), [])
        self.assertEqual(scenario.mon.pending_events, [])
        self.assertNotIn("WAN1", scenario.mon._connectivity_notified)

    def test_connectivity_result_freshness_rejects_future_invalid_and_expired_samples(self):
        fresh = connectivity.result_is_fresh
        self.assertTrue(fresh(900, 1000))
        self.assertTrue(fresh(820, 1000))
        self.assertFalse(fresh(819, 1000))
        self.assertFalse(fresh(1001, 1000))
        self.assertFalse(fresh("nan", 1000))
        self.assertFalse(fresh(True, 1000))
        self.assertFalse(fresh(None, 1000))

    def test_confirmed_outage_diagnosis_is_sent_once_until_result_changes(self):
        import tempfile

        from tests.harness import Scenario, local

        start = local(12)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        scenario = Scenario(tmp.name, start)
        self.addCleanup(scenario.close)
        result = ConnectivityResult(start, True, True,
                                    "ICMP probes failed, but DNS and HTTPS are reachable")

        scenario.mon.on_connectivity_result("WAN1", result, start)
        scenario.mon.on_connectivity_result("WAN1", result, start + 60)

        message = "🔎 Example ISP A outage check: ICMP probes failed, but DNS and HTTPS are reachable."
        self.assertEqual(scenario.outbox.texts(), [message])
        self.assertEqual([event[1] for event in scenario.mon.pending_events], ["connectivity"])


if __name__ == "__main__":
    unittest.main()
