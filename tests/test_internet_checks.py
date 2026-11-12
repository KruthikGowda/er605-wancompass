import errno
import ssl
import tempfile
import unittest
from unittest import mock

from netpulse.probes import connectivity as c
from netpulse.health.internet import InternetIncidents
from netpulse.notifications.durable import AlertOutbox
from netpulse.storage.sqlite import KeyValueFile
from tests.harness import Scenario, local


class MemoryStore:
    def __init__(self): self.values = {}
    def get(self, key): return self.values.get(key)
    def set(self, key, value): self.values[key] = value


def result(ts, passed=2, status=None):
    checks = tuple(c.WebCheck(name, i < passed, 204 if i < passed else status,
                             "" if i < passed else "timeout") for i, (name, _, _) in enumerate(c.WEB_ENDPOINTS))
    return c.ConnectivityResult(ts, True, True, "diagnostic", icmp_state="HEALTHY", web_checks=checks)


class WebChecks(unittest.TestCase):
    def run_response(self, response):
        raw, tls, ctx = mock.MagicMock(), mock.MagicMock(), mock.Mock()
        raw.__enter__.return_value = raw
        tls.__enter__.return_value = tls
        tls.recv.side_effect = [response, b""]
        ctx.wrap_socket.return_value = tls
        with (mock.patch.object(c, "_dns_query", return_value=(b"", 0, 1)),
              mock.patch.object(c, "_answer_addresses", return_value=["93.184.216.34"]),
              mock.patch.object(c.socket, "socket", return_value=raw),
              mock.patch.object(c.ssl, "create_default_context", return_value=ctx)):
            response = c._web_check("192.0.2.7", .5, c.WEB_ENDPOINTS[0])
        raw.bind.assert_called_once_with(("192.0.2.7", 0))
        raw.connect.assert_called_once_with(("93.184.216.34", 443))
        ctx.wrap_socket.assert_called_once_with(raw, server_hostname="cp.cloudflare.com")
        self.assertIn(b"GET /generate_204 HTTP/1.1", tls.sendall.call_args.args[0])
        return response

    def test_only_expected_empty_response_passes(self):
        self.assertTrue(self.run_response(b"HTTP/1.1 204 No Content\r\n\r\n").ok)
        for response in [b"HTTP/1.1 200 OK\r\n\r\nportal", b"HTTP/1.1 302 Found\r\nLocation: /login\r\n\r\n",
                         b"HTTP/1.1 500 Error\r\n\r\n", b"HTTP/1.1 204 No Content\r\n\r\nbody",
                         b"HTTP/1.1 204 No Content\r\nContent-Length: 20\r\n\r\n",b"garbage"]:
            with self.subTest(response=response): self.assertFalse(self.run_response(response).ok)

    def test_dns_poisoning_cannot_probe_private_addresses(self):
        with (mock.patch.object(c, "_dns_query", return_value=(b"",0,1)),
              mock.patch.object(c, "_answer_addresses", return_value=["192.168.1.1"]),
              mock.patch.object(c.socket, "socket") as sock):
            self.assertEqual(c._web_check("192.0.2.7",.5,c.WEB_ENDPOINTS[0]).error,"dns_failed")
            sock.assert_not_called()

    def test_dns_and_source_errors_are_distinct(self):
        for error, expected in [(OSError(errno.EADDRNOTAVAIL,"bind"),"source_unavailable"),
                                (TimeoutError(),"timeout"), (ssl.SSLError(),"tls_failed")]:
            with mock.patch.object(c,"_dns_query",side_effect=error):
                self.assertEqual(c._web_check("192.0.2.7",.5,c.WEB_ENDPOINTS[0]).error,expected)

    def test_partial_web_success_is_not_total_outage(self):
        self.assertEqual(c.internet_state(result(10,1))[0],"PARTIAL")
        self.assertEqual(c.internet_state(result(10,0,302))[0],"RESTRICTED")
        self.assertEqual(c.internet_state(result(10,0))[0],"NO_INTERNET")
        self.assertEqual(c.internet_state(result(10,2))[0],"ONLINE")


class IncidentConfirmation(unittest.TestCase):
    def test_restart_deduplication_recovery_and_repeated_timestamp(self):
        store=MemoryStore(); tracker=InternetIncidents(store)
        self.assertIsNone(tracker.observe("WAN1","NO_INTERNET",1000))
        self.assertIsNone(tracker.observe("WAN1","NO_INTERNET",1000))
        event=tracker.observe("WAN1","DNS_FAILURE",1030)
        self.assertIsNotNone(event);tracker.acknowledge("WAN1",event)
        tracker=InternetIncidents(store)
        self.assertIsNone(tracker.observe("WAN1","NO_INTERNET",1060))
        self.assertIsNone(tracker.observe("WAN1","ONLINE",1090))
        event=tracker.observe("WAN1","ONLINE",1150)
        self.assertTrue(event["recovered"]);tracker.acknowledge("WAN1",event)
        self.assertIsNone(tracker.observe("WAN1","ONLINE",1210))

    def test_stale_observations_cannot_confirm_an_incident(self):
        tracker=InternetIncidents(MemoryStore())
        tracker.observe("WAN1","NO_INTERNET",1000)
        self.assertIsNone(tracker.observe("WAN1","NO_INTERNET",1300))

    def test_monitor_records_one_incident_and_one_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            s=Scenario(directory,local(12))
            try:
                start=s.clock()
                for offset in (0,60,90,120):s.mon.on_connectivity_result("WAN1",result(start+offset,0),start+offset)
                self.assertEqual(len(s.outbox.texts()),1)
                self.assertIn("Internet checks failing",s.outbox.texts()[0])
                for offset in (180,240):s.mon.on_connectivity_result("WAN1",result(start+offset,2),start+offset)
                self.assertEqual(len(s.outbox.texts()),2)
                self.assertIn("recovered",s.outbox.texts()[1])
                import json
                latest=json.loads(s.storage.get_value("internet_latest_v1"))["WAN1"]
                self.assertEqual(latest["internet_state"],"ONLINE")
                self.assertEqual(len(latest["web_checks"]),2)
            finally:s.close()


class DurableDelivery(unittest.TestCase):
    def test_actual_sqlite_queue_and_sender_survive_restart(self):
        from pathlib import Path
        from netpulse.storage.sqlite import Storage
        from netpulse.notifications.telegram import TelegramBot
        with tempfile.TemporaryDirectory() as directory:
            path=str(Path(directory)/'queue.db');Storage(path).close()
            bot=TelegramBot('synthetic-token','123',{},store=KeyValueFile(path))
            self.assertTrue(bot.send_reliable('Internet incident','internet-WAN1',True))
            bot=TelegramBot('synthetic-token','123',{},store=KeyValueFile(path))
            self.assertEqual(bot.delivery_stats()['durable_pending'],1)
            with mock.patch.object(bot,'_call',return_value={'ok':True}) as send:
                bot._deliver_pending_alert()
            self.assertEqual(send.call_args.args[1]['text'],'Internet incident')
            self.assertEqual(bot.delivery_stats()['accepted'],1)
            self.assertEqual(AlertOutbox(KeyValueFile(path)).stats()['durable_pending'],0)

    def test_disk_queue_survives_restart_and_recovery_replaces_outage(self):
        store=MemoryStore(); q=AlertOutbox(store)
        q.enqueue("wan","outage",["owner"],True,now=1000)
        q=AlertOutbox(store);key,row=q.due(["owner"],now=1000)
        q.result(key,row["version"],"owner",False,now=1000,retry_after=90)
        self.assertIsNone(q.due(["owner"],now=1080))
        q.enqueue("wan","recovered",["owner"],True,now=1080)
        key,new=q.due(["owner"],now=1080)
        self.assertEqual(new["text"],"recovered")
        q.result(key,row["version"],"owner",True,now=1080)
        self.assertEqual(q.stats()["durable_pending"],1)
        q.result(key,new["version"],"owner",True,now=1080)
        self.assertEqual(AlertOutbox(store).stats()["durable_pending"],0)

    def test_removed_recipients_and_stale_alerts_are_not_replayed(self):
        q=AlertOutbox(MemoryStore());q.enqueue("wan","old",["removed"],True,now=1000)
        self.assertIsNone(q.due(["owner"],now=1001))
        q.enqueue("wan","old",["owner"],True,now=1000)
        self.assertIsNone(q.due(["owner"],now=1000+86400))

    def test_only_pending_recipients_are_retried(self):
        q=AlertOutbox(MemoryStore());q.enqueue("wan","outage",["a","b"],True,now=1000)
        key,row=q.due(["a","b"],now=1000);q.result(key,row["version"],"a",True,now=1000)
        self.assertEqual(AlertOutbox(q.store).due(["a","b"],now=1000)[1]["targets"],["b"])
