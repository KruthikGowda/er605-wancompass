import csv
import http.client
import io
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from netpulse import speedtest, summary
from netpulse.speedtest import SpeedResult, SpeedTester, mbps
from netpulse.storage import sqlite
from netpulse.storage.sqlite import Storage
from netpulse.web import app as web
from netpulse.web import report


def result(wan, down=90.0, up=40.0, idle=20.0, loaded=25.0, ip=None, error=None, ts=None):
    return SpeedResult(wan=wan, ts=ts or time.time(), trigger="manual", down_mbps=down, up_mbps=up,
                       idle_ms=idle, loaded_ms=loaded, public_ip=ip or f"ip-{wan}", colo="MAA", error=error)


class Maths(unittest.TestCase):
    def test_mbps(self):
        self.assertEqual(mbps(25_000_000, 2.0), 100.0)

    def test_bufferbloat(self):
        self.assertEqual(result("WAN1", idle=20, loaded=65).bufferbloat_ms, 45)
        self.assertIsNone(result("WAN1", loaded=None).bufferbloat_ms)


class Tester(unittest.TestCase):
    def test_runs_each_wan_and_passes_seen_ips_for_route_check(self):
        seen = []
        configured = []

        def runner(wan, ip, trigger, other_ips, expected_asns, **_):
            seen.append(set(other_ips))
            configured.append(expected_asns)
            return result(wan, ip="1.2.3.4")          # both WANs report the same public IP

        saved = []
        t = SpeedTester([("WAN1", ".201"), ("WAN2", ".202")], saved.append, runner=runner,
                        expected_asns={"WAN1": ("AS12345",)})
        t.run_now("manual")
        self.assertEqual(seen, [set(), {"1.2.3.4"}])  # second WAN is told the first one's IP
        self.assertEqual(configured, [("AS12345",), ()])
        self.assertEqual(len(saved), 2)

    def test_route_check_in_run_one(self):
        with mock.patch.object(speedtest, "trace", return_value={"ip": "1.2.3.4", "colo": "MAA"}):
            r = speedtest.run_one("WAN2", ".202", "manual", {"1.2.3.4"})
        self.assertIn("route check failed", r.error)
        self.assertIsNone(r.down_mbps)

    def test_configured_egress_asn_mismatch_skips_the_measurement(self):
        with mock.patch.object(speedtest, "trace", return_value={"ip": "1.2.3.4", "colo": "MAA"}), \
             mock.patch.object(speedtest, "origin_asns", return_value={"64500"}), \
             mock.patch.object(speedtest, "_transfer") as transfer:
            r = speedtest.run_one("WAN1", ".201", "manual", set(), expected_asns=("AS64501",))
        self.assertIn("AS64500", r.error)
        self.assertIsNone(r.down_mbps)
        transfer.assert_not_called()

    def test_matching_egress_asn_allows_measurement(self):
        with mock.patch.object(speedtest, "trace", return_value={"ip": "1.2.3.4", "colo": "MAA"}), \
             mock.patch.object(speedtest, "origin_asns", return_value={"64500"}), \
             mock.patch.object(speedtest, "_ping_median", return_value=20.0), \
             mock.patch.object(speedtest, "_transfer", side_effect=[(1000, 1.0), (1000, 1.0)]):
            r = speedtest.run_one("WAN1", ".201", "manual", set(), expected_asns=("AS64500",))
        self.assertIsNone(r.error)
        self.assertIsNotNone(r.down_mbps)

    def test_ripe_lookup_extracts_announcing_asns(self):
        response = mock.Mock(status=200)
        response.read.return_value = b'{"data":{"asns":[64500,"64501"]}}'
        conn = mock.Mock()
        conn.getresponse.return_value = response
        with mock.patch.object(speedtest.http.client, "HTTPSConnection", return_value=conn) as connect:
            self.assertEqual(speedtest.origin_asns("203.0.113.4", ".201"), {"64500", "64501"})
        self.assertEqual(connect.call_args.args[0], speedtest.ASN_HOST)
        self.assertIn("203.0.113.4", conn.request.call_args.args[1])

    def test_one_at_a_time_and_manual_rate_limit(self):
        gate = threading.Event()

        def slow(wan, ip, trigger, other_ips, **_):
            gate.wait(5)
            return result(wan)

        done = threading.Event()
        t = SpeedTester([("WAN1", ".201")], lambda r: None, runner=slow, min_gap_seconds=300)
        self.assertIsNone(t.try_start("manual", on_done=lambda res: done.set()))
        self.assertEqual(t.try_start("manual"), "A speed test is already running.")
        gate.set()
        self.assertTrue(done.wait(5))
        time.sleep(0.05)
        self.assertIn("Please wait", t.try_start("manual"))
        self.assertIsNone(t.try_start("scheduled"))   # the schedule isn't blocked by the manual gap

    def test_crash_does_not_stick_running(self):
        def boom(*a, **k):
            raise RuntimeError("x")
        done = threading.Event()
        t = SpeedTester([("WAN1", ".201")], lambda r: None, runner=boom, min_gap_seconds=0)
        t.try_start("manual", on_done=lambda res: done.set())
        self.assertTrue(done.wait(5))
        time.sleep(0.05)
        self.assertFalse(t.running)


class Wording(unittest.TestCase):
    def test_dip_and_lines(self):
        r = result("WAN1", down=30, idle=20, loaded=80).to_dict()
        self.assertTrue(summary.is_dip(r, 95, 50))
        line = summary.speed_line(r, "Example ISP A", 95)
        self.assertTrue(line.startswith("📉 Example ISP A"))
        self.assertIn("+60 ms lag when busy", line)
        self.assertIn("usual ⬇ 95 Mbps", line)
        self.assertFalse(summary.is_dip(result("WAN1", down=80).to_dict(), 95, 50))
        self.assertFalse(summary.is_dip(r, None, 50))  # no history yet -> never a dip

    def test_failed_test_wording(self):
        line = summary.speed_line(result("WAN2", error="route check failed").to_dict(), "Example ISP B")
        self.assertIn("test failed (route check failed)", line)


class StorageAndReport(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.tmp.name) / "t.db")
        s = Storage(self.path)
        now = int(time.time())
        rows = [(now - 7200 + i * 60, "WAN1", "OFFLINE" if 10 <= i < 25 else "HEALTHY", 90, 0, 20, 1, 100)
                for i in range(100)]
        rows.extend((now - 7200 + i * 60, "WAN2", "HEALTHY", 95, 0, 15, 1, 100)
                    for i in range(100))
        events = [(now - 7200 + 600, "state", "WAN1", "Example ISP A (WAN1): HEALTHY -> OFFLINE (x)"),
                  (now - 7200 + 1500, "state", "WAN1", "Example ISP A (WAN1): OFFLINE -> HEALTHY (y)")]
        s.write_minute(rows, events, [])
        s.close()
        for i, down in enumerate([90, 95, 100, 20]):
            sqlite.insert_speedtest(self.path, result("WAN1", down=down, ts=now - 3600 + i).to_dict())
        sqlite.insert_speedtest(self.path, result("WAN1", down=None, up=None, error="route failed",
                                                  ts=now - 1800).to_dict())

    def tearDown(self):
        self.tmp.cleanup()

    def test_usual_download_is_median(self):
        self.assertEqual(sqlite.usual_download(self.path, "WAN1", 0), 92.5)
        self.assertIsNone(sqlite.usual_download(self.path, "WAN2", 0))

    def test_report_outages_and_html(self):
        rep = report.build(self.path, {"WAN1": "Example ISP A"}, {"WAN1": 200}, 1)
        w = rep["wans"][0]
        self.assertEqual(len(w["outages"]), 1)
        self.assertEqual(w["outages"][0][1] - w["outages"][0][0], 900)
        self.assertFalse(w["outages"][0][2])
        self.assertEqual(w["down_min"], 15)
        html = report.to_html(rep)
        self.assertIn("Internet connection report", html)
        self.assertIn("15 min", html)
        self.assertIn("200 Mbps plan", html)
        csv_text = report.to_csv(rep, self.path, {"WAN1": "Example ISP A"})
        rows = list(csv.DictReader(io.StringIO(csv_text)))
        self.assertEqual(rows[0]["record_type"], "hour")
        self.assertEqual(rows[0]["isp"], "Example ISP A")
        outages = [row for row in rows if row["record_type"] == "outage"]
        self.assertEqual(len(outages), 1)
        self.assertEqual(outages[0]["down_minutes"], "15")
        speed_rows = [row for row in rows if row["record_type"] == "speed_test"]
        self.assertEqual(len(speed_rows), 5)
        self.assertIn("20.0", [row["download_mbps"] for row in speed_rows])
        self.assertEqual(sum(row["test_status"] == "failed" for row in speed_rows), 1)
        self.assertIn("timestamp", rows[0])
        self.assertIn("+", rows[0]["timestamp"][-5:])  # local UTC offset is explicit

        one_isp = report.build(self.path, {"WAN1": "Example ISP A", "WAN2": "Example ISP B"}, {}, 1,
                               selected_wan="WAN2")
        selected_rows = list(csv.DictReader(io.StringIO(report.to_csv(
            one_isp, self.path, {"WAN1": "Example ISP A", "WAN2": "Example ISP B"}))))
        self.assertTrue(selected_rows)
        self.assertEqual({row["wan"] for row in selected_rows}, {"WAN2"})
        self.assertEqual(one_isp["wans"][0]["label"], "Example ISP B")

    def test_outages_still_open(self):
        spans = report.outages([{"kind": "state", "wan": "WAN1", "ts": 5, "message": "x: HEALTHY -> OFFLINE"}], "WAN1")
        self.assertEqual(spans, [(5, None, False)])

    def test_report_includes_outage_spanning_the_start_of_the_date_window(self):
        path = str(Path(self.tmp.name) / "window.db")
        storage = Storage(path)
        now = int(time.time())
        expected_boundary = now - 86400
        events = [
            (expected_boundary - 120, "state", "WAN1", "Example ISP A (WAN1): HEALTHY -> OFFLINE"),
            (expected_boundary + 300, "state", "WAN1", "Example ISP A (WAN1): OFFLINE -> HEALTHY"),
        ]
        storage.write_minute([(expected_boundary + 600, "WAN1", "HEALTHY", 90, 0, 25, 1, 100)],
                             events, [])
        storage.close()

        rep = report.build(path, {"WAN1": "Example ISP A"}, {}, 1)
        outage = rep["wans"][0]["outages"][0]
        self.assertEqual(outage, (rep["since"], expected_boundary + 300, True))
        self.assertIn("before report window", report.to_html(rep))
        rows = list(csv.DictReader(io.StringIO(report.to_csv(rep, path, {"WAN1": "Example ISP A"}))))
        outage_row = next(row for row in rows if row["record_type"] == "outage")
        self.assertEqual(outage_row["timestamp"], "")
        self.assertEqual(outage_row["test_status"], "started_before_window")


class FakeMon:
    def __init__(self):
        self.tester = SpeedTester([("WAN1", ".201")], lambda r: None,
                                  runner=lambda *a, **k: result("WAN1"), min_gap_seconds=300)
        self.labels = {"WAN1": type("W", (), {"label": "Example ISP A", "plan_mbps": 200})()}

    def usual_speeds(self):
        return {"WAN1": None}


class WebEndpoints(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.tmp.name) / "t.db")
        Storage(self.path).close()
        self.board = web.StatusBoard()
        self.board.set_extra("speedtest", FakeMon())
        self.server = web.start("127.0.0.1", 0, self.board, self.path)
        self.port = self.server.server_address[1]

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.tmp.cleanup()

    def req(self, method, path, headers=None, body=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        c.request(method, path, body=body, headers=headers or {})
        r = c.getresponse()
        body = r.read()
        c.close()
        return r.status, body

    def test_speedtests_and_report_pages(self):
        status, body = self.req("GET", "/api/speedtests?days=30")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["plans"], {"WAN1": 200})
        self.assertEqual(self.req("GET", "/report?days=7")[0], 200)
        status, body = self.req("GET", "/report?days=7&wan=WAN1")
        self.assertEqual(status, 200)
        self.assertIn(b"Example ISP A", body)
        status, body = self.req("GET", "/api/report.csv?days=7")
        self.assertEqual(status, 200)
        self.assertTrue(body.startswith(b"record_type,timestamp,end_time,isp,wan"))
        status, body = self.req("GET", "/api/report.csv?days=7&wan=WAN1")
        self.assertEqual(status, 200)
        self.assertTrue(all(row["wan"] == "WAN1" for row in csv.DictReader(io.StringIO(body.decode()))))
        self.assertEqual(self.req("GET", "/report?wan=UNKNOWN")[0], 400)

    def test_post_starts_test_then_rate_limits(self):
        status, body = self.req("POST", "/api/speedtest", {"Origin": f"http://127.0.0.1:{self.port}"})
        self.assertEqual(status, 202)
        time.sleep(0.2)
        status, body = self.req("POST", "/api/speedtest")
        self.assertEqual(status, 429)
        self.assertIn("Please wait", json.loads(body)["reason"])

    def test_cross_site_post_refused(self):
        status, _ = self.req("POST", "/api/speedtest", {"Origin": "https://evil.example"})
        self.assertEqual(status, 403)

    def test_rename_saves_a_local_label_and_rejects_bad_input(self):
        self.board.publish({"router": {"checked_at": 1234.0}})
        self.board.set_extra("router_raw", {"clients": [{"name": "phone", "macaddr": "aa-bb-cc-dd-ee-ff",
                                                           "ipaddr": "192.168.0.101", "leasetime": "Permanent"}]})
        headers = {"Origin": f"http://127.0.0.1:{self.port}", "Content-Type": "application/json"}
        status, body = self.req("POST", "/api/devices/label", headers,
                                json.dumps({"mac": "aa-bb-cc-dd-ee-ff", "label": " Work phone "}))
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body), {"saved": True})
        status, body = self.req("GET", "/api/devices")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["devices"][0]["label"], "Work phone")
        status, _ = self.req("POST", "/api/devices/label", headers,
                             json.dumps({"mac": "not-a-mac", "label": "x"}))
        self.assertEqual(status, 400)


if __name__ == "__main__":
    unittest.main()
