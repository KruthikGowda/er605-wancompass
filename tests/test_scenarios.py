"""End-to-end regression scenarios: the real Monitor on simulated time, scripted ISPs.

Each scenario states the behaviour a person would notice (alerts, recommendations, what the
dashboard says) so that a future change that alters it fails here first.
"""

import tempfile
import unittest
from types import SimpleNamespace

from netpulse.probes.connectivity import ConnectivityResult
from netpulse.storage import sqlite
from tests.harness import Condition, Scenario, local

KINDS = ("state", "router", "speedtest", "decision")


def all_events(s):
    return sqlite.events_between(s.cfg.db_path, 0, 2**62, KINDS)


def window(start: float, end: float, inside: Condition, outside: Condition = Condition()):
    return lambda t: inside if start <= t < end else outside


class Base(unittest.TestCase):
    def scenario(self, start, scripts=None, **overrides) -> Scenario:
        """overrides: config sections to change, e.g. telegram={"digest_time": ""}."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        s = Scenario(tmp.name, start, scripts or {}, overrides)
        self.addCleanup(s.close)
        return s

    def events(self, s: Scenario, kind: str | None = None) -> list[str]:
        return [e["message"] for e in all_events(s) if kind is None or e["kind"] == kind]


class SteadyDay(Base):
    def test_all_quiet_when_both_healthy(self):
        s = self.scenario(local(12), telegram={"digest_time": ""})
        s.run(30 * 60)
        self.assertEqual((s.state("WAN1"), s.state("WAN2")), ("HEALTHY", "HEALTHY"))
        self.assertEqual(s.outbox.texts(), [], "no alerts on a quiet day")
        self.assertEqual(s.board.get()["headline"]["level"], "HEALTHY")
        # Only the start-up transitions are logged.
        self.assertEqual(len(self.events(s, "state")), 2)
        # Every minute was stored for both WANs.
        pts = sqlite.history(s.cfg.db_path, 0, 60)
        self.assertGreaterEqual(len(pts), 2 * 29)

    def test_daily_digest_sent_once_and_catches_up(self):
        s = self.scenario(local(8, 58), telegram={"digest_time": "09:00"})
        s.run(10 * 60)                       # crosses 09:00
        digests = [t for t in s.outbox.texts() if "daily summary" in t]
        self.assertEqual(len(digests), 1)
        s.run(60 * 60)
        self.assertEqual(len([t for t in s.outbox.texts() if "daily summary" in t]), 1, "never twice a day")

    def test_daily_digest_surfaces_lease_updates_held_during_quiet_hours(self):
        start = local(9)
        s = self.scenario(start)
        ts = int(start - 60)
        s.storage.write_minute(
            [(ts, "WAN1", "HEALTHY", 99, 0, 10, 1, 100)],
            [
                (ts, "device", None, "DHCP lease no longer listed by the ER605: Test camera (192.0.2.10)"),
                (ts + 10, "device", None, "Device stopped replying to LAN ping: Test camera (192.0.2.10)"),
            ], [],
        )
        digest = s.mon.digest(start, "Daily summary")
        self.assertIn("Home-device lease updates (last 24 hours)", digest)
        self.assertIn("DHCP lease no longer listed by the ER605: Test camera", digest)
        self.assertNotIn("stopped replying to LAN ping", digest)


class SlowEvening(Base):
    """Example ISP A gets slow and lossy for 20 minutes, then recovers. Example ISP B stays fine."""

    def setUp(self):
        start = local(20)
        bad = Condition(rtt_mult=4.5, loss=0.2)
        self.s = self.scenario(start, {"WAN1": window(start + 300, start + 1500, bad)},
                               telegram={"digest_time": ""})
        self.s.run(40 * 60)

    def test_alerts_once_when_bad_and_once_when_recovered(self):
        texts = self.s.outbox.texts()
        bad = [t for t in texts if t.startswith(("🟠 Example ISP A is bad", "🟡 Example ISP A is slow"))]
        good = [t for t in texts if "Example ISP A is healthy again" in t]
        self.assertTrue(1 <= len(bad) <= 2, texts)            # slow, then maybe bad (rate-limited)
        self.assertEqual(len(good), 1, texts)
        self.assertEqual(texts[-1], good[0], "nothing after the all-clear (no alerts while improving)")
        self.assertIn("Example ISP B is healthy", bad[0])
        self.assertIn("of packets lost", bad[0])
        self.assertRegex(good[0], r"was (bad|slow) for 2\d min")

    def test_no_recommendation_change_because_oneott_is_current(self):
        self.assertEqual(self.events(self.s, "decision"), [])
        self.assertEqual(self.s.mon.engine.current, "WAN2")

    def test_minutes_recorded_as_bad(self):
        summ = sqlite.period_summary(self.s.cfg.db_path, 0, 2**62)
        bad_minutes = summ["wans"]["WAN1"]["minutes"].get("BAD", 0) + summ["wans"]["WAN1"]["minutes"].get("DEGRADED", 0)
        self.assertGreaterEqual(bad_minutes, 18)
        self.assertEqual(summ["wans"]["WAN2"]["minutes"].get("BAD", 0), 0)


class RecommendedLineGetsWorse(Base):
    """Example ISP B (the recommended line) degrades: after the hold time, recommend Example ISP A."""

    def test_would_switch_after_hold_not_before(self):
        start = local(14)
        s = self.scenario(start, {"WAN2": window(start + 120, start + 3600, Condition(rtt_mult=5, loss=0.1))},
                          telegram={"digest_time": ""})
        s.run(4 * 60)
        self.assertEqual(self.events(s, "decision"), [], "not within the 180 s hold")
        s.run(8 * 60)   # the problem needs a few minutes to show in the 5-min window, then the 180 s hold
        decisions = self.events(s, "decision")
        self.assertEqual(len(decisions), 1)
        self.assertIn("WOULD SWITCH Example ISP B (WAN2) -> Example ISP A (WAN1)", decisions[0])
        self.assertTrue(any(t.startswith("🔀 Critical devices would move to Example ISP A") for t in s.outbox.texts()))


class Outage(Base):
    """Example ISP B goes completely down for 12 minutes."""

    def setUp(self):
        start = local(11)
        self.start = start
        self.s = self.scenario(start, {"WAN2": window(start + 300, start + 300 + 720, Condition(down=True))},
                               telegram={"digest_time": ""})
        self.s.run(30 * 60)

    def test_down_and_back_alerts(self):
        texts = self.s.outbox.texts()
        down = [(t, x) for t, x, _ in self.s.outbox.sent if x.startswith("🔴 Example ISP B is DOWN")]
        self.assertEqual(len(down), 1, texts)
        # Confirmed within 3 cycles (30 s) of the outage starting.
        self.assertLessEqual(down[0][0] - (self.start + 300), 40)
        back = [x for x in texts if x.startswith("✅ Example ISP B is back online")]
        self.assertEqual(len(back), 1, texts)
        self.assertRegex(back[0], r"was down for 1[12] min")
        self.assertFalse(any(x.startswith("🟠 Example ISP B is bad") for x in texts), "recovery must not look like a new problem")
        self.assertFalse(any(x.startswith("🟡 Example ISP B is slow") for x in texts), "no 'slow' before 'down'")
        # The "still settling" message promises a follow-up: it must arrive (not be rate-limited away).
        self.assertTrue(any(x.startswith("🟢 Example ISP B is fully healthy again") for x in texts), texts)

    def test_secondary_dns_https_success_does_not_rewrite_icmp_health(self):
        start = local(11)
        s = self.scenario(start, {"WAN2": lambda _t: Condition(down=True)},
                          telegram={"digest_time": ""})
        s.run(15 * 60)
        self.assertEqual(s.state("WAN2"), "OFFLINE")

        # A successful secondary check is evidence for diagnosis only. It must not
        # turn a line with failed ICMP evaluation into HEALTHY or alter its score.
        s.mon.connectivity_results["WAN2"] = ConnectivityResult(
            checked_at=s.clock(), dns_ok=True, https_ok=True,
            diagnosis="ICMP probes failed, but DNS and HTTPS are reachable",
        )
        before = s.evals["WAN2"]
        snapshot = s.mon._snapshot(s.clock(), s.evals)
        wan = next(row for row in snapshot["wans"] if row["name"] == "WAN2")
        self.assertEqual(wan["state"], "OFFLINE")
        self.assertEqual(wan["score"], before.score)
        self.assertTrue(wan["connectivity"]["dns_ok"])
        self.assertTrue(wan["connectivity"]["https_ok"])

        # Secondary evidence belongs to the outage episode that triggered it. Do not
        # keep showing that diagnosis after reachability recovers.
        s.net.scripts["WAN2"] = lambda _now: Condition()
        s.run(8 * 60)
        self.assertEqual(s.state("WAN2"), "HEALTHY")
        recovered = s.mon._snapshot(s.clock(), s.evals)
        recovered_wan = next(row for row in recovered["wans"] if row["name"] == "WAN2")
        self.assertIsNone(recovered_wan["connectivity"])
        self.assertNotIn("WAN2", s.mon.connectivity_results)

    def test_dns_https_results_are_visible_during_healthy_icmp_without_changing_health(self):
        start = local(11)
        s = self.scenario(start, {"WAN1": lambda _t: Condition()})
        s.run(15 * 60)
        before = s.evals["WAN1"]
        s.mon.connectivity_results["WAN1"] = ConnectivityResult(
            checked_at=s.clock(), dns_ok=False, https_ok=True,
            diagnosis="ICMP probes are healthy; HTTPS is reachable, but the direct DNS check failed",
            icmp_state="HEALTHY",
        )

        snapshot = s.mon._snapshot(s.clock(), s.evals)
        wan = next(row for row in snapshot["wans"] if row["name"] == "WAN1")

        self.assertEqual(wan["state"], "HEALTHY")
        self.assertEqual(wan["score"], before.score)
        self.assertFalse(wan["connectivity"]["dns_ok"])
        self.assertTrue(wan["connectivity"]["https_ok"])
        self.assertEqual(wan["connectivity"]["icmp_state"], "HEALTHY")


    def test_future_connectivity_diagnosis_is_not_exposed_during_clock_rollback(self):
        start = local(11)
        s = self.scenario(start, {"WAN2": lambda _t: Condition(down=True)},
                          telegram={"digest_time": ""})
        s.run(15 * 60)
        s.mon.connectivity_results["WAN2"] = ConnectivityResult(
            checked_at=s.clock() + 3600, dns_ok=True, https_ok=True,
            diagnosis="sample from the future",
        )

        snapshot = s.mon._snapshot(s.clock(), s.evals)
        wan = next(row for row in snapshot["wans"] if row["name"] == "WAN2")
        self.assertIsNone(wan["connectivity"])

    def test_emergency_switch_is_immediate(self):
        decisions = [e for e in all_events(self.s) if e["kind"] == "decision"]
        self.assertGreaterEqual(len(decisions), 1)
        self.assertIn("OFFLINE, failing over to WAN1", decisions[0]["message"])
        self.assertLessEqual(decisions[0]["ts"] - (self.start + 300), 40)

    def test_return_is_delayed_after_recovery(self):
        decisions = [e for e in all_events(self.s) if e["kind"] == "decision"]
        # Recovered at +1020 s; returning needs recovery (600 s) + hold (180 s) at least.
        returns = [d for d in decisions if "-> Example ISP B" in d["message"]]
        for d in returns:
            self.assertGreaterEqual(d["ts"] - (self.start + 1020), 600 + 180)

    def test_report_lists_the_outage(self):
        from netpulse.web import report
        rep = report.build(self.s.cfg.db_path, {"WAN1": "Example ISP A", "WAN2": "Example ISP B"}, {}, 400)
        oneott = next(w for w in rep["wans"] if w["wan"] == "WAN2")
        self.assertEqual(len(oneott["outages"]), 1)
        a, b, clipped = oneott["outages"][0]
        self.assertFalse(clipped)
        self.assertAlmostEqual((b - a) / 60, 12, delta=1)


class GroupRecommendation(Base):
    def test_omada_pause_keeps_smart_candidate_pending_without_disabling_group(self):
        start = local(11)
        s = self.scenario(start)
        group = sqlite.save_device_group(s.cfg.db_path, "Example Work Group",
                                        ["AA-BB-CC-DD-EE-01"], int(start))
        sqlite.set_group_smart_routing(s.cfg.db_path, group["id"], True, now=int(start))
        s.mon.group_recommendations[group["id"]] = {"ready": True, "candidate": "WAN2"}
        s.mon.pending_smart_group_routes[group["id"]] = "WAN2"
        pause = {"paused_until": start + 1800}
        readiness = {"enabled": False}
        calls = []
        s.mon.router = SimpleNamespace(snapshot=lambda: pause)
        s.mon.router_control = SimpleNamespace(
            state=lambda: readiness,
            apply_smart_group_route=lambda *args: calls.append(args))

        self.assertIsNone(s.mon.next_smart_group_route())
        self.assertEqual(s.mon.pending_smart_group_routes, {group["id"]: "WAN2"})
        s.mon.apply_smart_group_route(group["id"], "WAN2")
        self.assertEqual(calls, [])
        self.assertTrue(sqlite.device_groups(s.cfg.db_path)[0]["smart_routing_enabled"])
        self.assertEqual(s.outbox.texts(), [])

        pause["paused_until"] = 0
        self.assertIsNone(s.mon.next_smart_group_route())
        s.mon.apply_smart_group_route(group["id"], "WAN2")
        self.assertEqual(calls, [])
        self.assertTrue(sqlite.device_groups(s.cfg.db_path)[0]["smart_routing_enabled"])
        readiness["enabled"] = True
        self.assertEqual(s.mon.next_smart_group_route(), (group["id"], "WAN2"))

    def test_smart_route_verification_error_disables_automation_and_records_pause(self):
        start = local(11)
        s = self.scenario(start)
        group = sqlite.save_device_group(s.cfg.db_path, "Example Work Group",
                                        ["AA-BB-CC-DD-EE-01"], int(start))
        sqlite.set_group_smart_routing(s.cfg.db_path, group["id"], True, now=int(start))
        s.mon.group_recommendations[group["id"]] = {
            "ready": True, "candidate": "WAN2",
        }
        s.mon.router_control = SimpleNamespace(
            apply_smart_group_route=lambda *_args: (_ for _ in ()).throw(RuntimeError("router error")))

        s.mon.apply_smart_group_route(group["id"], "WAN2")

        self.assertFalse(sqlite.device_groups(s.cfg.db_path)[0]["smart_routing_enabled"])
        history = sqlite.device_group_history(s.cfg.db_path)
        self.assertEqual(history[0]["result"], "paused")
        self.assertIn("Smart routing", "\n".join(s.outbox.texts()))

    def test_smart_group_routing_waits_its_full_opt_in_hold_before_queueing(self):
        start = local(11)
        s = self.scenario(start, {"WAN1": lambda _t: Condition(rtt_mult=1.5)})
        group = sqlite.save_device_group(s.cfg.db_path, "Example Work Group",
                                        ["AA-BB-CC-DD-EE-01"], int(start))
        sqlite.set_device_route(s.cfg.db_path, "AA-BB-CC-DD-EE-01", "192.168.0.120",
                                "WAN1", int(start), "test", "AUTO", "applied")
        sqlite.set_group_smart_routing(s.cfg.db_path, group["id"], True, now=int(start))

        s.run(60)
        self.assertEqual(s.mon.pending_smart_group_routes, {})
        self.assertEqual(sqlite.device_routes(s.cfg.db_path)["AA-BB-CC-DD-EE-01"]["route"], "WAN1")

        s.run(180)
        self.assertEqual(s.mon.pending_smart_group_routes, {group["id"]: "WAN2"})
        # Scenario monitor runs only the local decision cycle; it cannot contact or write the ER605.
        self.assertEqual(sqlite.device_routes(s.cfg.db_path)["AA-BB-CC-DD-EE-01"]["route"], "WAN1")

    def test_monitor_only_candidate_requires_a_sustained_lead_and_never_changes_routes(self):
        start = local(11)
        s = self.scenario(start, {"WAN1": lambda _t: Condition(rtt_mult=1.5)})
        members = ["AA-BB-CC-DD-EE-01", "AA-BB-CC-DD-EE-02"]
        group = sqlite.save_device_group(s.cfg.db_path, "Example Work Group", members, int(start))
        for index, mac in enumerate(members, start=120):
            sqlite.set_device_route(s.cfg.db_path, mac, f"192.168.0.{index}", "WAN1",
                                    int(start), "test", "AUTO", "applied")

        s.run(15 * 60)

        advice = s.mon.group_recommendations[group["id"]]
        self.assertEqual(advice["status"], "stable")
        self.assertTrue(advice["ready"])
        self.assertEqual(advice["candidate"], "WAN2")
        self.assertEqual(advice["current"], "WAN1")
        self.assertTrue(all(sqlite.device_routes(s.cfg.db_path)[mac]["route"] == "WAN1"
                            for mac in members))

class Flapping(Base):
    """Example ISP A alternates bad/good every minute: alerts must stay calm and recommendations stable."""

    def test_rate_limited_and_no_flip_flop(self):
        start = local(16)
        flappy = lambda t: Condition(rtt_mult=5, loss=0.25) if int((t - start) // 60) % 2 else Condition()
        s = self.scenario(start, {"WAN1": flappy}, telegram={"digest_time": ""})
        s.run(30 * 60)
        ant_alerts = [t for t in s.outbox.texts() if t.split()[1:2] == ["Example ISP A"]]
        self.assertLessEqual(len(ant_alerts), 7, ant_alerts)   # at most ~1 per 5 min
        self.assertLessEqual(len(self.events(s, "decision")), 1)


class QuietHours(Base):
    def test_slow_held_at_night_but_down_always_sent(self):
        start = local(2)
        s = self.scenario(start, {
            "WAN1": window(start + 120, start + 900, Condition(rtt_mult=5, loss=0.2)),
            "WAN2": window(start + 1200, start + 1500, Condition(down=True)),
        }, telegram={"digest_time": ""})
        s.run(40 * 60)
        texts = s.outbox.texts()
        self.assertFalse(any(t.startswith(("🟡 Example ISP A", "🟠 Example ISP A")) for t in texts), texts)
        self.assertTrue(any(t.startswith("🔴 Example ISP B is DOWN") for t in texts))


class WeeklyReport(Base):
    def test_opt_in_report_waits_until_sunday_time_and_sends_once(self):
        sunday_858 = local(8, 58, day_offset=6)
        s = self.scenario(sunday_858, telegram={"digest_time": "", "weekly_report_time": "09:00"})
        s.mon.maybe_send_weekly_report(s.clock())
        self.assertFalse(any("weekly report" in message.lower() for message in s.outbox.texts()))

        s.run(6 * 60)
        reports = [message for message in s.outbox.texts() if "weekly report" in message.lower()]
        self.assertEqual(len(reports), 1, s.outbox.texts())
        self.assertIn("last 7 days", reports[0])
        self.assertIn("Example ISP A (WAN1)", reports[0])

        # A late catch-up on Monday belongs to the same Sunday slot and must not repeat it.
        s.mon.maybe_send_weekly_report(local(10, day_offset=7))
        self.assertEqual(len([message for message in s.outbox.texts()
                             if "weekly report" in message.lower()]), 1)

    def test_week_command_returns_a_seven_day_report(self):
        s = self.scenario(local(12), telegram={"digest_time": ""})
        s.run(5 * 60)
        text = s.mon.bot_handlers()["week"]()
        self.assertTrue(text.startswith("📊 Last 7 days"))
        self.assertIn("Example ISP A (WAN1)", text)

    def test_missed_sunday_report_catches_up_once_on_monday(self):
        monday = self.scenario(local(10, day_offset=7),
                               telegram={"digest_time": "", "weekly_report_time": "09:00"})
        monday.mon.maybe_send_weekly_report(monday.clock())
        monday.mon.maybe_send_weekly_report(monday.clock() + 60)
        reports = [message for message in monday.outbox.texts() if "weekly report" in message.lower()]
        self.assertEqual(len(reports), 1)


class OneBadTestServer(Base):
    def test_one_dead_target_does_not_fail_a_line(self):
        s = self.scenario(local(10), {"WAN1": lambda t: Condition(dead_targets=("9.9.9.9",))},
                          telegram={"digest_time": ""})
        s.run(15 * 60)
        self.assertEqual(s.state("WAN1"), "HEALTHY")
        self.assertEqual(s.outbox.texts(), [])


class SpeedTestFromTelegram(Base):
    def test_speed_button_replies_to_the_asker_with_results(self):
        import time as _time
        s = self.scenario(local(12), telegram={"digest_time": ""})
        s.run(2 * 60)
        handler = s.mon.bot_handlers()["speed"]
        self.assertTrue(getattr(handler, "wants_chat", False))
        self.assertIn("Testing both connections", handler("42"))
        for _ in range(100):
            if any(chat == "42" for _, _, chat in s.outbox.sent):
                break
            _time.sleep(0.05)
        reply = [t for _, t, chat in s.outbox.sent if chat == "42"]
        self.assertEqual(len(reply), 1)
        self.assertIn("⚡ Example ISP A: ⬇ 190 Mbps", reply[0])
        self.assertEqual(len(sqlite.speedtests(s.cfg.db_path, 0)), 2)


if __name__ == "__main__":
    unittest.main()
