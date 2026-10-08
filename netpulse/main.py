"""NetPulse service: probe every WAN, evaluate health, recommend, record, alert."""

from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import logging
import math
import re
import signal
import sqlite3
import sys
import time

from netpulse import __version__, config as config_mod, summary
from netpulse.config import Config, parse_hhmm
from netpulse.decision.engine import Decision, DecisionEngine
from netpulse.decision.best_wan import recommend_group as recommend_group_wan
from netpulse.decision.throughput import (MAX_SPEED_SAMPLE_AGE_SECONDS,
                                          compare_recent_samples, latest_recent_success)
from netpulse.decision.group_advisor import GroupAdvisor
from netpulse.health import metrics
from netpulse.health.baseline import Baselines
from netpulse.health.evaluator import Evaluation, State, WanTracker
from netpulse.notifications.alerts import Alerter
from netpulse.notifications.base import DEVICE_NOTICE_CATEGORY, Notifier, NullNotifier
from netpulse.notifications.telegram import TelegramBot, parse_command, profile_texts
from netpulse.probes.icmp import probe
from netpulse.probes.connectivity import (
    ConnectivityResult,
    check_interval_seconds as connectivity_check_interval,
    diagnose as diagnose_connectivity,
    result_is_fresh as connectivity_result_is_fresh,
)
from netpulse.probes.presence import (MAX_CLIENTS_PER_SCAN, MAX_CLIENT_ROWS_TO_SCAN,
                                      per_device_scan_interval_seconds,
                                      scan as scan_lan_presence,
                                      scan_rounds as lan_presence_rounds)
from netpulse.devices.presence import PresenceSettings, PresenceTracker
from netpulse.devices.identity import display_name as display_device_name, normalize_mac
from netpulse.freshness import age_seconds
from netpulse.router.er605 import ER605Client, RouterError
from netpulse.router.control import (ControlError, RouterControl, observed_netpulse_route,
                                     summarize_group_routes)
from netpulse.router.pause import PauseControl
from netpulse.router.watch import RouterEvent, RouterWatch
from netpulse.router.syslog import DhcpAllocation, RouterSyslogProtocol
from netpulse.speedtest import SpeedResult, SpeedTester
from netpulse.storage import sqlite
from netpulse.storage import backup as db_backup
from netpulse.storage.sqlite import Storage
from netpulse import system_health
from netpulse.web import app as web

log = logging.getLogger("netpulse")

WORD = {State.DEGRADED: "slow", State.BAD: "bad", State.OFFLINE: "down", State.HEALTHY: "healthy"}
MASS_DEVICE_MISSING_THRESHOLD = 3
DEVICE_PRESENCE_ALERT_COOLDOWN_SECONDS = 30 * 60
SEVERITY = {State.UNKNOWN: 0, State.HEALTHY: 1, State.DEGRADED: 2, State.BAD: 3, State.OFFLINE: 4}


def _single_line_device_name(value, fallback="Unknown device") -> str:
    """Keep router-supplied labels from forging extra fields in Telegram replies."""
    cleaned = re.sub(r"[\x00-\x1f\x7f]+", " ", str(value or "")).strip()
    return cleaned[:80] or fallback


HELP = (
    "NetPulse watches your two internet connections.\n\n"
    "📶 Status: how both connections are doing right now\n"
    "🩺 Pi health: storage, backups, memory, power, and performance readings\n"
    "📈 Last 24h: summary of the last day\n"
    "📊 Last 7d: summary of the last week\n"
    "⚡ Speed test: measure both connections now (about a minute)\n"
    "🔕 Mute 1h: pause non-critical alerts for an hour\n"
    "🔔 Unmute: alerts back on\n"
    "🛠 Using Omada: pause NetPulse's router checks for 30 min, so it doesn't log you out "
    "of the Omada web page (the ER605 allows one login at a time)\n\n"
    "Quiet hours and mute hold non-critical alerts. Device join/leave and LAN-ping alerts are off by "
    "default; set telegram.device_activity_notifications = true to enable them. Use /devices or "
    "/device MAC-or-name when you want device details. Recent DHCP lease changes appear in "
    "on-demand /today and /week reports; other held alerts stay in history. WAN down/back-up "
    "alerts always come through, even when muted or at night.\n\n"
    "Owner only: /devices lists the current device inventory; /device MAC-or-name shows one device. "
    "/reserve lists devices; /reserve MAC-or-name previews a DHCP reservation and "
    "/reserve_confirm TOKEN creates the reviewed reservation. /route lists devices and "
    "/route MAC-or-name WAN1|WAN2|AUTO [1h|6h|24h|7d|forever] previews a route; "
    "/route_confirm TOKEN applies it. /device MAC-or-name shows router listing, reservation, "
    "last-seen, optional LAN ping evidence, group, and saved WAN preference details. /groups lists named device groups; "
    "/group_reserve exact group name previews DHCP reservations for all unreserved members, then "
    "/group_reserve_confirm TOKEN creates the reviewed batch. "
    "/group_suggest exact group name previews the stable monitor-only WAN suggestion; "
    "/group_smart exact group name on|off opts a group into or out of stable automatic WAN steering; "
    "/group_route exact group name WAN1|WAN2|AUTO [1h|6h|24h|7d|forever] previews one group change, "
    "and /group_confirm TOKEN applies it to every eligible member. Omitted route duration defaults "
    "to 1 hour; use forever to keep a WAN pin until changed. Internet access controls are "
    "review-first: /pause <MAC or exact device name> [15m|1h|6h|until-resumed], /resume <MAC or "
    "exact device name>, /group_pause <exact group name> [duration], /group_resume <exact group "
    "name>, /paused, then /pause_confirm TOKEN. "
    "/invite lets someone join (2 minutes, you approve them), "
    "/close stops it early, /people shows who has access."
)


class Monitor:
    def __init__(self, cfg: Config, storage: Storage, alerter: Alerter, board: web.StatusBoard,
                 router: RouterWatch | None = None, clock=time.time, speed_runner=None):
        self.clock = clock  # injectable so scenario tests can run days of simulated time in seconds
        self.cfg = cfg
        self.storage = storage
        self.alerter = alerter
        self.board = board
        self.router = router
        self.router_control = (RouterControl(router, cfg.db_path, cfg.router.controls_enabled,
                                             cfg.router.kill_switch) if router else None)
        self.pause_control = (PauseControl(
            self.router_control, cfg.db_path,
            enabled=cfg.router.internet_controls_enabled,
            protected_macs=cfg.router.protected_macs,
        ) if self.router_control else None)
        self.baselines = Baselines(storage.load_baselines())
        self.trackers = {w.name: WanTracker(w.name, cfg.window_seconds, cfg.thresholds) for w in cfg.wans}
        self.labels = {w.name: w for w in cfg.wans}
        initial = cfg.preferred_wan or cfg.wans[0].name
        self.engine = DecisionEngine(cfg.decision, initial) if cfg.mode == "dry-run" else None
        self.group_advisor = GroupAdvisor(
            cfg.decision.hold_seconds, max(30.0, cfg.interval_seconds * 3))
        self.group_recommendations: dict[int, dict] = {}
        self.pending_smart_group_routes: dict[int, str] = {}
        self.pending_events: list[tuple] = []
        self.last_decision: Decision | None = None
        self.episodes: dict[str, dict] = {}   # wan -> {"start": ts, "worst": State} while not healthy
        self.local_problems: set[str] = set()  # WANs the Pi currently can't test (its own fault)
        self.last_device_scan: float | None = None
        self._recent_syslog_allocations: dict[tuple[str, str], float] = {}
        self.syslog_device_events = 0
        self.syslog_known_renewals_suppressed = 0
        self.device_presence = PresenceTracker(
            cfg.router.presence_confirm_misses,
            probe_interval_seconds=cfg.router.presence_probe_interval_seconds,
        )
        self._last_route_drift_scan: float | None = None
        self._route_drift_notified: dict[str, tuple[str, str]] = {}
        # Secondary checks are display-only; they never affect WAN health or decisions.
        self.connectivity_results: dict[str, ConnectivityResult] = {}
        self.connectivity_started: dict[str, float] = {}
        self._connectivity_notified: set[str] = set()
        self._application_reachability: dict[str, dict] = {}
        self._disk_low: bool | None = None
        self._memory_low: bool | None = None
        self._system_health_stale: bool | None = None
        self._undervoltage: bool | None = None
        self._power_boot_id: str | None = None
        self._undervoltage_occurred: bool | None = None
        self._pi_limit_flags: dict[str, bool] = {}
        self._pi_limit_history_mask: int | None = None
        st = cfg.speedtest
        extra = {"runner": speed_runner} if speed_runner else {}
        self.tester = SpeedTester([(w.name, w.source_ip) for w in cfg.wans], self.save_speed,
                                  st.download_mb, st.upload_mb, st.streams,
                                  expected_asns={w.name: w.expected_asns for w in cfg.wans}, **extra)

    async def cycle(self) -> dict[str, Evaluation]:
        p = self.cfg.probe
        jobs = [(w, t) for w in self.cfg.wans for t in p.targets]
        results = await asyncio.gather(
            *(probe(t, w.source_ip, p.count, p.packet_interval, p.timeout_seconds) for w, t in jobs)
        )
        now = self.clock()
        by_wan: dict[str, dict] = {w.name: {} for w in self.cfg.wans}
        for (w, t), r in zip(jobs, results):
            by_wan[w.name][t] = r
            self.baselines.update(w.name, r)

        evals, changes = {}, []
        for name, res in by_wan.items():
            tracker = self.trackers[name]
            before, before_since = tracker.state, tracker.state_since
            tracker.add(metrics.Cycle(now, res))
            e = tracker.evaluate(now, self.baselines)
            evals[name] = e
            if e.state != before:
                changes.append((e, before, now - before_since))
        for e, before, lasted in changes:
            self._on_state_change(now, e, before, lasted, evals)

        if self.engine:
            d = self.engine.decide(now, evals)
            self.last_decision = d
            if d.switch:
                self._on_decision(now, d, evals)

        self.group_recommendations = self._update_group_recommendations(now, evals)

        self.board.publish(self._snapshot(now, evals))
        return evals

    def _update_group_recommendations(self, now: float,
                                      evals: dict[str, Evaluation]) -> dict[int, dict]:
        """Track sustained read-only WAN candidates for groups with one saved route preference."""
        groups = sqlite.device_groups(self.cfg.db_path)
        saved_routes = sqlite.device_routes(self.cfg.db_path)
        speed_rows = sqlite.speedtests(
            self.cfg.db_path, int(now - MAX_SPEED_SAMPLE_AGE_SECONDS), int(now) + 1)
        recent_speeds = latest_recent_success(speed_rows, now)
        speed_comparison = compare_recent_samples(recent_speeds)
        samples = [{"name": name, "state": evaluation.state.value,
                    "rtt_ms": evaluation.metrics.rtt_ms,
                    "loss_pct": evaluation.metrics.loss_pct,
                    "jitter_ms": evaluation.metrics.jitter_ms}
                   for name, evaluation in evals.items()]
        advice = {}
        for group in groups:
            members = group.get("members", [])
            current_routes = {saved_routes.get(mac, {}).get("route", "AUTO") for mac in members}
            current = (next(iter(current_routes)) if members and len(current_routes) == 1
                       else "MIXED")
            recommendation = recommend_group_wan(
                samples, now, now, current if current in ("WAN1", "WAN2") else "AUTO",
                speed_comparison)
            result = self.group_advisor.update(group["id"], current, recommendation, now)
            if result:
                advice[group["id"]] = result
                last_action = group.get("smart_last_action_at")
                cooling = (last_action is not None
                           and now - last_action < 15 * 60)
                enabled_at = group.get("smart_enabled_at")
                enabled_hold_complete = (enabled_at is not None
                                         and now - enabled_at >= result["required_seconds"])
                if (group.get("smart_routing_enabled") and result["ready"]
                        and enabled_hold_complete and not cooling
                        and current != result["candidate"]):
                    self.pending_smart_group_routes[group["id"]] = result["candidate"]
        self.group_advisor.retain({group["id"] for group in groups})
        self.pending_smart_group_routes = {
            group_id: route for group_id, route in self.pending_smart_group_routes.items()
            if group_id in {g["id"] for g in groups}
        }
        return advice

    def next_smart_group_route(self) -> tuple[int, str] | None:
        """Pop one stable, opted-in candidate for the background router worker."""
        if self._smart_router_checks_paused() or not self._smart_control_ready():
            return None
        for group_id, route in list(self.pending_smart_group_routes.items()):
            del self.pending_smart_group_routes[group_id]
            advice = self.group_recommendations.get(group_id)
            if advice and advice.get("ready") and advice.get("candidate") == route:
                return group_id, route
        return None

    def _smart_router_checks_paused(self) -> bool:
        snapshot = getattr(self.router, "snapshot", None)
        return bool(callable(snapshot) and
                    (snapshot().get("paused_until") or 0) > self.clock())

    def _smart_control_ready(self) -> bool:
        if not self.router_control:
            return False
        state = getattr(self.router_control, "state", None)
        return not callable(state) or bool(state().get("enabled"))

    def apply_smart_group_route(self, group_id: int, route: str) -> None:
        """Apply one stable group candidate without blocking WAN probing."""
        if self._smart_router_checks_paused() or not self._smart_control_ready():
            return
        control = self.router_control
        advice = self.group_recommendations.get(group_id)
        if (not control or not advice or not advice.get("ready")
                or advice.get("candidate") != route):
            return
        try:
            result = control.apply_smart_group_route(group_id, route, self.clock())
        except Exception as exc:  # noqa: BLE001 - automatic controls fail closed
            groups = sqlite.device_groups(self.cfg.db_path)
            group = next((g for g in groups if g["id"] == group_id), None)
            if group and group["smart_routing_enabled"]:
                sqlite.set_group_smart_routing(self.cfg.db_path, group_id, False)
                sqlite.record_group_smart_action(self.cfg.db_path, group_id, int(self.clock()))
                sqlite.log_device_group_action(
                    self.cfg.db_path, int(self.clock()), group_id, group["name"],
                    "smart automation", route, "paused", len(group["members"]),
                    "Automatic steering paused after a fresh eligibility or router verification error.")
                self.alerter.alert(
                    f"⚠️ Smart routing for {group['name']} was paused after a router check or "
                    "verification error. Review the group and router status before enabling it again.",
                    key=f"smart-route-{group_id}", now=self.clock())
            log.warning("smart group route paused after %s", type(exc).__name__)
            return
        if result.get("applied"):
            self.alerter.alert(
                f"🧭 Smart routing moved {result['group']} to {self.display(route)} after a stable "
                "health and latency recommendation. The ER605 read back every group member's route.",
                key=f"smart-route-{group_id}", now=self.clock())

    # --- events & alerts ---

    def _on_state_change(self, now: float, e: Evaluation, before: State, lasted: float,
                         evals: dict[str, Evaluation]) -> None:
        if e.state != State.OFFLINE:
            self._connectivity_notified.discard(e.wan)
            previous_check = self.connectivity_results.get(e.wan)
            if previous_check and previous_check.icmp_state == State.OFFLINE.value:
                self.connectivity_results.pop(e.wan, None)
                self.connectivity_started.pop(e.wan, None)
        detail = "; ".join(e.reasons) if e.reasons else _numbers(e)
        msg = f"{self.display(e.wan)}: {before.value} -> {e.state.value} ({detail})"
        log.info("state %s", msg)
        self.pending_events.append((int(now), "state", e.wan, msg))
        name = self.label(e.wan)
        if e.state == State.UNKNOWN and e.local_problem:
            self.local_problems.add(e.wan)
            err = "; ".join(e.errors) or "unknown error"
            self.alerter.alert(
                f"⚠️ NetPulse can't test {name} right now\n{err}\n"
                f"This is a problem on the Pi (its network settings), not necessarily with {name}. "
                f"Try: sudo ./scripts/setup-probe-ips.sh, or restart the Pi.", key=f"local-{e.wan}", now=now)
            return
        if before == State.UNKNOWN and e.wan in self.local_problems:
            self.local_problems.discard(e.wan)
            self.alerter.alert(f"✅ NetPulse can test {name} again", key=f"local-{e.wan}", critical=True, now=now)
            return
        if before == State.UNKNOWN or e.state == State.UNKNOWN:
            return  # startup, not news
        # Track a whole problem episode (first leaving HEALTHY -> back to HEALTHY) and its worst state,
        # so the all-clear says "was bad for 20 min", not just the length of the last step.
        ep = self.episodes.get(e.wan)
        if e.state == State.HEALTHY:
            episode = self.episodes.pop(e.wan, None)
        else:
            episode = None
            if ep is None:
                self.episodes[e.wan] = {"start": now, "worst": e.state}
            elif SEVERITY[e.state] > SEVERITY[ep["worst"]]:
                ep["worst"] = e.state
        coming_back = before == State.OFFLINE
        if coming_back:
            # The outage began a few cycles before it was confirmed; count those too.
            lasted += self.cfg.thresholds.offline_cycles * self.cfg.interval_seconds
        improving = SEVERITY[e.state] < SEVERITY[before]
        if improving and e.state != State.HEALTHY and not coming_back:
            return  # e.g. bad -> slow while recovering: not news; the "healthy again" alert follows
        critical = e.state == State.OFFLINE or coming_back
        if episode and e.state == State.HEALTHY and not coming_back:
            if episode["worst"] == State.OFFLINE:
                # Follow-up promised by the "back online ... still settling" message: always deliver it.
                others = self._others_line(e.wan, evals)
                text = f"🟢 {self.label(e.wan)} is fully healthy again" + (f"\n{others}" if others else "")
                self.alerter.alert(text, key=e.wan, critical=True, now=now)
                return
            before, lasted = episode["worst"], now - episode["start"]
        self.alerter.alert(self._alert_text(e, before, lasted, evals, now),
                           key=e.wan, critical=critical, now=now)

    def on_connectivity_result(self, wan: str, result: ConnectivityResult, now: float) -> None:
        """Report confirmed ICMP outages or sustained DNS/HTTPS issues without steering WANs."""
        if not connectivity_result_is_fresh(result.checked_at, now):
            return
        if result.icmp_state == State.OFFLINE.value:
            if wan in self._connectivity_notified:
                return
            self._connectivity_notified.add(wan)
            message = f"{self.label(wan)} outage check: {result.diagnosis}."
            self.pending_events.append((int(result.checked_at), "connectivity", wan, message))
            self.alerter.alert(f"🔎 {message}", key=f"connectivity-{wan}", now=now)
            return

        failures = tuple(name for name, failed in (
            ("public DNS", not result.dns_ok),
            ("HTTPS", not result.https_ok),
            ("WAN-assigned DNS", result.wan_dns_ok is False),
        ) if failed)
        status = self._application_reachability.setdefault(
            wan, {"failures": (), "failure_count": 0, "success_count": 0,
                  "warning_recorded": False, "alerted": False})
        if failures:
            if status["failures"] == failures:
                status["failure_count"] += 1
            else:
                status.update(failures=failures, failure_count=1, success_count=0,
                              warning_recorded=False)
            status["success_count"] = 0
            if status["failure_count"] >= 3 and not status["alerted"]:
                message = (f"{self.label(wan)} DNS/HTTPS warning: {result.diagnosis}. "
                           f"ICMP is {result.icmp_state.lower()}; this does not change the WAN "
                           "health score or routing.")
                if not status["warning_recorded"]:
                    self.pending_events.append((int(result.checked_at), "connectivity", wan, message))
                    status["warning_recorded"] = True
                status["alerted"] = self.alerter.alert(
                    f"⚠️ {message}", key=f"reachability-{wan}", now=now)
            return

        if status["alerted"]:
            status["success_count"] += 1
            if status["success_count"] >= 2:
                message = (f"{self.label(wan)} DNS/HTTPS checks recovered; ICMP is "
                           f"{result.icmp_state.lower()}. Health scoring and routing were not changed.")
                self.pending_events.append((int(result.checked_at), "connectivity", wan, message))
                self.alerter.alert(f"✅ {message}", key=f"reachability-recovered-{wan}", now=now)
                status.update(failures=(), failure_count=0, success_count=0,
                              warning_recorded=False, alerted=False)
        else:
            status.update(failures=(), failure_count=0, success_count=0,
                          warning_recorded=False)

    def on_route_expiry_failure(self, now: float, failure: dict) -> None:
        """Tell the owner when a temporary WAN pin may outlive its chosen duration."""
        mac = str(failure.get("mac", ""))
        ip = _single_line_device_name(failure.get("ip"), "")
        route = failure.get("route") if failure.get("route") in ("WAN1", "WAN2") else "WAN"
        label = _single_line_device_name(sqlite.device_labels(self.cfg.db_path).get(mac), mac)
        address = f" ({ip})" if ip else ""
        text = (f"⚠️ Timed WAN preference for {label}{address} expired, but NetPulse could not verify "
                f"return to Auto. The previous {route} pin may still affect this device; NetPulse will retry. "
                "See route history in the dashboard.")
        self.alerter.alert(text, key=f"route-expiry-{mac}", now=now)

    def _alert_text(self, e: Evaluation, before: State, lasted: float, evals: dict[str, Evaluation],
                    now: float | None = None) -> str:
        name = self.label(e.wan)
        emoji = summary.STATE_EMOJI[e.state.value]
        if before == State.OFFLINE:
            # The 5-minute window still contains the outage, so loss numbers would look alarming.
            lines = [f"✅ {name} is back online (was down for {_duration(lasted)})"]
            if e.state != State.HEALTHY:
                lines.append("Still settling; you'll get a message when it's fully healthy.")
        else:
            if e.state == State.HEALTHY:
                head = f"{emoji} {name} is healthy again (was {WORD[before]} for {_duration(lasted)})"
            elif e.state == State.OFFLINE:
                head = f"{emoji} {name} is DOWN"
            else:
                head = f"{emoji} {name} is {WORD[e.state]}"
            lines = [head]
            if e.state not in (State.OFFLINE, State.HEALTHY):
                lines.append(f"{_numbers(e)}, jitter {e.metrics.jitter_ms or 0:.0f} ms")
            if e.reasons and e.state != State.HEALTHY:
                lines.append(f"why: {'; '.join(summary.plain_reason(r) for r in e.reasons)}")
        others = self._others_line(e.wan, evals)
        if others:
            lines.append(others)
        if e.state == State.OFFLINE:
            link_context = self._router_link_context(e.wan, time.time() if now is None else now)
            if link_context:
                lines.append(link_context)
        return "\n".join(lines)

    def _others_line(self, wan: str, evals: dict[str, Evaluation]) -> str:
        """'Example ISP A is healthy': how the other connection(s) are doing, for context in alerts."""
        return ", ".join(f"{self.label(n)} is {WORD.get(o.state, o.state.value.lower())}"
                         for n, o in evals.items() if n != wan and o.state != State.UNKNOWN)

    def _router_link_context(self, wan: str, now: float) -> str | None:
        """Include only a fresh ER605 WAN status, separate from NetPulse's Internet probes."""
        if not self.router:
            return None
        snap = self.router.snap
        checked_at = getattr(snap, "checked_at", None)
        if not getattr(snap, "ok", False) or checked_at is None:
            return None
        max_age = max(300, getattr(self.router, "poll_seconds", 600) * 2)
        age = age_seconds(checked_at, now)
        if age is None or age > max_age:
            return None
        links = getattr(snap, "links", {})
        link = links.get(wan) if isinstance(links, dict) else None
        up = link.get("up") if isinstance(link, dict) else getattr(link, "up", None)
        if up is not True and up is not False:
            return None
        state = "Online" if up else "Offline"
        detail = (f"ER605 last reported {self.label(wan)} WAN status {state} "
                  f"{_duration(age)} ago. "
                  "This router status is separate from physical carrier and NetPulse Internet probes.")
        interface_up = (link.get("interface_up") if isinstance(link, dict)
                        else getattr(link, "interface_up", None))
        if interface_up is True or interface_up is False:
            flag = "up" if interface_up else "down"
            detail += (f" ER605 interface flag: {flag}; this raw flag does not confirm "
                       "physical carrier or Internet reachability.")
        return detail

    def _on_decision(self, now: float, d: Decision, evals: dict[str, Evaluation]) -> None:
        numbers = " | ".join(f"{self.display(n)} {_numbers(e)} score {e.score:.0f}" for n, e in evals.items())
        msg = (f"WOULD SWITCH {self.display(d.current)} -> {self.display(d.target)}: {d.reason}. "
               "Not executed (dry-run).")
        log.info("decision %s [%s]", msg, numbers)
        self.pending_events.append((int(now), "decision", d.target, msg))
        why = summary.plain_decision(d.reason, {n: self.label(n) for n in self.labels})
        text = (f"🔀 Critical devices would move to {self.label(d.target)}\n{why}\n"
                "(Recommendation only: nothing on the router was changed.)")
        self.alerter.alert(text, key="decision", critical=d.emergency, now=now)

    def on_router_syslog_allocation(self, allocation: DhcpAllocation, now: float) -> None:
        """Report a new lease-allocation hint; the next authenticated scan remains authoritative."""
        # Keep this identity-free: it lets operators distinguish an idle listener from a
        # functioning receiver even when the lease is already known and no alert is warranted.
        log.info("accepted ER605 DHCP allocation syslog hint")
        known = sqlite.known_device(self.cfg.db_path, allocation.mac)
        if known and known["listed"] and known["ip"] == allocation.ip:
            self.syslog_known_renewals_suppressed += 1
            return  # normal same-address renewals are not device-arrival notifications
        labels = sqlite.device_labels(self.cfg.db_path)
        label = labels.get(allocation.mac) or display_device_name(
            known["name"] if known else "", allocation.mac)
        description = f"{label} ({allocation.ip})"
        if known and known["ip"] and known["ip"] != allocation.ip:
            detail = f"ER605 logged a DHCP address change for {description}."
        elif known:
            detail = f"ER605 logged a DHCP allocation for returning {description}."
        else:
            detail = f"ER605 logged a DHCP allocation for {description}."
        message = (f"{detail} The lease-list scan will confirm it; this does not prove the device is online.")
        self.pending_events.append((int(now), "device", None, message))
        self.syslog_device_events += 1
        if self.cfg.telegram.device_activity_notifications:
            self.alerter.alert(f"🆕 {message}", key=f"device-dhcp-syslog-{allocation.mac}", now=now,
                               delivery_category=DEVICE_NOTICE_CATEGORY)
        self._recent_syslog_allocations[(allocation.mac, allocation.ip)] = now + 900
        if len(self._recent_syslog_allocations) > 256:
            oldest = min(self._recent_syslog_allocations, key=self._recent_syslog_allocations.get)
            self._recent_syslog_allocations.pop(oldest, None)

    def _syslog_already_announced(self, device: dict, now: float) -> bool:
        key = (device.get("mac", ""), device.get("ip", ""))
        expiry = self._recent_syslog_allocations.pop(key, 0.0)
        return expiry > now

    def on_router_events(self, now: float, events: list[RouterEvent]) -> None:
        for ev in events:
            log.info("router %s", ev.message)
            self.pending_events.append((int(now), ev.kind, ev.wan, ev.message))
            if ev.alert:
                self.alerter.alert(ev.alert, key=f"router-{ev.wan}", critical=ev.critical, now=now)
        if self.router:
            review_notice = (self.router_control.claim_firmware_review_notice()
                             if self.router_control else None)
            if review_notice:
                version = review_notice.get("version")
                version_text = f"{version}" if version else "unavailable"
                message = (f"ER605 firmware {version_text} needs review; NetPulse manual route controls "
                           "are locked until the owner reviews the version in the dashboard.")
                alert = (f"⚠️ {message}" if version else
                         "⚠️ NetPulse cannot read the ER605 firmware version. Manual route controls are locked "
                         "until the firmware version can be confirmed and reviewed.")
                self.pending_events.append((int(now), "router", None, message))
                self.alerter.alert(alert, key="router-firmware-review", critical=True, now=now)
            self.board.set_extra("router_raw", self.router.snap.raw)
            self._check_route_drift(now)
            checked = self.router.snap.checked_at
            clients = self.router.snap.raw.get("clients") if isinstance(self.router.snap.raw, dict) else None
            if checked is not None and checked != self.last_device_scan and isinstance(clients, list):
                self.last_device_scan = checked
                changes = sqlite.observe_device_listing(self.cfg.db_path, clients, int(checked))
                names = sqlite.device_labels(self.cfg.db_path)

                def device_label(device):
                    return names.get(device["mac"]) or display_device_name(
                        device["name"], device["mac"])

                for device in changes["new"]:
                    if self._syslog_already_announced(device, checked):
                        continue
                    label = device_label(device)
                    description = f"{label} ({device['ip']})" if device["ip"] else label
                    message = f"New DHCP lease listed by the ER605: {description}"
                    self.pending_events.append((int(checked), "device", None, message))
                    if self.cfg.telegram.device_activity_notifications:
                        self.alerter.alert(f"🆕 {message}", key=f"device-{device['mac']}", now=now,
                                           delivery_category=DEVICE_NOTICE_CATEGORY)
                missing = changes["missing"]
                if len(missing) >= MASS_DEVICE_MISSING_THRESHOLD:
                    reachability = ("The router's uptime check is responding."
                                    if self.router.snap.ok else
                                    "The router's uptime check is unavailable.")
                    message = (f"{len(missing)} DHCP leases are no longer listed by the ER605 after "
                               f"repeated valid scans. This does not confirm the devices are offline. {reachability}")
                    self.pending_events.append((int(checked), "device", None, message))
                    if self.cfg.telegram.device_activity_notifications:
                        self.alerter.alert(f"📴 {message}", key="devices-mass-missing", now=now,
                                           delivery_category=DEVICE_NOTICE_CATEGORY)
                else:
                    for device in missing:
                        label = device_label(device)
                        description = f"{label} ({device['ip']})" if device["ip"] else label
                        message = f"DHCP lease no longer listed by the ER605: {description}"
                        self.pending_events.append((int(checked), "device", None, message))
                        if self.cfg.telegram.device_activity_notifications:
                            self.alerter.alert(f"📴 {message}", key=f"device-missing-{device['mac']}", now=now,
                                               delivery_category=DEVICE_NOTICE_CATEGORY)
                for device in changes["returned"]:
                    if self._syslog_already_announced(device, checked):
                        continue
                    label = device_label(device)
                    description = f"{label} ({device['ip']})" if device["ip"] else label
                    message = f"DHCP lease listed again by the ER605: {description}"
                    self.pending_events.append((int(checked), "device", None, message))
                    if self.cfg.telegram.device_activity_notifications:
                        self.alerter.alert(f"🟢 {message}", key=f"device-returned-{device['mac']}", now=now,
                                           delivery_category=DEVICE_NOTICE_CATEGORY)

    def on_presence_scan(self, results: dict[str, dict], now: float, scan_rounds: int = 1) -> None:
        """Publish local ping evidence and alert only after a known responder stops replying."""
        transitions = self.device_presence.observe(results, scan_rounds=scan_rounds)
        self.board.set_extra("device_presence", self.device_presence.snapshot())
        if not transitions:
            return
        raw = self.router.snap.raw if self.router and isinstance(self.router.snap.raw, dict) else {}
        clients = raw.get("clients", []) if isinstance(raw, dict) else []
        names = sqlite.device_labels(self.cfg.db_path)
        labels = {}
        if isinstance(clients, list):
            for device in clients:
                if isinstance(device, dict):
                    mac = normalize_mac(device.get("macaddr", device.get("mac", "")))
                    labels[mac] = names.get(mac) or display_device_name(device.get("name"), mac)
        for mac, transition, ip in transitions:
            label = _single_line_device_name(names.get(mac) or labels.get(mac), mac)
            description = f"{label} ({ip})" if ip else label
            if transition == "no_reply":
                interval = per_device_scan_interval_seconds(
                    self.cfg.router.presence_probe_interval_seconds,
                    len(clients) if isinstance(clients, list) else 0)
                if interval is None:
                    interval = (self.cfg.router.presence_probe_interval_seconds
                                * max(1, min(int(scan_rounds), 4)))
                lower = max(0, self.cfg.router.presence_confirm_misses - 1) * interval
                upper = self.cfg.router.presence_confirm_misses * interval
                lower_minutes = math.ceil(lower / 60)
                upper_minutes = math.ceil(upper / 60)
                window = (f"about {lower_minutes}–{upper_minutes} minutes"
                          if lower_minutes != upper_minutes else f"about {upper_minutes} minutes")
                message = (f"Device stopped replying to LAN ping: {description}. Confirmed after "
                           f"{self.cfg.router.presence_confirm_misses} missed checks ({window} at this "
                           "inventory size). It may be asleep or filtering ping; this does not confirm "
                           "it is offline.")
                key = f"device-ping-no-reply-{mac}"
                emoji = "📡"
            else:
                message = f"Device is replying to LAN ping again: {description}."
                key = f"device-ping-restored-{mac}"
                emoji = "🟢"
            self.pending_events.append((int(now), "device_presence", None, message))
            if self.cfg.telegram.device_activity_notifications:
                self.alerter.alert(f"{emoji} {message}", key=key, now=now,
                                   rate_limit_seconds=DEVICE_PRESENCE_ALERT_COOLDOWN_SECONDS,
                                   persist_rate_limit=True,
                                   delivery_category=DEVICE_NOTICE_CATEGORY)

    def _check_route_drift(self, now: float) -> None:
        """Alert on fresh, read-only evidence that an NP_ route differs from its saved preference."""
        raw = self.router.snap.raw if self.router and isinstance(self.router.snap.raw, dict) else {}
        checked_at = raw.get("policy_routes_checked_at")
        routes = raw.get("policy_routes")
        if checked_at is None or checked_at == self._last_route_drift_scan or not isinstance(routes, list):
            return
        self._last_route_drift_scan = checked_at

        saved_routes = sqlite.device_routes(self.cfg.db_path)
        known = set(saved_routes) | set(self._route_drift_notified)
        clients = raw.get("clients")
        reservations = raw.get("reservations")
        for rows in (clients, reservations):
            if isinstance(rows, list):
                for row in rows:
                    if not isinstance(row, dict):
                        continue
                    mac = normalize_mac(row.get("macaddr", row.get("mac", "")))
                    if mac:
                        known.add(mac)
        for row in routes:
            if isinstance(row, dict):
                match = re.fullmatch(r"NP_R_([0-9A-F]{12})", str(row.get("name", "")).upper())
                if match:
                    compact = match.group(1)
                    known.add("-".join(compact[i:i + 2] for i in range(0, 12, 2)))

        for mac in known:
            if self.router_control and self.router_control.is_local_device(mac):
                continue
            observed = observed_netpulse_route(raw, mac)["route"]
            if observed is None:
                continue
            saved = saved_routes.get(mac, {}).get("route", "AUTO")
            previous = self._route_drift_notified.get(mac)
            if observed != saved:
                current = (saved, observed)
                if previous == current:
                    continue
                label = _single_line_device_name(sqlite.device_labels(self.cfg.db_path).get(mac), mac)
                text = (f"⚠️ ER605 route rule changed for {label} ({mac}). Saved preference: {saved}; "
                        f"last observed router rule: {observed}. NetPulse did not change the router. "
                        "Review Device details before applying any route action.")
                if self.alerter.alert(text, key=f"route-drift-{mac}", now=now):
                    self.pending_events.append((int(checked_at), "router_route", None,
                                                f"Route rule drift for {label} ({mac}): saved {saved}, observed {observed}"))
                    self._route_drift_notified[mac] = current
            elif previous:
                text = f"✅ ER605 route rule for {mac} matches its saved NetPulse preference again."
                if self.alerter.alert(text, key=f"route-drift-{mac}", now=now):
                    self.pending_events.append((int(checked_at), "router_route", None,
                                                f"Route rule for {mac} matches its saved preference again"))
                    self._route_drift_notified.pop(mac, None)

    def on_system_health(self, now: float, health: dict) -> None:
        boot_id = health.pop("boot_id", None)
        if boot_id and boot_id != self._power_boot_id:
            self._power_boot_id = boot_id
            try:
                saved = self.storage.get_value("pi_power_undervoltage") or ""
                saved_boot, _, was_reported = saved.partition(":")
                if saved_boot != boot_id:
                    was_reported = "0"
                    self.storage.set_value("pi_power_undervoltage", f"{boot_id}:0")
                self._undervoltage_occurred = was_reported == "1"
            except sqlite3.Error:
                self._undervoltage_occurred = None
                log.warning("could not restore Pi undervoltage alert state from the database")

        if boot_id and boot_id != getattr(self, "_pi_limits_boot_id", None):
            self._pi_limits_boot_id = boot_id
            try:
                saved = self.storage.get_value("pi_limit_flags") or ""
                saved_boot, _, saved_mask = saved.partition(":")
                self._pi_limit_history_mask = int(saved_mask, 16) if saved_boot == boot_id and saved_mask else 0
                if saved_boot != boot_id:
                    self.storage.set_value("pi_limit_flags", f"{boot_id}:0")
            except (sqlite3.Error, ValueError):
                self._pi_limit_history_mask = None
                log.warning("could not restore Pi performance-limit alert state from the database")

        memory_pct = health.get("memory_available_pct")
        memory_low = self._memory_low
        if (isinstance(memory_pct, (int, float)) and not isinstance(memory_pct, bool)
                and 0 <= memory_pct <= 100):
            threshold = self.cfg.system_health.low_memory_pct
            recovery = self.cfg.system_health.memory_recovery_pct
            memory_low = (memory_pct < recovery if self._memory_low is True
                          else memory_pct < threshold)
        health = {**health, "checked_at": now,
                  "max_age_seconds": self.cfg.system_health.interval_seconds * 2,
                  "disk_low":
                  health.get("disk_free_pct") is not None and health["disk_free_pct"] < self.cfg.system_health.low_disk_pct,
                  "memory_low": memory_low}
        self.board.set_extra("system_health", health)
        recovery = health.get("acl_recovery")
        recovery_status = recovery.get("status") if isinstance(recovery, dict) else None
        self.on_acl_recovery_status(now, recovery_status)
        disk_low = health["disk_low"]
        if health.get("disk_free_pct") is not None and disk_low != self._disk_low:
            if disk_low:
                pct = health["disk_free_pct"]
                self._system_alert(now, f"⚠️ NetPulse Pi disk is nearly full ({pct:.1f}% free)",
                                   f"Pi disk low ({pct:.1f}% free)", "pi-disk")
            elif self._disk_low:
                self._system_alert(now, "✅ NetPulse Pi disk space is back to normal",
                                   "Pi disk space recovered", "pi-disk-clear")
            self._disk_low = disk_low
        if memory_low is not None and memory_low != self._memory_low:
            if memory_low:
                self._system_alert(
                    now,
                    f"⚠️ NetPulse Pi available memory is low ({memory_pct:.1f}% available)",
                    f"Pi available memory low ({memory_pct:.1f}%)", "pi-memory",
                )
            elif self._memory_low:
                self._system_alert(now, "✅ NetPulse Pi available memory has recovered",
                                   "Pi available memory recovered", "pi-memory-clear")
            self._memory_low = memory_low
        undervoltage = health.get("undervoltage")
        if undervoltage is not None and undervoltage != self._undervoltage:
            if undervoltage:
                self._system_alert(now, "⚠️ Raspberry Pi power is undervoltage; check its power supply",
                                   "Pi undervoltage detected", "pi-power")
            elif self._undervoltage:
                self._system_alert(now, "✅ Raspberry Pi power is back in range",
                                   "Pi undervoltage cleared", "pi-power-clear")
            self._undervoltage = undervoltage
        occurred = health.get("undervoltage_occurred")
        if occurred is not None and occurred != self._undervoltage_occurred:
            if occurred and not undervoltage:
                self._system_alert(
                    now,
                    "⚠️ Raspberry Pi power has reported an undervoltage event since its last reboot; check the power supply and cable",
                    "Pi undervoltage occurred since boot", "pi-power-history")
            self._undervoltage_occurred = occurred
            if boot_id:
                try:
                    self.storage.set_value("pi_power_undervoltage", f"{boot_id}:{int(occurred)}")
                except sqlite3.Error:
                    log.warning("could not save Pi undervoltage alert state to the database")

        limits = (
            ("arm_frequency_capped", "ARM frequency is capped", 0x20000),
            ("throttled", "the CPU is being throttled", 0x40000),
            ("soft_temp_limit", "the soft temperature limit is active", 0x80000),
        )
        current = {name: health.get(name) for name, _, _ in limits}
        started = [label for name, label, _ in limits
                   if current[name] is True and self._pi_limit_flags.get(name) is not True]
        cleared = [label for name, label, _ in limits
                   if current[name] is False and self._pi_limit_flags.get(name) is True]
        if started:
            self._system_alert(now, "⚠️ Raspberry Pi performance limit active: " + ", ".join(started),
                               "Pi performance limit active: " + ", ".join(started), "pi-throttle")
        elif cleared:
            self._system_alert(now, "✅ Raspberry Pi performance limit cleared: " + ", ".join(cleared),
                               "Pi performance limit cleared: " + ", ".join(cleared), "pi-throttle-clear")
        self._pi_limit_flags = {name: state for name, state in current.items() if state is not None}

        history_mask = 0
        for name, _, bit in limits:
            if health.get(name + "_occurred") is True:
                history_mask |= bit
        if self._pi_limit_history_mask is not None and history_mask != self._pi_limit_history_mask:
            new_labels = [label for name, label, bit in limits
                          if history_mask & bit and not self._pi_limit_history_mask & bit
                          and current.get(name) is not True]
            if new_labels:
                self._system_alert(
                    now,
                    "⚠️ Raspberry Pi reports performance limiting since the last reboot: " + ", ".join(new_labels),
                    "Pi performance limiting occurred since boot: " + ", ".join(new_labels),
                    "pi-throttle-history",
                )
            self._pi_limit_history_mask = history_mask
            if boot_id:
                try:
                    self.storage.set_value("pi_limit_flags", f"{boot_id}:{history_mask:x}")
                except sqlite3.Error:
                    log.warning("could not save Pi performance-limit alert state to the database")

    def on_acl_recovery_status(self, now: float, recovery_status: str | None) -> None:
        """Persist and alert only on terminal ACL recovery state transitions."""
        if recovery_status not in ("failed", "ok"):
            return
        try:
            previous = self.storage.get_value("pi_acl_recovery_failed")
            if recovery_status == "failed" and previous != "1":
                self.storage.set_value("pi_acl_recovery_failed", "1")
                self._system_alert(
                    now,
                    "⚠️ NetPulse could not clean up an interrupted temporary router test; inspect the ACL recovery status before resuming router controls",
                    "Temporary router-test ACL cleanup failed", "pi-acl-recovery-failed",
                )
            elif recovery_status == "ok" and previous == "1":
                self.storage.set_value("pi_acl_recovery_failed", "0")
                self._system_alert(
                    now,
                    "✅ NetPulse temporary router-test ACL recovery completed",
                    "Temporary router-test ACL recovery completed", "pi-acl-recovery-clear",
                )
        except sqlite3.Error:
            log.warning("could not persist temporary ACL recovery alert state")

    def on_system_health_stale(self, now: float, stale: bool) -> None:
        """Alert once when Pi health sampling stops, and once when it resumes."""
        if stale == self._system_health_stale:
            return
        if stale:
            self._system_alert(now, "⚠️ Raspberry Pi health sampling is stale; check the NetPulse service",
                               "Pi health sampling became stale", "pi-health-stale")
        elif self._system_health_stale:
            self._system_alert(now, "✅ Raspberry Pi health sampling has resumed",
                               "Pi health sampling resumed", "pi-health-resumed")
        self._system_health_stale = stale

    def _system_alert(self, now: float, text: str, event: str, key: str) -> None:
        self.pending_events.append((int(now), "system", None, event))
        self.alerter.alert(text, key=key, now=now)

    def on_backup_failure(self, now: float, error: Exception) -> None:
        reason = type(error).__name__
        self.pending_events.append((int(now), "system", None, f"Database backup failed ({reason})"))
        self.alerter.alert(f"⚠️ NetPulse database backup failed ({reason})", key="db-backup", now=now)

    # --- speed tests ---

    def usual_speeds(self, now: float | None = None) -> dict[str, float | None]:
        since = int((now or time.time()) - 14 * 86400)
        return {n: sqlite.usual_download(self.cfg.db_path, n, since) for n in self.labels}

    def save_speed(self, r: SpeedResult) -> None:
        """Called from the speed-test thread: uses its own DB connection."""
        d = r.to_dict()
        if r.error:
            msg = f"{self.display(r.wan)}: speed test failed ({r.error})"
        else:
            msg = (f"{self.display(r.wan)}: speed test {r.down_mbps:.0f} down / {r.up_mbps:.0f} up Mbps"
                   + (f", +{r.bufferbloat_ms:.0f} ms when busy" if r.bufferbloat_ms is not None else ""))
        sqlite.insert_speedtest(self.cfg.db_path, d, (int(r.ts), "speedtest", r.wan, msg))

    def speedtest_data_usage(self, now: float | None = None) -> dict:
        """Return this local calendar month's measured test payload and a conservative next-run estimate."""
        now = time.time() if now is None else now
        lt = time.localtime(now)
        month_start = time.mktime((lt.tm_year, lt.tm_mon, 1, 0, 0, 0, 0, 0, -1))
        rows = sqlite.speedtests(self.cfg.db_path, int(month_start), int(now) + 1)
        used_bytes = sum(int(row.get("bytes_down") or 0) + int(row.get("bytes_up") or 0) for row in rows)
        st = self.cfg.speedtest
        next_mb = (st.download_mb + st.upload_mb) * len(self.labels)
        return {
            "used_mb": used_bytes / 1_000_000,
            "budget_mb": st.monthly_budget_mb,
            "next_run_mb": next_mb * 1.05,  # reserve 5% for transfer overhead
            "budget_enabled": st.monthly_budget_mb > 0,
        }

    def _speedtest_budget_reason(self, now: float | None = None) -> str | None:
        usage = self.speedtest_data_usage(now)
        if not usage["budget_enabled"]:
            return None
        projected = usage["used_mb"] + usage["next_run_mb"]
        if projected > usage["budget_mb"]:
            remaining = max(0, usage["budget_mb"] - usage["used_mb"])
            return (f"Monthly speed-test allowance: {usage['used_mb']:.0f} MB used of "
                    f"{usage['budget_mb']:.0f} MB; the next two-WAN run needs about "
                    f"{usage['next_run_mb']:.0f} MB, with {remaining:.0f} MB remaining.")
        return None

    def start_speedtest(self, trigger: str, on_done=None, now: float | None = None) -> str | None:
        reason = self._speedtest_budget_reason(now)
        return reason or self.tester.try_start(trigger, on_done=on_done)

    def speed_report(self, results: list[SpeedResult], title: str = "⚡ Speed test results") -> str:
        labels = {n: self.label(n) for n in self.labels}
        return summary.speed_text([r.to_dict() for r in results], labels, self.usual_speeds(),
                                  self.cfg.speedtest.dip_pct, title)

    def _scheduled_done(self, results: list[SpeedResult]) -> None:
        usual = self.usual_speeds()
        for r in results:
            if summary.is_dip(r.to_dict(), usual.get(r.wan), self.cfg.speedtest.dip_pct):
                self.alerter.alert(
                    f"📉 {self.label(r.wan)} is much slower than usual: ⬇ {r.down_mbps:.0f} Mbps "
                    f"(usually about {usual[r.wan]:.0f})", key=f"speed-{r.wan}")

    def maybe_run_scheduled_speedtest(self, now: float) -> None:
        st = self.cfg.speedtest
        if not st.schedule_enabled:
            return
        lt = time.localtime(now)
        minute = lt.tm_hour * 60 + lt.tm_min
        due = [t for t in st.times if parse_hhmm(t) <= minute < parse_hhmm(t) + 10]
        if not due:
            return
        slot = f"{time.strftime('%Y-%m-%d', lt)} {due[0]}"
        if self.storage.get_value("speedtest_last_slot") == slot:
            return
        self.storage.set_value("speedtest_last_slot", slot)
        why = self.start_speedtest("scheduled", on_done=self._scheduled_done, now=now)
        if why:
            log.info("scheduled speed test skipped: %s", why)

    # --- digest & bot commands ---

    def _period_digest(self, now: float, seconds: int, title: str) -> str:
        s = sqlite.period_summary(self.cfg.db_path, int(now - seconds), int(now))
        if not s["wans"]:
            return f"{title}\n\nNo data yet: check back after NetPulse has run for a while."
        speeds = sqlite.speedtests(self.cfg.db_path, int(now - seconds), int(now) + 1)
        lease_events, more_lease_events = sqlite.recent_device_lease_events(
            self.cfg.db_path, int(now - seconds), int(now), limit=4)
        period = "last 24 hours" if seconds <= 86400 else "last 7 days"
        return summary.digest_text(s, {n: self.label(n) for n in self.labels}, title, speeds,
                                   lease_events, more_lease_events, period)

    def digest(self, now: float, title: str) -> str:
        return self._period_digest(now, 86400, title)

    def weekly_digest(self, now: float, title: str) -> str:
        return self._period_digest(now, 7 * 86400, title)

    def maybe_send_digest(self, now: float) -> None:
        t = self.cfg.telegram.digest_time
        if not t:
            return
        lt = time.localtime(now)
        today = time.strftime("%Y-%m-%d", lt)
        if lt.tm_hour * 60 + lt.tm_min < parse_hhmm(t):
            return
        if self.storage.get_value("last_digest_date") == today:
            return
        # Mark first: a crash while building/sending must not cause a digest storm.
        self.storage.set_value("last_digest_date", today)
        log.info("daily digest queued for %s", today)
        self.alerter.notifier.send(self.digest(now, f"☀️ NetPulse daily summary ({time.strftime('%d %b', lt)})"))

    def maybe_send_weekly_report(self, now: float) -> None:
        report_time = self.cfg.telegram.weekly_report_time
        if not report_time:
            return
        lt = time.localtime(now)
        sunday = dt.date.fromtimestamp(now) - dt.timedelta(days=(lt.tm_wday + 1) % 7)
        hour, minute = divmod(parse_hhmm(report_time), 60)
        due = time.mktime((sunday.year, sunday.month, sunday.day, hour, minute, 0, 0, 0, -1))
        # On Sunday, wait for this week's selected time. On later days, catch up a missed report.
        if lt.tm_wday == 6 and now < due:
            return
        slot = sunday.isoformat()
        if self.storage.get_value("last_weekly_report_sunday") == slot:
            return
        self.storage.set_value("last_weekly_report_sunday", slot)
        title = f"📊 NetPulse weekly report (last 7 days · ending {time.strftime('%d %b', lt)})"
        log.info("weekly report queued for Sunday %s", slot)
        self.alerter.notifier.send(self.weekly_digest(now, title))

    def bot_handlers(self) -> dict:
        def status():
            snap = self.board.get()
            return summary.status_text(snap) if snap.get("updated") else "Starting up, try again in a minute."

        def pi_health():
            if not self.cfg.system_health.enabled:
                return "Pi health checks are disabled in NetPulse configuration."
            health = self.board.get_extra("system_health")
            if not isinstance(health, dict):
                return "No Pi health sample is available yet."
            checked_at = health.get("checked_at")
            health_age = age_seconds(checked_at, self.clock())
            if health_age is not None:
                age = int(health_age)
                age_text = f"{age // 60} min ago" if age >= 60 else "under 1 min ago"
                stale = age > max(60, self.cfg.system_health.interval_seconds * 2)
                sample_line = f"Sample {age_text}" + (" · STALE; readings may be out of date" if stale else " · current")
            else:
                sample_line = "Sample time unavailable; readings may be out of date"

            def measured(value, precision=1, suffix=""):
                return f"{value:.{precision}f}{suffix}" if isinstance(value, (int, float)) else "unknown"

            lines = ["🩺 NetPulse Pi health", sample_line]
            disk_pct = health.get("disk_free_pct")
            if disk_pct is None and health.get("disk_check_status") == "unavailable":
                lines.append("Storage: disk space check unavailable")
            else:
                lines.append(f"Storage: {measured(disk_pct)}% free")
            backup = health.get("backup")
            if not isinstance(backup, dict) or not backup.get("enabled"):
                lines.append("Database backups: disabled")
            else:
                backup_status = backup.get("status")
                if backup_status == "ok":
                    age = backup.get("age_seconds")
                    age_text = (_duration(age) if isinstance(age, (int, float))
                                and not isinstance(age, bool) and math.isfinite(age) and age >= 0
                                else "age unknown")
                    count = backup.get("count")
                    kept_text = f"{count} kept" if isinstance(count, int) and not isinstance(count, bool) else "retention unknown"
                    lines.append(f"Database backups: current; last {age_text} ago; {kept_text}")
                elif backup_status == "stale":
                    lines.append("Database backups: STALE; create a fresh backup")
                elif backup_status == "missing":
                    lines.append("Database backups: no snapshot found")
                elif backup_status == "unavailable":
                    lines.append("Database backups: destination unavailable")
                else:
                    lines.append("Database backups: status unknown")
            temperature = health.get("temperature_c")
            lines.append("Temperature: " + (f"{measured(temperature)} °C" if temperature is not None else "unavailable"))
            lines.append("Load: " + (f"{measured(health.get('load_per_core'))} per core"))
            memory = health.get("memory_available_pct")
            memory_mb = health.get("memory_available_mb")
            memory_status = "LOW · " if health.get("memory_low") is True else ""
            lines.append("Memory available: " + memory_status +
                         (f"{measured(memory)}% ({measured(memory_mb)} MB)" if memory is not None else "unknown"))

            if health.get("undervoltage") is True:
                power = "undervoltage reported now"
            elif health.get("undervoltage") is False:
                power = "normal now"
            else:
                power_status = health.get("power_check_status")
                power = {
                    "tool_missing": "unavailable; vcgencmd not found in service PATH",
                    "command_failed": "unavailable; vcgencmd could not read power status",
                    "unexpected_response": "unavailable; vcgencmd returned unrecognized output",
                }.get(power_status, "unavailable")
            if health.get("undervoltage_occurred") is True:
                power += "; undervoltage occurred since boot"
            elif health.get("undervoltage_occurred") is False and health.get("undervoltage") is False:
                power += "; no undervoltage reported since boot"
            lines.append("Power: " + power)

            limit_labels = {
                "arm_frequency_capped": "ARM frequency cap",
                "throttled": "CPU throttling",
                "soft_temp_limit": "soft temperature limit",
            }
            active = [label for key, label in limit_labels.items() if health.get(key) is True]
            occurred = [label for key, label in limit_labels.items()
                        if health.get(key + "_occurred") is True]
            if active:
                performance = "active: " + ", ".join(active)
            elif occurred:
                performance = "occurred since boot: " + ", ".join(occurred)
            elif all(health.get(key) is False for key in limit_labels):
                performance = "no active limits reported"
            else:
                performance = "unavailable"
            lines.append("Performance limits: " + performance)
            recovery = health.get("acl_recovery")
            recovery_status = recovery.get("status") if isinstance(recovery, dict) else None
            recovery_line = {
                "ok": "Recovery status: last check passed",
                "failed": "Recovery status: FAILED; review the temporary ACL recovery unit",
                "pending": "Recovery status: cleanup is running",
                "unavailable": "Recovery status: unavailable",
            }.get(recovery_status, "Recovery status: unavailable")
            lines.append("Temporary router-test recovery: " + recovery_line)
            return "\n".join(lines)

        def mute():
            self.alerter.mute(3600)
            until = time.strftime("%H:%M", time.localtime(self.alerter.muted_until()))
            return (f"🔕 Non-critical alerts muted until {until}; this includes device and router notices. "
                    "WAN down/back-up alerts still come through.")

        def unmute():
            self.alerter.unmute()
            return "🔔 Alerts are back on."

        def omada():
            if not self.router:
                return "Router checks aren't set up yet (sudo python3 tools/router_setup.py)."
            self.router.pause(1800)
            return ("🛠 Router checks paused for 30 min, so you can use the Omada web page without "
                    "being logged out. Internet monitoring and alerts continue as normal.")

        def speed(chat=None):
            bot = self.alerter.notifier
            why = self.start_speedtest(
                "manual", on_done=lambda res: bot.send(self.speed_report(res), chat=chat))
            if why:
                return f"⏳ {why}"
            return "⚡ Testing both connections, one after the other. Results in about a minute…"
        speed.wants_chat = True

        def resolve_device_mac(identity, include_saved_pauses=False):
            value = str(identity or "").strip()
            if re.fullmatch(r"[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}", value):
                return normalize_mac(value)
            raw = self.router.snap.raw if self.router else {}
            rows = []
            if isinstance(raw, dict):
                for key in ("clients", "reservations"):
                    values = raw.get(key)
                    if isinstance(values, list):
                        rows.extend(x for x in values if isinstance(x, dict))
            wanted = value.casefold()
            labels = sqlite.device_labels(self.cfg.db_path)
            history = sqlite.device_history(self.cfg.db_path)
            matches = set()
            for row in rows:
                mac = normalize_mac(row.get("macaddr", row.get("mac", "")))
                if not mac:
                    continue
                names = [labels.get(mac, ""), str(row.get("name") or ""),
                         str(row.get("note") or ""), str(row.get("hostname") or "")]
                if any(name and name.strip().casefold() == wanted for name in names):
                    matches.add(mac)
            # Friendly labels remain useful when a previously seen device is not in the latest
            # router scan. A subsequent control preview still revalidates eligibility itself.
            matches.update(mac for mac, label in labels.items()
                           if label.strip().casefold() == wanted and mac in history)
            if include_saved_pauses:
                try:
                    records = self.pause_control.records()
                except Exception as exc:  # noqa: BLE001 - stored identities must fail closed
                    raise ValueError("Saved pause identities are unavailable; use the device MAC address.") from None
                if not isinstance(records, (list, tuple)):
                    raise ValueError("Saved pause identities are invalid; use the device MAC address.")
                for record in records:
                    if not isinstance(record, dict):
                        raise ValueError("Saved pause identities are invalid; use the device MAC address.")
                    mac = record.get("mac")
                    label = record.get("label")
                    status = record.get("status")
                    if (not isinstance(mac, str) or normalize_mac(mac) != mac
                            or status not in ("paused", "applying", "resuming", "error")
                            or not isinstance(label, str) or not label.strip() or len(label) > 128
                            or any(ord(ch) < 32 or ord(ch) == 127 for ch in label)):
                        raise ValueError("Saved pause identities are invalid; use the device MAC address.")
                    if label.strip().casefold() == wanted:
                        matches.add(mac)
            if len(matches) == 1:
                return next(iter(matches))
            if len(matches) > 1:
                raise ValueError("That device name matches more than one MAC; use the MAC address.")
            raise ValueError("No router device matches that name. Use /route or /reserve to see names and MACs.")

        def device(text="", chat=None):
            if not self.router:
                return "ER605 device inventory is not configured."
            raw_text = (text or "").strip()
            command, separator, argument = raw_text.partition(" ")
            if command.split("@", 1)[0].lower() == "/device":
                identity = argument.strip() if separator else ""
            elif parse_command(raw_text) == "device":
                identity = ""  # button opens the inventory list
            else:
                identity = raw_text
            if not identity:
                raw = self.router.snap.raw if isinstance(self.router.snap.raw, dict) else {}
                clients = raw.get("clients") if isinstance(raw.get("clients"), list) else []
                reservations = raw.get("reservations") if isinstance(raw.get("reservations"), list) else []
                by_mac = {}
                for row in clients:
                    if not isinstance(row, dict):
                        continue
                    candidate = normalize_mac(row.get("macaddr", row.get("mac", "")))
                    if candidate:
                        by_mac[candidate] = {"client": row, "reservation": None}
                for row in reservations:
                    if not isinstance(row, dict) or str(row.get("enable", "1")).lower() in ("0", "false", "off"):
                        continue
                    candidate = normalize_mac(row.get("mac", row.get("macaddr", "")))
                    if candidate:
                        by_mac.setdefault(candidate, {"client": None, "reservation": None})["reservation"] = row
                if not by_mac:
                    return "No device inventory is available from the latest ER605 scan. Try again after the next router check."
                labels = sqlite.device_labels(self.cfg.db_path)
                checked_at = self.router.snap.checked_at
                lines = ["Devices visible in the latest ER605 inventory (owner only):"]
                age_seconds_checked = age_seconds(checked_at, self.clock())
                if age_seconds_checked is not None:
                    age_minutes = int(age_seconds_checked // 60)
                    lines.append(f"Last successful scan: {age_minutes} min ago.")
                elif checked_at is not None:
                    lines.append("Last successful scan time is invalid or in the future; treat the inventory as stale.")
                scan_minutes = max(1, math.ceil(self.router.poll_seconds / 60))
                confirm_scans = sqlite.DEVICE_OFFLINE_AFTER_SCANS
                delay_min = max(0, confirm_scans - 1) * scan_minutes
                delay_max = confirm_scans * scan_minutes
                delay = (f"{delay_min}–{delay_max} minutes" if delay_min != delay_max
                         else f"{delay_max} minutes")
                for candidate, records in sorted(by_mac.items(),
                                                  key=lambda item: (labels.get(item[0]) or "").casefold()):
                    client, reservation = records["client"], records["reservation"]
                    saved_name = labels.get(candidate) or (reservation or {}).get("note")
                    raw_name = saved_name if saved_name else display_device_name(
                        (client or {}).get("name"), candidate)
                    name = _single_line_device_name(raw_name)
                    address = str((client or {}).get("ipaddr", (client or {}).get("ip", "")) or
                                  (reservation or {}).get("ip", (reservation or {}).get("ipaddr", "")) or
                                  "IP unavailable")
                    status_text = "listed" if client else "reservation only"
                    lease = _single_line_device_name((client or {}).get("leasetime"), "")
                    lease_text = f" · lease {lease}" if lease else ""
                    line = f"• {name}: {address} · {candidate} · {status_text}{lease_text}"
                    if sum(map(len, lines)) + len(line) > 3300:
                        lines.append("…list shortened; use the dashboard for the full inventory.")
                        break
                    lines.append(line)
                lines.extend(["", (f"Lease removal can lag until the displayed lease expires, then about {delay} "
                                   f"for {confirm_scans} missed scans. Permanent leases may stay listed. "
                                   "Optional LAN-ping hints can arrive sooner but show reply changes, "
                                   "not proof a device left."),
                              "For details: /device <MAC or exact name>",
                              "Internet access: /paused, /pause <MAC or exact name> [15m|1h|6h|until-resumed], "
                              "or /group_pause <exact group name> [duration]. Review before /pause_confirm TOKEN."])
                return "\n".join(lines)
            try:
                mac = resolve_device_mac(identity)
            except ValueError as e:
                return str(e)

            raw = self.router.snap.raw if isinstance(self.router.snap.raw, dict) else {}
            clients = raw.get("clients")
            reservations = raw.get("reservations")
            client_rows = clients if isinstance(clients, list) else []
            reservation_rows = reservations if isinstance(reservations, list) else []
            client = next((r for r in client_rows if isinstance(r, dict)
                           and normalize_mac(r.get("macaddr", r.get("mac", ""))) == mac), None)
            any_reservation = next((r for r in reservation_rows if isinstance(r, dict)
                                    and normalize_mac(r.get("mac", r.get("macaddr", ""))) == mac), None)
            reservation = (any_reservation if any_reservation and
                           str(any_reservation.get("enable", "1")).lower() not in ("0", "false", "off")
                           else None)
            label = sqlite.device_labels(self.cfg.db_path).get(mac)
            history = sqlite.device_history(self.cfg.db_path).get(mac, {})
            groups_by_mac = {member: group["name"] for group in sqlite.device_groups(self.cfg.db_path)
                             for member in group["members"]}
            route = sqlite.device_routes(self.cfg.db_path).get(mac)
            observed = observed_netpulse_route(raw, mac)

            saved_name = label or (reservation or {}).get("note")
            raw_name = saved_name if saved_name else display_device_name(
                (client or {}).get("name"), mac)
            display_name = _single_line_device_name(raw_name)
            ip = str((client or {}).get("ipaddr", (client or {}).get("ip", "")) or
                     (reservation or {}).get("ip", (reservation or {}).get("ipaddr", "")) or
                     history.get("ip") or "IP unavailable")
            snap = self.router.snap
            checked_at = snap.checked_at
            max_age = max(120, getattr(self.router, "poll_seconds", 600) * 2)
            now = self.clock()
            inventory_age = age_seconds(checked_at, now)
            age = int(inventory_age) if inventory_age is not None else None
            if checked_at is None:
                listing = "ER605 listing: no successful full inventory scan yet."
            elif age is None:
                listing = "ER605 listing: stale; scan timestamp is invalid or in the future."
            elif age is not None and age > max_age:
                checked = time.strftime("%Y-%m-%d %H:%M", time.localtime(checked_at))
                listing = f"ER605 listing: stale; last successful inventory scan {checked}."
            elif client is not None:
                listing = "ER605 listing: present in the latest successful client scan."
            elif isinstance(clients, list):
                listing = "ER605 listing: not present in the latest successful client scan."
            else:
                listing = "ER605 listing: latest client scan is unavailable."

            if reservation:
                reserve_line = f"DHCP reservation: enabled at {ip}."
            elif any_reservation:
                reserve_line = "DHCP reservation: present but disabled."
            elif client:
                reserve_line = "DHCP reservation: none enabled; address may change."
            else:
                reserve_line = "DHCP reservation: none visible in the latest scan."
            lease_line = None
            if client is not None:
                lease_value = _single_line_device_name(client.get("leasetime"), "")
                if lease_value:
                    if lease_value.casefold() == "permanent":
                        lease_line = "ER605 DHCP lease: permanent."
                    else:
                        lease_line = f"ER605 DHCP lease time remaining (router-reported): {lease_value}."
            def seen(ts):
                if ts is None:
                    return "not recorded"
                return (time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))
                        if age_seconds(ts, now) is not None else "time unknown")

            if route and route.get("route") in ("WAN1", "WAN2"):
                until = route.get("expires_at")
                expiry = (time.strftime("%Y-%m-%d %H:%M", time.localtime(until))
                          if until else "until changed")
                preference = f"Prefer {route['route']} until {expiry}"
            else:
                preference = "Auto (no saved NetPulse WAN pin)"
            actual_route = observed["route"]
            if actual_route is None:
                router_rule = "ER605 NetPulse rule: unavailable or ambiguous in the last policy-rule read."
            else:
                observed_label = "Auto" if actual_route == "AUTO" else f"Prefer {actual_route}"
                checked = observed["checked_at"]
                checked_age_seconds = age_seconds(checked, now)
                if checked_age_seconds is not None:
                    checked_age = int(checked_age_seconds)
                    checked_text = f"; checked {checked_age // 60} min ago"
                    if checked_age > max_age:
                        checked_text += "; stale read"
                elif checked is not None:
                    checked_text = "; timestamp invalid or in the future; stale read"
                else:
                    checked_text = "; read time unavailable"
                drift = "; differs from saved preference" if actual_route != (route or {}).get("route", "AUTO") else "; matches saved preference"
                router_rule = f"ER605 NetPulse rule last read: {observed_label}{drift}{checked_text}."
            presence_settings = self.board.get_extra("device_presence_settings")
            if not presence_settings or not presence_settings.enabled:
                presence_line = "Pi LAN ping: checks disabled."
            elif isinstance(client_rows, list) and len(client_rows) > MAX_CLIENT_ROWS_TO_SCAN:
                presence_line = (f"Pi LAN ping: skipped; the {len(client_rows)}-lease inventory exceeds "
                                 f"the safe {MAX_CLIENT_ROWS_TO_SCAN}-device scan limit.")
            else:
                presence = self.device_presence.snapshot().get(mac)
                if not presence or presence.get("checked_at") is None:
                    presence_line = "Pi LAN ping: unknown; no completed probe is available yet."
                else:
                    probe_age_seconds = age_seconds(presence["checked_at"], now)
                    cycle = per_device_scan_interval_seconds(
                        self.cfg.router.presence_probe_interval_seconds, len(client_rows))
                    cycle = cycle or self.cfg.router.presence_probe_interval_seconds
                    max_presence_age = max(180, cycle * 3)
                    if probe_age_seconds is None:
                        presence_line = "Pi LAN ping: timestamp invalid or in the future; treating result as stale."
                    elif probe_age_seconds > max_presence_age:
                        presence_line = f"Pi LAN ping: last result is stale ({int(probe_age_seconds) // 60} min ago)."
                    elif presence.get("state") == "replying":
                        reply_at = presence.get("last_reply_at")
                        reply_age_value = age_seconds(reply_at, now) if reply_at is not None else None
                        reply_age = int(reply_age_value) if reply_age_value is not None else None
                        if presence.get("misses", 0):
                            last_reply = (f"last reply {reply_age // 60} min ago"
                                          if reply_age is not None else "last reply time unknown")
                            presence_line = (f"Pi LAN ping: no reply to {presence['misses']} recent check(s); "
                                             f"{last_reply}.")
                        else:
                            presence_line = (f"Pi LAN ping: replied {reply_age // 60} min ago."
                                             if reply_age is not None else
                                             "Pi LAN ping: reply time unknown.")
                    elif presence.get("state") == "no_reply":
                        recovery = int(presence.get("recovery_replies", 0) or 0)
                        if recovery:
                            presence_line = (f"Pi LAN ping: no reply for {presence.get('misses', 0)} checks; "
                                             f"reply seen {recovery}/2 confirmation checks. This does not "
                                             "prove the device is offline.")
                        else:
                            presence_line = (f"Pi LAN ping: no reply for {presence.get('misses', 0)} checks; "
                                             "device may sleep or block ping, so this does not prove it is offline.")
                    else:
                        presence_line = "Pi LAN ping: unknown; this device has not replied to ping yet."
            group = _single_line_device_name(groups_by_mac.get(mac), "None")
            lines = [f"Device: {display_name}", f"MAC: {mac}", f"IP: {ip}", listing]
            if lease_line:
                lines.append(lease_line)
            lines.extend([reserve_line, presence_line, f"Group: {group}",
                     f"Saved NetPulse WAN preference: {preference}",
                     router_rule, "This rule state is not live per-flow tracking.",
                     f"First listed: {seen(history.get('first_seen'))}",
                     f"Last listed: {seen(history.get('last_seen'))}"])
            if checked_at is not None and age is not None:
                lines.append(f"Inventory checked: {age // 60} min ago")
            return "\n".join(lines)
        device.wants_text = True

        def route(text="", chat=None):
            if not self.router_control:
                return "ER605 controls are not configured."
            words = (text or "").strip().split(maxsplit=1)
            if len(words) == 1:
                raw = self.router.snap.raw if self.router else {}
                reservations = raw.get("reservations", []) if isinstance(raw, dict) else []
                clients = raw.get("clients", []) if isinstance(raw, dict) else []
                friendly = sqlite.device_labels(self.cfg.db_path)
                saved_routes = self.router_control.route_state()
                lines = ["Device WAN preferences (owner only; saved NetPulse settings, not live flow tracking):"]
                for row in reservations if isinstance(reservations, list) else []:
                    if not isinstance(row, dict) or str(row.get("enable", "1")).lower() in ("0", "false", "off"):
                        continue
                    mac = normalize_mac(row.get("mac", row.get("macaddr", "")))
                    ip = str(row.get("ip", row.get("ipaddr", "")) or "")
                    if (re.fullmatch(r"[0-9A-F]{2}(?:-[0-9A-F]{2}){5}", mac)
                            and not self.router_control.is_local_device(mac)):
                        label = friendly.get(mac) or str(row.get("note") or "Device")
                        saved = saved_routes.get(mac, {})
                        preference = saved.get("route", "AUTO")
                        if preference == "AUTO":
                            preference_text = "Auto"
                        elif saved.get("expires_at"):
                            until = time.strftime("%Y-%m-%d %H:%M", time.localtime(saved["expires_at"]))
                            preference_text = f"Prefer {preference} until {until}"
                        else:
                            preference_text = f"Prefer {preference} until changed"
                        lines.append(f"• {label}: {mac} ({ip or 'IP unavailable'}) · {preference_text}")
                if len(lines) == 1:
                    lines.append("No enabled DHCP reservations are visible. Reserve a device in Omada first.")
                lines.extend(["", "Choose: /route <MAC or exact device name> <AUTO|WAN1|WAN2> [1h|6h|24h|7d|forever]",
                    "Duration defaults to 1h; use forever to keep a WAN pin until changed.",
                    "Then confirm the 2-minute preview with /route_confirm <token>."])
                unreserved = [r for r in clients if isinstance(r, dict) and
                    normalize_mac(r.get("macaddr", r.get("mac", ""))) and
                    not self.router_control.is_local_device(normalize_mac(
                        r.get("macaddr", r.get("mac", "")))) and not any(
                        isinstance(x, dict) and normalize_mac(x.get("mac", x.get("macaddr", ""))) ==
                        normalize_mac(r.get("macaddr", r.get("mac", ""))) and
                        str(x.get("enable", "1")).lower() not in ("0", "false", "off")
                        for x in (reservations if isinstance(reservations, list) else []))]
                if unreserved:
                    lines.append("To reserve a currently connected device first: /reserve <MAC> [friendly name].")
                if not self.router_control.state()["enabled"]:
                    lines.append(self.router_control.state().get("reason") or "Controls are currently locked.")
                return "\n".join(lines)
            if len(words) != 2:
                return "Usage: /route <MAC or exact device name> <AUTO|WAN1|WAN2> [1h|6h|24h|7d|forever]"
            pieces = words[1].rsplit(maxsplit=2)
            expiry_aliases = {"forever": 0, "1h": 3600, "6h": 21600, "24h": 86400, "7d": 604800}
            if len(pieces) == 3 and pieces[-1].lower() in expiry_aliases:
                identity, raw_choice, expiry_seconds = pieces[0], pieces[1], expiry_aliases[pieces[2].lower()]
            elif len(pieces) >= 2:
                identity, raw_choice = " ".join(pieces[:-1]), pieces[-1]
                expiry_seconds = 3600
            else:
                return "Usage: /route <MAC or exact device name> <AUTO|WAN1|WAN2> [1h|6h|24h|7d|forever]"
            try:
                target_mac = resolve_device_mac(identity)
            except ValueError as e:
                return str(e)
            choice = raw_choice.upper()
            for wan in self.cfg.wans:
                if wan.label and choice == wan.label.upper():
                    choice = wan.name.upper()
            try:
                p = self.router_control.preview(target_mac, choice, "telegram owner", expiry_seconds)
            except ValueError as e:
                return str(e)
            return (f"Review route change\nDevice: {p['device']} ({p['mac']})\nIP: {p['ip']}\n"
                    f"Now: {p['current']} → {p['route']}\nDuration: {p['expiry_label']}\n{p['effect']}\n\n"
                    f"Confirm within 2 minutes: /route_confirm {p['token']}")
        route.wants_text = True

        def route_confirm(text="", chat=None):
            if not self.router_control:
                return "ER605 controls are not configured."
            words = (text or "").strip().split()
            if len(words) != 2:
                return "Usage: /route_confirm <preview-token>"
            try:
                result = self.router_control.apply(words[1])
            except (ValueError, RouterError) as e:
                return f"Could not apply route: {e}"
            except Exception as e:  # noqa: BLE001
                log.exception("Telegram route change failed")
                return f"Could not apply route ({type(e).__name__}). No success was reported."
            return f"✅ {result['ip']} is now set to {result['route']}. {result['detail']}"
        route_confirm.wants_text = True

        def groups(text="", chat=None):
            entries = sqlite.device_groups(self.cfg.db_path)
            if not entries:
                return "No device groups yet. Create one in the dashboard, then use /groups to see it here."
            labels = sqlite.device_labels(self.cfg.db_path)
            snapshot = self.board.get()
            routes = sqlite.device_routes(self.cfg.db_path)
            now = time.time()
            recent_speeds = latest_recent_success(
                sqlite.speedtests(self.cfg.db_path, int(now - MAX_SPEED_SAMPLE_AGE_SECONDS),
                                  int(now) + 1), now)
            speed_comparison = compare_recent_samples(recent_speeds)
            raw = self.board.get_extra("router_raw")
            reservation_coverage = None
            if (isinstance(raw, dict) and isinstance(raw.get("clients"), list)
                    and isinstance(raw.get("reservations"), list)):
                clients_by_mac = {
                    normalize_mac(row.get("macaddr", row.get("mac", ""))): row
                    for row in raw["clients"] if isinstance(row, dict)
                    and normalize_mac(row.get("macaddr", row.get("mac", "")))}
                reserved_macs = {
                    normalize_mac(row.get("mac", row.get("macaddr", "")))
                    for row in raw["reservations"] if isinstance(row, dict)
                    and normalize_mac(row.get("mac", row.get("macaddr", "")))
                    and str(row.get("enable", "1")).lower() not in ("0", "false", "off")}
                reservation_coverage = {}
                for group in entries:
                    covered = 0
                    for mac in group["members"]:
                        client = clients_by_mac.get(mac, {})
                        permanent = str(client.get("leasetime", "")).lower() == "permanent"
                        bound = str(client.get("bind", "0")).lower() in ("1", "true")
                        covered += int(mac in reserved_macs or permanent or bound)
                    reservation_coverage[group["id"]] = covered
            lines = ["Device groups (owner only):"]
            for group in entries:
                members = [labels.get(mac, mac) for mac in group["members"]]
                lines.append(f"• {group['name']} (ID {group['id']}, {len(members)} devices)"
                             + (f": {', '.join(members)}" if members else ": empty"))
                if reservation_coverage is None:
                    lines.append("  DHCP reservation coverage unavailable; refresh router status.")
                else:
                    lines.append(f"  DHCP reservation coverage: "
                                 f"{reservation_coverage[group['id']]}/{len(members)}. "
                                 "Route preview separately checks every member's eligibility.")
                current_routes = {routes.get(mac, {}).get("route", "AUTO")
                                  for mac in group["members"]}
                current = next(iter(current_routes)) if len(current_routes) == 1 else "MIXED"
                current_label = ("Auto balance" if current == "AUTO" else
                                 f"Prefer {self.display(current)}" if current in ("WAN1", "WAN2") else
                                 "Mixed across members")
                lines.append(f"  Saved NetPulse route preference: {current_label}. "
                             "This preference alone does not prove the observed policy row.")
                router_status = snapshot.get("router")
                max_route_age = (router_status.get("links_max_age_seconds", 1200)
                                 if isinstance(router_status, dict) else 1200)
                route_summary = summarize_group_routes(raw, group["members"], routes,
                                                       now, max_route_age)
                if route_summary["route_readback"] == "matches":
                    readback_text = "all observed ER605 rules match saved preferences"
                elif route_summary["route_readback"] == "drift":
                    readback_text = (f"{route_summary['route_drift_count']} ER605 rules differ "
                                     "from saved preferences")
                elif route_summary["route_readback"] == "stale":
                    readback_text = "ER605 rule read-back is stale"
                else:
                    readback_text = (f"ER605 rule read-back unavailable for "
                                     f"{route_summary['route_unknown_count']} members")
                lines.append(f"  Router rule read-back: {readback_text}.")
                lines.append("  Smart WAN automation: " +
                             ("ON; stable recommendations may change every member route" if
                              group["smart_routing_enabled"] else "off") + ".")
                recommendation = recommend_group_wan(
                    snapshot.get("wans"), snapshot.get("updated"), now,
                    current if current in ("WAN1", "WAN2") else "AUTO",
                    speed_comparison)
                if recommendation:
                    reason = recommendation["reason"]
                    if reason.startswith("comparable recent throughput"):
                        basis = "comparable download/upload speed broke a ping tie"
                    elif reason.startswith("current WAN retained"):
                        basis = "current WAN retained inside the 2 ms ping tie band"
                    elif recommendation["state"] == "DEGRADED":
                        basis = "lowest ping among degraded links"
                    else:
                        basis = "healthy-link probe latency"
                    lines.append(f"  Group WAN suggestion: {self.display(recommendation['wan'])}, "
                                 f"{recommendation['rtt_ms']:.1f} ms, "
                                 f"{recommendation['loss_pct']:.1f}% loss; {basis}. "
                                 "Monitor only; nothing was changed.")
                else:
                    lines.append("  No fresh WAN ping recommendation.")
                monitor_advice = snapshot.get("group_recommendations", {}).get(group["id"])
                if monitor_advice:
                    held = _duration(monitor_advice["held_seconds"])
                    required = _duration(monitor_advice["required_seconds"])
                    progress = (f"stable for {held}" if monitor_advice["ready"]
                                else f"observed {monitor_advice['observations']} times for {held} "
                                     f"of {required}")
                    lines.append(f"  Monitor-only candidate: Prefer "
                                 f"{self.display(monitor_advice['candidate'])}; {progress}. "
                                 "No route was changed.")
            speed_parts = []
            for wan in self.labels:
                sample = recent_speeds.get(wan)
                if sample:
                    upload = (f"{sample['up_mbps']:.1f}" if sample["up_mbps"] is not None
                              else "unknown")
                    loaded = (f", loaded ping {sample['loaded_ms']:.1f} ms"
                              if sample["loaded_ms"] is not None else "")
                    speed_parts.append(f"{self.display(wan)} {sample['down_mbps']:.1f}/"
                                       f"{upload} Mbps down/up{loaded}, "
                                       f"{_duration(sample['age_seconds'])} ago")
            lines.append("Recent speed tests (last 24h; may break a close-ping tie only): " +
                         ("; ".join(speed_parts) if speed_parts else "none available."))
            if speed_comparison:
                download = speed_comparison["download_winner"]
                upload = speed_comparison["upload_winner"]
                d_label = ("tie" if download == "tie" else
                           self.display(download) if download else "unavailable")
                u_label = ("tie" if upload == "tie" else
                           self.display(upload) if upload else "unavailable")
                lines.append(f"Closest-in-time test comparison (within 15 min): fastest download "
                             f"{d_label}; fastest upload {u_label}. A route tie-break requires the "
                             "same WAN to lead both by at least 15%, with no worse live "
                             "health/loss/jitter and ping within 2 ms.")
            else:
                lines.append("No close-in-time pair of successful speed tests for comparison.")
            lines.extend(["", "Review missing DHCP reservations for this group: /group_reserve exact group name",
                          "Then confirm the 2-minute reservation preview with /group_reserve_confirm TOKEN.",
                          "Opt into/out of automatic stable WAN steering: /group_smart exact group name on|off.",
                          "", "Preview: /group_route exact group name WAN1|WAN2|AUTO [1h|6h|24h|7d|forever]",
                          "Duration defaults to 1h; use forever to keep a WAN pin until changed.",
                          "Then confirm the 2-minute all-member preview with /group_confirm TOKEN.",
                          "Internet access: /paused; preview /group_pause exact group name [15m|1h|6h|until-resumed] "
                          "or /group_resume exact group name, then /pause_confirm TOKEN."])
            return "\n".join(lines)

        def format_group_preview(preview, heading="Review group route change"):
            rows = [f"{heading}: {preview['group']}",
                    f"Target: {preview['route']} · duration: {preview['expiry_label']}"]
            for m in preview["members"]:
                current = m["current"]
                current_until = m.get("current_expires_at")
                saved_route = m.get("saved_current", current)
                if current in ("WAN1", "WAN2"):
                    if current == saved_route:
                        expiry = (time.strftime("%Y-%m-%d %H:%M", time.localtime(current_until))
                                  if current_until else "until changed")
                        current = f"{current} until {expiry}"
                    else:
                        current = f"{current} observed"
                saved = f" · NetPulse saved {saved_route}" if saved_route != m["current"] else ""
                rows.append(f"• {m['name']}: {m['ip']} · {m['mac']} · {current}{saved} → {preview['route']}")
            rows.extend([preview["effect"], "",
                         f"Confirm within 2 minutes: /group_confirm {preview['token']}"])
            message = "\n".join(rows)
            if len(message) > 3500:
                return ("This group is too large to review safely in one Telegram message. "
                        "Use the dashboard, which shows the complete member list before confirmation.")
            return message

        def group_smart(text="", chat=None):
            if not self.router_control:
                return "ER605 controls are not configured."
            raw_text = (text or "").strip()
            command, separator, arguments = raw_text.partition(" ")
            rest = arguments.strip() if separator and command.split("@", 1)[0].lower() == "/group_smart" else raw_text
            pieces = rest.rsplit(maxsplit=1)
            if len(pieces) != 2 or pieces[1].lower() not in ("on", "off"):
                return "Usage: /group_smart exact group name on|off"
            name, enabled = pieces[0], pieces[1].lower() == "on"
            group = next((g for g in sqlite.device_groups(self.cfg.db_path)
                          if g["name"].casefold() == name.casefold()), None)
            if not group:
                return "No exact group name match. Use /groups to see the names. Nothing changed."
            try:
                result = self.router_control.set_group_smart_routing(
                    group["id"], enabled, "telegram owner")
            except (ValueError, RouterError) as exc:
                return f"Smart WAN setting not changed: {exc}"
            except Exception as exc:  # noqa: BLE001
                log.exception("Telegram smart group setting failed")
                return f"Smart WAN setting not changed ({type(exc).__name__})."
            if enabled:
                return (f"🧭 Smart WAN enabled for {result['group']} ({result['members']} devices). "
                        "No route changed now. Stable recommendations may automatically move every "
                        "member after the hold and cooldown; use /group_smart exact group name off "
                        "to stop automatic changes.")
            return (f"Smart WAN disabled for {result['group']}. Automatic steering has stopped; "
                    "the current WAN preference remains. Use /group_route exact group name AUTO "
                    "to preview a return to Auto balance.")
        group_smart.wants_text = True

        def group_suggest(text="", chat=None):
            if not self.router_control:
                return "ER605 controls are not configured."
            raw_text = (text or "").strip()
            command, separator, arguments = raw_text.partition(" ")
            name = arguments.strip() if separator and command.split("@", 1)[0].lower() == "/group_suggest" else raw_text
            if not name:
                return "Usage: /group_suggest exact group name"
            group = next((g for g in sqlite.device_groups(self.cfg.db_path)
                          if g["name"].casefold() == name.casefold()), None)
            if not group:
                return "No device group matches that exact name. Use /groups to see available groups."
            now = time.time()
            snapshot = self.board.get()
            advice = snapshot.get("group_recommendations", {}).get(group["id"])
            if not isinstance(advice, dict) or not advice.get("ready"):
                return ("There is no stable monitor-only WAN suggestion for this group yet. "
                        "Use /groups to see its current recommendation. Nothing changed.")
            routes = sqlite.device_routes(self.cfg.db_path)
            current_routes = {routes.get(mac, {}).get("route", "AUTO") for mac in group["members"]}
            current = next(iter(current_routes)) if len(current_routes) == 1 else "MIXED"
            speed_rows = sqlite.speedtests(
                self.cfg.db_path, int(now - MAX_SPEED_SAMPLE_AGE_SECONDS), int(now) + 1)
            speed_comparison = compare_recent_samples(latest_recent_success(speed_rows, now))
            recommendation = recommend_group_wan(
                snapshot.get("wans"), snapshot.get("updated"), now,
                current if current in ("WAN1", "WAN2") else "AUTO", speed_comparison)
            if not recommendation:
                return ("There is no fresh WAN recommendation now. Refresh /groups and review again. "
                        "Nothing changed.")
            if advice.get("current") != current:
                return ("The group's saved WAN preference changed after the recommendation. "
                        "Refresh /groups and review again. Nothing changed.")
            if recommendation["wan"] != advice.get("candidate"):
                return ("The WAN recommendation changed after it was marked stable. "
                        "Refresh /groups and review again. Nothing changed.")
            try:
                preview = self.router_control.preview_group(
                    group["id"], recommendation["wan"], "telegram owner", 3600)
            except (ValueError, RouterError) as e:
                return str(e)
            heading = (f"Stable monitor-only suggestion: {recommendation['wan']} · "
                       f"{recommendation['rtt_ms']:.1f} ms; review only, not applied\n"
                       "Review suggested group route")
            return format_group_preview(preview, heading)
        group_suggest.wants_text = True

        def group_route(text="", chat=None):
            if not self.router_control:
                return "ER605 controls are not configured."
            raw_text = (text or "").strip()
            command, separator, arguments = raw_text.partition(" ")
            rest = arguments.strip() if separator and command.split("@", 1)[0].lower() == "/group_route" else raw_text
            aliases = {"forever": 0, "1h": 3600, "6h": 21600, "24h": 86400, "7d": 604800}
            parts = rest.rsplit(maxsplit=2)
            if len(parts) == 3 and parts[-1].lower() in aliases:
                name, raw_choice, expiry = parts[0], parts[1], aliases[parts[2].lower()]
            elif len(parts) >= 2:
                name, raw_choice, expiry = " ".join(parts[:-1]), parts[-1], 3600
            else:
                return "Usage: /group_route exact group name <AUTO|WAN1|WAN2> [1h|6h|24h|7d|forever]"
            group = next((g for g in sqlite.device_groups(self.cfg.db_path)
                          if g["name"].casefold() == name.casefold()), None)
            if not group:
                return "No device group matches that exact name. Use /groups to see available groups."
            choice = raw_choice.upper()
            for wan in self.cfg.wans:
                if wan.label and choice == wan.label.upper():
                    choice = wan.name.upper()
            try:
                preview = self.router_control.preview_group(group["id"], choice, "telegram owner", expiry)
            except (ValueError, RouterError) as e:
                return str(e)
            return format_group_preview(preview)
        group_route.wants_text = True

        def group_confirm(text="", chat=None):
            if not self.router_control:
                return "ER605 controls are not configured."
            words = (text or "").strip().split()
            if len(words) != 2:
                return "Usage: /group_confirm <preview-token>"
            try:
                result = self.router_control.apply_group(words[1])
            except (ValueError, RouterError) as e:
                return f"Could not apply group route: {e}"
            except Exception as e:  # noqa: BLE001
                log.exception("Telegram group route change failed")
                return f"Could not apply group route ({type(e).__name__}). No success was reported."
            return (f"✅ {result['group']}: {result['route']} applied to {result['count']} devices. "
                    f"{result['detail']}")
        group_confirm.wants_text = True

        def group_reserve(text="", chat=None):
            if not self.router_control:
                return "ER605 controls are not configured."
            raw_text = (text or "").strip()
            if raw_text == "🧾 Reserve group":
                name = ""
            else:
                command, separator, arguments = raw_text.partition(" ")
                name = (arguments.strip() if separator and
                        command.split("@", 1)[0].lower() == "/group_reserve" else raw_text)
            if not name:
                groups = sqlite.device_groups(self.cfg.db_path)
                if not groups:
                    return "No device groups yet. Create one in the dashboard, then retry /group_reserve."
                choices = "\n".join(f"• {g['name']}" for g in groups)
                return ("Choose a group with /group_reserve exact group name. Available groups:\n"
                        + choices)
            group = next((g for g in sqlite.device_groups(self.cfg.db_path)
                          if g["name"].casefold() == name.casefold()), None)
            if not group:
                return "No device group matches that exact name. Use /groups to see available groups."
            try:
                preview = self.router_control.preview_group_reservations(group["id"], "telegram owner")
            except (ValueError, RouterError) as e:
                return str(e)
            group_name = _single_line_device_name(preview.get("group"), "Device group")
            rows = [f"Review group DHCP reservations: {group_name}"]
            for member in preview["members"]:
                device_name = _single_line_device_name(member.get("name"), "Home device")
                rows.append(f"• {device_name}: {member['ip']} · {member['mac']} · {member['status']}")
            rows.extend([preview["effect"], ""])
            if preview["token"]:
                rows.append(f"Confirm within 2 minutes: /group_reserve_confirm {preview['token']}")
            else:
                rows.append("No router change is needed; every member is already reserved.")
            message = "\n".join(rows)
            if len(message) > 3500:
                return ("This group is too large to review safely in one Telegram message. "
                        "Use the dashboard, which shows the complete member list before confirmation.")
            return message
        group_reserve.wants_text = True

        def group_reserve_confirm(text="", chat=None):
            if not self.router_control:
                return "ER605 controls are not configured."
            words = (text or "").strip().split()
            if len(words) != 2:
                return "Usage: /group_reserve_confirm <preview-token>"
            try:
                result = self.router_control.apply_group_reservations(words[1])
            except (ValueError, RouterError) as e:
                return f"Could not add group reservations: {e}"
            except Exception as e:  # noqa: BLE001
                log.exception("Telegram group DHCP reservation failed")
                return f"Could not add group reservations ({type(e).__name__}). No success was reported."
            return (f"✅ {result['group']}: created and verified {result['count']} DHCP reservation(s). "
                    f"{result['detail']}")
        group_reserve_confirm.wants_text = True

        def reserve(text="", chat=None):
            if not self.router_control:
                return "ER605 controls are not configured."
            words = (text or "").strip().split(maxsplit=2)
            if len(words) == 1:
                raw = self.router.snap.raw if self.router else {}
                clients = raw.get("clients", []) if isinstance(raw, dict) else []
                reservations = raw.get("reservations", []) if isinstance(raw, dict) else []
                labels = sqlite.device_labels(self.cfg.db_path)
                lines = ["Currently connected devices eligible for a DHCP reservation:"]
                seen = set()
                for row in clients if isinstance(clients, list) else []:
                    if not isinstance(row, dict):
                        continue
                    mac = normalize_mac(row.get("macaddr", row.get("mac", "")))
                    ip = str(row.get("ipaddr", row.get("ip", "")) or "")
                    if not mac or mac in seen:
                        continue
                    seen.add(mac)
                    if self.router_control.is_local_device(mac):
                        continue
                    if any(isinstance(r, dict) and normalize_mac(r.get("mac", r.get("macaddr", ""))) == mac
                           for r in (reservations if isinstance(reservations, list) else [])):
                        continue
                    name = labels.get(mac) or str(row.get("name") or "Device")
                    lines.append(f"• {name}: {mac} ({ip or 'IP unavailable'})")
                if len(lines) == 1:
                    lines.append("No eligible unreserved online devices were found.")
                lines.extend(["", "Preview a reservation: /reserve <MAC> [friendly name]",
                    "Confirm the exact IP and device within 2 minutes: /reserve_confirm <token>."])
                if not self.router_control.state()["enabled"]:
                    lines.append(self.router_control.state().get("reason") or "Controls are currently locked.")
                return "\n".join(lines)
            if re.fullmatch(r"[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}", words[1]):
                mac = resolve_device_mac(words[1])
                name = words[2] if len(words) > 2 else ""
            else:
                try:
                    mac = resolve_device_mac(" ".join(words[1:]))
                except ValueError as e:
                    return str(e)
                name = ""
            try:
                p = self.router_control.preview_reservation(mac, name, "telegram owner")
            except (ValueError, RouterError) as e:
                return str(e)
            return (f"Review DHCP reservation\nDevice: {p['device']} ({p['mac']})\n"
                    f"Current IP: {p['ip']}\nRouter name: {p['reservation']}\n"
                    f"{p['effect']}\n\nConfirm within 2 minutes: /reserve_confirm {p['token']}")
        reserve.wants_text = True

        def reserve_confirm(text="", chat=None):
            if not self.router_control:
                return "ER605 controls are not configured."
            words = (text or "").strip().split()
            if len(words) != 2:
                return "Usage: /reserve_confirm <preview-token>"
            try:
                result = self.router_control.apply_reservation(words[1])
            except (ValueError, RouterError) as e:
                return f"Could not add reservation: {e}"
            except Exception as e:  # noqa: BLE001
                log.exception("Telegram DHCP reservation failed")
                return f"Could not add reservation ({type(e).__name__}). No success was reported."
            return (f"✅ {result['device']} has a verified DHCP reservation at {result['ip']}. "
                    f"{result['detail']} Then use /route {result['mac']} WAN1 or WAN2 to preview a route.")
        reserve_confirm.wants_text = True

        pause_durations = {"15m": 900, "1h": 3600, "6h": 21600, "until-resumed": 0}

        def pause_status_reason():
            if not self.pause_control:
                return "Internet pause has not been enabled. Awaiting WAN2 and recovery validation."
            state = self.pause_control.state()
            if state.get("enabled"):
                return None
            if not state.get("configured"):
                return "Internet pause has not been enabled. Awaiting WAN2 and recovery validation."
            return "Internet pause is temporarily unavailable; router safety checks need attention."

        def format_pause_preview(preview):
            members = preview.get("members")
            if isinstance(members, list):
                lines = [f"• {_single_line_device_name(m.get('name', m.get('device')), 'Device')} · "
                         f"{m.get('ip') or 'IP unavailable'} · {m.get('mac', '')}" for m in members]
                subject = preview.get("group", preview.get("device", "Selected device"))
            else:
                lines = []
                subject = preview.get("device", "Device")
            action = "resume" if preview.get("action") == "resume" else "pause"
            rows = [f"Review Internet {action}", f"{subject}"]
            if preview.get("ip"):
                rows.append(f"IP: {preview['ip']}")
            if lines:
                rows.extend(lines)
            if action == "pause":
                rows.append(f"Duration: {preview.get('expiry_label', 'Until resumed')}")
            rows.extend([preview.get("effect", "IPv4 Internet.") +
                         " LAN remains only as validated; timed resume requires Pi running "
                         "(no router-native expiry while off).",
                         "Confirm within 2 minutes: /pause_confirm " + str(preview.get("token", ""))])
            message = "\n".join(rows)
            if len(message) > 3500:
                return ("This group is too large to review safely in one Telegram message. "
                        "Use the dashboard to inspect the complete member list before confirming.")
            return message

        def pause(text="", chat=None):
            reason = pause_status_reason()
            if reason:
                return reason
            words = (text or "").strip().split(maxsplit=1)
            if len(words) != 2:
                return "Usage: /pause <MAC or exact device name> [15m|1h|6h|until-resumed]"
            pieces = words[1].rsplit(maxsplit=1)
            duration = pause_durations.get(pieces[-1].lower()) if len(pieces) == 2 else None
            identity = " ".join(pieces[:-1]) if duration is not None else words[1]
            try:
                mac = resolve_device_mac(identity)
                preview = self.pause_control.preview(
                    mac, action="pause", actor=f"telegram owner:{chat}",
                    duration_seconds=3600 if duration is None else duration)
            except (ValueError, ControlError, RouterError) as exc:
                return str(exc)
            return format_pause_preview(preview)
        pause.wants_text = True

        def resume(text="", chat=None):
            if not self.pause_control:
                return "No saved Internet pause controller is available to review."
            words = (text or "").strip().split(maxsplit=1)
            if len(words) != 2:
                return "Usage: /resume <MAC or exact device name>"
            try:
                mac = resolve_device_mac(words[1], include_saved_pauses=True)
                preview = self.pause_control.preview(
                    mac, action="resume", actor=f"telegram owner:{chat}", duration_seconds=0)
            except (ValueError, ControlError, RouterError) as exc:
                return str(exc)
            return format_pause_preview(preview)
        resume.wants_text = True

        def paused():
            if not self.pause_control:
                return "Internet pause has not been enabled. Awaiting WAN2 and recovery validation."
            records = self.pause_control.records()
            if not records:
                return "No devices currently have a saved Internet pause."
            lines = ["Saved Internet pause intents:"]
            for record in records:
                name = _single_line_device_name(record.get("label", record.get("mac")), "Device")
                expires = record.get("expires_at")
                try:
                    expiry = ("until resumed" if expires is None else
                              time.strftime("until %Y-%m-%d %H:%M", time.localtime(expires)))
                except (OverflowError, OSError, TypeError, ValueError):
                    expiry = "expiry time unavailable"
                state = "Paused" if record.get("status") == "paused" else (
                    f"Needs review · {record.get('status', 'unknown')}")
                lines.append(f"• {name} · {state} · {expiry}")
            lines.append("Review or resume a device: /resume <MAC or exact name>. Group controls are in /groups.")
            return "\n".join(lines)

        def group_pause(text="", chat=None):
            reason = pause_status_reason()
            if reason:
                return reason
            words = (text or "").strip().split(maxsplit=1)
            if len(words) != 2:
                return "Usage: /group_pause <exact group name> [15m|1h|6h|until-resumed]"
            pieces = words[1].rsplit(maxsplit=1)
            duration = pause_durations.get(pieces[-1].lower()) if len(pieces) == 2 else None
            name = " ".join(pieces[:-1]) if duration is not None else words[1]
            group = next((g for g in sqlite.device_groups(self.cfg.db_path) if g["name"] == name), None)
            if not group:
                return "No exact group name match. Use /groups to see names. Nothing changed."
            try:
                preview = self.pause_control.preview_group(
                    group["id"], action="pause", actor=f"telegram owner:{chat}",
                    duration_seconds=3600 if duration is None else duration)
            except (ValueError, ControlError, RouterError) as exc:
                return str(exc)
            return format_pause_preview(preview)
        group_pause.wants_text = True

        def group_resume(text="", chat=None):
            if not self.pause_control:
                return "No saved Internet pause controller is available to review."
            words = (text or "").strip().split(maxsplit=1)
            if len(words) != 2:
                return "Usage: /group_resume <exact group name>"
            group = next((g for g in sqlite.device_groups(self.cfg.db_path) if g["name"] == words[1]), None)
            if not group:
                return "No exact group name match. Use /groups to see names. Nothing changed."
            try:
                preview = self.pause_control.preview_group(
                    group["id"], action="resume", actor=f"telegram owner:{chat}", duration_seconds=0)
            except (ValueError, ControlError, RouterError) as exc:
                return str(exc)
            return format_pause_preview(preview)
        group_resume.wants_text = True

        def pause_confirm(text="", chat=None):
            if not self.pause_control:
                return "No saved Internet pause controller is available to review."
            words = (text or "").strip().split()
            if len(words) != 2:
                return "Usage: /pause_confirm <preview-token>"
            try:
                result = self.pause_control.apply(words[1], actor=f"telegram owner:{chat}")
            except (ValueError, ControlError, RouterError) as exc:
                return f"Could not apply Internet control: {exc}"
            return (f"✅ Internet {result.get('action', 'change')} applied to "
                    f"{result.get('count', 1)} device(s). {result.get('detail', '')}")
        pause_confirm.wants_text = True

        return {
            "speed": speed,
            "omada": omada,
            "route": route,
            "route_confirm": route_confirm,
            "device": device,
            "devices": lambda text="", chat=None: device("/device"),
            "reserve": reserve,
            "reserve_confirm": reserve_confirm,
            "groups": groups,
            "group_smart": group_smart,
            "group_reserve": group_reserve,
            "group_reserve_confirm": group_reserve_confirm,
            "group_suggest": group_suggest,
            "group_route": group_route,
            "group_confirm": group_confirm,
            "pause": pause,
            "resume": resume,
            "paused": paused,
            "group_pause": group_pause,
            "group_resume": group_resume,
            "pause_confirm": pause_confirm,
            "status": status,
            "pi": pi_health,
            "today": lambda: self.digest(time.time(), "📈 Last 24 hours"),
            "week": lambda: self.weekly_digest(time.time(), "📊 Last 7 days"),
            "mute": mute,
            "unmute": unmute,
            "help": lambda: HELP,
            "start": lambda: "👋 Hi! " + HELP + "\n\n" + status(),
        }

    # --- snapshot & storage ---

    def _snapshot(self, now: float, evals: dict[str, Evaluation]) -> dict:
        labels = self.labels
        d = self.last_decision
        delivery_stats = getattr(self.alerter.notifier, "delivery_stats", None)
        telegram_delivery = delivery_stats() if self.cfg.telegram.enabled and callable(delivery_stats) else None
        snap = {
            "version": __version__,
            "mode": self.cfg.mode,
            "updated": now,
            "targets": list(self.cfg.probe.targets),
            "muted_until": self.alerter.muted_until(),
            "alert_policy": {
                "telegram_enabled": self.cfg.telegram.enabled,
                "device_activity_notifications": self.cfg.telegram.device_activity_notifications,
                "quiet_start": self.cfg.telegram.quiet_start,
                "quiet_end": self.cfg.telegram.quiet_end,
                "suppressed_since_start": self.alerter.suppression_counts(),
                "device_notice_suppressed_since_start": self.alerter.category_suppression_counts(
                    DEVICE_NOTICE_CATEGORY),
                "delivery_since_start": telegram_delivery,
            },
            "decision": d and {"current": self.engine.current, "reason": d.reason, "switch": d.switch},
            "group_recommendations": self.group_recommendations,
            "wans": [
                {
                    "name": n,
                    "label": labels[n].label,
                    "source_ip": labels[n].source_ip,
                    "state": e.state.value,
                    "state_since": self.trackers[n].state_since,
                    "score": e.score,
                    "loss_pct": e.metrics.loss_pct,
                    "rtt_ms": e.metrics.rtt_ms,
                    "jitter_ms": e.metrics.jitter_ms,
                    "availability_pct": e.metrics.availability_pct,
                    "rtt_ratio": e.rtt_ratio,
                    "reasons": e.reasons,
                    "why": [summary.plain_reason(r) for r in e.reasons],
                    "errors": e.errors,
                    "connectivity": (
                        self.connectivity_results[n].as_dict()
                        if e.state != State.UNKNOWN
                        and n in self.connectivity_results
                        and connectivity_result_is_fresh(
                            self.connectivity_results[n].checked_at, now)
                        else None
                    ),
                    "targets": [t.__dict__ for t in e.metrics.targets],
                }
                for n, e in evals.items()
            ],
        }
        if self.router:
            router_status = self.router.snapshot()
            if self.router_control:
                router_status["control"] = self.router_control.state()
            snap["router"] = router_status
        snap["speedtest_running"] = self.tester.running
        snap["headline"] = summary.headline(snap)
        return snap

    def every_minute(self, minute_start: float, now: float, evals: dict[str, Evaluation]) -> None:
        """Once-a-minute work. The service loop and the scenario tests both call exactly this."""
        try:
            self.flush_minute(minute_start, evals)
        except sqlite3.Error:
            # e.g. "database is locked" or disk full: keep running. Pending events stay queued and are
            # written with the next successful minute; only this minute's averages are lost.
            log.exception("could not save this minute; will retry next minute")
        if not isinstance(self.alerter.notifier, NullNotifier):
            try:
                self.maybe_send_digest(now)
                self.maybe_send_weekly_report(now)
            except Exception:  # noqa: BLE001
                log.exception("scheduled Telegram report failed")
        try:
            self.maybe_run_scheduled_speedtest(now)
        except Exception:  # noqa: BLE001
            log.exception("scheduled speed test failed to start")

    def flush_minute(self, minute_start: float, evals: dict[str, Evaluation]) -> None:
        rows, target_rows = [], []
        ts = int(minute_start)
        for name, e in evals.items():
            m = metrics.compute(self.trackers[name].cycles_since(minute_start))
            if m.cycles:
                rows.append((ts, name, e.state.value, e.score,
                             m.loss_pct, m.rtt_ms, m.jitter_ms, m.availability_pct))
                target_rows += [(ts, name, t.target, t.loss_pct, t.rtt_ms, t.jitter_ms) for t in m.targets]
        self.storage.write_minute(rows, self.pending_events, self.baselines.items(), target_rows)
        self.pending_events = []

    def label(self, wan: str) -> str:
        return self.labels[wan].label or wan

    def display(self, wan: str) -> str:
        """'Example ISP A (WAN1)' when the WAN has a label, else just 'WAN1'."""
        label = self.labels[wan].label
        return f"{label} ({wan})" if label else wan


def _numbers(e: Evaluation) -> str:
    m = e.metrics
    rtt = "-" if m.rtt_ms is None else f"{m.rtt_ms:.0f} ms"
    return f"{rtt}, {m.loss_pct:.0f}% loss"


def _duration(seconds: float) -> str:
    minutes = int(seconds // 60)
    if minutes < 1:
        return "under a minute"
    if minutes < 60:
        return f"{minutes} min"
    return f"{minutes // 60} h {minutes % 60} min"


async def run_async(cfg: Config) -> None:
    storage = Storage(cfg.db_path)
    storage.prune()
    board = web.StatusBoard()

    bot: TelegramBot | None = None
    notifier: Notifier = NullNotifier()
    if cfg.telegram.enabled:
        bot = TelegramBot(cfg.telegram.bot_token, cfg.telegram.chat_id, handlers={},
                          profile=profile_texts([w.label or w.name for w in cfg.wans]),
                          store=sqlite.KeyValueFile(cfg.db_path))
        notifier = bot
    router = _make_router(cfg)
    board.set_extra("router_watch", router)
    presence_settings = PresenceSettings(
        cfg.db_path, available=bool(router), default_enabled=cfg.router.presence_probes_enabled)
    mon = Monitor(cfg, storage, Alerter(
        notifier, cfg.telegram, rate_limit_store=sqlite.KeyValueFile(cfg.db_path)), board, router)
    try:
        recovery = await asyncio.to_thread(system_health.sample_acl_recovery)
        status = recovery.get("status") if isinstance(recovery, dict) else None
        mon.on_acl_recovery_status(time.time(), status)
    except Exception:  # noqa: BLE001 - recovery visibility must not prevent monitoring startup
        log.exception("startup ACL recovery check failed")
    board.set_extra("speedtest", mon)
    board.set_extra("router_control", mon.router_control)
    board.set_extra("pause_control", mon.pause_control)
    board.set_extra("device_presence_settings", presence_settings)
    board.set_extra("device_presence_enabled", presence_settings.enabled)
    board.set_extra("device_presence_interval_seconds", cfg.router.presence_probe_interval_seconds)
    board.set_extra("device_presence_confirm_misses", cfg.router.presence_confirm_misses)
    board.set_extra("router_syslog", {
        "enabled": bool(cfg.router.syslog_enabled), "listening": False,
        "accepted_allocations": 0, "duplicates_suppressed": 0,
        "device_events": 0, "known_renewals_suppressed": 0,
        "last_allocation_at": None,
    })
    web.start(cfg.web.host, cfg.web.port, board, cfg.db_path, cfg.web.auth_file)
    if bot:
        bot.handlers = mon.bot_handlers()
        bot.start()

    for w in cfg.wans:
        if not w.source_ip:
            log.warning("%s has no source_ip: its probes follow the ER605's normal routing, "
                        "so they do NOT prove which WAN they used", w.name)
    log.info("NetPulse %s started in %s mode, WANs: %s, telegram %s, router %s", __version__, cfg.mode,
             ", ".join(f"{w.name}@{w.source_ip or 'default'}" for w in cfg.wans),
             "on" if bot else "off", "on" if router else "off")

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, stop.set)
        except (NotImplementedError, AttributeError):  # Windows dev machines
            pass

    minute = int(time.time() // 60 * 60)
    last_prune = time.time()
    evals: dict[str, Evaluation] = {}
    router_task: asyncio.Task | None = None
    next_router_tick = 0.0
    presence_task: asyncio.Task | None = None
    next_presence_tick = 0.0
    presence_scan_offset = 0
    active_presence_scan_rounds = 1
    route_expiry_task: asyncio.Task | None = None
    next_route_expiry_tick = 0.0
    pause_expiry_task: asyncio.Task | None = None
    next_pause_expiry_tick = 0.0
    smart_route_task: asyncio.Task | None = None
    system_task: asyncio.Task | None = None
    next_system_tick = 0.0
    last_system_health_success_mono = time.monotonic()
    backup_task: asyncio.Task | None = None
    next_backup_tick = 0.0
    connectivity_tasks: dict[str, asyncio.Task] = {}
    syslog_transport = None
    syslog_protocol: RouterSyslogProtocol | None = None

    def on_syslog_status(status: dict) -> None:
        board.set_extra("router_syslog", {
            "enabled": True, **status,
            "device_events": mon.syslog_device_events,
            "known_renewals_suppressed": mon.syslog_known_renewals_suppressed,
        })

    try:
        if cfg.router.syslog_enabled:
            try:
                syslog_protocol = RouterSyslogProtocol(
                    cfg.router.host, mon.on_router_syslog_allocation,
                    clock=time.time, on_status=on_syslog_status)
                syslog_transport, _ = await loop.create_datagram_endpoint(
                    lambda: syslog_protocol,
                    local_addr=("0.0.0.0", cfg.router.syslog_port),
                )
                log.info("ER605 DHCP syslog listening on UDP/%d; source-filtered to router host",
                         cfg.router.syslog_port)
            except (OSError, ValueError):
                board.set_extra("router_syslog", {
                    "enabled": True, "listening": False,
                    "accepted_allocations": 0, "duplicates_suppressed": 0,
                    "device_events": mon.syslog_device_events,
                    "known_renewals_suppressed": mon.syslog_known_renewals_suppressed,
                    "last_allocation_at": None, "error": "bind_failed",
                })
                log.exception("ER605 DHCP syslog receiver could not start; syslog hints are unavailable")
        while not stop.is_set():
            started = time.monotonic()
            try:
                evals = await mon.cycle()
            except Exception:  # noqa: BLE001 - one bad cycle must not kill the service
                log.exception("probe cycle failed")

            now = time.time()
            connectivity_changed = False
            for name, task in list(connectivity_tasks.items()):
                if task.done():
                    connectivity_tasks.pop(name, None)
                    try:
                        result = task.result()
                        evaluation = evals.get(name) if evals else None
                        if (evaluation and evaluation.state != State.UNKNOWN
                                and result.icmp_state == evaluation.state.value
                                and connectivity_result_is_fresh(result.checked_at, now)):
                            mon.connectivity_results[name] = result
                            mon.on_connectivity_result(name, result, now)
                        else:
                            mon.connectivity_results.pop(name, None)
                    except Exception:  # noqa: BLE001 - diagnostics must not affect monitoring
                        log.exception("secondary connectivity check failed for %s", name)
                    connectivity_changed = True

            if evals:
                for name, evaluation in evals.items():
                    label = mon.labels[name]
                    if (evaluation.state != State.UNKNOWN and not evaluation.errors
                            and label.source_ip
                            and name not in connectivity_tasks
                            and now - mon.connectivity_started.get(name, 0.0)
                            >= connectivity_check_interval(evaluation.state.value)):
                        mon.connectivity_started[name] = now
                        connectivity_tasks[name] = asyncio.create_task(asyncio.to_thread(
                            diagnose_connectivity, label.source_ip, now,
                            wan_dns_servers=_fresh_router_dns_servers(router, name, now),
                            icmp_state=evaluation.state.value,
                        ))
                if connectivity_changed:
                    board.publish(mon._snapshot(now, evals))

            if router_task and router_task.done():
                try:
                    mon.on_router_events(now, router_task.result())
                except Exception:  # noqa: BLE001
                    log.exception("router check failed")
                router_task = None
            if router and router_task is None and now >= next_router_tick:
                next_router_tick = now + 60
                # Blocking HTTP in a worker thread: probing never waits for the router.
                router_task = asyncio.create_task(asyncio.to_thread(
                    router.tick, now, advance_during_wait=True))

            if presence_task and presence_task.done():
                try:
                    results = presence_task.result()
                    if presence_settings.enabled:
                        mon.on_presence_scan(results, now, active_presence_scan_rounds)
                except Exception:  # noqa: BLE001 - optional LAN probes must not stop monitoring
                    log.exception("local device presence scan failed")
                presence_task = None
            if (router and presence_settings.enabled and presence_task is None
                    and now >= next_presence_tick):
                next_presence_tick = now + cfg.router.presence_probe_interval_seconds
                checked_at = router.snap.checked_at
                raw = router.snap.raw if isinstance(router.snap.raw, dict) else {}
                clients = raw.get("clients", [])
                checked_age = age_seconds(checked_at, now)
                if (checked_age is not None and isinstance(clients, list)
                        and checked_age <= router.poll_seconds * 2):
                    excluded = [cfg.router.host, *(w.source_ip for w in cfg.wans if w.source_ip)]
                    if mon.router_control:
                        local_macs = mon.router_control.local_device_macs()
                        clients = [device for device in clients if not (
                            isinstance(device, dict)
                            and normalize_mac(device.get("macaddr", device.get("mac", ""))) in local_macs
                        )]
                    presence_task = asyncio.create_task(scan_lan_presence(
                        clients, now=now, exclude_ips=excluded, offset=presence_scan_offset))
                    active_presence_scan_rounds = lan_presence_rounds(len(clients))
                    presence_scan_offset += MAX_CLIENTS_PER_SCAN

            if route_expiry_task and route_expiry_task.done():
                try:
                    expired_count = route_expiry_task.result()
                    if expired_count:
                        log.info("returned %d timed device route preference(s) to Auto", expired_count)
                    for failure in mon.router_control.drain_expiry_failures():
                        mon.on_route_expiry_failure(now, failure)
                except Exception:  # noqa: BLE001
                    log.exception("timed route expiry worker failed")
                route_expiry_task = None
            if mon.router_control and route_expiry_task is None and now >= next_route_expiry_tick:
                next_route_expiry_tick = now + 60
                route_expiry_task = asyncio.create_task(asyncio.to_thread(
                    mon.router_control.expire_due_routes, now))

            if pause_expiry_task and pause_expiry_task.done():
                try:
                    expired = pause_expiry_task.result()
                    if expired:
                        log.info("resumed %d timed Internet pause(s)", expired)
                    for failure in mon.pause_control.drain_failures():
                        label = "a saved device"
                        mon._system_alert(
                            now,
                            f"⚠️ Timed Internet pause for {label} could not be resumed. NetPulse will retry.",
                            f"Timed Internet pause for {label} could not be resumed",
                            f"internet-pause-expiry-{failure.get('mac', 'group')}",
                        )
                except Exception:  # noqa: BLE001 - Internet expiry must not stop monitoring
                    log.exception("timed Internet pause expiry worker failed")
                pause_expiry_task = None
            if mon.pause_control and pause_expiry_task is None and now >= next_pause_expiry_tick:
                next_pause_expiry_tick = now + 60
                pause_expiry_task = asyncio.create_task(asyncio.to_thread(
                    mon.pause_control.expire_due, now))

            if smart_route_task and smart_route_task.done():
                try:
                    smart_route_task.result()
                except Exception:  # noqa: BLE001 - smart routing must not stop monitoring
                    log.exception("smart group route worker failed")
                smart_route_task = None
            if mon.router_control and smart_route_task is None:
                candidate = mon.next_smart_group_route()
                if candidate:
                    smart_route_task = asyncio.create_task(asyncio.to_thread(
                        mon.apply_smart_group_route, candidate[0], candidate[1]))

            if system_task and system_task.done():
                try:
                    mon.on_system_health(now, system_task.result())
                    last_system_health_success_mono = time.monotonic()
                except Exception:  # noqa: BLE001
                    log.exception("system health check failed")
                system_task = None
            if cfg.system_health.enabled:
                stale = (time.monotonic() - last_system_health_success_mono
                         > cfg.system_health.interval_seconds * 2)
                mon.on_system_health_stale(now, stale)
            if cfg.system_health.enabled and system_task is None and now >= next_system_tick:
                next_system_tick = now + cfg.system_health.interval_seconds
                system_task = asyncio.create_task(asyncio.to_thread(
                    system_health.sample, cfg.db_path, cfg.backup))

            if backup_task and backup_task.done():
                try:
                    path = backup_task.result()
                    log.info("database backup completed: %s", path)
                except Exception as e:  # noqa: BLE001
                    log.exception("database backup failed")
                    mon.on_backup_failure(now, e)
                    next_backup_tick = now + 3600
                backup_task = None
            if cfg.backup.enabled and backup_task is None and now >= next_backup_tick:
                next_backup_tick = now + cfg.backup.interval_days * 86400
                backup_task = asyncio.create_task(asyncio.to_thread(
                    db_backup.create, cfg.db_path, cfg.backup.directory, cfg.backup.keep, cfg.backup.mount_path))

            if evals and now >= minute + 60:
                mon.every_minute(minute, now, evals)
                minute = int(now // 60 * 60)
            if now - last_prune > 86400:
                storage.prune(now)
                last_prune = now

            delay = max(0.0, cfg.interval_seconds - (time.monotonic() - started))
            try:
                await asyncio.wait_for(stop.wait(), timeout=delay)
            except asyncio.TimeoutError:
                pass
    finally:
        if syslog_transport:
            syslog_transport.close()
        if route_expiry_task:
            route_expiry_task.cancel()
        if pause_expiry_task:
            pause_expiry_task.cancel()
        if presence_task:
            presence_task.cancel()
        for task in connectivity_tasks.values():
            task.cancel()
        if system_task:
            system_task.cancel()
        if backup_task:
            backup_task.cancel()
        if bot:
            bot.stop()
        if evals:
            mon.flush_minute(minute, evals)
        storage.close()
        log.info("stopped")


def _make_router(cfg: Config) -> RouterWatch | None:
    if not cfg.router.enabled:
        return None
    try:
        creds = config_mod.load_router_credentials(cfg.router.credentials_file)
    except (OSError, ValueError) as e:
        log.error("router checks disabled: %s", e)
        return None
    client = ER605Client(cfg.router.host, creds.username, creds.password, creds.cert_sha256)
    return RouterWatch(client, {w.name: w.label for w in cfg.wans}, cfg.router.poll_minutes)


def _fresh_router_dns_servers(router, wan: str, now: float) -> tuple[str, ...]:
    """Use WAN resolver addresses only while the corresponding ER605 read is fresh."""
    if router is None:
        return ()
    snap = getattr(router, "snap", None)
    checked_at = getattr(snap, "checked_at", None)
    if checked_at is None:
        return ()
    max_age = max(60, float(getattr(router, "poll_seconds", 600)) * 2)
    age = age_seconds(checked_at, now)
    if age is None or age > max_age:
        return ()
    links = getattr(snap, "links", {})
    link = links.get(wan) if isinstance(links, dict) else None
    servers = getattr(link, "dns_servers", ())
    return tuple(servers[:2]) if isinstance(servers, (list, tuple)) else ()


def run(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="netpulse", description="Dual-WAN quality monitor")
    ap.add_argument("-c", "--config", default="/etc/netpulse/config.toml")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",  # journald adds timestamps
        stream=sys.stdout,
    )
    try:
        cfg = config_mod.load(args.config)
    except (OSError, ValueError, TypeError) as e:
        log.error("bad config %s: %s", args.config, e)
        sys.exit(2)
    for w in cfg.warnings:
        log.warning("config: %s", w)
    asyncio.run(run_async(cfg))


if __name__ == "__main__":
    run()
