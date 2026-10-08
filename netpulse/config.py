"""Load and validate the TOML config into typed dataclasses."""

from __future__ import annotations

import ipaddress
import math
import tomllib
from dataclasses import dataclass, field, fields
from pathlib import Path
from netpulse.devices.identity import normalize_mac


@dataclass(frozen=True)
class WanConfig:
    name: str
    label: str = ""
    source_ip: str = ""
    plan_mbps: float = 0          # the ISP plan's download speed, for context in reports
    expected_asns: tuple[str, ...] = ()  # optional public egress origin ASN(s), e.g. ["AS12345"]


@dataclass(frozen=True)
class SpeedTestConfig:
    schedule_enabled: bool = False   # keep off until the Pi has a proper power supply
    times: tuple[str, ...] = ("06:00", "13:00", "20:30", "23:30")
    download_mb: float = 25
    upload_mb: float = 10
    streams: int = 4
    dip_pct: float = 50              # a test below this % of the ISP's usual speed is a dip
    monthly_budget_mb: float = 0      # zero disables the cap; otherwise applies to manual and scheduled tests


@dataclass(frozen=True)
class ProbeConfig:
    targets: tuple[str, ...] = ("1.1.1.1", "8.8.8.8", "9.9.9.9")
    count: int = 5
    packet_interval: float = 0.2
    timeout_seconds: float = 1.0


@dataclass(frozen=True)
class Thresholds:
    degraded_loss_pct: float = 5
    bad_loss_pct: float = 15
    degraded_rtt_ms: float = 120
    bad_rtt_ms: float = 250
    degraded_jitter_ms: float = 30
    degraded_rtt_factor: float = 2.5
    bad_rtt_factor: float = 4.0
    min_rtt_increase_ms: float = 20
    offline_cycles: int = 3


@dataclass(frozen=True)
class DecisionConfig:
    min_score_advantage: float = 15
    hold_seconds: float = 180
    cooldown_seconds: float = 600
    recovery_seconds: float = 600


@dataclass(frozen=True)
class WebConfig:
    host: str = "0.0.0.0"
    port: int = 8080
    auth_file: str = "/etc/netpulse/web.auth"


@dataclass(frozen=True)
class TelegramConfig:
    enabled: bool = False
    bot_token: str = ""
    chat_id: str = ""
    quiet_start: str = "23:00"   # non-critical alerts are held back between these times
    quiet_end: str = "07:00"
    digest_time: str = ""        # daily summary; "" disables it
    weekly_report_time: str = ""  # Sunday 7-day report; "" disables it
    device_activity_notifications: bool = False  # DHCP and LAN-ping activity alerts are opt-in


@dataclass(frozen=True)
class RouterConfig:
    enabled: bool = False
    host: str = "192.168.0.1"
    poll_minutes: float = 10         # each full check logs in, which logs out the Omada web UI
    credentials_file: str = "/etc/netpulse/router.toml"
    controls_enabled: bool = False
    internet_controls_enabled: bool = False
    protected_macs: tuple[str, ...] = ()
    kill_switch: str = "/etc/netpulse/controls.disabled"
    presence_probes_enabled: bool = False
    presence_probe_interval_seconds: int = 60
    presence_confirm_misses: int = 3
    syslog_enabled: bool = False
    syslog_port: int = 514


@dataclass(frozen=True)
class SystemHealthConfig:
    enabled: bool = True
    interval_seconds: int = 300
    low_disk_pct: float = 10
    low_memory_pct: float = 10
    memory_recovery_pct: float = 15


@dataclass(frozen=True)
class BackupConfig:
    enabled: bool = False
    directory: str = "/var/lib/netpulse/backups"
    mount_path: str = ""
    interval_days: int = 7
    keep: int = 8


@dataclass(frozen=True)
class RouterCredentials:
    username: str
    password: str
    cert_sha256: str


def load_router_credentials(path: str) -> RouterCredentials:
    with open(path, "rb") as f:
        raw = tomllib.load(f)
    try:
        return RouterCredentials(raw["username"], raw["password"], raw["cert_sha256"])
    except KeyError as e:
        raise ValueError(f"{path} is missing {e.args[0]} (run tools/router_setup.py)") from None


def parse_hhmm(s: str) -> int:
    """'07:30' -> minutes after midnight."""
    h, m = s.split(":")
    h, m = int(h), int(m)
    if not (0 <= h < 24 and 0 <= m < 60):
        raise ValueError(s)
    return h * 60 + m


@dataclass(frozen=True)
class Config:
    wans: tuple[WanConfig, ...]
    mode: str = "dry-run"
    interval_seconds: float = 10
    window_seconds: float = 300
    db_path: str = "/var/lib/netpulse/netpulse.db"
    preferred_wan: str = ""
    probe: ProbeConfig = field(default_factory=ProbeConfig)
    thresholds: Thresholds = field(default_factory=Thresholds)
    decision: DecisionConfig = field(default_factory=DecisionConfig)
    web: WebConfig = field(default_factory=WebConfig)
    telegram: TelegramConfig = field(default_factory=TelegramConfig)
    router: RouterConfig = field(default_factory=RouterConfig)
    system_health: SystemHealthConfig = field(default_factory=SystemHealthConfig)
    backup: BackupConfig = field(default_factory=BackupConfig)
    speedtest: SpeedTestConfig = field(default_factory=SpeedTestConfig)
    warnings: tuple[str, ...] = ()   # settings this version ignored (logged at start-up)


MODES = ("monitor", "dry-run")


def load(path: str | Path) -> Config:
    with open(path, "rb") as f:
        raw = tomllib.load(f)
    return parse(raw)


def _known(cls, values: dict, where: str, warnings: list[str]) -> dict:
    """Keep only settings this version understands; note the rest instead of refusing to start.
    (Upgrades keep the old config file, so a renamed or retired key must not stop the service.)"""
    names = {f.name for f in fields(cls)}
    for key in values:
        if key not in names:
            warnings.append(f"unknown setting {where}.{key} (ignored)")
    return {k: v for k, v in values.items() if k in names}


def parse(raw: dict) -> Config:
    warnings: list[str] = []
    general = _known(Config, raw.get("general", {}), "general", warnings)
    for reserved in ("wans", "warnings", "probe", "thresholds", "decision", "web", "telegram", "router", "speedtest", "system_health", "backup"):
        if reserved in general:
            warnings.append(f"unknown setting general.{reserved} (ignored)")
            general.pop(reserved)
    probe = _known(ProbeConfig, raw.get("probe", {}), "probe", warnings)
    if "targets" in probe:
        probe = {**probe, "targets": tuple(probe["targets"])}
    speed = _known(SpeedTestConfig, raw.get("speedtest", {}), "speedtest", warnings)
    if "times" in speed:
        speed = {**speed, "times": tuple(speed["times"])}

    wan_configs = []
    for i, item in enumerate(raw.get("wan", []), 1):
        values = _known(WanConfig, item, f"wan[{i}]", warnings)
        if "expected_asns" in values:
            values["expected_asns"] = tuple("AS" + str(x).upper().removeprefix("AS")
                                            for x in values["expected_asns"])
        wan_configs.append(WanConfig(**values))
    wans = tuple(wan_configs)
    cfg = Config(
        wans=wans,
        probe=ProbeConfig(**probe),
        thresholds=Thresholds(**_known(Thresholds, raw.get("thresholds", {}), "thresholds", warnings)),
        decision=DecisionConfig(**_known(DecisionConfig, raw.get("decision", {}), "decision", warnings)),
        web=WebConfig(**_known(WebConfig, raw.get("web", {}), "web", warnings)),
        telegram=TelegramConfig(**_known(TelegramConfig, raw.get("telegram", {}), "telegram", warnings)),
        router=RouterConfig(**_router_values(raw.get("router", {}), warnings)),
        system_health=SystemHealthConfig(**_known(SystemHealthConfig, raw.get("system_health", {}), "system_health", warnings)),
        backup=BackupConfig(**_known(BackupConfig, raw.get("backup", {}), "backup", warnings)),
        speedtest=SpeedTestConfig(**speed),
        warnings=tuple(warnings),
        **general,
    )
    _validate(cfg)
    return cfg


def _router_values(raw: dict, warnings: list[str]) -> dict:
    values = _known(RouterConfig, raw, "router", warnings)
    if "protected_macs" in values:
        macs = values["protected_macs"]
        if not isinstance(macs, (list, tuple)):
            raise ValueError("router.protected_macs must be a list of MAC addresses")
        normalized = [normalize_mac(mac) if isinstance(mac, str) else "" for mac in macs]
        if any(not mac for mac in normalized) or len(set(normalized)) != len(normalized):
            raise ValueError("router.protected_macs must contain unique valid MAC addresses")
        values["protected_macs"] = tuple(normalized)
    return values


def _validate(cfg: Config) -> None:
    names = [w.name for w in cfg.wans]
    if len(names) < 2:
        raise ValueError("config needs at least two [[wan]] entries")
    if len(set(names)) != len(names):
        raise ValueError("WAN names must be unique")
    if cfg.mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}, got {cfg.mode!r}")
    if not isinstance(cfg.router.internet_controls_enabled, bool):
        raise ValueError("router.internet_controls_enabled must be true or false")
    if cfg.web.host not in ("127.0.0.1", "::1", "localhost") and not cfg.web.auth_file.strip():
        raise ValueError("web.auth_file is required when the dashboard listens beyond loopback")
    if cfg.preferred_wan and cfg.preferred_wan not in names:
        raise ValueError(f"preferred_wan {cfg.preferred_wan!r} is not a configured WAN")
    if len(cfg.probe.targets) < 2:
        raise ValueError("use at least two probe targets so one bad target can't fail a WAN")
    if cfg.window_seconds < cfg.interval_seconds * 3:
        raise ValueError("window_seconds must cover at least 3 probe intervals")
    for t in cfg.speedtest.times:
        try:
            parse_hhmm(t)
        except ValueError:
            raise ValueError(f"speedtest.times must be HH:MM values, got {t!r}") from None
    for wan in cfg.wans:
        if any(not value.removeprefix("AS").isdigit() for value in wan.expected_asns):
            raise ValueError(f"wan[{wan.name}].expected_asns must contain ASN values like 'AS12345'")
    if cfg.system_health.interval_seconds < 60:
        raise ValueError("system_health.interval_seconds must be at least 60")
    if not 1 <= cfg.system_health.low_disk_pct <= 50:
        raise ValueError("system_health.low_disk_pct must be between 1 and 50")
    if not 1 <= cfg.system_health.low_memory_pct <= 50:
        raise ValueError("system_health.low_memory_pct must be between 1 and 50")
    if not cfg.system_health.low_memory_pct < cfg.system_health.memory_recovery_pct <= 100:
        raise ValueError("system_health.memory_recovery_pct must be greater than low_memory_pct and at most 100")
    if not 1 <= cfg.backup.interval_days <= 365:
        raise ValueError("backup.interval_days must be between 1 and 365")
    if not 1 <= cfg.backup.keep <= 52:
        raise ValueError("backup.keep must be between 1 and 52")
    if cfg.backup.enabled and not cfg.backup.directory.strip():
        raise ValueError("backup.directory is required when backups are enabled")
    if not 30 <= cfg.router.presence_probe_interval_seconds <= 3600:
        raise ValueError("router.presence_probe_interval_seconds must be between 30 and 3600")
    if not 2 <= cfg.router.presence_confirm_misses <= 10:
        raise ValueError("router.presence_confirm_misses must be between 2 and 10")
    if not 1 <= cfg.router.syslog_port <= 65535:
        raise ValueError("router.syslog_port must be between 1 and 65535")
    if cfg.router.syslog_enabled:
        try:
            ipaddress.IPv4Address(cfg.router.host)
        except ipaddress.AddressValueError:
            raise ValueError("router.host must be an IPv4 address when router.syslog_enabled is true") from None
    if not 1 <= cfg.speedtest.streams <= 8:
        raise ValueError("speedtest.streams must be between 1 and 8")
    budget = cfg.speedtest.monthly_budget_mb
    if (isinstance(budget, bool) or not isinstance(budget, (int, float))
            or not math.isfinite(budget) or budget < 0):
        raise ValueError("speedtest.monthly_budget_mb must be a finite value that is zero (disabled) or greater")
    tg = cfg.telegram
    if tg.enabled and not (tg.bot_token and tg.chat_id):
        raise ValueError("telegram.enabled needs bot_token and chat_id (run tools/telegram_setup.py)")
    for field_name in ("quiet_start", "quiet_end", "digest_time", "weekly_report_time"):
        value = getattr(tg, field_name)
        if value or field_name in ("quiet_start", "quiet_end"):
            try:
                parse_hhmm(value)
            except ValueError:
                raise ValueError(f"telegram.{field_name} must be HH:MM, got {value!r}") from None
