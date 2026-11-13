"""Root-only candidate recovery worker; no public apply CLI or acceptance bypass.

The operator trial API is netpulse.router.trial.run_trial. Device approval and
the endpoint probe are supplied only after owner review of a concrete plan.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
from contextlib import contextmanager
from copy import deepcopy
import os
from pathlib import Path
import subprocess
import sys
import time

from netpulse.config import load, load_router_credentials
from netpulse.router.compatibility import CompatibilityError, CANDIDATE_FIRMWARE
from netpulse.router.control import _balance_enabled
from netpulse.router.er605 import ER605Client, acl_pilot_effective_match
from netpulse.router.trial import (TrialJournal, boottime, private_metadata, recover,
                                   rows_equal, MAX_RECORD)
from netpulse.router.trial_lock import TRIAL_JOURNAL, TRIAL_PENDING
from netpulse.storage.sqlite import KeyValueFile


def service_active():
    return subprocess.run(['systemctl', 'is-active', '--quiet', 'netpulse'], capture_output=True).returncode == 0


class RouterTrialAdapter:
    """Only a single existing endpoint route or one temporary ACL may change."""
    def __init__(self, cfg, *, protected_ips, ready, client=None):
        self.cfg, self.protected_ips, self.ready = cfg, list(protected_ips), ready
        if client is None:
            credentials = load_router_credentials(cfg.router.credentials_file)
            client = ER605Client(cfg.router.host, credentials.username, credentials.password,
                                 credentials.cert_sha256)
        self.client = client

    @staticmethod
    def monitor_active():
        return service_active()

    @staticmethod
    def quiesce():
        subprocess.run(['systemctl', 'stop', 'netpulse'], check=True, timeout=30, capture_output=True)

    @staticmethod
    def resume():
        subprocess.run(['systemctl', 'start', 'netpulse'], check=True, timeout=30, capture_output=True)

    @classmethod
    def for_trial(cls, cfg, *, management_ip):
        """Owner-run candidate adapter; does not expand ordinary feature gates."""
        from tools.router_acl_pilot import _local_address, _validate_no_near_expiries
        try:
            admin = ipaddress.IPv4Address(management_ip)
            if not admin.is_private or admin.is_loopback or admin.is_link_local:
                raise ValueError
        except (ValueError, TypeError):
            raise CompatibilityError('The separate private administration endpoint must be protected.') from None
        kv = KeyValueFile(cfg.db_path)
        def ready():
            _validate_no_near_expiries(cfg.db_path, time.time(), 600)
            return (cfg.router.enabled and cfg.router.controls_enabled
                    and not Path(cfg.router.kill_switch).exists()
                    and kv.get('pi_acl_recovery_failed') != '1'
                    and kv.get('router_firmware_accepted') == CANDIDATE_FIRMWARE
                    and not kv.get('router_firmware_pending')
                    and not Path('/var/lib/netpulse/router-acl-pilot/watchdog.json').exists()
                    and not Path('/var/lib/netpulse/router-acl-pilot/watchdog.failed').exists())
        addresses = [_local_address(cfg.router.host), str(admin)] + [w.source_ip for w in cfg.wans if w.source_ip]
        return cls(cfg, protected_ips=addresses, ready=ready)

    @contextmanager
    def transaction(self):
        if service_active():
            raise CompatibilityError('Quiesce monitoring before opening a trial router session.')
        with self.client.session():
            yield

    def snapshot(self):
        start = boottime()
        info = self.client.public_info()
        versions = self.client.get('firmware', 'upgrade')
        raw = {'model': info.get('model'), 'uptime': info.get('uptime'),
               'router_host': self.client.host, 'cert_sha256': self.client.cert_sha256,
               'hardware_version': versions.get('hardware_version'),
               'firmware_version': versions.get('firmware_version'),
               'protected_ips': self.protected_ips, 'protected_macs': list(self.cfg.router.protected_macs),
               'ready': False}
        for key, module, form in (
            ('clients','dhcps','client'), ('reservations','dhcps','reservation'),
            ('ipscopes','ipgroup','ipscope_reservation'), ('ipgroups','ipgroup','ipgroup_reservation'),
            ('routes','policy_route','policy_route')):
            raw[key] = self.client.get(module, form)
        raw['lan'] = self.client.get('dhcps','lan')
        raw['lan_scopes'] = self.client.get('ipgroup','ipscope_list')
        from netpulse.storage import sqlite
        from netpulse.storage.pauses import blocked_macs
        blocked = blocked_macs(self.cfg.db_path) | set(sqlite.device_routes(self.cfg.db_path))
        for group in sqlite.device_groups(self.cfg.db_path):
            if group.get('smart_routing_enabled'): blocked.update(group.get('members',[]))
        raw['preparation_blocked_macs'] = sorted(blocked)
        raw['acls'] = self.client.read_acl_pilot_rows()
        balance = self.client.get('balance', 'balance_basic')
        raw['ready'] = bool(self.ready() and _balance_enabled(balance) is True)
        if boottime() - start > 20:
            raise CompatibilityError('Fresh trial snapshot exceeded its bounded collection time.')
        return raw

    def _set_route(self, old, new):
        rows = self.client.get('policy_route', 'policy_route')
        matches = [(i, row) for i, row in enumerate(rows) if row.get('name') == old['name']]
        if len(matches) != 1 or not rows_equal([matches[0][1]], [old]):
            raise CompatibilityError('Route identity changed; refusing indexed update.')
        index, observed = matches[0]
        desired = deepcopy(new)
        if 'index' in observed:
            desired['index'] = observed['index']
        self.client.set_row('policy_route', 'policy_route', index, f'key-{index}', observed, desired)

    def apply(self, plan):
        if plan['approval']['action'] == 'pause':
            self.client.add_acl_pilot_rule(plan['before']['acls'], plan['change'])
        else:
            old = next(r for r in plan['before']['routes'] if r['name'] == plan['change']['name'])
            self._set_route(old, plan['change'])

    def create_preparation_object(self,index,obj):
        from netpulse.router.preparation import FORMS
        module,form = FORMS[index]
        rows = self.client.get(module,form)
        if index == 0: return self.client.add_dhcp_reservation(rows,obj)
        return self.client.add_row(module,form,rows,obj)

    def delete_preparation_object(self,index,receipt):
        from netpulse.router.preparation import FORMS
        self.client.delete_exact_preparation_row(*FORMS[index],receipt)

    def restore(self, plan, current):
        if plan['approval']['action'] == 'pause':
            matches = [r for r in current['acls'] if r.get('name') == plan['change']['name']]
            if not matches:
                return
            if len(matches) != 1 or not acl_pilot_effective_match(matches[0], plan['change']):
                raise CompatibilityError('Changed or ambiguous trial ACL requires manual recovery.')
            self.client.delete_acl_pilot_rule(plan['change']['name'], matches[0])
        else:
            before = next(r for r in plan['before']['routes'] if r['name'] == plan['change']['name'])
            matches = [r for r in current['routes'] if r.get('name') == before['name']]
            if len(matches) == 1 and rows_equal(matches, [before]):
                return
            if len(matches) != 1 or not rows_equal(matches, [plan['change']]):
                raise CompatibilityError('Changed or missing trial route requires manual recovery.')
            self._set_route(matches[0], before)


class IndependentWatchdog:
    def start(self, journal, record):
        if journal.path != TRIAL_JOURNAL or journal.marker != TRIAL_PENDING:
            raise CompatibilityError('The live watchdog requires its fixed protected journal paths.')
        if subprocess.run(['systemctl', 'is-enabled', '--quiet', 'netpulse-compat-recovery.service'],
                          capture_output=True).returncode != 0:
            return False
        unit = 'netpulse-compat-watch-' + record['nonce']
        result = subprocess.run([
            'systemd-run', '--quiet', '--collect', '--unit=' + unit,
            '--property=Type=exec', '--property=WorkingDirectory=/opt/netpulse',
            '--property=User=root', '--property=UMask=0077', '--property=RuntimeMaxSec=720',
            '--property=Restart=on-abnormal', '--property=RestartSec=1',
            '--property=StartLimitBurst=3', '--property=StartLimitIntervalSec=60',
            '/usr/bin/python3', '-m', 'tools.router_compat_trial', '--watch'], capture_output=True)
        if result.returncode != 0:
            return False
        deadline = boottime() + 10
        ready = journal.path.with_suffix('.ready')
        while boottime() < deadline:
            if ready.exists():
                private_metadata(ready.lstat())
                return (ready.read_text() == record['nonce'] and
                        subprocess.run(['systemctl', 'is-active', '--quiet', unit], capture_output=True).returncode == 0)
            time.sleep(.1)
        return False


class RehearsalAdapter:
    """Synthetic no-network recovery adapter, selected only by a journaled mode.

    No ER605 client, credentials or socket is constructed. Mutation attempts fail.
    It exercises the same watchdog, locking, service restoration and clear path.
    """
    def __init__(self, snapshot):
        self.before = deepcopy(snapshot)

    @contextmanager
    def transaction(self):
        yield

    def snapshot(self):
        return deepcopy(self.before)

    def apply(self, plan):
        raise CompatibilityError('Router mutations are forbidden during rehearsal.')

    def restore(self, plan, current):
        if current != plan['before']:
            raise CompatibilityError('Rehearsal state differs; no router recovery may be attempted.')


class RehearsalPreparationAdapter:
    """Persisted synthetic state, with no router client/configuration/network path."""
    def __init__(self,record,path):
        if record['mode'] != 'rehearsal' or record['plan'].get('kind') != 'preparation':
            raise CompatibilityError('Synthetic preparation mode is required.')
        self.path = Path(path)
        private_metadata(self.path.lstat())
        fd = os.open(self.path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
        with os.fdopen(fd,'rb') as stream:
            private_metadata(os.fstat(stream.fileno())); data = stream.read(MAX_RECORD+1)
        if len(data)>MAX_RECORD: raise CompatibilityError('Synthetic fixture exceeds its size limit.')
        self.current = json.loads(data)
        from netpulse.router.preparation import inspect_progress
        inspect_progress(record,self.current)

    @contextmanager
    def transaction(self): yield

    def snapshot(self): return deepcopy(self.current)

    def delete_preparation_object(self,index,receipt):
        from netpulse.router.preparation import COLLECTIONS
        key = COLLECTIONS[index]
        matches = [i for i,row in enumerate(self.current[key]) if row == receipt]
        if len(matches)!=1: raise CompatibilityError('Synthetic receipt changed.')
        self.current[key].pop(matches[0])
        temp = self.path.with_name('.rehearsal-state-new')
        fd = os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
        try:
            with os.fdopen(fd,'w') as stream:
                json.dump(self.current,stream);stream.flush();os.fsync(stream.fileno())
            os.replace(temp,self.path)
        finally: temp.unlink(missing_ok=True)


def pid_alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


def watch(journal, *, sleep=time.sleep, alive=pid_alive):
    with journal.locked():
        record = journal.read()
        if record is None:
            if journal.marker.exists():
                raise CompatibilityError('Orphan trial marker requires manual review.')
            return False  # A safely cancelled or completed trial needs no worker.
        ready = journal.path.with_suffix('.ready')
        if ready.exists():
            private_metadata(ready.lstat())
            if ready.read_text() != record['nonce']:
                raise CompatibilityError('Stale watchdog readiness identity requires review.')
        else:
            fd = os.open(ready, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
            with os.fdopen(fd, 'w') as stream:
                stream.write(record['nonce']); stream.flush(); os.fsync(stream.fileno())
    while not journal.due(record, alive):
        current = journal.read()
        if current is None:
            if journal.marker.exists():
                raise CompatibilityError('Orphan trial marker requires manual review.')
            return False
        if current != record:
            raise CompatibilityError('Watchdog journal identity changed.')
        sleep(min(1, max(.01, record['deadline'] - journal.clock())))
    return True


def root_runtime():
    return os.name == 'posix' and os.geteuid() == 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--watch', action='store_true')
    mode.add_argument('--recover-on-boot', action='store_true')
    args = parser.parse_args(argv)
    if not root_runtime():
        parser.error('Run the recovery worker as root on the Pi.')
    journal = TrialJournal(TRIAL_JOURNAL)
    if not args.watch and not args.recover_on_boot:
        print('Candidate trial status: ' + ('pending recovery' if TRIAL_PENDING.exists() else 'no pending recovery'))
        return 0
    if args.recover_on_boot and not TRIAL_PENDING.exists() and not TRIAL_JOURNAL.exists():
        return 0
    restart = False
    resume_attempted = False
    def resume_monitor():
        nonlocal resume_attempted
        resume_attempted = True
        subprocess.run(['systemctl', 'start', 'netpulse'], check=True, timeout=30, capture_output=True)
    try:
        if args.watch and not watch(journal):
            return 0
        record = journal.read()
        if record is None:
            if journal.marker.exists():
                raise CompatibilityError('Orphan trial marker requires manual review.')
            return 0
        # Recovery ignores ordinary enable flags/kill switch, but only restores
        # exact journaled owned objects on the exact original router/build.
        restart = not args.recover_on_boot and (record['restart_service'] or service_active())
        if service_active():
            subprocess.run(['systemctl', 'stop', 'netpulse'], check=True, timeout=30)
        if record['mode'] == 'rehearsal':
            if record['plan'].get('kind') == 'preparation':
                adapter = RehearsalPreparationAdapter(record,journal.path.with_name('rehearsal-state.json'))
            else:
                adapter = RehearsalAdapter(record['plan']['before'])
        else:
            cfg = load('/etc/netpulse/config.toml')
            adapter = RouterTrialAdapter(cfg, protected_ips=record['plan']['before']['protected_ips'], ready=lambda: False)
        recover(journal, adapter, after_restore=resume_monitor if restart else None,
                expected_nonce=record['nonce'])
        return 0
    except Exception:
        # Corrupt/orphan journal state must also keep ordinary control writes locked.
        if not TRIAL_PENDING.exists():
            fd = os.open(TRIAL_PENDING, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
            with os.fdopen(fd, 'w') as stream:
                stream.write('manual-review'); stream.flush(); os.fsync(stream.fileno())
        print('Candidate recovery incomplete; journal/marker retained for owner review.', file=sys.stderr)
        return 2
    finally:
        if restart and not resume_attempted:
            resume_monitor()


if __name__ == '__main__':
    raise SystemExit(main())
