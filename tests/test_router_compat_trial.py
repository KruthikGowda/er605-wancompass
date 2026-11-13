"""Candidate 2.4.10 transaction/recovery tests; no live probes or router writes."""
from contextlib import contextmanager
from copy import deepcopy
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from netpulse.router.compatibility import (CANDIDATE_FIRMWARE, CompatibilityError,
                                           build_plan, capabilities, validate_plan)
from netpulse.router.trial import TrialJournal, recover, run_trial
from netpulse.router import trial_lock
from tools.router_compat_trial import RouterTrialAdapter, RehearsalAdapter, watch, main, IndependentWatchdog

MAC = '02-00-00-00-00-11'
IP = '10.77.0.11'
SUFFIX = MAC.replace('-', '')
BOOT = '11111111-1111-4111-8111-111111111111'
OTHER_BOOT = '22222222-2222-4222-8222-222222222222'
ACL_NAME = 'NP_TEST_P_' + 'A' * 32


def snapshot():
    return {'model': 'ER605', 'hardware_version': 'v2.30', 'firmware_version': CANDIDATE_FIRMWARE,
            'router_host': '10.77.0.1', 'cert_sha256': 'a' * 64,
            'uptime': 1000, 'ready': True, 'protected_ips': ['10.77.0.2'], 'protected_macs': [],
            'clients': [{'macaddr': MAC, 'ipaddr': IP, 'name': 'Disposable endpoint'}],
            'reservations': [{'mac': MAC, 'ip': IP, 'enable': 'on'}],
            'ipscopes': [{'name': 'NP_I_' + SUFFIX, 'scope': f'{IP}-{IP}'}],
            'ipgroups': [{'name': 'NP_G_' + SUFFIX, 'rule_scope': ['NP_I_' + SUFFIX], 'uniq_id': 'synthetic'}],
            'routes': [{'name': 'NP_R_' + SUFFIX, 'mode': 'Priority', 'interfaces': 'WAN1',
                        'src_ipgroup': 'NP_G_' + SUFFIX, 'dst_ipgroup': 'IPGROUP_ANY',
                        'state': 'on', 'service_type': 'ALL', 'timeobj': 'Any', 'comment': 'NetPulse'}],
            'acls': []}


def approval(action='pause', wan='WAN1'):
    return {'confirmed': True, 'mac': MAC, 'ip': IP, 'action': action, 'wan': wan}


class MemoryRouter(RouterTrialAdapter):
    def __init__(self, state):
        self.current = deepcopy(state)
        self.writes = []
        self.lost_ack = False
        self.was_active = False
        self.service_events = []

    def monitor_active(self): return self.was_active
    def quiesce(self): self.service_events.append('stop')
    def resume(self): self.service_events.append('start')

    @contextmanager
    def transaction(self):
        yield

    def snapshot(self):
        return deepcopy(self.current)

    def _set_route(self, old, new):
        index = next(i for i, r in enumerate(self.current['routes']) if r['name'] == old['name'])
        self.current['routes'][index] = deepcopy(new)
        self.writes.append('route')

    def apply(self, plan):
        if plan['approval']['action'] == 'pause':
            self.current['acls'].append(deepcopy(plan['change']))
            self.writes.append('add')
        else:
            self._set_route(plan['before']['routes'][0], plan['change'])
        if self.lost_ack:
            self.lost_ack = False
            raise TimeoutError('synthetic lost acknowledgement')

    def restore(self, plan, current):
        client = SimpleNamespace(delete_acl_pilot_rule=self.delete)
        self.client = client
        return super().restore(plan, current)

    def delete(self, name, expected):
        self.current['acls'] = [r for r in self.current['acls'] if r['name'] != name]
        self.writes.append('delete')


class CandidateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)
        self.directory.chmod(0o700)
        if os.name == 'posix':
            owner = patch('netpulse.router.trial.required_uid', return_value=os.getuid())
            owner.start(); self.addCleanup(owner.stop)
        self.now = 100.0
        self.boot = BOOT
        self.journal = TrialJournal(self.directory / 'journal.json', clock=lambda: self.now,
                                    boot=lambda: self.boot, marker=self.directory / 'pending')
        self.state = snapshot()
        self.adapter = MemoryRouter(self.state)
        self.plan = build_plan(self.state, approval(), acl_name=ACL_NAME)
        self.watchdog = SimpleNamespace(start=Mock(return_value=True))

    def observer(self, plan):
        if plan is None:
            return {'lan_ok': True, 'internet_ipv4_ok': True}
        if plan['approval']['action'] == 'pause':
            return {'lan_ok': True, 'internet_ipv4_ok': False, 'established_blocked': True}
        return {'lan_ok': True, 'egress_wan': plan['approval']['wan'], 'old_wan_leak': False,
                'established_checked': True}

    def test_exact_build_candidate_is_not_production_acceptance(self):
        self.assertEqual(capabilities(CANDIDATE_FIRMWARE), {
            'pause': False, 'only_wan': False, 'group_trial': False, 'candidate_trial': True})
        self.assertFalse(capabilities(CANDIDATE_FIRMWARE + 'x')['candidate_trial'])
        actual_client_shape = deepcopy(self.state)
        actual_client_shape['cert_sha256'] = 'A' * 64  # ER605Client normalizes pins to uppercase.
        actual_client_shape['model'] = 'ER605 v2.30'
        actual_client_shape['hardware_version'] = 'ER605 v2.30'
        self.assertEqual(build_plan(actual_client_shape, approval(), acl_name=ACL_NAME)['before'], actual_client_shape)

    def test_pause_and_each_wan_strict_transition_restore_before_state(self):
        for action, wan in [('pause','WAN1'), ('only_wan','WAN1'), ('only_wan','WAN2')]:
            with self.subTest(action=action, wan=wan):
                plan = build_plan(self.state, approval(action, wan), acl_name=ACL_NAME)
                result = run_trial(plan, self.journal, self.adapter, self.watchdog, self.observer)
                self.assertEqual(self.adapter.current, self.state)
                self.assertFalse(result['production_enabled'])
                self.assertFalse(self.journal.path.exists())
                self.assertFalse(self.journal.marker.exists())

    def test_unknown_schema_identity_protected_or_ambiguous_targets_are_rejected(self):
        changes = [lambda s: s.update(firmware_version='2.4.11'), lambda s: s.update(hardware_version='v2.0'),
                   lambda s: s.update(ready=False), lambda s: s.update(uptime=10),
                   lambda s: s['protected_ips'].append(IP), lambda s: s['protected_macs'].append(MAC),
                   lambda s: s['clients'].append(deepcopy(s['clients'][0])),
                   lambda s: s['reservations'].append(deepcopy(s['reservations'][0])),
                   lambda s: s['routes'][0].update(unreviewed='value'),
                   lambda s: s['acls'].append({'name':'owner ACL'}),
                   lambda s: s['clients'][0].update(name='OnePlus protected phone')]
        for change in changes:
            state = deepcopy(self.state); change(state)
            with self.subTest(state=state), self.assertRaises(CompatibilityError):
                build_plan(state, approval(), acl_name=ACL_NAME)
        bad = approval(); bad['confirmed'] = False
        with self.assertRaises(CompatibilityError): build_plan(self.state, bad, acl_name=ACL_NAME)

    def test_no_watchdog_ack_no_write_and_no_reapply_after_lost_ack(self):
        self.watchdog.start.return_value = False
        with self.assertRaisesRegex(CompatibilityError, 'acknowledge'):
            run_trial(self.plan, self.journal, self.adapter, self.watchdog, self.observer)
        self.assertEqual(self.adapter.writes, [])
        self.watchdog.start.return_value = True
        self.adapter.lost_ack = True
        with self.assertRaises(TimeoutError):
            run_trial(self.plan, self.journal, self.adapter, self.watchdog, self.observer)
        self.assertEqual(self.adapter.writes, ['add', 'delete'])
        self.assertEqual(self.adapter.current, self.state)

    def test_failed_enforcement_still_checks_endpoint_recovery(self):
        calls = []
        def probe(plan):
            calls.append(plan)
            return {'lan_ok': True, 'internet_ipv4_ok': True}
        with self.assertRaisesRegex(CompatibilityError, 'enforcement'):
            run_trial(self.plan, self.journal, self.adapter, self.watchdog, probe)
        self.assertEqual(len(calls), 2)
        self.assertIsNone(calls[-1])
        self.assertEqual(self.adapter.current, self.state)

    def test_changed_owned_object_retains_journal_and_recovery_lock(self):
        def probe(plan):
            self.adapter.current['acls'][0]['policy'] = 'ACCEPT'
            return self.observer(plan)
        with self.assertRaisesRegex(CompatibilityError, 'ambiguous'):
            run_trial(self.plan, self.journal, self.adapter, self.watchdog, probe)
        self.assertTrue(self.journal.path.exists())
        self.assertTrue(self.journal.marker.exists())
        self.assertNotIn('delete', self.adapter.writes)

    def test_clock_change_dead_owner_and_reboot_force_recovery(self):
        record = self.journal.arm(self.plan, 60)
        self.assertFalse(self.journal.due(record, lambda pid: True))
        with patch('time.time', return_value=-10**12):
            self.assertFalse(self.journal.due(record, lambda pid: True))
        self.assertTrue(self.journal.due(record, lambda pid: False))
        self.now = 99
        self.assertTrue(self.journal.due(record, lambda pid: True))
        self.now = 120; self.boot = OTHER_BOOT
        self.assertTrue(self.journal.due(record, lambda pid: True))
        self.adapter.apply(self.plan)
        recover(self.journal, self.adapter)
        recover(self.journal, self.adapter)
        self.assertEqual(self.adapter.current, self.state)

    def test_watchdog_ack_wait_and_abandoned_worker(self):
        self.journal.arm(self.plan, 60)
        def wait(seconds): self.now += seconds
        self.assertTrue(watch(self.journal, sleep=wait, alive=lambda pid: self.now < 102))
        self.assertEqual(self.now, 102)
        self.assertTrue(self.journal.path.with_suffix('.ready').exists())
        recover(self.journal, self.adapter)
        self.assertFalse(self.journal.path.with_suffix('.ready').exists())

    def test_journal_tampering_deadline_bounds_duplicates_and_symlinks(self):
        record = self.journal.arm(self.plan, 60)
        for field, value in [('deadline', 10000), ('owner_pid', True), ('boot','not-a-boot-id')]:
            data = deepcopy(record); data[field] = value
            self.journal.path.write_text(json.dumps(data))
            with self.assertRaises(ValueError): self.journal.read()
        self.journal.path.write_text('{"version":1,"version":1}')
        with self.assertRaisesRegex(CompatibilityError, 'Duplicate'): self.journal.read()
        self.journal.path.write_text(json.dumps(record)); self.journal.path.unlink()
        target = self.directory / 'other'; target.write_text(json.dumps(record)); target.chmod(0o600)
        try: self.journal.path.symlink_to(target)
        except OSError: return  # Windows may not grant symlink creation.
        with self.assertRaises(CompatibilityError): self.journal.read()

    def test_plan_cannot_be_expanded_to_a_different_target_or_route(self):
        plan = deepcopy(self.plan); plan['change']['src'] = 'IPGROUP_ANY'
        with self.assertRaises(CompatibilityError): validate_plan(plan)
        with self.assertRaises(CompatibilityError):
            run_trial(self.plan, self.journal, self.adapter, self.watchdog, None)
        with self.assertRaises(CompatibilityError):
            run_trial(self.plan, self.journal, self.adapter, self.watchdog, self.observer, seconds=61)
        self.assertFalse(self.journal.path.exists())

    def test_failed_endpoint_recovery_retains_an_operator_review_marker(self):
        def probe(plan): return self.observer(plan) if plan else {'lan_ok': False}
        with self.assertRaisesRegex(CompatibilityError, 'unconfirmed'):
            run_trial(self.plan, self.journal, self.adapter, self.watchdog, probe)
        self.assertEqual(self.adapter.current, self.state)
        self.assertTrue(self.journal.marker.exists())
        with self.assertRaisesRegex(CompatibilityError, 'Orphan'):
            recover(self.journal, self.adapter)

    def test_runtime_marker_is_visible_to_ordinary_control_gate(self):
        self.journal.arm(self.plan, 60)
        with patch.object(trial_lock, 'TRIAL_PENDING', self.journal.marker):
            self.assertTrue(trial_lock.trial_recovery_pending())
            recover(self.journal, self.adapter)
            self.assertFalse(trial_lock.trial_recovery_pending())

    def test_independent_process_uses_systemd_and_requires_fixed_journal_paths(self):
        record = self.journal.arm(self.plan, 60)
        with self.assertRaises(CompatibilityError): IndependentWatchdog().start(self.journal, record)
        with patch('tools.router_compat_trial.TRIAL_JOURNAL', self.journal.path), \
             patch('tools.router_compat_trial.TRIAL_PENDING', self.journal.marker), \
             patch('tools.router_compat_trial.subprocess.run', side_effect=[SimpleNamespace(returncode=0),
                                                                          SimpleNamespace(returncode=1)]) as run:
            self.assertFalse(IndependentWatchdog().start(self.journal, record))
        args = run.call_args.args[0]
        self.assertEqual(args[0], 'systemd-run')
        self.assertIn('--property=RuntimeMaxSec=720', args)
        self.assertNotIn('synthetic password', str(args))

    def test_normal_router_route_update_rechecks_current_row_and_uses_current_index(self):
        plan = build_plan(self.state, approval('only_wan','WAN2'))
        client = Mock()
        client.get.return_value = [{'name':'owner row'}, self.state['routes'][0]]
        adapter = RouterTrialAdapter(SimpleNamespace(), protected_ips=[], ready=lambda: True, client=client)
        adapter._set_route(self.state['routes'][0], plan['change'])
        self.assertEqual(client.set_row.call_args.args[:4], ('policy_route','policy_route',1,'key-1'))
        client.get.return_value[1] = {**self.state['routes'][0], 'interfaces':'WAN2'}
        with self.assertRaises(CompatibilityError): adapter._set_route(self.state['routes'][0], plan['change'])

    def test_cli_exposes_no_apply_or_unrestricted_plan_path(self):
        with self.assertRaises(SystemExit): main(['--apply'])
        with self.assertRaises(SystemExit): main(['--journal','arbitrary-file'])

    def test_candidate_does_not_unlock_real_production_controllers(self):
        from tests.test_router_strict_wan import StrictWanControls
        from netpulse.router.pause import PauseControl
        from netpulse.router.control import ControlError
        fixture = StrictWanControls()
        fixture.setUp()
        try:
            fixture.router.snap.firmware_version = CANDIDATE_FIRMWARE
            fixture.control._firmware_store.set('router_firmware_accepted', CANDIDATE_FIRMWARE)
            fixture.control._firmware_store.set('router_firmware_pending', '')
            self.assertFalse(fixture.control.state()['strict_wan_available'])
            with self.assertRaises(ControlError): fixture.control._check_route_capability('WAN1_ONLY')
            pause = PauseControl(fixture.control, fixture.db, enabled=True)
            self.assertFalse(pause.state()['enabled'])
            self.assertFalse(pause.state()['cleanup_enabled'])
            with self.assertRaises(ControlError): pause._ensure_allowed('resume')
        finally:
            fixture.doCleanups()

    def test_router_or_pin_change_retains_exact_undo_journal(self):
        self.journal.arm(self.plan, 60)
        self.adapter.apply(self.plan)
        self.adapter.current['cert_sha256'] = 'b' * 64
        with self.assertRaisesRegex(CompatibilityError, 'identity'):
            recover(self.journal, self.adapter)
        self.assertTrue(self.journal.marker.exists())
        self.assertNotIn('delete', self.adapter.writes)

    def test_installer_stages_recovery_without_enabling_candidate_features(self):
        root = Path(__file__).resolve().parents[1]
        script = (root / 'scripts/install.sh').read_text()
        self.assertLess(script.index('$REPO/tools/router_compat_trial.py'), script.index('systemctl restart netpulse.service'))
        self.assertLess(script.index('$REPO/systemd/netpulse-compat-recovery.service'), script.index('systemctl restart netpulse.service'))
        self.assertNotIn('systemctl enable netpulse-compat-recovery', script)
        unit = (root / 'systemd/netpulse-compat-recovery.service').read_text()
        self.assertIn('Before=netpulse.service', unit)
        self.assertIn('--recover-on-boot', unit)
        self.assertNotIn('After=netpulse.service', unit)

    def test_monitor_restoration_intent_is_journaled_before_shutdown(self):
        self.adapter.was_active = True
        def ready(journal, record):
            self.assertTrue(journal.read()['restart_service'])
            self.assertEqual(self.adapter.service_events, [])
            return True
        self.watchdog.start.side_effect = ready
        self.adapter.lost_ack = True
        with self.assertRaises(TimeoutError):
            run_trial(self.plan, self.journal, self.adapter, self.watchdog, self.observer)
        self.assertEqual(self.adapter.service_events, ['stop', 'start'])
        self.assertEqual(self.adapter.current, self.state)

    def test_boot_and_detached_recovery_entry_points_use_same_exact_restore(self):
        from tools import router_compat_trial as worker
        for mode in ('--watch', '--recover-on-boot'):
            with self.subTest(mode=mode):
                self.journal.arm(self.plan, 60, restart_service=True)
                self.adapter.apply(self.plan)
                with patch.object(worker, 'root_runtime', return_value=True), \
                     patch.object(worker, 'TRIAL_JOURNAL', self.journal.path), \
                     patch.object(worker, 'TRIAL_PENDING', self.journal.marker), \
                     patch.object(worker, 'TrialJournal', return_value=self.journal), \
                     patch.object(worker, 'watch', return_value=True), \
                     patch.object(worker, 'load', return_value=SimpleNamespace()), \
                     patch.object(worker, 'RouterTrialAdapter', return_value=self.adapter), \
                     patch.object(worker, 'service_active', return_value=False), \
                     patch.object(worker.subprocess, 'run') as run:
                    self.assertEqual(worker.main([mode]), 0)
                    if mode == '--watch':
                        self.assertEqual(run.call_args.args[0], ['systemctl', 'start', 'netpulse'])
                    else:
                        run.assert_not_called()
                self.assertEqual(self.adapter.current, self.state)
                self.assertFalse(self.journal.marker.exists())

    def test_expired_endpoint_observation_still_restores_without_a_second_add(self):
        def probe(plan):
            if plan is not None: self.now += 61
            return self.observer(plan)
        with self.assertRaisesRegex(CompatibilityError, 'window'):
            run_trial(self.plan, self.journal, self.adapter, self.watchdog, probe)
        self.assertEqual(self.adapter.writes, ['add','delete'])
        self.assertFalse(self.journal.marker.exists())

    def test_unrelated_concurrent_edit_is_preserved_and_requires_review(self):
        owner_row = {'name':'OWNER_NEW_RULE', 'state':'on'}
        def probe(plan):
            self.adapter.current['routes'].append(owner_row)
            return self.observer(plan)
        with self.assertRaisesRegex(CompatibilityError, 'objects differ'):
            run_trial(self.plan, self.journal, self.adapter, self.watchdog, probe)
        self.assertIn(owner_row, self.adapter.current['routes'])
        self.assertEqual(self.adapter.current['acls'], [])
        self.assertTrue(self.journal.path.exists())
        self.assertTrue(self.journal.marker.exists())

    def test_late_worker_after_safe_cancellation_does_not_create_a_failure_lock(self):
        self.journal.arm(self.plan, 60)
        record = self.journal.read()
        with self.journal.locked(): self.journal.clear(record['nonce'])
        self.assertFalse(watch(self.journal))
        self.assertFalse(self.journal.marker.exists())

    def test_old_recovery_generation_cannot_restore_a_new_trial(self):
        self.journal.arm(self.plan, 60)
        self.adapter.apply(self.plan)
        with self.assertRaisesRegex(CompatibilityError, 'generation'):
            recover(self.journal, self.adapter, expected_nonce=OTHER_BOOT)
        self.assertNotIn('delete', self.adapter.writes)
        self.assertTrue(self.journal.marker.exists())

    def test_rehearsal_entry_point_never_constructs_a_router_client_or_loads_credentials(self):
        from tools import router_compat_trial as worker
        self.journal.arm(self.plan, 60, mode='rehearsal')
        with patch.object(worker, 'root_runtime', return_value=True), \
             patch.object(worker, 'TRIAL_JOURNAL', self.journal.path), \
             patch.object(worker, 'TRIAL_PENDING', self.journal.marker), \
             patch.object(worker, 'TrialJournal', return_value=self.journal), \
             patch.object(worker, 'service_active', return_value=False), \
             patch.object(worker, 'load', side_effect=AssertionError('No config/credentials needed')), \
             patch.object(worker, 'ER605Client', side_effect=AssertionError('No router network allowed')), \
             patch.object(worker, 'RouterTrialAdapter', side_effect=AssertionError('No real adapter allowed')):
            self.assertEqual(worker.main(['--recover-on-boot']), 0)
        self.assertFalse(self.journal.path.exists())
        self.assertFalse(self.journal.marker.exists())

    def test_rehearsal_adapter_refuses_any_mutation_or_changed_state(self):
        adapter = RehearsalAdapter(self.state)
        with self.assertRaises(CompatibilityError): adapter.apply(self.plan)
        changed = deepcopy(self.state); changed['acls'] = [self.plan['change']]
        with self.assertRaises(CompatibilityError): adapter.restore(self.plan, changed)
        adapter.restore(self.plan, self.state)

    def test_marker_removal_failure_retains_exact_recovery_record(self):
        record = self.journal.arm(self.plan, 60)
        original = Path.unlink
        def unlink(path, *args, **kwargs):
            if path == self.journal.marker: raise PermissionError('synthetic sandbox restriction')
            return original(path, *args, **kwargs)
        with patch.object(Path, 'unlink', unlink), self.assertRaises(PermissionError):
            recover(self.journal, self.adapter)
        self.assertEqual(self.journal.read(), record)
        self.assertTrue(self.journal.marker.exists())

    def test_restricted_unit_can_use_root_owned_status_directory(self):
        from netpulse.router.trial_lock import TRIAL_PENDING
        self.assertEqual(str(TRIAL_PENDING).replace('\\', '/'), '/var/lib/netpulse/router-compat-status/pending')
