"""Four-object preparation recovery uses synthetic state; never a live endpoint."""
from contextlib import contextmanager
from copy import deepcopy
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from netpulse.router.compatibility import CompatibilityError
from netpulse.router.preparation import (preparation_plan, validate_preparation, COLLECTIONS,
                                         FORMS, run_preparation, matches_object)
from netpulse.router.trial import TrialJournal, recover
from netpulse.router.er605 import ER605Client, RouterError
from tools import router_compat_trial as worker
from tests.test_router_compat_trial import snapshot, MAC, IP, BOOT


def before_state():
    result = snapshot()
    for key in COLLECTIONS: result[key] = []
    result['lan_scopes'] = [{'name':'IP_LAN','scope':'10.77.0.0/24'}]
    result['lan'] = {'ipRangePool':[{'start':'10.77.0.10','end':'10.77.0.240'}]}
    return result


def review():
    return {'confirmed':True,'mac':MAC,'ip':IP,'wan':'WAN1','note':'NetPulse: Disposable trial'}


class MemoryPreparation:
    def __init__(self,state,journal):
        self.current = deepcopy(state); self.journal = journal
        self.created = []; self.deleted = []; self.fail_before = None; self.fail_after = None
        self.delete_lost_ack = False; self.change_receipt = False; self.active = False; self.service = []
    @contextmanager
    def transaction(self): yield
    def snapshot(self): return deepcopy(self.current)
    def monitor_active(self): return self.active
    def quiesce(self): self.service.append('stop')
    def resume(self): self.service.append('start')
    def create_preparation_object(self,i,obj):
        record = self.journal.read()
        assert record['inflight'] == i and len(record['receipts']) == i, 'intent must precede RPC'
        if self.fail_before == i: raise TimeoutError('synthetic rejected/unknown add')
        row = deepcopy(obj); row['id'] = str(100+i)
        if i == 2: row['uniq_id'] = 'synthetic-group-identity'
        self.current[COLLECTIONS[i]].append(row); self.created.append(i)
        if self.change_receipt: row['unreviewed_field'] = 'unsafe'
        if self.fail_after == i: raise TimeoutError('synthetic lost add acknowledgment')
        return row
    def delete_preparation_object(self,i,row):
        record = self.journal.read()
        assert i < len(record['receipts']), 'exact receipt must be durable before delete'
        self.current[COLLECTIONS[i]].remove(row); self.deleted.append(i)
        if self.delete_lost_ack:
            self.delete_lost_ack = False
            raise TimeoutError('synthetic lost delete acknowledgment')


class PreparationTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.root = Path(temp.name); self.root.chmod(0o700)
        if os.name == 'posix':
            check = patch('netpulse.router.trial.required_uid',return_value=os.getuid())
            check.start(); self.addCleanup(check.stop)
        self.now = 100.0
        self.journal = TrialJournal(self.root/'journal.json',clock=lambda:self.now,boot=lambda:BOOT,marker=self.root/'pending')
        self.before = before_state(); self.plan = preparation_plan(self.before,review())
        self.adapter = MemoryPreparation(self.before,self.journal)
        self.watchdog = SimpleNamespace(start=Mock(return_value=True))

    def run_plan(self):
        return run_preparation(self.plan,self.journal,self.adapter,self.watchdog)

    def seed(self,count,lost_ack=False):
        record = self.journal.arm(self.plan,180,mode='rehearsal')
        for i in range(count):
            next_record = deepcopy(record);next_record['inflight'] = i
            with self.journal.locked():self.journal.replace(next_record,record)
            record = next_record
            self.adapter.create_preparation_object(i,self.plan['objects'][i])
            if not (lost_ack and i == count-1):
                next_record = deepcopy(record);next_record['receipts'].append(deepcopy(self.adapter.current[COLLECTIONS[i]][-1]))
                with self.journal.locked():self.journal.replace(next_record,record)
                record = next_record
        return record

    def test_complete_transaction_tears_down_in_dependency_order(self):
        self.adapter.active = True
        result = self.run_plan()
        self.assertFalse(result['production_enabled'])
        self.assertEqual(self.adapter.created,[0,1,2,3])
        self.assertEqual(self.adapter.deleted,[3,2,1,0])
        self.assertEqual(self.adapter.current,self.before)
        self.assertEqual(self.adapter.service,['stop','start'])
        self.assertFalse(self.journal.marker.exists())

    def test_every_add_failure_before_or_after_acknowledgment_restores_only_created_prefix(self):
        for i in range(4):
            for after in (False,True):
                with self.subTest(index=i,lost_ack=after):
                    self.adapter = MemoryPreparation(self.before,self.journal)
                    if after:self.adapter.fail_after = i
                    else:self.adapter.fail_before = i
                    with self.assertRaises(TimeoutError): self.run_plan()
                    expected = list(range(i+1 if after else i))
                    self.assertEqual(self.adapter.created,expected)
                    self.assertEqual(self.adapter.deleted,list(reversed(expected)))
                    self.assertEqual(self.adapter.current,self.before)
                    self.assertFalse(self.journal.path.exists())

    def test_crash_recovery_for_every_durable_prefix_and_unknown_add_outcome(self):
        for count in range(1,5):
            for lost in (False,True):
                self.adapter = MemoryPreparation(self.before,self.journal)
                self.seed(count,lost)
                recover(self.journal,self.adapter)
                recover(self.journal,self.adapter)
                self.assertEqual(self.adapter.deleted,list(reversed(range(count))))
                self.assertEqual(self.adapter.current,self.before)

    def test_unknown_readback_or_changed_generated_identity_retains_lock_without_deletion(self):
        self.adapter.change_receipt = True
        with self.assertRaises(CompatibilityError):self.run_plan()
        self.assertEqual(self.adapter.deleted,[])
        self.assertTrue(self.journal.marker.exists())
        # A separate case starts with a clean owned receipt then changes its ID.
        self.adapter.current = deepcopy(self.before)
        with self.journal.locked():self.journal.clear(self.journal.read()['nonce'])
        self.adapter.change_receipt = False
        self.seed(1)
        self.adapter.current['reservations'][0]['id'] = '999'
        with self.assertRaises(CompatibilityError):recover(self.journal,self.adapter)
        self.assertEqual(self.adapter.deleted,[])

    def test_lost_delete_acknowledgment_is_idempotent_without_recreating_rows(self):
        self.seed(4);self.adapter.delete_lost_ack = True
        with self.assertRaises(TimeoutError):recover(self.journal,self.adapter)
        self.assertTrue(self.journal.path.exists())
        recover(self.journal,self.adapter)
        self.assertEqual(self.adapter.deleted,[3,2,1,0])
        self.assertEqual(self.adapter.created,[0,1,2,3])
        self.assertEqual(self.adapter.current,self.before)

    def test_foreign_change_or_duplicate_prevents_cleanup_and_is_preserved(self):
        self.seed(2)
        owner = {'name':'OWNER_SCOPE','scope':'10.77.0.90-10.77.0.90'}
        self.adapter.current['ipscopes'].append(owner)
        with self.assertRaises(CompatibilityError):recover(self.journal,self.adapter)
        self.assertIn(owner,self.adapter.current['ipscopes'])
        self.assertEqual(self.adapter.deleted,[])
        self.adapter.current['ipscopes'].remove(owner)
        self.adapter.current['reservations'].append(deepcopy(self.adapter.current['reservations'][0]))
        with self.assertRaises(CompatibilityError):recover(self.journal,self.adapter)
        self.assertEqual(self.adapter.deleted,[])

    def test_existing_or_referenced_objects_are_never_adopted(self):
        for i,key in enumerate(COLLECTIONS):
            changed = deepcopy(self.before);changed[key].append(deepcopy(self.plan['objects'][i]))
            with self.assertRaises(CompatibilityError):preparation_plan(changed,review())
        changed = deepcopy(self.before)
        changed['ipgroups'].append({'name':'OWNER_GROUP','rule_scope':[self.plan['objects'][1]['name']]})
        with self.assertRaises(CompatibilityError):preparation_plan(changed,review())

    def test_lan_pool_identity_and_approval_fail_closed(self):
        for change in (lambda b:b['lan'].update(ipRangePool=[]),
                       lambda b:b['lan'].update(ipaddr_start='10.77.0.1'),
                       lambda b:b['lan'].update(ipRangePool=[{'start':'10.77.0.200','end':'10.77.0.240'}]),
                       lambda b:b.update(firmware_version='unreviewed'),
                       lambda b:b.update(preparation_blocked_macs=[MAC]),
                       lambda b:b['protected_ips'].append(IP)):
            changed = deepcopy(self.before);change(changed)
            with self.assertRaises(CompatibilityError):preparation_plan(changed,review())
        changed = review();changed['confirmed'] = False
        with self.assertRaises(CompatibilityError):preparation_plan(self.before,changed)

    def test_journal_progress_cannot_skip_or_rewrite_approval(self):
        record = self.journal.arm(self.plan,180)
        changed = deepcopy(record);changed['inflight'] = 2
        with self.assertRaises(CompatibilityError):self.journal.replace(changed,record)
        changed = deepcopy(record);changed['deadline'] += 1
        with self.assertRaises(CompatibilityError):self.journal.replace(changed,record)
        changed = deepcopy(record);changed['plan']['objects'][3]['mode'] = 'Only'
        with self.assertRaises(CompatibilityError):self.journal.replace(changed,record)

    def test_no_watchdog_or_expired_preflight_never_leaves_preparation(self):
        self.watchdog.start.return_value = False
        with self.assertRaises(CompatibilityError):self.run_plan()
        self.assertEqual(self.adapter.created,[])
        self.watchdog.start.side_effect = lambda journal,record:setattr(self,'now',1000) or True
        with self.assertRaises(CompatibilityError):self.run_plan()
        self.assertEqual(self.adapter.created,[])

    def test_receipt_persistence_failure_after_write_is_recovered_from_inflight(self):
        original = self.journal.replace;failed = False
        def replace(new,old):
            nonlocal failed
            if len(new['receipts'])==2 and not failed:
                failed = True;raise OSError('synthetic disk failure before receipt persist')
            return original(new,old)
        with patch.object(self.journal,'replace',side_effect=replace), self.assertRaises(OSError):self.run_plan()
        self.assertEqual(self.adapter.deleted,[1,0])
        self.assertEqual(self.adapter.current,self.before)

    def test_rehearsal_boot_worker_cleans_persisted_synthetic_prefix_without_router_client(self):
        self.seed(4,lost_ack=True)
        fixture = self.journal.path.with_name('rehearsal-state.json')
        fixture.write_text(json.dumps(self.adapter.current));fixture.chmod(0o600)
        with patch.object(worker,'root_runtime',return_value=True), \
             patch.object(worker,'TRIAL_JOURNAL',self.journal.path), \
             patch.object(worker,'TRIAL_PENDING',self.journal.marker), \
             patch.object(worker,'TrialJournal',return_value=self.journal), \
             patch.object(worker,'service_active',return_value=False), \
             patch.object(worker,'ER605Client',side_effect=AssertionError('No router network')), \
             patch.object(worker,'load',side_effect=AssertionError('No live configuration')):
            self.assertEqual(worker.main(['--recover-on-boot']),0)
        self.assertEqual(json.loads(fixture.read_text()),self.before)
        self.assertFalse(self.journal.marker.exists())

    def test_exact_delete_protocol_uses_current_numeric_id_and_preserves_foreign_rows(self):
        client = ER605Client('192.0.2.1','synthetic','synthetic','A'*64);client._stok = 'synthetic'
        row = deepcopy(self.plan['objects'][0]);row['id'] = '123'
        other = {'id':'321','mac':'02-00-00-00-00-22','ip':'10.77.0.22'}
        with patch.object(client,'get',side_effect=[[other,row],[other]]), \
             patch.object(client,'_post',return_value={'error_code':'0'}) as post:
            client.delete_exact_preparation_row(*FORMS[0],row)
            params = json.loads(post.call_args.args[1]['data'])['params']
            self.assertEqual(params,{'index':'1','key':'123'})
        changed = {**row,'note':'owner changed this'}
        with patch.object(client,'get',return_value=[changed]),patch.object(client,'_post') as post:
            with self.assertRaises(RouterError):client.delete_exact_preparation_row(*FORMS[0],row)
            post.assert_not_called()

    def test_observed_2410_metadata_and_derived_reference_counts_survive_full_lifecycle(self):
        self.before['ipgroups'].append({'name':'IPGROUP_ANY','ref':'100'})
        self.plan = preparation_plan(self.before,review())
        journal = self.journal
        class FirmwareShape(MemoryPreparation):
            def create_preparation_object(inner,i,obj):
                row = super().create_preparation_object(i,obj)
                if i==0:row.update(ip_bind='on',dhcp_option_bind='off')
                if i==1:
                    row.pop('scope_start');row.pop('scope_end')
                    row.update({'.anonymous':False,'.type':'rule_ipscope','.name':'synthetic-scope-id'})
                if i==2:
                    row.pop('comment');row.update({'.anonymous':False,'.type':'rule_ipgroup',
                                                  '.name':'synthetic-group-id','ref':'0'})
                if i==3:
                    row['t_label']='WAN1'
                    inner.current['ipgroups'][0]['ref']='101'
                    inner.current['ipgroups'][1]['ref']='1'
                return row
            def delete_preparation_object(inner,i,row):
                super().delete_preparation_object(i,row)
                if i==3:
                    inner.current['ipgroups'][0]['ref']='100'
                    inner.current['ipgroups'][1]['ref']='0'
        self.adapter = FirmwareShape(self.before,journal)
        self.run_plan()
        self.assertEqual(self.adapter.current,self.before)
        self.assertEqual(self.adapter.deleted,[3,2,1,0])

    def test_non_neutral_or_unknown_firmware_metadata_is_not_discarded(self):
        for i,metadata in ((0,{'dhcp_option_bind':'on'}),(1,{'.anonymous':True}),
                           (2,{'.type':'different-rule'}),(3,{'t_label':'wrong WAN label'})):
            row = {**self.plan['objects'][i],**metadata,'id':'100'}
            self.assertFalse(matches_object(i,row,self.plan['objects'][i]))

    def test_unreadable_existing_route_priority_prevents_preparation_plan(self):
        self.before['routes'].append({'name':'OWNER_ROUTE','index':'not-an-index'})
        with self.assertRaises(CompatibilityError):preparation_plan(self.before,review())

    def pause_bundle(self):
        self.plan=preparation_plan(self.before,review(),pause_name='NP_TEST_P_'+'B'*32)
        parent=self
        class WithPause(MemoryPreparation):
            fail_pause_ack=False
            def create_pause_rule(inner,row):
                saved=parent.journal.read()
                assert saved['pause_intent'] and saved['pause_deadline']<=parent.now+60
                inner.current['acls'].append(deepcopy(row))
                if inner.fail_pause_ack:raise TimeoutError('synthetic lost child add acknowledgment')
            def delete_pause_rule(inner,row):
                assert parent.journal.read()['pause_receipt'] is not None
                inner.current['acls'].remove(row);inner.deleted.append('pause')
        self.adapter=WithPause(self.before,self.journal)
        return SimpleNamespace(prepared=lambda:{'internet_ipv4_ok':True,'lan_ok':True,'wan1_verified':True},
                               blocked=lambda:{'internet_ipv4_ok':False,'lan_ok':True},
                               resumed=lambda:{'internet_ipv4_ok':True,'lan_ok':True})

    def test_combined_pause_uses_one_journal_and_removes_acl_before_setup(self):
        probe=self.pause_bundle()
        run_preparation(self.plan,self.journal,self.adapter,self.watchdog,probe=probe)
        self.assertEqual(self.adapter.deleted,['pause',3,2,1,0])
        self.assertEqual(self.adapter.current,self.before)
        self.assertFalse(self.journal.marker.exists())

    def test_failed_baseline_never_adds_acl_and_rolls_back_setup(self):
        probe=self.pause_bundle();probe.prepared=lambda:{'internet_ipv4_ok':True,'lan_ok':True,'wan1_verified':False}
        with self.assertRaisesRegex(CompatibilityError,'WAN1 baseline'):
            run_preparation(self.plan,self.journal,self.adapter,self.watchdog,probe=probe)
        self.assertEqual(self.adapter.deleted,[3,2,1,0])
        self.assertEqual(self.adapter.current,self.before)

    def test_lost_child_add_ack_and_failed_block_observation_restore_everything(self):
        for lost in (True,False):
            probe=self.pause_bundle();self.adapter.fail_pause_ack=lost
            if not lost:probe.blocked=lambda:{'internet_ipv4_ok':True,'lan_ok':True}
            with self.assertRaises((TimeoutError,CompatibilityError)):
                run_preparation(self.plan,self.journal,self.adapter,self.watchdog,probe=probe)
            self.assertEqual(self.adapter.deleted,['pause',3,2,1,0])
            self.assertEqual(self.adapter.current,self.before)

    def test_watcher_follows_durable_setup_progress_and_child_deadline(self):
        from tools.router_compat_trial import watch
        probe=self.pause_bundle()
        record=self.journal.arm(self.plan,180,mode='rehearsal')
        def advance(seconds):
            self.now+=seconds
            old=self.journal.read();n=len(old['receipts'])
            if n<4:
                new=deepcopy(old);new['inflight']=n
                with self.journal.locked():self.journal.replace(new,old)
                row={**self.plan['objects'][n],'id':str(100+n)}
                newer=deepcopy(new);newer['receipts'].append(row)
                with self.journal.locked():self.journal.replace(newer,new)
            elif not old['pause_intent']:
                new=deepcopy(old);new.update(pause_intent=True,pause_deadline=self.now+3)
                with self.journal.locked():self.journal.replace(new,old)
        self.assertTrue(watch(self.journal,sleep=advance,alive=lambda pid:True))
        self.assertLess(self.now,120)

    def test_child_deadline_cannot_be_extended(self):
        self.pause_bundle();record=self.journal.arm(self.plan,180)
        for i,obj in enumerate(self.plan['objects']):
            new=deepcopy(record);new['inflight']=i
            with self.journal.locked():self.journal.replace(new,record)
            record=new;new=deepcopy(record);new['receipts'].append({**obj,'id':str(100+i)})
            with self.journal.locked():self.journal.replace(new,record)
            record=new
        new=deepcopy(record);new.update(pause_intent=True,pause_deadline=self.now+60)
        with self.journal.locked():self.journal.replace(new,record)
        changed=deepcopy(new);changed['pause_deadline']+=1
        with self.journal.locked(),self.assertRaises(CompatibilityError):self.journal.replace(changed,new)
