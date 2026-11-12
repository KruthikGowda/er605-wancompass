"""Observed router accounting: resets, identities, gaps, persistence and API isolation."""
import datetime as dt
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from contextlib import contextmanager
from netpulse.storage.usage import UsageStore, day_bounds
from netpulse.storage.sqlite import Storage
from netpulse.router.usage import UsageCollector
from netpulse.router.er605 import RouterAuthError
from tests.test_router_traffic import FakeClock
from tests import test_pause_http

MAC='02-00-00-00-00-01'
IP='192.0.2.5'
def row(down=100,up=50,kind='wan',identity='WAN1',binding='WAN1',**kw):
    return dict(kind=kind,identity=identity,down=down,up=up,binding=binding,**kw)

class UsageStorageTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.path=str(Path(self.tmp.name)/'usage.db');self.s=UsageStore(self.path)
        self.now=day_bounds('2026-11-12')[0]+3600
    def accept(self,rows,seconds=0,uptime=None,store=None,**kw):
        return (store or self.s).accept(rows,self.now+seconds,100+seconds,1000+seconds if uptime is None else uptime,**kw)
    def daily(self):return self.s.read('2026-11-12',now=self.now+120)['daily']
    def test_baseline_and_exact_rates(self):
        self.assertFalse(self.accept([row()])[('wan','WAN1')]['available'])
        r=self.accept([row(3750100,1875050)],30)[('wan','WAN1')]
        self.assertEqual((r['down_mbps'],r['up_mbps']),(1,.5))
        self.assertEqual(self.daily()[0]['down'],3750000)
        self.assertEqual(self.daily()[0]['seconds'],30)
    def test_64bit_counter_precision(self):
        self.accept([row(2**45,2**45)])
        self.accept([row(2**45+1,2**45+3)],30)
        self.assertEqual((self.daily()[0]['down'],self.daily()[0]['up']),(1,3))
    def test_restart_recovers_baseline_without_recounting(self):
        self.accept([row()]);self.accept([row(200,100)],30)
        other=UsageStore(self.path);self.accept([row(300,150)],60,store=other)
        self.assertEqual(self.daily()[0]['down'],200)
        self.assertFalse(self.accept([row(300,150)],60,store=other)[('wan','WAN1')]['available'])
        self.assertEqual(self.daily()[0]['down'],200)
    def test_reset_and_reboot_do_not_add_bytes(self):
        for seconds,uptime,value in [(0,1000,100),(30,1030,1),(60,3,100)]:
            self.assertFalse(self.accept([row(value,value)],seconds,uptime)[('wan','WAN1')]['available'])
        self.assertEqual(self.daily(),[])
    def test_long_gap_is_not_counted(self):
        self.accept([row()]);self.accept([row(10000,5000)],181)
        self.assertEqual(self.daily(),[])
    def test_clock_correction_is_not_counted(self):
        self.accept([row()]);self.s.accept([row(200,100)],self.now+90,130,1030)
        self.assertEqual(self.daily(),[])
    def test_changed_binding_cannot_inherit_usage(self):
        self.accept([row()]);self.accept([row(200,100,binding='changed')],30)
        self.assertEqual(self.daily(),[])
    def test_impossible_delta_is_rejected(self):
        self.accept([row()]);self.accept([row(100_000_000_000,100)],30)
        self.assertEqual(self.daily(),[])
    def test_stale_native_counter_waits_then_counts_whole_interval(self):
        self.accept([row()]);r=self.accept([row(defer=True)],30)[('wan','WAN1')]
        self.assertFalse(r['available']);self.accept([row(700,350)],60)
        self.assertEqual(self.daily()[0]['down'],600);self.assertEqual(self.daily()[0]['seconds'],60)
    def test_stale_native_counter_rebases_after_reboot_or_gap(self):
        self.accept([row()]);self.accept([row(defer=True)],181,uptime=1181)
        self.accept([row(200,100)],211,uptime=1211)
        self.assertEqual(self.daily()[0]['seconds'],30)
    def test_midnight_conserves_all_bytes_and_marks_estimate(self):
        self.now=day_bounds('2026-11-12')[1]-10
        self.accept([row()]);self.accept([row(201,101)],30)
        rows=self.daily()+self.s.read('2026-11-13',now=self.now+30)['daily']
        self.assertEqual(sum(r['down'] for r in rows),101)
        self.assertEqual(sum(r['up'] for r in rows),51)
        self.assertEqual(sum(r['seconds'] for r in rows),30)
        self.assertTrue(all(r['estimated'] for r in rows))
    def test_missing_device_invalidates_only_its_baseline(self):
        device=row(kind='device',identity=MAC,binding=IP)
        self.accept([row(),device],device_poll=True)
        self.accept([row(200,100)],30,device_poll=True)
        r=self.accept([{**device,'down':10000}],60,device_poll=True)
        self.assertFalse(r[('device',MAC)]['available'])
        self.assertEqual(len(self.daily()),1)
    def test_missing_wan_requires_new_baseline(self):
        self.accept([row()]);self.s.invalidate('wan',{'WAN1'})
        self.assertFalse(self.accept([row(200,100)],30)[('wan','WAN1')]['available'])
    def test_history_distributes_slow_refresh_over_observed_buckets(self):
        self.accept([row()]);self.accept([row(6000100,3000050)],60)
        points=self.s.read('2026-11-12',.25,now=self.now+60)['points']
        self.assertEqual(sum(p['seconds'] for p in points),60)
        self.assertTrue(all(p['seconds']<=15 for p in points))
        self.assertTrue(all(p['down_mbps']==.8 for p in points))

class Client:
    def __init__(self,clock):self.clock=clock;self.calls=[];self.value=100;self.fail=None;self.duplicate=False
    @contextmanager
    def session(self):yield self
    def public_info(self):return {'uptime':1000+int(self.clock.mono-100)}
    def get(self,module,form,*args):
        self.calls.append((module,form))
        if self.fail=='auth':raise RouterAuthError('private data')
        if module=='ifstat' and form=='switch':return {'status':'on'}
        if module=='ifstat':return [{'interface':name,'rx_bytes':self.value,'tx_bytes':self.value//2} for name in ('WAN1','WAN/LAN2')]
        if module=='dhcps':return [{'macaddr':MAC,'ipaddr':IP}]*(2 if self.duplicate else 1)
        if module=='ipstats' and self.fail=='device':raise ValueError('private data')
        if form=='setting':return {'status':'on'}
        return [{'addr':IP,'rx_bytes':str(self.value),'tx_bytes':str(self.value//2)}]

class UsageCollectorTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.path=str(Path(self.tmp.name)/'usage.db');Storage(self.path).close()
        self.clock=FakeClock();self.client=Client(self.clock)
        self.watch=SimpleNamespace(client=self.client,api_lock=threading.RLock(),poll_seconds=600,
            snap=SimpleNamespace(checked_at=self.clock.time(),ok=True,error=''))
        self.c=UsageCollector(self.watch,self.path,['WAN1','WAN2'],self.clock.time,self.clock.monotonic)
    def advance(self,seconds=30):self.clock.sleep(seconds);self.client.value+=1000;self.c.poll()
    def test_interface_mapping_and_direction(self):
        rows=UsageCollector.wan_counters([{'interface':'WAN/LAN2','rx_bytes':2**40,'tx_bytes':'100'}],['WAN2'])
        self.assertEqual((rows['WAN2']['down'],rows['WAN2']['up']),(2**40,100))
        for v in (True,-1,'NaN',float('inf')):
            self.assertEqual(UsageCollector.wan_counters([{'interface':'WAN1','rx_bytes':v,'tx_bytes':1}],['WAN1']),{})
        with self.assertRaises(ValueError):UsageCollector.wan_counters([{'interface':'WAN1'}]*2,['WAN1'])
    def test_snapshot_never_polls_router_and_hides_stale_rates(self):
        self.c.poll();self.advance(60);calls=len(self.client.calls)
        report=self.c.snapshot();self.assertTrue(report['available']);self.assertEqual(len(report['devices']),1)
        self.c.snapshot();self.assertEqual(len(self.client.calls),calls)
        self.clock.sleep(121);report=self.c.snapshot()
        self.assertFalse(report['available']);self.assertIsNone(report['wans'][0]['down_mbps'])
        self.assertFalse(report['devices'][0]['available']);self.assertFalse(report['accounting_complete'])
    def test_pause_guard_and_error_redaction(self):
        self.watch._paused_until=self.clock.time()+60;self.c.poll();self.assertEqual(self.client.calls,[])
        self.clock.sleep(61);self.client.fail='auth';self.c.poll();calls=len(self.client.calls)
        self.clock.sleep(60);self.c.poll();self.assertEqual(len(self.client.calls),calls)
        self.assertNotIn('private data',str(self.c.snapshot()))
    def test_device_failure_does_not_discard_wan_observations(self):
        self.c.poll();self.client.fail='device';self.advance(60)
        report=self.c.snapshot();self.assertTrue(report['available']);self.assertEqual(report['devices'],[])
        self.assertIn('failed',report['device_reason'])
    def test_duplicate_dhcp_identity_excluded(self):
        self.client.duplicate=True;self.c.poll();self.advance(60)
        self.assertEqual(self.c.snapshot()['devices'],[])
    def test_poll_throttle_uses_monotonic_clock(self):
        self.c.poll();calls=len(self.client.calls);self.clock.wall+=3600;self.c.poll()
        self.assertEqual(len(self.client.calls),calls)
    def test_invalid_queries(self):
        for kwargs in ({'day':'invalid'},{'day':'2999-01-01'},{'hours':float('nan')},{'hours':25},{'ranking':'bad'}):
            with self.subTest(kwargs=kwargs),self.assertRaises(ValueError):self.c.snapshot(**kwargs)

class UsageHttpTests(unittest.TestCase):
    setUp=test_pause_http.PauseHttp.setUp
    request=test_pause_http.PauseHttp.request
    def test_authentication_disabled_and_validation(self):
        self.assertEqual(self.request('GET','/api/usage',auth=False)[0],401)
        self.assertFalse(self.request('GET','/api/usage')[1]['enabled'])
        class ReadOnly:
            def snapshot(self,day,hours,ranking):
                if hours!=1:raise ValueError('invalid')
                return {'wans':[],'available':False}
        self.board.set_extra('usage_collector',ReadOnly())
        self.assertEqual(self.request('GET','/api/usage?hours=nan')[0],400)
        self.assertTrue(self.request('GET','/api/usage')[1]['enabled'])
