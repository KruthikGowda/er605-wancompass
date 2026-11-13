"""Synthetic socket evidence and local-only barrier checks; no phone or router."""
from copy import deepcopy
import json
import queue
import shlex
import shutil
import subprocess
import tempfile
from pathlib import Path
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from types import SimpleNamespace
import threading
import time
import unittest
import urllib.error
import urllib.request
from unittest.mock import Mock,patch

from tools import adb_flow_probe as flow
from tools.router_acl_pilot import EndpointProbe,PROBE_PATH

PHONE='10.77.0.11'


def metrics(**updates):
    return {'code':'200','connects':'1','local_ip':PHONE,'local_port':'40123',
            'remote_ip':'8.8.8.8','remote_port':'443','http_version':'1.1',**updates}


def frame(**updates):
    return flow.parse_frame('{"ip":"1.1.1.1"}',metrics(**updates),PHONE)


def report(phase='blocked',**updates):
    value={'phase':phase,'internet_ipv4_ok':True,'lan_ok':True,'public_ip':'1.1.1.1',
           'transport':'native_curl','checks':{'ipify':False,'cloudflare':False},
           'flow':{'prepared_new_connection':True,'reuse_confirmed':True,
                   'existing_request_ok':True,'fresh_processes_verified':True,
                   'existing_result_conclusive':True}}
    value.update(updates);return value


class NativeEvidenceTests(unittest.TestCase):
    def test_fresh_socket_is_bound_ipv4_tls_http11_and_pinned(self):
        output='{"ip":"1.1.1.1"}\n'+flow.MARKER+json.dumps(metrics())+'\n'
        runner=Mock(return_value=SimpleNamespace(stdout=output,returncode=0))
        result=flow.fresh_request('synthetic-serial',PHONE,flow.IPIFY,pin='8.8.8.8',runner=runner)
        self.assertTrue(result['ok']);args=shlex.split(runner.call_args.args[0][-1])
        self.assertIn('--ipv4',args);self.assertIn('--http1.1',args)
        self.assertEqual(args[args.index('--interface')+1],PHONE)
        self.assertEqual(args[args.index('--resolve')+1],'api4.ipify.org:443:8.8.8.8')
        self.assertNotIn('--insecure',args);self.assertNotIn('-k',args)
        runner.return_value.stdout=output.replace('"connects": "1"','"connects": "0"')
        with self.assertRaises(flow.ProbeError):
            flow.fresh_request('synthetic-serial',PHONE,flow.IPIFY,runner=runner)

    def test_socket_identity_tls_http_and_output_ambiguity_fail_closed(self):
        for update in ({'local_ip':'10.77.0.12'},{'remote_ip':'127.0.0.1'},
                       {'local_port':'0'},{'remote_port':'80'},{'http_version':'2'},
                       {'code':'503'},{'connects':'-1'},{'local_port':'99999'}):
            with self.subTest(update=update),self.assertRaises(flow.ProbeError):frame(**update)
        for text in ('no metrics',flow.MARKER+'{}'+flow.MARKER+'{}','x'*9000):
            with self.assertRaises(flow.ProbeError):flow.split_frame(text,PHONE)
        with self.assertRaises(flow.ProbeError):flow.parse_frame('not JSON',metrics(),PHONE)

    def test_only_transport_failures_can_be_observed_as_unreachable(self):
        failed=metrics(code='000',connects='0',local_ip='',local_port='0',remote_ip='',remote_port='0',http_version='0')
        result=flow.parse_frame('',failed,PHONE,exit_code=28)
        self.assertFalse(result['ok'])
        for code in (6,22,45,60,127):
            with self.subTest(code=code),self.assertRaises(flow.ProbeError):
                flow.parse_frame('',failed,PHONE,exit_code=code)
        with self.assertRaises(flow.ProbeError):flow.parse_frame('',metrics(code='403'),PHONE,exit_code=22)

    def test_connection_reuse_requires_zero_connects_and_same_socket(self):
        first=frame();second=frame(connects='0');evidence=flow.classify_reuse(first,second)
        self.assertTrue(evidence['reuse_confirmed']);self.assertTrue(evidence['existing_request_ok'])
        for changed in ({'connects':'1'},{'local_port':'40124'},{'remote_ip':'1.0.0.1'}):
            with self.subTest(changed=changed),self.assertRaises(flow.ProbeError):
                flow.classify_reuse(first,frame(**{'connects':'0',**changed}))

    def test_surviving_reused_flow_cannot_be_reported_as_successful_block(self):
        good=report();self.assertEqual(flow.validate_native_report(good)['flow'],good['flow'])
        bad=deepcopy(good);bad['internet_ipv4_ok']=False
        with self.assertRaises(flow.ProbeError):flow.validate_native_report(bad)
        for key in ('prepared_new_connection','fresh_processes_verified','existing_result_conclusive','reuse_confirmed'):
            bad=deepcopy(good);bad['flow'][key]=False
            with self.subTest(key=key),self.assertRaises(flow.ProbeError):flow.validate_native_report(bad)

    def test_baseline_needs_both_destinations_and_prepared_needs_open_flow(self):
        for phase in ('baseline','prepared','recovery','restored'):
            good=report(phase,checks={'ipify':True,'cloudflare':True})
            flow.validate_native_report(good)
            good['checks']['cloudflare']=False
            with self.assertRaises(flow.ProbeError):flow.validate_native_report(good)
        bad=report('prepared',checks={'ipify':True,'cloudflare':True});bad['flow']['prepared_new_connection']=False
        with self.assertRaises(flow.ProbeError):flow.validate_native_report(bad)

    @patch.object(flow,'adb_shell')
    @patch.object(flow,'check_phone')
    def test_native_runner_refuses_browser_endpoint_without_external_probe(self,check,adb):
        adb.return_value=SimpleNamespace(stdout=json.dumps({'phase':'baseline','expires_in':50}),returncode=0)
        with patch.object(flow,'fresh_request') as external:
            with self.assertRaises(flow.ProbeError):
                flow.run_probe('http://10.77.0.2:12345/probe/?t=synthetic-token','serial','02-00-00-00-00-11',PHONE)
        check.assert_called_once();external.assert_not_called()

    def test_persistent_command_has_one_process_three_operations_and_no_tls_bypass(self):
        import io
        fake=SimpleNamespace(stdout=io.StringIO(''),poll=Mock(return_value=0))
        popen=Mock(return_value=fake)
        probe=flow.ReusedRequest('synthetic-serial',PHONE,'http://10.77.0.2:12345','synthetic-token','8.8.8.8',popen=popen)
        probe.reader.join(1);args=shlex.split(popen.call_args.args[0][-1]);probe.close()
        self.assertEqual(args.count('--next'),2);self.assertEqual(args.count('--http1.1'),3)
        self.assertIn('--fail-early',args);self.assertNotIn('--insecure',args)
        self.assertEqual(args.count('--resolve'),2)

    @patch.object(flow,'check_phone')
    def test_reporter_keeps_surviving_reuse_visible_and_allows_original_dual_wan_egress(self,check):
        phases=['baseline','prepared','blocked','restored'];index=[0];posted=[]
        def pi(serial,ip,url,**kwargs):
            if 'payload' in kwargs:
                posted.append(kwargs['payload']);index[0]+=1;return ''
            return json.dumps({'phase':phases[index[0]],'native_flow':True,'expires_in':200})
        def fresh(serial,ip,url,**kwargs):
            if phases[index[0]]=='blocked':return {'ok':False,'public_ip':None}
            result=frame()
            if phases[index[0]] in {'baseline','restored'} and url.startswith(flow.CLOUDFLARE):
                result['public_ip']='8.8.8.8'
            return result
        persistent=SimpleNamespace(first=Mock(return_value=frame()),finish=Mock(return_value=frame(connects='0')),close=Mock())
        recorder=Mock()
        with patch.object(flow,'_pi',side_effect=pi),patch.object(flow,'fresh_request',side_effect=fresh),\
                patch.object(flow,'ReusedRequest',return_value=persistent):
            result=flow.run_probe('http://10.77.0.2:12345/probe/?t=synthetic-token','serial','02-00-00-00-00-11',PHONE,record=recorder)
        self.assertEqual(set(result),set(phases))
        self.assertTrue(result['blocked']['internet_ipv4_ok'])
        self.assertTrue(result['blocked']['flow']['reuse_confirmed'])
        self.assertFalse(any(result['blocked']['checks'].values()))
        self.assertEqual(check.call_count,5);persistent.close.assert_called_once()
        self.assertEqual(recorder.call_count,8)
        self.assertFalse(recorder.call_args_list[0].args[1]['accepted_by_pi'])
        self.assertTrue(recorder.call_args_list[1].args[1]['accepted_by_pi'])
        self.assertIn('existing_after',recorder.call_args_list[4].args[1]['socket_evidence'])

    def test_wrong_phone_never_reaches_pi_or_public_targets(self):
        with patch.object(flow,'check_phone',side_effect=flow.ProbeError('identity mismatch')),\
                patch.object(flow,'_pi') as pi,patch.object(flow,'fresh_request') as public:
            with self.assertRaises(flow.ProbeError):
                flow.run_probe('http://10.77.0.2:12345/probe/?t=synthetic-token','serial','02-00-00-00-00-11',PHONE)
        pi.assert_not_called();public.assert_not_called()

    def test_cli_retains_private_partial_evidence_when_reporting_stops(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);identity=root/'identity.json';url=root/'url.txt';output=root/'result.json'
            identity.write_text(json.dumps({'serial':'synthetic-serial','mac':'02-00-00-00-00-11','ip':PHONE}))
            url.write_text('http://10.77.0.2:12345/probe/?t=synthetic-token')
            def stopped(*args,record,**kwargs):
                record('blocked',{'accepted_by_pi':False,'socket_evidence':{'fresh':frame()}})
                raise flow.ProbeError('synthetic disconnect')
            with patch.object(flow,'run_probe',side_effect=stopped),patch('builtins.print'):
                self.assertEqual(flow.main(['--identity-file',str(identity),'--url-file',str(url),'--output',str(output)]),2)
            result=json.loads(output.read_text());self.assertEqual(result['status'],'inconclusive')
            self.assertFalse(result['phases']['blocked']['accepted_by_pi'])
            self.assertFalse((root/'.result.json.native-partial').exists())


class NativeBarrierTests(unittest.TestCase):
    def setUp(self):
        self.probe=EndpointProbe('127.0.0.1','127.0.0.1',60,include_egress=True,native_flow=True)
        self.addCleanup(self.probe.close)
        self.base=f'http://127.0.0.1:{self.probe.server.server_address[1]}'
        self.suffix='?t='+self.probe.token

    def submit(self,data):
        request=urllib.request.Request(self.base+'/report'+self.suffix,data=json.dumps(data).encode(),
            headers={'Origin':self.base,'Content-Type':'application/json'},method='POST')
        return urllib.request.urlopen(request,timeout=2)

    def test_browser_page_does_not_issue_probes_or_forge_native_evidence(self):
        with urllib.request.urlopen(self.probe.url,timeout=2) as r:page=r.read().decode()
        self.assertNotIn('<script>',page);self.assertNotIn(flow.IPIFY,page)
        with self.assertRaises(urllib.error.HTTPError):
            self.submit({'phase':'baseline','internet_ipv4_ok':True,'lan_ok':True,'public_ip':'1.1.1.1'})
        self.assertNotIn('baseline',self.probe.reports)
        with self.submit(report('baseline',checks={'ipify':True,'cloudflare':True})) as r:self.assertEqual(r.status,204)

    def test_barrier_releases_only_after_blocked_and_rejects_replay(self):
        self.probe.set_phase('prepared');done=queue.Queue()
        def fetch():
            try:
                with urllib.request.urlopen(self.base+'/barrier'+self.suffix,timeout=3) as r:done.put(r.status)
            except urllib.error.HTTPError as exc:done.put(exc.code)
        thread=threading.Thread(target=fetch);thread.start()
        for _ in range(100):
            if self.probe.barrier_started:break
            time.sleep(.005)
        self.assertTrue(self.probe.barrier_started);self.assertTrue(done.empty())
        self.probe.set_phase('blocked');self.assertEqual(done.get(timeout=2),200);thread.join(1)
        with self.assertRaises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(self.base+'/barrier'+self.suffix,timeout=2)
        self.assertEqual(caught.exception.code,409)
        # Fresh destinations fail while the previously established socket still works.
        with self.submit(report()) as r:self.assertEqual(r.status,204)
        observed=self.probe.wait_report('blocked',0)
        self.assertTrue(observed['internet_ipv4_ok']);self.assertTrue(observed['flow']['reuse_confirmed'])

    def test_recovery_cancels_barrier_without_releasing_the_external_request(self):
        self.probe.set_phase('prepared');done=queue.Queue()
        def fetch():
            try:urllib.request.urlopen(self.base+'/barrier'+self.suffix,timeout=3)
            except urllib.error.HTTPError as exc:done.put(exc.code)
        thread=threading.Thread(target=fetch);thread.start()
        for _ in range(100):
            if self.probe.barrier_started:break
            time.sleep(.005)
        self.probe.set_phase('restored');self.assertEqual(done.get(timeout=2),409);thread.join(1)

    @unittest.skipUnless(shutil.which('curl'), 'local curl is required for connection-cache rehearsal')
    def test_real_local_curl_reuses_public_socket_across_separate_lan_barrier(self):
        peers=[]
        class Public(BaseHTTPRequestHandler):
            protocol_version='HTTP/1.1'
            def log_message(self,*args):pass
            def do_GET(self):
                peers.append(self.client_address)
                body=b'{"ip":"1.1.1.1"}'
                self.send_response(200);self.send_header('Content-Length',str(len(body)))
                self.end_headers();self.wfile.write(body)
        server=ThreadingHTTPServer(('127.0.0.1',0),Public)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        self.addCleanup(server.server_close);self.addCleanup(server.shutdown)
        public=f'http://127.0.0.1:{server.server_address[1]}/public'
        def local_popen(argv,**kwargs):
            args=shlex.split(argv[-1]);converted=[];i=1
            while i<len(args):
                if args[i]=='--resolve':i+=2;continue
                converted.append(public if args[i].startswith(flow.IPIFY) else args[i]);i+=1
            return subprocess.Popen([shutil.which('curl'),*converted],**kwargs)
        self.probe.set_phase('prepared')
        request=flow.ReusedRequest('synthetic-serial','127.0.0.1',self.base,self.probe.token,'8.8.8.8',popen=local_popen)
        self.addCleanup(request.close)
        first=request.frames.get(timeout=3);self.assertIsInstance(first,tuple)
        self.assertEqual(first[1]['connects'],'1')
        for _ in range(100):
            if self.probe.barrier_started:break
            time.sleep(.005)
        self.assertTrue(self.probe.barrier_started);self.assertEqual(len(peers),1)
        self.probe.set_phase('blocked')
        middle=request.frames.get(timeout=3);last=request.frames.get(timeout=3)
        self.assertEqual(middle[1]['code'],'200');self.assertEqual(last[1]['connects'],'0')
        self.assertEqual(first[1]['local_port'],last[1]['local_port'])
        self.assertEqual(len(peers),2);self.assertEqual(peers[0],peers[1])
        self.assertEqual(request.process.wait(timeout=3),0)


if __name__=='__main__':unittest.main()
