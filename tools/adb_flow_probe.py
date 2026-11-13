"""Phone-originated connection evidence for an explicitly reviewed ACL trial.

No router writes and no phone settings changes. Fresh requests use separate curl
processes. A three-transfer curl operation holds a previously verified connection
across a private Pi barrier; num_connects and socket endpoints prove actual reuse.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import json
import os
from pathlib import Path
import queue
import re
import shlex
import subprocess
import threading
import time
from urllib.parse import urlencode

from tools.adb_acl_probe import ProbeError, adb_shell, check_phone, validate_url
from netpulse.router.compatibility import CompatibilityError
from netpulse.router.flow_evidence import PHASES,FLOW_KEYS,validate_flow_evidence

IPIFY = 'https://api4.ipify.org?format=json'
CLOUDFLARE = 'https://1.1.1.1/cdn-cgi/trace'
MARKER = 'NP_FLOW='
WRITE_OUT = '\\n' + MARKER + '{"code":"%{http_code}","connects":"%{num_connects}","local_ip":"%{local_ip}","local_port":"%{local_port}","remote_ip":"%{remote_ip}","remote_port":"%{remote_port}","http_version":"%{http_version}"}\\n'
NETWORK_FAILURES = {7, 28, 35, 52, 55, 56}


def validate_native_report(data):
    """Bounded transport evidence; never downgrade an inconclusive result to block."""
    try:return validate_flow_evidence(data)
    except CompatibilityError as exc:raise ProbeError(str(exc)) from None


def curl_args(phone_ip, url, *, maximum=8, pin=None):
    args = ['curl', '--ipv4', '--http1.1', '--noproxy', '*', '--interface', phone_ip,
            '--silent', '--show-error', '--no-buffer', '--globoff', '--max-redirs', '0',
            '--connect-timeout', '3', '--max-time', str(maximum), '--max-filesize', '4096',
            '--write-out', WRITE_OUT]
    if pin is not None:
        address = ipaddress.IPv4Address(pin)
        if not address.is_global: raise ProbeError('Only a verified public IPv4 pin is allowed.')
        args += ['--resolve', 'api4.ipify.org:443:' + str(address)]
    return args + [url]


def parse_frame(body, metrics, phone_ip, *, exit_code=0):
    try:
        if set(metrics) != {'code','connects','local_ip','local_port','remote_ip','remote_port','http_version'}:
            raise ValueError
        integers = {k:int(metrics[k]) for k in ('code','connects','local_port','remote_port')}
        if any(not re.fullmatch(r'\d{1,5}', str(metrics[k])) for k in integers): raise ValueError
        if not 0 <= integers['code'] <= 599 or not 0 <= integers['connects'] <= 8: raise ValueError
        if any(not 0 <= integers[k] <= 65535 for k in ('local_port','remote_port')): raise ValueError
        if metrics['local_ip'] not in ('', phone_ip): raise ValueError
        if metrics['remote_ip'] and not ipaddress.IPv4Address(metrics['remote_ip']).is_global: raise ValueError
    except (ValueError,TypeError,KeyError):
        raise ProbeError('Invalid or mismatched native socket evidence.') from None
    result = {**metrics, **integers, 'ok':False, 'public_ip':None}
    if exit_code:
        if exit_code not in NETWORK_FAILURES or integers['code'] != 0:
            raise ProbeError('Native request failed inconclusively; do not report a block.')
        return result
    if (integers['code'] != 200 or metrics['local_ip'] != phone_ip
            or integers['local_port'] == 0 or integers['remote_port'] != 443
            or not metrics['remote_ip'] or metrics['http_version'] != '1.1'):
        raise ProbeError('Native HTTPS response is not verified; do not report a block.')
    try:
        value = (re.search(r'^ip=(.+)$',body,re.M).group(1).strip()
                 if body.startswith('fl=') or '\nip=' in body else json.loads(body)['ip'])
        public = ipaddress.IPv4Address(value)
        if not public.is_global: raise ValueError
    except (ValueError,TypeError,KeyError,AttributeError):
        raise ProbeError('Native response did not contain a verified public IPv4 address.') from None
    result.update(ok=True, public_ip=str(public))
    return result


def split_frame(output, phone_ip, *, exit_code=0):
    if len(output) > 8192 or output.count(MARKER) != 1:
        raise ProbeError('Missing, duplicate or oversized curl evidence.')
    body, _, raw = output.partition(MARKER)
    try: metrics = json.loads(raw.strip())
    except (TypeError, ValueError): raise ProbeError('Malformed curl evidence.') from None
    return parse_frame(body.strip(),metrics,phone_ip,exit_code=exit_code)


def fresh_request(serial, phone_ip, url, *, pin=None, runner=subprocess.run):
    args = curl_args(phone_ip, url, pin=pin)
    result = adb_shell(serial, shlex.join(args), timeout=12, runner=runner)
    frame = split_frame(result.stdout or '', phone_ip, exit_code=result.returncode)
    if frame['ok'] and frame['connects'] < 1:
        raise ProbeError('A purported fresh request reused a connection.')
    if pin and frame['remote_ip'] and frame['remote_ip'] != pin:
        raise ProbeError('The native request did not use its reviewed public IPv4 pin.')
    return frame


def classify_reuse(first, second):
    if not first['ok'] or first['connects'] < 1:
        raise ProbeError('The existing-flow baseline was not established.')
    same = all(first[k] == second[k] for k in ('local_ip','local_port','remote_ip','remote_port'))
    reused = second['connects'] == 0 and same
    if second['ok'] and not reused:
        raise ProbeError('Curl reconnected; existing-session survival is unproven.')
    # A connection error after a known baseline is a flow-stop observation,
    # not proof that the gateway caused it; fresh/recovery brackets are required.
    return {'prepared_new_connection':True, 'reuse_confirmed':reused,
            'existing_request_ok':second['ok'], 'fresh_processes_verified':True,
            'existing_result_conclusive':True}


class ReusedRequest:
    """One native curl process; a LAN-only barrier separates public requests."""
    def __init__(self, serial, phone_ip, base, token, pin, *, popen=subprocess.Popen):
        url = IPIFY + '&n=' + str(time.time_ns())
        first = curl_args(phone_ip,url,pin=pin)
        barrier = curl_args(phone_ip,base+'/barrier?'+urlencode({'t':token}),maximum=45)[1:]
        last = curl_args(phone_ip,IPIFY+'&n='+str(time.time_ns()),pin=pin)[1:]
        # fail-early prevents proceeding after a failed initial public request or
        # failed barrier. Only final transfer errors are admissible observations.
        args = first[:1] + ['--fail-early','--fail'] + first[1:] + ['--next','--fail'] + barrier + ['--next','--fail'] + last
        # curl's body no-buffer option does not flush write-out stdout while a
        # later transfer waits. stderr is unbuffered; merge it into the evidence
        # pipe so the controller can validate the first socket before the ACL.
        args = ['%{stderr}'+value if value == WRITE_OUT else value for value in args]
        self.process = popen(['adb','-s',serial,'shell',shlex.join(args)],stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT,text=True,encoding='utf-8',errors='replace')
        self.frames = queue.Queue(maxsize=4); self.phone_ip = phone_ip
        def read():
            body=''; size=0
            try:
                for line in self.process.stdout:
                    size += len(line)
                    if size > 20000: raise ProbeError('Oversized persistent probe output.')
                    if line.startswith(MARKER):
                        self.frames.put((body,json.loads(line[len(MARKER):])));body=''
                    else: body += line
            except Exception:
                self.frames.put(ProbeError('Persistent probe evidence could not be read.'))
            finally: self.frames.put(None)
        self.reader = threading.Thread(target=read,daemon=True);self.reader.start()

    def first(self):
        try: value=self.frames.get(timeout=12)
        except queue.Empty: raise ProbeError('Existing-flow baseline timed out.') from None
        if not isinstance(value,tuple): raise ProbeError('No existing-flow baseline evidence.')
        return parse_frame(*value,self.phone_ip)

    def finish(self):
        frames=[];deadline=time.monotonic()+14
        while len(frames)<2:
            try: value=self.frames.get(timeout=max(.01,deadline-time.monotonic()))
            except queue.Empty: raise ProbeError('Existing-flow observation timed out.') from None
            if not isinstance(value,tuple): raise ProbeError('Incomplete existing-flow evidence.')
            frames.append(value)
        try: code=self.process.wait(timeout=max(.01,deadline-time.monotonic()))
        except subprocess.TimeoutExpired: raise ProbeError('Persistent probe did not finish.') from None
        # The middle result must be the successful private LAN barrier.
        if str(frames[0][1].get('code')) != '200': raise ProbeError('The LAN barrier failed.')
        return parse_frame(*frames[1],self.phone_ip,exit_code=code)

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:self.process.kill()
        if self.process.stdout:self.process.stdout.close()
        self.reader.join(timeout=1)


def _pi(serial, phone_ip, url, *, payload=None, origin=None):
    args=['curl','--ipv4','--noproxy','*','--interface',phone_ip,'--silent','--show-error',
          '--fail','--connect-timeout','2','--max-time','4','--max-filesize','4096']
    if origin:args += ['--header','Origin: '+origin]
    if payload is not None:args += ['--header','Content-Type: application/json','--data',json.dumps(payload,separators=(',',':'))]
    r=adb_shell(serial,shlex.join(args+[url]),timeout=6)
    if r.returncode:raise ProbeError('Private Pi heartbeat/report failed.')
    return r.stdout


def run_probe(url, serial, phone_mac, phone_ip, *, seconds=1200, record=None):
    _host,_port,token,base=validate_url(url);check_phone(serial,phone_mac,phone_ip)
    deadline=time.monotonic()+min(max(seconds,1),1800);seen={};persistent=None;first=None;pin=None
    try:
        while time.monotonic()<deadline:
            state=json.loads(_pi(serial,phone_ip,base+'/state?'+urlencode({'t':token})))
            phase=state.get('phase')
            if not state.get('native_flow') or phase not in PHASES:
                raise ProbeError('This is not a native-flow diagnostic endpoint.')
            if state.get('expires_in',0)<=0:raise ProbeError('The diagnostic endpoint expired.')
            if phase in seen:time.sleep(1);continue
            predecessor={'prepared':'baseline','blocked':'prepared','recovery':'blocked'}
            if ((phase in predecessor and predecessor[phase] not in seen)
                    or (phase=='restored' and 'baseline' not in seen)):
                raise ProbeError('Native diagnostic phases arrived out of order.')
            check_phone(serial,phone_mac,phone_ip)
            with ThreadPoolExecutor(max_workers=2) as pool:
                a=pool.submit(fresh_request,serial,phone_ip,IPIFY+'&n='+str(time.time_ns()),pin=pin)
                b=pool.submit(fresh_request,serial,phone_ip,CLOUDFLARE+'?n='+str(time.time_ns()))
                ipify,cloudflare=a.result(),b.result()
            checks={'ipify':ipify['ok'],'cloudflare':cloudflare['ok']}
            flow=dict.fromkeys(FLOW_KEYS,False);flow['fresh_processes_verified']=True
            sockets={'fresh_ipify':ipify,'fresh_cloudflare':cloudflare}
            public=next((x['public_ip'] for x in (ipify,cloudflare) if x['ok']),None)
            if phase!='blocked':
                if (not all(checks.values()) or (phase in {'prepared','recovery'}
                        and ipify['public_ip']!=cloudflare['public_ip'])):
                    raise ProbeError('Native baseline/recovery destinations disagree or are unavailable.')
                pin=ipify['remote_ip']
            if phase=='prepared':
                persistent=ReusedRequest(serial,phone_ip,base,token,pin);first=persistent.first()
                if not first['ok'] or first['connects']<1 or first['public_ip']!=public:
                    raise ProbeError('Persistent baseline does not match verified WAN egress.')
                flow['prepared_new_connection']=True
                sockets['existing_before']=first
            elif phase=='blocked':
                if persistent is None or first is None:raise ProbeError('Missing prepared flow.')
                second=persistent.finish();flow=classify_reuse(first,second)
                sockets.update(existing_before=first,existing_after=second)
                if second['ok']:public=second['public_ip']
                persistent.close();persistent=None
            elif phase=='restored' and persistent is not None:
                persistent.close();persistent=None
            reachable=any(checks.values()) or flow['existing_request_ok']
            report={'phase':phase,'internet_ipv4_ok':reachable,'lan_ok':True,
                    'public_ip':public if reachable else None,'transport':'native_curl',
                    'checks':checks,'flow':flow}
            evidence={'report':report,'socket_evidence':sockets,'accepted_by_pi':False}
            if record is not None:record(phase,evidence)
            validate_native_report(report)
            if json.loads(_pi(serial,phone_ip,base+'/state?'+urlencode({'t':token}))).get('phase')!=phase:
                raise ProbeError('Phase changed during native observation; discard it.')
            _pi(serial,phone_ip,base+'/report?'+urlencode({'t':token}),payload=report,origin=base)
            if record is not None:record(phase,{**evidence,'accepted_by_pi':True})
            seen[phase]=report
            if phase=='restored':return seen
        raise ProbeError('Native diagnostic window expired.')
    finally:
        if persistent is not None:persistent.close()


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--identity-file',required=True,help='Private JSON with serial, mac, ip')
    parser.add_argument('--url-file',required=True,help='Private file containing the current Pi probe URL')
    parser.add_argument('--output',required=True,help='Private result JSON outside the repository')
    args=parser.parse_args(argv)
    output=Path(args.output);progress={'status':'running','phases':{}}
    def persist():
        temporary=output.with_name('.'+output.name+'.native-partial')
        fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w',encoding='utf-8') as stream:json.dump(progress,stream);stream.flush();os.fsync(stream.fileno())
        os.replace(temporary,output)
    def record(phase,evidence):
        progress['phases'][phase]=evidence;persist()
    try:
        identity=json.loads(Path(args.identity_file).read_text(encoding='utf-8-sig'))
        run_probe(Path(args.url_file).read_text().strip(),identity['serial'],identity['mac'],identity['ip'],record=record)
        progress['status']='completed';persist()
        print('Native phone observations completed; private results saved.')
        return 0
    except (ProbeError,OSError,ValueError,KeyError,subprocess.SubprocessError) as exc:
        progress.update(status='inconclusive',error_type=type(exc).__name__)
        try:persist()
        except OSError:pass
        print('Native observations stopped inconclusively; the router trial must recover.')
        return 2


if __name__=='__main__':raise SystemExit(main())
