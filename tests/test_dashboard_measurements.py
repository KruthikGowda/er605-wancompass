"""Execute dashboard rendering against missing and partial measurement history."""
from pathlib import Path
import shutil
import subprocess
import unittest


@unittest.skipUnless(shutil.which("node"), "Node is needed for dashboard rendering checks")
class DashboardMeasurements(unittest.TestCase):
    def test_partial_history_and_hover_preserve_missing_observations(self):
        html = (Path(__file__).resolve().parents[1] / "netpulse/web/static/index.html").read_text(encoding="utf-8")
        history = html[html.index("async function refreshHistory()"):html.index("/* ---------- events, in plain words")]
        cards = html[html.index("function renderISPs(s)"):html.index("function renderRouter(")]
        setup = r'''
const assert = require('node:assert/strict');
const now = 1700000000;
Date.now = () => now * 1000;
const nodes = new Map();
const cursor = {setAttribute() {}};
const $ = id => {
  if (!nodes.has(id)) nodes.set(id, {innerHTML:'', textContent:'',style:{},clientWidth:800,
    setAttribute(){},querySelector(){return cursor},getBoundingClientRect(){return {left:0,width:800}}});
  return nodes.get(id);
};
let fixture;
const getJSON = async () => fixture;
const order=['WAN1'];
const hours=24, server='', metric='rtt_ms';
const colorOf=()=>'#000000', labelOf=n=>n, esc=String, fmt=v=>v==null?'—':String(v);
const duration=String, when=String, css=()=>'#000000';
const STATE_WORD={HEALTHY:'healthy',UNKNOWN:'unknown'}, SERVER={};
const speedWord=()=>'', lossWords=v=>`${v}% loss`, jitterWords=()=>'';
'''
        assertions = r'''
(async () => {
  fixture={hours:24,bucket:60,points:[{wan:'WAN1',ts:now-60,rtt_ms:20}],
    state_minutes:{WAN1:{HEALTHY:10,OFFLINE:2,UNKNOWN:3}}};
  await refreshHistory();
  assert.match($('totals').innerHTML,/Observed online 83.3%/);
  assert.match($('totals').innerHTML,/Measurement coverage 1.0%/);
  assert.match($('totals').innerHTML,/15 recorded minutes of 1440/);
  assert.ok($('chart').innerHTML.includes(String(now-86400)));
  $('chart').onpointermove({clientX:414});
  assert.match($('tip').innerHTML,/no measurement/);
  assert.doesNotMatch($('tip').innerHTML,/20 ms/);
  fixture={hours:24,bucket:60,points:[],state_minutes:{WAN1:{UNKNOWN:3}}};
  await refreshHistory();
  assert.match($('totals').innerHTML,/Observed online unavailable/);
  assert.match($('totals').innerHTML,/No confirmed health measurements/);
  fixture.state_minutes={};
  await refreshHistory();
  assert.match($('totals').innerHTML,/Measurement coverage 0.0%/);
  renderISPs({wans:[{name:'WAN1',state:'UNKNOWN',rtt_ms:null,loss_pct:100,
    errors:['Cannot assign requested address'],targets:[]}]});
  assert.match($('isps').innerHTML,/Measurement unavailable/);
  assert.match($('isps').innerHTML,/The Pi cannot send measurements/);
  assert.doesNotMatch($('isps').innerHTML,/100% loss/);
})().catch(error=>{console.error(error);process.exitCode=1;});
'''
        completed = subprocess.run([shutil.which("node"), "-e", setup + history + cards + assertions],
                                   capture_output=True, text=True, encoding="utf-8", timeout=10)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
