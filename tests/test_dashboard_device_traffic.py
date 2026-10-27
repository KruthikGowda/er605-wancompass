"""Focused behavior checks for read-only device traffic in the dashboard."""

from __future__ import annotations

import json
import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HTML_PATH = ROOT / "netpulse" / "web" / "static" / "index.html"


class DashboardDeviceTraffic(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.html = HTML_PATH.read_text(encoding="utf-8")

    def test_compact_read_only_panel_and_truthful_router_copy(self):
        self.assertIn('id="device-traffic-load"', self.html)
        self.assertIn('id="device-traffic-status"', self.html)
        self.assertIn('id="device-traffic-results"', self.html)
        self.assertIn("ER605 RX/TX byte-counter deltas", self.html)
        self.assertIn("Awaiting router enforcement and recovery validation", self.html)
        self.assertNotIn("Awaiting WAN2 and recovery validation", self.html)

    @unittest.skipUnless(shutil.which("node"), "Node.js is not installed")
    def test_device_and_group_fetches_render_text_only_and_ignore_old_scope_results(self):
        helper_start = self.html.index("const QUICK_ACTIONS = [")
        helper_end = self.html.index("\nfunction quickActionDialog(preview)", helper_start)
        helpers = self.html[helper_start:helper_end]
        handler_start = self.html.index('$ ("device-traffic-load")') if '$ ("device-traffic-load")' in self.html else self.html.index('$("device-traffic-load").addEventListener("click", async event => {')
        handler_end = self.html.index("\nfunction renderDevices()", handler_start)
        handler = self.html[handler_start:handler_end]
        harness = r"""
const assert = require('node:assert/strict');
(async () => {
const helpers = JSON.parse(process.argv[1]);
const handler = JSON.parse(process.argv[2]);
class Element {
  constructor(tag='div') { this.tag=tag; this.value=''; this.textContent=''; this.innerHTML='';
    this.hidden=false; this.disabled=false; this.children=[]; this.handlers={}; this.dataset={};
    this.className=''; this.classList={toggle(){}}; }
  replaceChildren(...children) { this.children=[...children]; }
  append(...children) { this.children.push(...children); }
  addEventListener(name, callback) { this.handlers[name]=callback; }
}
const ids = ['quick-action-choice','quick-action-category','quick-action-category-label','quick-action-duration-label','quick-action-duration',
  'quick-action-count','quick-action-status','quick-action-capability','quick-action-clear',
  'quick-action-review','device-traffic-load','device-traffic-status','device-traffic-results'];
const elements = Object.fromEntries(ids.map(id => [id,new Element()]));
const $ = id => elements[id];
const document = {createElement(tag) { return new Element(tag); }};
const esc = value => String(value);
const duration = value => `${Math.round(value/60)} min`;
const actionCatalog = {control:{enabled:true},actions:[{id:'auto',label:'Auto balance',enabled:true}]};
const actionCatalogError = '';
const deviceData = {devices:[
  {mac:'AA-BB-CC-DD-EE-FF',name:'<TV>',ip:'192.0.2.8',protected:false},
  {mac:'11-22-33-44-55-66',name:'Laptop',ip:'192.0.2.9',protected:false}
],groups:[{id:7,name:'Work',members:['AA-BB-CC-DD-EE-FF','11-22-33-44-55-66']} ]};
const quickActionMacs = new Set(['AA-BB-CC-DD-EE-FF']);
const calls=[];
let nextReport = {enabled:true,available:true,sample_seconds:2,age_seconds:1.2,reason:'',devices:[
  {mac:'AA-BB-CC-DD-EE-FF',ip:'192.0.2.8',available:true,stale:false,rx_mbps:0.25,tx_mbps:0.125,reason:''}
]};
let pending = null;
async function fetch(url, init) {
  calls.push({url,init});
  if (pending) return pending.promise;
  const report=nextReport;
  return {ok:true,json:async()=>report};
}
const source = 'let actionTargetGroupId = null;\n' + helpers + '\n' + handler +
  '\nreturn {render:renderQuickActions,setGroup(id){actionTargetGroupId=id;},getScope(){return deviceTrafficScope;}};';
const controls = new Function('$','document','esc','duration','actionCatalog','actionCatalogError',
  'deviceData','quickActionMacs','fetch',source)(
    $,document,esc,duration,actionCatalog,actionCatalogError,deviceData,quickActionMacs,fetch);
controls.render();
assert.equal(elements['device-traffic-load'].disabled,false);
await elements['device-traffic-load'].handlers.click({currentTarget:elements['device-traffic-load']});
assert.equal(calls[0].url,'/api/devices/traffic?mac=AA-BB-CC-DD-EE-FF');
assert.equal(calls[0].init.credentials,'same-origin');
assert.equal(calls[0].init.cache,'no-store');
assert.match(elements['device-traffic-status'].textContent,/Measured over 2.0 s · sample 1.2 s old/);
assert.equal(elements['device-traffic-results'].children[0].children[0].children[0].textContent,'<TV>',
  'device names are inserted as text, not HTML');
assert.match(elements['device-traffic-results'].children[0].children[1].children[0].textContent,/RX 0.250 Mbps/);

quickActionMacs.clear();
controls.setGroup(7);
nextReport = {enabled:true,available:false,sample_seconds:2,age_seconds:5,reason:'ER605 refresh is delayed.',devices:[
  {mac:'AA-BB-CC-DD-EE-FF',ip:'192.0.2.8',available:false,stale:true,rx_mbps:0.5,tx_mbps:0.2,reason:'ER605 refresh is delayed.'}
]};
controls.render();
await elements['device-traffic-load'].handlers.click({currentTarget:elements['device-traffic-load']});
assert.equal(calls[1].url,'/api/devices/traffic?group_id=7');
assert.match(elements['device-traffic-status'].textContent,/Traffic sample is stale/);
assert.match(elements['device-traffic-results'].children[0].children[1].children[0].textContent,/Last RX 0.500 Mbps/);
assert.match(elements['device-traffic-results'].children[0].children[2].textContent,/Stale · ER605 refresh is delayed/);
deviceData.groups[0].members = ['AA-BB-CC-DD-EE-FF'];
controls.render();
assert.equal(elements['device-traffic-results'].children.length,0,'membership changes clear the prior group sample');
assert.match(elements['device-traffic-status'].textContent,/Choose View traffic/);

let finishPending;
pending = {promise:new Promise(resolve => { finishPending=resolve; })};
quickActionMacs.add('11-22-33-44-55-66');
controls.setGroup(null);
controls.render();
const oldRequest = elements['device-traffic-load'].handlers.click({currentTarget:elements['device-traffic-load']});
quickActionMacs.clear();
controls.setGroup(7);
controls.render();
finishPending({ok:true,json:async()=>({enabled:true,available:true,sample_seconds:2,age_seconds:1,
  devices:[{mac:'11-22-33-44-55-66',available:true,stale:false,rx_mbps:1,tx_mbps:1}]})});
await oldRequest;
assert.equal(elements['device-traffic-results'].children.length,0,'old selection results are discarded');
assert.match(elements['device-traffic-status'].textContent,/Choose View traffic/);
})().catch(error => { console.error(error); process.exitCode=1; });
"""
        result = subprocess.run(
            [shutil.which("node") or "node", "-e", harness, json.dumps(helpers), json.dumps(handler)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
            timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
