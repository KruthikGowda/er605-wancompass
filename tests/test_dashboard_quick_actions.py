"""Focused checks for the dashboard's reviewed quick-action controls."""

from __future__ import annotations

import json
import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HTML_PATH = ROOT / "netpulse" / "web" / "static" / "index.html"


class DashboardQuickActions(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.html = HTML_PATH.read_text(encoding="utf-8")

    def test_review_apply_and_separate_selection_contract_is_present(self):
        self.assertIn('id="quick-action-review"', self.html)
        self.assertIn('id="quick-action-dialog"', self.html)
        self.assertIn('"/api/actions/preview"', self.html)
        self.assertIn('"/api/actions/apply"', self.html)
        self.assertIn("{token:preview.token, confirmed:true}", self.html)
        self.assertIn("{...target, action, duration_seconds:durationSeconds}", self.html)
        self.assertIn("const quickActionMacs = new Set();", self.html)
        self.assertIn('class="quick-action-device-select"', self.html)
        self.assertIn('class="group-device-select"', self.html)
        self.assertIn("credentials:\"same-origin\"", self.html)
        self.assertIn("Advanced device controls", self.html)
        self.assertIn("Advanced group controls", self.html)
        self.assertNotRegex(self.html, r'<script[^>]+src=["\']https?://')

    @unittest.skipUnless(shutil.which("node"), "Node.js is not installed")
    def test_only_wan_is_not_offered_without_an_enabled_capability_and_stale_targets_block_review(self):
        start = self.html.index("const QUICK_ACTIONS = [")
        end = self.html.index("\nfunction quickActionDialog(preview)", start)
        source = self.html[start:end]
        harness = r"""
const assert = require('node:assert/strict');
const source = JSON.parse(process.argv[1]);
const ids = ['quick-action-choice', 'quick-action-duration-label', 'quick-action-duration',
  'quick-action-count', 'quick-action-status', 'quick-action-capability',
  'quick-action-clear', 'quick-action-review', 'device-traffic-load',
  'device-traffic-status', 'device-traffic-results'];
const elements = Object.fromEntries(ids.map(id => [id, {
  value: '', textContent: '', innerHTML: '', hidden: false, disabled: false,
  classList: {toggle() {}}, replaceChildren() { this.children = []; }
}]));
const $ = id => elements[id];
const esc = value => String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;')
  .replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&#39;');
let actionCatalog = {control: {enabled: true}, actions: [
  {id:'auto', label:'Auto balance', enabled:true},
  {id:'prefer_wan1', label:'Prefer WAN 1', enabled:true},
  {id:'prefer_wan2', label:'Prefer WAN 2', enabled:true},
  {id:'pause', label:'Pause Internet', enabled:false, reason:'not enabled'},
  {id:'resume', label:'Resume Internet', enabled:false, reason:'not enabled'},
  {id:'only_wan1', label:'Only WAN 1', enabled:false, reason:'router mode unsupported'}
]};
let actionCatalogError = '';
let deviceData = {devices:[{mac:'AA:BB:CC:DD:EE:FF', protected:false}], groups:[{id:7, members:['AA:BB:CC:DD:EE:FF']}]};
const quickActionMacs = new Set(['AA:BB:CC:DD:EE:FF']);
const controls = new Function('$', 'esc', 'actionCatalog', 'actionCatalogError', 'deviceData',
  'quickActionMacs', 'let actionTargetGroupId = null;\n' + source +
  '\nreturn {render: renderQuickActions, setGroup(id) { actionTargetGroupId = id; }};')(
    $, esc, actionCatalog, actionCatalogError, deviceData, quickActionMacs);
const render = controls.render;
render();
assert.match($('quick-action-choice').innerHTML, /Auto balance/);
assert.doesNotMatch($('quick-action-choice').innerHTML, /Only WAN 1/);
assert.match($('quick-action-capability').textContent, /unavailable/);
assert.equal($('quick-action-review').disabled, false, 'enabled server action can be reviewed');

quickActionMacs.add('11:22:33:44:55:66');
render();
assert.equal($('quick-action-review').disabled, true, 'a stale selection cannot be reviewed');
assert.match($('quick-action-status').textContent, /no longer in the current inventory/);

quickActionMacs.clear();
controls.setGroup(7);
render();
assert.match($('quick-action-count').textContent, /Group · 1 devices/);
assert.equal($('quick-action-review').disabled, false, 'group targets use their own selection mode');
"""
        result = subprocess.run(
            [shutil.which("node") or "node", "-e", harness, json.dumps(source)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
            timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    @unittest.skipUnless(shutil.which("node"), "Node.js is not installed")
    def test_device_and_group_selection_review_confirm_apply_flow(self):
        start = self.html.index("const QUICK_ACTIONS = [")
        end = self.html.index("\nfunction reviewRoute(preview)", start)
        actions_source = self.html[start:end]
        route_start = self.html.index("function routeLabel(route)")
        route_end = self.html.index("\nfunction strictWanAvailable", route_start)
        route_source = self.html[route_start:route_end]
        change_start = self.html.index('$ ("devices")', 0) if '$ ("devices")' in self.html else self.html.index('$("devices").addEventListener("change", e => {')
        change_end = self.html.index('\n$("group-save").addEventListener("click"', change_start)
        change_source = self.html[change_start:change_end]
        harness = r"""
const assert = require('node:assert/strict');
(async () => {
const actionsSource = JSON.parse(process.argv[1]);
const routeSource = JSON.parse(process.argv[2]);
const changeSource = JSON.parse(process.argv[3]);
const ids = ['quick-action-choice', 'quick-action-duration-label', 'quick-action-duration',
  'quick-action-count', 'quick-action-status', 'quick-action-capability', 'quick-action-clear',
  'quick-action-review', 'quick-action-dialog-title', 'quick-action-dialog-summary',
  'quick-action-dialog-members', 'quick-action-dialog-reservations', 'quick-action-dialog-effect',
  'quick-action-cancel', 'quick-action-apply', 'devices', 'device-traffic-load',
  'device-traffic-status', 'device-traffic-results'];
const elements = Object.fromEntries(ids.map(id => [id, {
  value: '', textContent: '', innerHTML: '', hidden: false, disabled: false, handlers: {},
  dataset: {}, classList: {toggle() {}}, replaceChildren() { this.children = []; },
  addEventListener(name, callback) { this.handlers[name] = callback; }
}]));
const dialog = elements['quick-action-dialog'] = {
  handlers: {}, returnValue: '', addEventListener(name, callback) { this.handlers[name] = callback; },
  showModal() { this.returnValue = 'apply'; this.handlers.close(); },
  close(value) { this.returnValue = value; this.handlers.close(); }
};
const $ = id => elements[id];
const esc = value => String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;')
  .replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&#39;');
const routeLabel = new Function('labelOf', routeSource + '\nreturn routeLabel;')(
  wan => wan === 'WAN1' ? 'WAN 1' : wan === 'WAN2' ? 'WAN 2' : wan);
const actionCatalog = {control:{enabled:true}, actions:[
  {id:'auto',label:'Auto balance',enabled:true}, {id:'prefer_wan1',label:'Prefer WAN 1',enabled:true},
  {id:'prefer_wan2',label:'Prefer WAN 2',enabled:true}, {id:'pause',label:'Pause',enabled:false},
  {id:'resume',label:'Resume',enabled:false}, {id:'only_wan1',label:'Only WAN 1',enabled:false},
  {id:'only_wan2',label:'Only WAN 2',enabled:false}
]};
const actionCatalogError = '';
const deviceData = {devices:[{mac:'AA:BB:CC:DD:EE:FF',protected:false}], groups:[{id:7,members:['AA:BB:CC:DD:EE:FF']}]};
const quickActionMacs = new Set();
const selectedDeviceMacs = new Set(['11:22:33:44:55:66']);
const calls = [];
const notices = [];
const previews = [
  {token:'device-token', action:'prefer_wan1', count:1, members:[{mac:'AA:BB:CC:DD:EE:FF',name:'<TV>',ip:'192.0.2.8',current:'WAN1_ONLY'}], effect:'Reviewed device route.'},
  {token:'group-token', action:'auto', group:'Work', count:1, members:[{mac:'AA:BB:CC:DD:EE:FF',name:'Laptop',ip:'192.0.2.8',current:'Paused (IPv4)'}], effect:'Reviewed group routes.'}
];
let actionTargetGroupId = null;
async function fetch(url, init) {
  calls.push({url, init, body: JSON.parse(init.body)});
  if (url === '/api/actions/preview') return {ok:true, json:async()=>previews.shift()};
  if (url === '/api/actions/apply') return {ok:true, json:async()=>({count:1,detail:'Verified.'})};
  throw new Error(`unexpected URL ${url}`);
}
const deviceNotice = message => notices.push(message);
const refreshDevices = async () => {};
const controls = new Function('$','esc','routeLabel','actionCatalog','actionCatalogError','deviceData',
  'quickActionMacs','selectedDeviceMacs','deviceNotice','refreshDevices','fetch',
  'let actionTargetGroupId = null;\n' + actionsSource + '\n' + changeSource +
  '\nreturn {render:renderQuickActions, setGroup(id){actionTargetGroupId=id;}, getGroup(){return actionTargetGroupId;}};')(
    $,esc,routeLabel,actionCatalog,actionCatalogError,deviceData,quickActionMacs,selectedDeviceMacs,deviceNotice,refreshDevices,fetch);
controls.render();

const actionBox = {checked:true,dataset:{mac:'AA:BB:CC:DD:EE:FF'}};
elements.devices.handlers.change({target:{closest(selector){return selector === '.quick-action-device-select' ? actionBox : null;}}});
assert.deepEqual([...quickActionMacs], ['AA:BB:CC:DD:EE:FF']);
assert.deepEqual([...selectedDeviceMacs], ['11:22:33:44:55:66'], 'quick selection preserves group membership draft');
elements['quick-action-choice'].value = 'prefer_wan1';
elements['quick-action-choice'].handlers.change();
await elements['quick-action-review'].handlers.click({currentTarget:elements['quick-action-review']});
assert.equal(calls[0].url, '/api/actions/preview');
assert.deepEqual(calls[0].body, {macs:['AA:BB:CC:DD:EE:FF'],action:'prefer_wan1',duration_seconds:0});
assert.equal(calls[1].url, '/api/actions/apply');
assert.deepEqual(calls[1].body, {token:'device-token',confirmed:true});
assert.match(elements['quick-action-dialog-members'].innerHTML, /&lt;TV&gt;/, 'review target is escaped in the dialog');
assert.match(elements['quick-action-dialog-members'].innerHTML, /Only WAN 1 · no fallback/, 'strict routes use friendly copy');
assert.deepEqual([...quickActionMacs], [], 'successful apply clears action targets');
assert.deepEqual([...selectedDeviceMacs], ['11:22:33:44:55:66']);

controls.setGroup(7);
elements['quick-action-choice'].value = 'auto';
elements['quick-action-choice'].handlers.change();
controls.render();
await elements['quick-action-review'].handlers.click({currentTarget:elements['quick-action-review']});
assert.deepEqual(calls[2].body, {group_id:7,action:'auto',duration_seconds:0});
assert.deepEqual(calls[3].body, {token:'group-token',confirmed:true});
assert.match(elements['quick-action-dialog-members'].innerHTML, /Paused \(IPv4\)/, 'pause state keeps its label');
assert.equal(controls.getGroup(), null, 'successful group apply clears the target');
assert.deepEqual([...selectedDeviceMacs], ['11:22:33:44:55:66']);
})().catch(error => { console.error(error); process.exitCode = 1; });
"""
        result = subprocess.run(
            [shutil.which("node") or "node", "-e", harness, json.dumps(actions_source),
             json.dumps(route_source), json.dumps(change_source)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
            timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
