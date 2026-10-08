"""Behavioral checks for the dashboard's group-member draft controls."""

from __future__ import annotations

import json
import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HTML_PATH = ROOT / "netpulse" / "web" / "static" / "index.html"


class DashboardGroupEditorBehavior(unittest.TestCase):
    @unittest.skipUnless(shutil.which("node"), "Node.js is not installed")
    def test_unavailable_member_removal_is_draft_only_and_save_is_gated(self):
        html = HTML_PATH.read_text(encoding="utf-8")
        start = html.index("function renderGroupSelection()")
        end = html.index("\nfunction renderGroups(groups)", start)
        editor_source = html[start:end]
        harness = r"""
const assert = require('node:assert/strict');
const source = JSON.parse(process.argv[1]);
const ids = ['group-selection-count', 'group-editor', 'group-name', 'group-editor-title',
  'group-editor-count', 'group-selection-empty', 'group-save', 'group-selection-members'];
const elements = Object.fromEntries(ids.map(id => [id, {
  value: '', textContent: '', innerHTML: '', hidden: false, disabled: false,
  handlers: {}, addEventListener(name, callback) { this.handlers[name] = callback; }
}]));
const $ = id => elements[id];
const selectedDeviceMacs = new Set(['AA:BB:CC:DD:EE:FF', '11:22:33:44:55:66']);
const deviceData = {devices: [{mac: 'AA:BB:CC:DD:EE:FF', label: '<strong>TV & tablet</strong>', ip: '192.0.2.8'}]};
const esc = value => String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;')
  .replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&#39;');
let render;
let renderCalls = 0;
let fetchCalls = 0;
globalThis.fetch = () => { fetchCalls++; throw new Error('fetch must not run while editing a draft'); };
const renderDevices = () => { renderCalls++; render(); };
render = new Function('$', 'selectedDeviceMacs', 'deviceData', 'esc', 'renderDevices', 'editingGroupId',
  source + '\nreturn renderGroupSelection;')($, selectedDeviceMacs, deviceData, esc, renderDevices, null);

render();
assert.equal($('group-save').disabled, true, 'save is disabled until a name is entered');
assert.equal($('group-selection-members').hidden, false);
assert.match($('group-selection-members').innerHTML, /Unavailable in the current router list/,
  'a MAC missing from the current/filtered router list remains visible');
assert.match($('group-selection-members').innerHTML, /11:22:33:44:55:66/);
assert.match($('group-selection-members').innerHTML, /&lt;strong&gt;TV &amp; tablet&lt;\/strong&gt;/,
  'member labels are HTML escaped');
assert.doesNotMatch($('group-selection-members').innerHTML, /<strong>/);

$('group-name').value = 'House';
render();
assert.equal($('group-save').disabled, false, 'save enables when name and members exist');
const click = $('group-selection-members').handlers.click;
assert.equal(typeof click, 'function', 'member remove handler was registered');
click({target: {closest(selector) {
  assert.equal(selector, '.group-member-remove');
  return {dataset: {mac: '11:22:33:44:55:66'}};
}}});
assert.equal(selectedDeviceMacs.has('11:22:33:44:55:66'), false, 'remove updates the draft selection');
assert.equal(selectedDeviceMacs.has('AA:BB:CC:DD:EE:FF'), true);
assert.equal(renderCalls, 1, 'removal rerenders the draft');
assert.equal(fetchCalls, 0, 'removing a member does not save or call the API');

click({target: {closest() { return {dataset: {mac: 'AA:BB:CC:DD:EE:FF'}}; }}});
assert.equal(selectedDeviceMacs.size, 0);
assert.equal($('group-selection-members').hidden, true);
assert.equal($('group-save').disabled, true, 'save disables again when the draft is empty');
assert.equal(fetchCalls, 0);
"""
        result = subprocess.run(
            [shutil.which("node") or "node", "-e", harness, json.dumps(editor_source)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
            timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    @unittest.skipUnless(shutil.which("node"), "Node.js is not installed")
    def test_disabled_device_activity_policy_hides_device_counters(self):
        html = HTML_PATH.read_text(encoding="utf-8")
        start = html.index("  const alertPolicy = s.alert_policy || {};")
        end = html.index("\n  renderISPs(s);", start)
        policy_source = html[start:end]
        harness = r"""
const assert = require('node:assert/strict');
const source = JSON.parse(process.argv[1]);
const elements = {'alert-policy': {textContent: ''}, 'alert-policy-summary': {textContent: ''}};
const $ = id => { assert.ok(elements[id], `unexpected dashboard element: ${id}`); return elements[id]; };
const renderPolicy = new Function('$', 's', source);
const base = {alert_policy: {
  telegram_enabled: true, quiet_start: '22:00', quiet_end: '07:00',
  suppressed_since_start: {mute: 0, quiet_hours: 0, rate_limited: 0},
  device_notice_suppressed_since_start: {mute: 0, quiet_hours: 0, rate_limited: 0},
  delivery_since_start: {accepted: 2, queued: 0, failed: 0, queue_dropped: 0,
    categories: {device_notice: {accepted: 0, queued: 0, failed: 0, queue_dropped: 0}}}
}};
renderPolicy($, {alert_policy: {...base.alert_policy, device_activity_notifications: false}});
assert.match(elements['alert-policy'].textContent, /Device activity alerts off; details available on request/);
assert.doesNotMatch(elements['alert-policy'].textContent, /Device notices:/);
assert.doesNotMatch(elements['alert-policy'].textContent, /0 accepted by Telegram/);
assert.match(elements['alert-policy'].textContent, /Telegram API accepted 2 recipient message\(s\)/,
  'general alert delivery remains visible');
assert.match(elements['alert-policy-summary'].textContent, /Quiet hours do not suppress WAN outage and recovery alerts/);

renderPolicy($, {alert_policy: {...base.alert_policy, telegram_enabled: false, device_activity_notifications: true,
  delivery_since_start: {...base.alert_policy.delivery_since_start,
    categories: {device_notice: {accepted: 1, queued: 2, failed: 3, queue_dropped: 4}}}}});
assert.match(elements['alert-policy'].textContent, /Device notices: 1 accepted by Telegram, 2 queued, 3 failed, 4 dropped/);
assert.match(elements['alert-policy-summary'].textContent, /Telegram alerts are off, including outage and recovery alerts/);
"""
        result = subprocess.run(
            [shutil.which("node") or "node", "-e", harness, json.dumps(policy_source)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
            timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

        self.assertIn("This inventory history describes changes to the router's lease list", html)
        self.assertNotIn("These alerts describe changes", html)

    @unittest.skipUnless(shutil.which("node"), "Node.js is not installed")
    def test_group_candidate_copy_tracks_smart_wan_opt_in_and_readiness(self):
        html = HTML_PATH.read_text(encoding="utf-8")
        start = html.index("function renderGroups(groups)")
        end = html.index('\n$("device-groups").addEventListener', start)
        render_source = html[start:end]
        harness = r"""
const assert = require('node:assert/strict');
const source = JSON.parse(process.argv[1]);
const host = {innerHTML: ''};
const $ = id => { assert.equal(id, 'device-groups'); return host; };
const esc = value => String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;')
  .replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&#39;');
const deviceData = {devices: [], control: {enabled: true}, recent_speeds: {}};
const labelOf = value => `<b>${value}</b>`;
const duration = value => `${value}s`;
const fmt = value => String(value);
const renderGroups = new Function('$', 'deviceData', 'esc', 'labelOf', 'duration', 'fmt',
  source + '\nreturn renderGroups;')($, deviceData, esc, labelOf, duration, fmt);
const group = (enabled, ready) => ({
  id: 7, name: '<img src=x>', members: ['AA:BB:CC:DD:EE:FF'], reserved_count: 1,
  blocked_count: 0, route: 'WAN1', route_readback: 'matches', smart_routing_enabled: enabled,
  monitor_advice: {ready, candidate: 'WAN1', observations: 3, held_seconds: 60, required_seconds: 120}
});
const render = (enabled, ready) => { renderGroups([group(enabled, ready)]); return host.innerHTML; };

let html = render(true, true);
assert.match(html, /Stable Smart WAN candidate: &lt;b&gt;WAN1&lt;\/b&gt;/);
assert.match(html, /automatic changes require fresh router checks and the 15-minute cooldown/);
assert.doesNotMatch(html, /no route changed|route applied/i,
  'an opted-in candidate is not described as already applied');
assert.match(html, /&lt;img src=x&gt;/, 'group label remains escaped');
assert.doesNotMatch(html, /<img src=x>/);

html = render(true, false);
assert.match(html, /Waiting for a stable Smart WAN candidate/);
assert.match(html, /3 samples over 60s of 120s/);
assert.match(html, /automatic changes require fresh router checks and the 15-minute cooldown/);

html = render(false, true);
assert.match(html, /Stable monitor-only candidate/);
assert.match(html, /no route changed/);
assert.doesNotMatch(html, /Smart WAN candidate/);

html = render(false, false);
assert.match(html, /Monitoring candidate/);
assert.match(html, /no route changed/);
"""
        result = subprocess.run(
            [shutil.which("node") or "node", "-e", harness, json.dumps(render_source)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
            timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
