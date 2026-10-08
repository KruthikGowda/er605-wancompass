from __future__ import annotations

import json
import shutil
import subprocess
import unittest
from pathlib import Path


HTML = Path(__file__).resolve().parents[1] / "netpulse" / "web" / "static" / "index.html"


class PauseDashboard(unittest.TestCase):
    def test_dashboard_exposes_review_first_pauses_and_disabled_reason(self):
        html = HTML.read_text(encoding="utf-8")
        for text in ("/api/devices/paused", "/api/devices/pause/preview", "/api/device-groups/pause/preview",
                     "/api/devices/pause/apply", "Awaiting Internet pause validation", "Saved Internet pause state",
                     "No saved pause", "Paused (IPv4)", "IPv4 Internet path only", "no router-native expiry"):
            self.assertIn(text, html)
        self.assertIn("esc(m.name || m.device || m.mac)", html)
        self.assertIn("g.members.includes(r.mac)", html,
                      "group resume includes members paused individually or in another group")

    @unittest.skipUnless(shutil.which("node"), "Node.js is not installed")
    def test_preview_members_are_rendered_as_escaped_text(self):
        html = HTML.read_text(encoding="utf-8")
        start = html.index("async function reviewPause(preview)")
        end = html.index("\n$(\"pause-cancel\")", start)
        source = html[start:end]
        harness = r"""
const assert = require('node:assert/strict');
const source = JSON.parse(process.argv[1]);
const values = {};
const dialog = {returnValue:'', handlers:{}, addEventListener(k, f){this.handlers[k]=f;}, showModal(){}};
const elements = Object.fromEntries(['pause-dialog-title','pause-dialog-summary','pause-dialog-members',
  'pause-dialog-effect','pause-dialog-expiry','pause-dialog'].map(id => [id, id === 'pause-dialog' ? dialog : {textContent:'',innerHTML:''}]));
const $ = id => elements[id];
const esc = value => String(value).replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;')
  .replaceAll('"','&quot;').replaceAll("'",'&#39;');
const reviewPause = new Function('$','esc',source + '\nreturn reviewPause;')($,esc);
reviewPause({action:'pause',group:'<img src=x>',expiry_label:'1 hour',effect:'checked',members:[
 {name:'<script>alert(1)</script>',ip:'192.0.2.2',mac:'AA-BB'}]});
assert.equal(elements['pause-dialog-summary'].textContent, '<img src=x>', 'summary uses textContent');
assert.match(elements['pause-dialog-members'].innerHTML, /&lt;script&gt;/);
assert.doesNotMatch(elements['pause-dialog-members'].innerHTML, /<script>/);
assert.equal(elements['pause-dialog-expiry'].textContent, '1 hour');
"""
        result = subprocess.run([shutil.which("node") or "node", "-e", harness, json.dumps(source)],
                                cwd=HTML.parents[3], capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
