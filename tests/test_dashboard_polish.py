"""Semantic and responsive safeguards for the single-file dashboard UI."""

from __future__ import annotations

import re
import unittest
from html.parser import HTMLParser
from pathlib import Path


HTML_PATH = Path(__file__).resolve().parents[1] / "netpulse" / "web" / "static" / "index.html"


class DashboardMarkup(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.ids: set[str] = set()
        self.links: list[str] = []
        self.nav_labels: list[str] = []
        self._in_nav = False
        self._in_link = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if values.get("id"):
            self.ids.add(values["id"] or "")
        if tag == "nav" and values.get("aria-label") == "Dashboard sections":
            self._in_nav = True
        if self._in_nav and tag == "a":
            href = values.get("href", "") or ""
            self.links.append(href.removeprefix("#"))
            self._in_link = True

    def handle_endtag(self, tag: str) -> None:
        if self._in_nav and tag == "a":
            self._in_link = False
        elif self._in_nav and tag == "nav":
            self._in_nav = False

    def handle_data(self, data: str) -> None:
        if self._in_nav and self._in_link:
            self.nav_labels.append(data.strip())


class DashboardPolish(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.html = HTML_PATH.read_text(encoding="utf-8")
        cls.markup = DashboardMarkup()
        cls.markup.feed(cls.html)

    def test_brand_and_navigation_have_real_targets(self):
        self.assertIn("WANCompass", self.html)
        self.assertIn("A clear view of your home internet and local network", self.html)
        self.assertEqual(self.markup.nav_labels, ["Overview", "Devices", "History", "System"])
        self.assertEqual(set(self.markup.links), {"overview", "devices-heading", "history-heading", "system-heading"})
        self.assertTrue(set(self.markup.links).issubset(self.markup.ids))
        self.assertIn('aria-label="Dashboard sections"', self.html)

    def test_mobile_targets_dialogs_and_status_have_accessible_state(self):
        self.assertRegex(self.html, r"@media\s*\(max-width:\s*520px\)")
        self.assertRegex(self.html, r"@media\s*\(max-width:\s*520px\)[\s\S]*?input,\s*select,\s*\.device-route-control button\s*\{\s*min-height:\s*44px")
        self.assertRegex(self.html, r"dialog\s*\{[^}]*max-height:\s*min\(88dvh, 760px\)[^}]*overflow:\s*auto")
        self.assertIn('id="updated" role="status" aria-live="polite"', self.html)
        self.assertIn("Connection lost · showing last known status", self.html)
        self.assertIn('classList.add("stale")', self.html)

    def test_advanced_guidance_collapses_without_hiding_safety_state(self):
        self.assertRegex(self.html, r'<details class="device-explainer"><summary>Device checks, activity notices, and pause safety</summary>')
        self.assertIn("controls remain disabled pending WAN2 and recovery validation", self.html)
        self.assertIn("WAN controls are locked:", self.html)
        self.assertIn("Smart WAN on", self.html)
        self.assertIn("Smart WAN unavailable", self.html)
        self.assertRegex(self.html, r'<details class="monitor-details"><summary>Alert settings and delivery</summary><p id="alert-policy"')
        self.assertIn('id="alert-policy-summary"', self.html)
        self.assertIn('id="syslog-critical" role="status" hidden', self.html)
        self.assertIn("Faster DHCP listener unavailable", self.html)
        self.assertIn("Show members and connection details", self.html)
        self.assertIn('class="smart-state"', self.html)

    def test_public_copy_uses_generic_provider_language_and_branding(self):
        self.assertIn("speed tests to share with your Internet provider", self.html)
        self.assertNotIn("ANT or ONEOTT", self.html)
        self.assertNotIn("NetPulse protects its own Pi connection", self.html)
        self.assertIn("--wan1", self.html)
        self.assertIn("--wan2", self.html)
        self.assertIn("Results can be limited by the monitoring device’s capacity", self.html)
        self.assertNotIn("220 Mbps", self.html)
        self.assertNotRegex(self.html, r"--(?:ant|oneott)\b")
        self.assertIn("#group-save, #group-new", self.html)


if __name__ == "__main__":
    unittest.main()
