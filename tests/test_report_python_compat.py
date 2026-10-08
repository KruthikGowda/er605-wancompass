"""Compatibility contracts for the report template on the minimum Python version."""

import ast
from pathlib import Path
import unittest

from netpulse.web.report import to_html


ROOT = Path(__file__).resolve().parents[1]
REPORT_SOURCE = ROOT / "netpulse" / "web" / "report.py"


class ReportPythonCompatibilityTests(unittest.TestCase):
    def test_report_source_parses_with_the_supported_python_grammar(self):
        source = REPORT_SOURCE.read_text(encoding="utf-8")
        # On Python 3.11 this uses the actual supported parser; CI runs this test on 3.11.
        ast.parse(source, filename=str(REPORT_SOURCE), feature_version=(3, 11))
        compile(source, str(REPORT_SOURCE), "exec")

    def test_report_links_keep_url_encoding_and_html_escaping(self):
        value = {
            "days": 1.5,
            "since": 0,
            "until": 90 * 86400,
            "selected_wan": "WAN&/1",
            "selected_label": "ISP <one>",
            "wan_options": [{"wan": "WAN&/1", "label": "ISP <one>"}],
            "wans": [],
        }
        rendered = to_html(value)
        self.assertIn('href="/report?days=1.5">All ISPs</a>', rendered)
        self.assertIn('href="/report?days=1.5&wan=WAN%26%2F1">ISP &lt;one&gt;</a>', rendered)
        self.assertIn("Internet connection report — ISP &lt;one&gt;", rendered)


if __name__ == "__main__":
    unittest.main()
