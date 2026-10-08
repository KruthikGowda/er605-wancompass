import json
from pathlib import Path
import re
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]


class RecoveryDashboard(unittest.TestCase):
    @unittest.skipUnless(shutil.which("node"), "Node is needed for actual renderer behavior")
    def test_recovery_text_keeps_unknown_distinct_from_success(self):
        page = (ROOT / "netpulse/web/static/index.html").read_text(encoding="utf-8")
        function = re.search(r"function aclRecoveryText\(status\) \{[\s\S]*?\n\}", page).group()
        source = function + '\nconsole.log(JSON.stringify(["failed","ok","pending",null,"<script>"].map(aclRecoveryText)));'
        result = subprocess.run([shutil.which("node"), "-e", source], capture_output=True,
                                text=True, timeout=10, check=True)
        texts = json.loads(result.stdout)
        self.assertIn("needs attention", texts[0])
        self.assertIn("last check passed", texts[1])
        self.assertIn("in progress", texts[2])
        self.assertEqual(texts[3], texts[4])
        self.assertIn("unavailable", texts[3])
        self.assertIn('$("pi-acl-recovery").textContent', page)


if __name__ == "__main__":
    unittest.main()
