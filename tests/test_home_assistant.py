"""The optional Home Assistant example validator catches configuration loss early."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tools import validate_home_assistant


class HomeAssistantYamlTests(unittest.TestCase):
    def test_duplicate_yaml_mapping_key_is_rejected(self):
        yaml, _, _ = validate_home_assistant._dependencies()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ha.md"
            path.write_text(
                "```yaml\nrest:\n  - resource: http://localhost/api/system\n"
                "    sensor: []\n    sensor: []\n```\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "Duplicate YAML key: sensor"):
                validate_home_assistant._config_from_markdown(path, yaml)

    def test_documented_configuration_still_validates(self):
        self.assertGreater(validate_home_assistant.validate(), 0)


if __name__ == "__main__":
    unittest.main()
