"""Publication checks report locations and categories, never matched values."""
import tempfile
import unittest
from pathlib import Path
from tools.publication_audit import audit


class PublicationAuditTests(unittest.TestCase):
    def test_reports_private_file_and_denied_value_without_echoing_value(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'router.toml').write_text('private-household-marker', encoding='utf-8')
            findings = audit(root, ['router.toml'], ['private-household-marker'])
            self.assertEqual({r['kind'] for r in findings}, {'runtime-or-private-file', 'private-deny-list'})
            self.assertNotIn('private-household-marker', str(findings))

    def test_rejects_missing_outside_and_secret_key_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'private.txt').write_text('-----BEGIN PRIVATE' + ' KEY-----', encoding='utf-8')
            findings = audit(root, ['../outside', 'missing', 'private.txt'])
            self.assertEqual({r['kind'] for r in findings}, {'unsafe-path', 'missing-file', 'private-key'})

    def test_documentation_network_examples_are_permitted(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'README.md').write_text('Example: 192.0.2.10 /home/EXAMPLE/project/', encoding='utf-8')
            self.assertEqual(audit(root, ['README.md']), [])
