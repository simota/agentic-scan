"""Excerpts must not publish credentials whose value has a well-known shape, whatever the variable is called."""

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "prune-scan" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import inventory  # noqa: E402
import render  # noqa: E402
from safe_source import sensitive_source  # noqa: E402

# Innocuous names: none of these trips the secret-name checks on its own.
VALUES = {
    "slack webhook": 'HOOK = "https://hooks.slack.com/services/T0AAAAAAA/B0BBBBBBB/abcdefghijklmnopqrstuvwx"',
    "discord webhook": 'HOOK = "https://discord.com/api/webhooks/123456789012345678/abcDEF_ghi-JKL"',
    "slack bot": 'BOT = "xoxb-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx"',
    "github classic": 'GH = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123"',
    "github fine-grained": 'GH = "github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJ"',
    "gitlab": 'GL = "glpat-abcdefghij0123456789"',
    "aws access key id": 'AWS_ID = "AKIAIOSFODNN7EXAMPLE"',
    "stripe": 'STRIPE = "sk_live_0123456789abcdefABCDEFGH"',
    "google api key": 'MAPS = "AIzaSyA0123456789abcdefghijklmnopqrstuv"',
    "openai": 'AI = "sk-proj-abcdefghijklmnopqrstuvwxyz012345"',
    "anthropic": 'AI = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz012345"',
    "npm": 'NPM = "npm_abcdefghijklmnopqrstuvwxyz0123456789"',
    "sendgrid": 'MAIL = "SG.abcdefghijklmnopqrstuv.abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"',
    "jwt": 'SESSION = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJl"',
    "bearer header": 'HEADERS = {"Authorization": "Bearer abcdefghijklmnopqrstuvwx"}',
    "basic header": 'HEADERS = {"Authorization": "Basic dXNlcjpodW50ZXIyMjIy"}',
}

# Ordinary source that resembles those shapes keeps its excerpt.
HARMLESS = (
    'link = "https://slack.com/help"',
    'className = "sk-button sk-button--primary"',
    'const glyph = "AKIA";',
    'doc = "uses basic auth when configured"',
    'name = "github_pages"',
)


class SecretValueTests(unittest.TestCase):
    def test_well_known_credential_values_suppress_the_excerpt(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            for label, line in VALUES.items():
                with self.subTest(label):
                    self.assertTrue(sensitive_source(line))
                    (repo / "notify.py").write_text('import json\n\n' + line + '\n\ndef post():\n    pass\n',
                                                    encoding="utf-8")
                    self.assertIsNone(render.snippet(repo, "notify.py:5"))

    def test_lookalike_source_keeps_its_excerpt(self):
        for line in HARMLESS:
            with self.subTest(line):
                self.assertFalse(sensitive_source(line))

    def test_inventory_marker_text_omits_sources_with_credential_values(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            (repo / "notify.py").write_text(
                '# deprecated: remove after 2020-01-01\n' + VALUES["slack webhook"] + '\n', encoding="utf-8")
            markers = inventory.inventory(repo)["markers"]
            self.assertEqual([m["text"] for m in markers], ["[omitted: source may contain secrets]"])

    def test_engine_diagnostics_with_credential_values_are_masked(self):
        self.assertEqual(render.redact_diagnostic("fetch failed: " + VALUES["github classic"]),
                         "[masked: looks like a secret]")
        self.assertEqual(render.redact_diagnostic("timed out after 60s"), "timed out after 60s")


if __name__ == "__main__":
    unittest.main()
