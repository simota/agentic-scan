"""Inventory candidates retain their identity without exporting sensitive source lines."""

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "prune-scan" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import inventory  # noqa: E402
import render  # noqa: E402


class InventorySecretExcerptTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.repo = self.base / "repo"
        self.repo.mkdir()

    def write(self, name, source):
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")

    def assert_masked(self, row):
        self.assertEqual(row["text"], "[omitted: source may contain secrets]")

    def test_environment_default_is_not_exposed_by_a_deprecation_marker(self):
        self.write("settings.py", 'API_TOKEN = os.getenv("API_TOKEN", "DO_NOT_PUBLISH")  # deprecated 2024-01\n')
        result = inventory.inventory(self.repo, today="2026-10-12")
        self.assertNotIn("DO_NOT_PUBLISH", json.dumps(result))
        self.assertEqual(result["files_scanned"], 1)
        self.assertEqual(result["env_read"], [{"name": "API_TOKEN", "count": 1, "locations": ["settings.py:1"]}])
        self.assertEqual(len(result["markers"]), 1)
        row = result["markers"][0]
        self.assertEqual({key: value for key, value in row.items() if key != "text"},
                         {"marker": "deprecated", "location": "settings.py:1", "date": "2024-01", "overdue": True})
        self.assert_masked(row)
        self.assertIsNone(render.snippet(self.repo, "settings.py:1"))

    def test_skipped_test_reasons_do_not_export_secret_values(self):
        sources = {
            "tests/test_settings.py": '@pytest.mark.skipif(os.getenv("API_TOKEN") == "DO_NOT_PUBLISH")\n',
            "tests/settings.test.ts": 'test.skip("DO_NOT_PUBLISH", () => use(apiToken));\n',
        }
        for name, source in sources.items():
            self.write(name, source)
        result = inventory.inventory(self.repo)
        self.assertNotIn("DO_NOT_PUBLISH", json.dumps(result))
        self.assertEqual({row["location"] for row in result["skipped_tests"]},
                         {f"{name}:1" for name in sources})
        for row in result["skipped_tests"]:
            self.assert_masked(row)

    def test_secret_names_anywhere_in_source_protect_continued_marker_and_test_lines(self):
        for before in (False, True):
            with self.subTest(before=before):
                marker = '# deprecated DO_NOT_PUBLISH\npytest.skip("DO_NOT_PUBLISH")\n'
                declaration = 'API_TOKEN = "first"\n'
                source = declaration + "\n" * 12 + marker if before else marker + "\n" * 12 + declaration
                self.write("tests/test_settings.py", source)
                result = inventory.inventory(self.repo)
                self.assertNotIn("DO_NOT_PUBLISH", json.dumps(result))
                self.assertEqual(len(result["markers"]), 1)
                self.assertEqual(len(result["skipped_tests"]), 1)
                for row in result["markers"] + result["skipped_tests"]:
                    self.assert_masked(row)
                self.assertEqual(result["markers"][0]["location"], f"tests/test_settings.py:{14 if before else 1}")

    def test_private_key_blocks_protect_optional_text_without_a_secret_identifier(self):
        for kind in ("RSA PRIVATE KEY", "OPENSSH PRIVATE KEY", "PGP PRIVATE KEY BLOCK"):
            with self.subTest(kind=kind):
                self.write("tests/test_settings.py", f'PEM = """-----BEGIN {kind}-----\n'
                           f'REDACTED_KEY_BYTES\n-----END {kind}-----"""\n'
                           'pytest.skip("DO_NOT_PUBLISH")  # deprecated\n')
                result = inventory.inventory(self.repo)
                self.assertNotIn("DO_NOT_PUBLISH", json.dumps(result))
                self.assertEqual(len(result["markers"]), 1)
                self.assertEqual(len(result["skipped_tests"]), 1)
                for row in result["markers"] + result["skipped_tests"]:
                    self.assert_masked(row)
                self.assertIsNone(render.snippet(self.repo, "tests/test_settings.py:4"))

    def test_public_text_and_candidate_caps_are_preserved(self):
        self.write("tests/test_settings.py", 'API_TOKEN = "first"\n'
                   'pytest.skip("DO_NOT_PUBLISH")  # deprecated 2024-01\n'
                   'pytest.skip("DO_NOT_PUBLISH")  # deprecated 2024-02\n')
        self.write("tests/test_widget.py", '@pytest.mark.skip(reason="public migration")\n# deprecated 2024-03\n')
        result = inventory.inventory(self.repo, today="2026-10-12")
        self.assertEqual(len(result["markers"]), 3)
        self.assertEqual(len(result["skipped_tests"]), 3)
        self.assertEqual(result["markers"][-1]["text"], "# deprecated 2024-03")
        self.assertEqual(result["skipped_tests"][-1]["text"], '@pytest.mark.skip(reason="public migration")')
        with mock.patch.object(inventory, "MAX_ROWS", 1):
            capped = inventory.inventory(self.repo, today="2026-10-12")
        for key in ("markers", "skipped_tests"):
            self.assertEqual(capped["truncated"][key], 2)
            self.assertEqual(len(capped[key]), 1)
            self.assert_masked(capped[key][0])

    def test_cli_publishes_sanitized_inventory_and_preserves_source(self):
        source = 'API_TOKEN = os.getenv("API_TOKEN", "DO_NOT_PUBLISH")  # deprecated\n'
        self.write("settings.py", source)
        out = self.base / "inventory.json"
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = inventory.main([str(self.repo), "--out", str(out), "--today", "2026-10-12"])
        self.assertEqual(status, 0, stderr.getvalue())
        published = out.read_text(encoding="utf-8")
        self.assertNotIn("DO_NOT_PUBLISH", published + stdout.getvalue() + stderr.getvalue())
        self.assert_masked(json.loads(published)["markers"][0])
        self.assertEqual((self.repo / "settings.py").read_text(encoding="utf-8"), source)

    def test_public_fixture_excerpts_keep_the_existing_text(self):
        result = inventory.inventory(ROOT / "examples" / "larder", today="2026-10-12")
        self.assertEqual([row["text"] for row in result["skipped_tests"]],
                         ['@pytest.mark.skip(reason="flaky since 2024-02")'])
        self.assertEqual([row["text"] for row in result["markers"]], [
            '"""Price A/B test. Experiment ended 2025-03-31; variant A won."""',
            '# Deprecated 2024-01; kept for the iOS app 2.x (docs/clients.md).',
            '"""Compatibility shims for the 0.x client. Remove after 2025-06-30."""',
        ])


if __name__ == "__main__":
    unittest.main()
