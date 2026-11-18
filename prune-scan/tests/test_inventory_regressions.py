"""Regression coverage for repository inputs outside the demonstration fixture."""
import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "prune-scan" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import inventory  # noqa: E402


class InventoryInputTests(unittest.TestCase):
    def test_openssh_private_key_names_are_never_scanned(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            key_names = ("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_xmss", "id_ecdsa_sk", "id_ed25519_sk")
            for name in key_names:
                (root / name).write_text("deprecated secret-key-material\n", encoding="utf-8")
            result = inventory.inventory(root)
            self.assertEqual(result["files_scanned"], 0)
            self.assertEqual(result["files_skipped"], len(key_names))
            self.assertNotIn("secret-key-material", json.dumps(result))

    def test_env_examples_never_expose_values_to_other_collectors(self):
        for filename in (".env.example", ".env.sample", ".env.template", ".env.dist", "example.env", "env.example"):
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / filename).write_text(
                    '# deprecated secret-comment\n'
                    'TOKEN=secret-token # remove after 2020-01-01\n'
                    'export ENABLE_TEST="secret-feature"\n'
                    'MULTILINE="start\n'
                    'EMBEDDED=secret-multiline\n'
                    'sunset secret-second-line\n'
                    '"\n'
                    'AFTER=secret-after\n'
                    'DYNAMIC=`secret-prefix.${value}`\n'
                    'CHECK=isEnabled("secret-flag")\n', encoding="utf-8")
                result = inventory.inventory(root, today="2026-10-12")
                serialized = json.dumps(result)
                self.assertNotIn("secret-", serialized)
                self.assertEqual(result["env_declared_not_read"], [
                    {"name": "AFTER", "location": f"{filename}:8"},
                    {"name": "CHECK", "location": f"{filename}:10"},
                    {"name": "DYNAMIC", "location": f"{filename}:9"},
                    {"name": "ENABLE_TEST", "location": f"{filename}:3"},
                    {"name": "MULTILINE", "location": f"{filename}:4"},
                    {"name": "TOKEN", "location": f"{filename}:2"},
                ])

    def test_multiline_env_values_preserve_following_declaration_locations(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".env.example").write_text(
                'lowercase="line one\\"\n'
                'EMBEDDED=secret-value\n'
                '"\n'
                'TOKEN="value\u2028with-unicode-separator"\n'
                'AFTER=last\n', encoding="utf-8")
            result = inventory.inventory(root)
            self.assertEqual(result["env_declared_not_read"], [
                {"name": "AFTER", "location": ".env.example:5"},
                {"name": "TOKEN", "location": ".env.example:4"},
            ])

    def test_dotenv_multiline_quotes_and_extended_keys_cannot_expose_value_lines(self):
        for key, quote in (("TOKEN", "`"), ("service.token", '"'), ("service-token", "'"), ("'TOKEN'", '"')):
            with self.subTest(key=key, quote=quote), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / ".env.example").write_text(
                    f"{key}={quote}first line\nPRIVATEKEYCONTENTS=value\n{quote}\nAFTER=ok\n", encoding="utf-8")
                result = inventory.inventory(root)
                self.assertNotIn("PRIVATEKEYCONTENTS", json.dumps(result))
                self.assertIn({"name": "AFTER", "location": ".env.example:4"}, result["env_declared_not_read"])

    def test_deep_locale_json_does_not_abort_the_repository_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "locales").mkdir()
            (root / "locales" / "en.json").write_text(
                '{"nested":' * 1100 + '"value"' + '}' * 1100, encoding="utf-8")
            (root / "unused.py").write_text("def unused_function():\n    pass\n", encoding="utf-8")
            result = inventory.inventory(root)
            self.assertEqual([r["name"] for r in result["unreferenced_symbols"]], ["unused_function"])
            self.assertEqual(result["i18n_unreferenced"], [])

    def test_asset_removed_after_directory_walk_does_not_abort_the_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "gone.png").write_bytes(b"image")
            (root / "unused.py").write_text("def unused_function():\n    pass\n", encoding="utf-8")
            iter_files = inventory.iter_files

            def remove_asset_after_discovery(repo, **kwargs):
                for path in iter_files(repo, **kwargs):
                    if path.name == "gone.png":
                        path.unlink()
                    yield path

            with mock.patch.object(inventory, "iter_files", side_effect=remove_asset_after_discovery):
                result = inventory.inventory(root)
            self.assertEqual([r["name"] for r in result["unreferenced_symbols"]], ["unused_function"])
            self.assertEqual(result["assets_unreferenced"], [])
            self.assertEqual(result["files_skipped"], 1)

    def test_malformed_package_shapes_do_not_abort_the_repository_scan(self):
        packages = [None, [], True, "package", {"scripts": []}, {"scripts": True},
                    {"dependencies": True}, {"dependencies": [3]},
                    {"dependencies": "not-a-map"}]
        for package in packages:
            with self.subTest(package=package), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "package.json").write_text(json.dumps(package), encoding="utf-8")
                (root / "unused.py").write_text("def unused_function():\n    pass\n", encoding="utf-8")
                result = inventory.inventory(root)
                self.assertEqual([r["name"] for r in result["unreferenced_symbols"]], ["unused_function"])
                self.assertEqual(result["unimported_dependencies"], [])
                self.assertEqual(result["scripts"], [])

    def test_invalid_package_section_does_not_hide_other_valid_sections(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(json.dumps({
                "dependencies": [17], "devDependencies": {"unused-package": "1"},
                "scripts": {"test": "test-runner"},
            }), encoding="utf-8")
            result = inventory.inventory(root)
            self.assertEqual([r["name"] for r in result["unimported_dependencies"]], ["unused-package"])
            self.assertEqual([r["name"] for r in result["scripts"]], ["test"])

    def test_today_rejects_impossible_calendar_dates_without_writing(self):
        for date in ("2026-02-29", "2026-04-31", "2026-00-10", "2026-13-01", "0000-01-01"):
            with self.subTest(date=date), tempfile.TemporaryDirectory() as tmp:
                out = Path(tmp) / "inventory.json"
                errors = io.StringIO()
                with contextlib.redirect_stderr(errors):
                    result = inventory.main([tmp, "--out", str(out), "--today", date])
                self.assertEqual(result, 2)
                self.assertIn("--today", errors.getvalue())
                self.assertFalse(out.exists())

    def test_today_accepts_a_real_leap_day(self):
        with tempfile.TemporaryDirectory() as tmp:
            out, repo = Path(tmp) / "inventory.json", Path(tmp) / "repo"
            repo.mkdir()
            with contextlib.redirect_stdout(io.StringIO()):
                result = inventory.main([str(repo), "--out", str(out), "--today", "2024-02-29"])
            self.assertEqual(result, 0)
            self.assertEqual(json.loads(out.read_text(encoding="utf-8"))["today"], "2024-02-29")

    def test_units_reject_ambiguous_and_nonstandard_json_without_writing(self):
        sample = (ROOT / "examples" / "units.sample.json").read_text(encoding="utf-8").lstrip()
        for prefix in ('"app":"duplicate",', '"extra":NaN,', '"extra":1e999,', '"extra":"\\ud800",'):
            with self.subTest(prefix=prefix), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                units, out = root / "units.json", root / "inventory.json"
                units.write_text("{" + prefix + sample[1:], encoding="utf-8")
                with contextlib.redirect_stderr(io.StringIO()):
                    result = inventory.main([tmp, "--out", str(out), "--units", str(units)])
                self.assertEqual(result, 2)
                self.assertFalse(out.exists())

    @unittest.skipUnless(hasattr(os, "mkfifo"), "named pipes require POSIX")
    def test_units_named_pipe_is_refused_without_waiting_for_a_writer(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            units, out, repo = root / "units.json", root / "inventory.json", root / "repo"
            repo.mkdir()
            os.mkfifo(units)
            result = subprocess.run(
                [sys.executable, str(SCRIPTS / "inventory.py"), str(repo), "--out", str(out), "--units", str(units)],
                capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            self.assertIn("regular JSON file", result.stderr)
            self.assertNotIn("Traceback", result.stderr)
            self.assertFalse(out.exists())


class DependencyParsingTests(unittest.TestCase):
    def test_http_named_requirements_are_packages_and_urls_are_skipped(self):
        text = "httpx>=0.27\nhttpcore\nhttptools\nhttps://example.test/package.whl\nHTTP://example.test/other.whl\n"
        self.assertEqual(list(inventory.parse_requirements("requirements.txt", text)), [
            ("httpx", "requirements", "requirements.txt:1"),
            ("httpcore", "requirements", "requirements.txt:2"),
            ("httptools", "requirements", "requirements.txt:3"),
        ])

    def test_pyproject_metadata_arrays_are_not_dependencies(self):
        text = '''[project]
name = "example"
classifiers = ["Programming Language :: Python"]
dynamic = ["version"]
authors = [{name = "Example", email = "example@example.test"}]
keywords = ["search"]
dependencies = ["requests"]
[project.optional-dependencies]
test = ["pytest"]
[dependency-groups]
dev = ["ruff", {include-group = "test"}]
'''
        self.assertEqual(list(inventory.parse_toml_lists("pyproject.toml", text)), [
            ("requests", "project", "pyproject.toml:7"),
            ("pytest", "project.optional-dependencies", "pyproject.toml:9"),
            ("ruff", "dependency-groups", "pyproject.toml:11"),
        ])

    def test_extras_markers_and_comments_do_not_end_dependency_arrays(self):
        text = '''[project]
dependencies = [
    "requests[socks]>=2", # extras are not an array terminator
    "importlib-metadata; python_version < '3.10'",
    "example @ https://example.test/archive#v1", # quoted fragments are not comments
    # ] "not-a-dependency"
    'httpx',
]
keywords = ["unrelated"]
'''
        self.assertEqual(list(inventory.parse_toml_lists("pyproject.toml", text)), [
            ("requests", "project", "pyproject.toml:3"),
            ("importlib-metadata", "project", "pyproject.toml:4"),
            ("example", "project", "pyproject.toml:5"),
            ("httpx", "project", "pyproject.toml:7"),
        ])

    def test_poetry_and_cargo_dependency_tables_remain_supported(self):
        examples = (
            ("pyproject.toml", '[tool.poetry.dependencies]\npython = "^3.10"\nrequests = "*"\n',
             [("requests", "tool.poetry.dependencies", "pyproject.toml:3")]),
            ("Cargo.toml", '[dependencies]\nserde = {version = "1", features = ["derive"]}\n',
             [("serde", "dependencies", "Cargo.toml:2")]),
        )
        for filename, source, expected in examples:
            with self.subTest(filename=filename):
                self.assertEqual(list(inventory.parse_toml_lists(filename, source)), expected)


class ScriptInventoryTests(unittest.TestCase):
    def test_pre_and_post_hooks_use_the_complete_base_script_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scripts = {name: "echo task" for name in (
                "test", "pretest", "posttest", "typecheck", "pretypecheck", "posttypecheck",
                "lint", "prelint", "postlint", "preabsent", "postabsent",
            )}
            (root / "package.json").write_text(json.dumps({"scripts": scripts}), encoding="utf-8")
            result = inventory.inventory(root)
            self.assertEqual([r["name"] for r in result["uninvoked_scripts"]], [
                "test", "typecheck", "lint", "preabsent", "postabsent",
            ])


if __name__ == "__main__":
    unittest.main()
