"""Outputs stay outside the reviewed repository; env-style secret files are never excerpted."""

import contextlib
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "prune-scan" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import inventory  # noqa: E402
import render  # noqa: E402


def quiet(function, *args):
    stderr = io.StringIO()
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(stderr):
        return function(*args), stderr.getvalue()


class OutputOutsideReviewedRepositoryTests(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.base)
        self.repo = self.base / "app"
        self.repo.mkdir()
        (self.repo / "main.py").write_text("print('app')\n", encoding="utf-8")
        self.record = self.base / "record"
        self.record.mkdir()
        shutil.copy(ROOT / "examples" / "findings.sample.json", self.record / "findings.json")
        shutil.copy(ROOT / "examples" / "units.sample.json", self.record / "units.json")

    def render(self, out, repo=None):
        args = [str(self.record / "findings.json"), "--out", str(out), "--no-pdf"]
        return quiet(render.main, args + ["--repo", str(repo or self.repo)])

    def test_render_refuses_the_repository_and_directories_inside_it(self):
        (self.repo / "report.html").write_text("<p>the app's own page</p>\n", encoding="utf-8")
        for out in (self.repo, self.repo / "docs" / "prune"):
            with self.subTest(out=out):
                status, stderr = self.render(out)
                self.assertEqual(status, 2)
                self.assertIn("outside --repo", stderr)
                self.assertEqual((self.repo / "report.html").read_text(encoding="utf-8"),
                                 "<p>the app's own page</p>\n")
                self.assertFalse((self.repo / "dashboard.html").exists())
                self.assertFalse((self.repo / "docs").exists())

    def test_render_refuses_an_alias_of_the_repository(self):
        alias = self.base / "alias"
        alias.symlink_to(self.repo, target_is_directory=True)
        status, _ = self.render(alias / "out")
        self.assertEqual(status, 2)
        self.assertFalse((self.repo / "out").exists())
        status, _ = self.render(self.base / "out", repo=alias)
        self.assertEqual(status, 0)

    def test_render_accepts_a_sibling_whose_name_extends_the_repository(self):
        status, _ = self.render(self.base / "app-review")
        self.assertEqual(status, 0)
        self.assertTrue((self.base / "app-review" / "report.html").is_file())

    def test_inventory_refuses_an_output_inside_the_repository(self):
        (self.repo / "inventory.json").write_text('{"mine": 1}\n', encoding="utf-8")
        for out in (self.repo / "inventory.json", self.repo / "sub" / "inventory.json"):
            with self.subTest(out=out):
                status, stderr = quiet(inventory.main, [str(self.repo), "--out", str(out)])
                self.assertEqual(status, 2)
                self.assertIn("outside the reviewed repository", stderr)
        self.assertEqual(json.loads((self.repo / "inventory.json").read_text(encoding="utf-8")), {"mine": 1})
        self.assertFalse((self.repo / "sub").exists())

    def test_inventory_writes_beside_the_repository(self):
        out = self.base / "app-review" / "inventory.json"
        out.parent.mkdir()
        status, _ = quiet(inventory.main, [str(self.repo), "--out", str(out)])
        self.assertEqual(status, 0)
        self.assertTrue(out.is_file())


class EnvStyleSecretFileTests(unittest.TestCase):
    def test_env_and_htpasswd_variants_are_never_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            for name in (".envrc", "production.env", "deploy/staging.env", ".env-prod", ".env_local",
                         "deploy/htpasswd.txt", "nginx/site.htpasswd"):
                with self.subTest(name=name):
                    path = repo / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text("export GITHUB_PAT=ghp_DO_NOT_PUBLISH\n", encoding="utf-8")
                    self.assertTrue(render.secret_path(name))
                    self.assertIsNone(render.snippet(repo, f"{name}:1"))

    def test_ordinary_files_named_like_env_still_excerpt(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            for name in ("env.ts", "environment.py", "src/envelope.js", "config/env.py", ".environment.ts"):
                with self.subTest(name=name):
                    path = repo / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text("print('public')\n", encoding="utf-8")
                    self.assertFalse(render.secret_path(name))
                    self.assertEqual(render.snippet(repo, f"{name}:1")["lines"], ["print('public')"])


if __name__ == "__main__":
    unittest.main()
