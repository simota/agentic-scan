"""Regressions for checkout aliases, demo paths and messages with backslashes."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import test_install
from test_install import REPO, clean_environment


def make(cwd, *args, env=None):
    return subprocess.run(["make", "--no-print-directory", *args], cwd=cwd,
                          env=clean_environment(env),
                          capture_output=True, text=True, timeout=30)


class AliasTests(unittest.TestCase):
    run_make = test_install.InstallTests.run_make
    assert_success = test_install.InstallTests.assert_success
    copy_checkout = test_install.InstallTests.copy_checkout

    def test_links_made_through_an_alias_belong_to_the_same_checkout(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d).resolve()
            checkout, _ = self.copy_checkout(root, "checkout")
            alias = root / "alias"
            alias.symlink_to(checkout, target_is_directory=True)
            requested = root / "skills"
            requested.mkdir()
            destination = requested / "privacy-scan"
            self.assert_success(self.run_make(root, "link", makefile=alias / "Makefile",
                                              SKILLS_DIR=str(requested)))
            self.assertEqual(destination.readlink(), alias / "skills" / "privacy-scan")
            linked = self.run_make(checkout, "link", makefile=None, SKILLS_DIR=str(requested))
            self.assert_success(linked)
            self.assertIn("already linked", linked.stdout)
            self.assert_success(self.run_make(checkout, "unlink", makefile=None,
                                              SKILLS_DIR=str(requested)))
            self.assertFalse(destination.is_symlink())

    def test_links_to_another_copy_are_still_refused(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d).resolve()
            checkout, _ = self.copy_checkout(root, "checkout")
            _, other = self.copy_checkout(root, "other")
            requested = root / "skills"
            requested.mkdir()
            (requested / "privacy-scan").symlink_to(other, target_is_directory=True)
            linked = self.run_make(checkout, "link", makefile=None, SKILLS_DIR=str(requested))
            self.assertNotEqual(linked.returncode, 0)
            self.assert_success(self.run_make(checkout, "unlink", makefile=None,
                                              SKILLS_DIR=str(requested)))
            self.assertEqual((requested / "privacy-scan").readlink(), other)

    def test_backslashes_in_paths_are_printed_literally(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d).resolve()
            requested = root / "skills\\back"
            requested.mkdir()
            linked = self.run_make(root, "link", SKILLS_DIR=str(requested))
            self.assert_success(linked)
            self.assertIn(str(requested / "privacy-scan"), linked.stdout)
            status = self.run_make(root, "status", SKILLS_DIR=str(requested))
            self.assertIn(str(requested / "privacy-scan"), status.stdout)
            self.assert_success(self.run_make(root, "unlink", SKILLS_DIR=str(requested)))


class DemoTests(unittest.TestCase):
    def test_environment_paths_are_literal(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d).resolve()
            out = root / "demo $HOME 'q'"
            result = make(REPO, "demo", env={**os.environ, "DEMO_OUT": str(out)})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((out / "report.md").is_file())
            tmp = root / "tmp $x"
            tmp.mkdir()
            env = {k: v for k, v in os.environ.items() if k != "DEMO_OUT"}
            result = make(REPO, "demo", env={**env, "TMPDIR": str(tmp)})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((tmp / "privacy-scan-demo" / "dashboard.html").is_file())

    def test_leading_hyphen_paths_are_not_options(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d).resolve()
            sample = root / "-in.json"
            sample.write_bytes((REPO / "examples" / "findings.sample.json").read_bytes())
            result = make(root, "-f", str(REPO / "Makefile"), "demo",
                          "DEMO_OUT=-out", "DEMO_INPUT=-in.json", "LANG_OUT=en")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((root / "-out" / "report.md").is_file())


if __name__ == "__main__":
    unittest.main()
