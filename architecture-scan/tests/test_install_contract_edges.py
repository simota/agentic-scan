"""Check that the package gate requires every localized filing template."""
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

from test_architecture_scan import make_env


REPO = Path(__file__).resolve().parents[1]
TEMPLATES = ("issue.ja.md", "issue.en.md", "report.ja.md", "report.en.md")


@unittest.skipUnless(shutil.which("make"), "make is required for package checks")
class PackageTemplateTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="architecture-scan-package-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.repo = self.root / "checkout"
        shutil.copytree(REPO, self.repo, ignore=shutil.ignore_patterns(".git", "__pycache__"))
        self.templates = self.repo / "skills" / "architecture-scan" / "templates"

    def run_check(self):
        env = make_env()
        return subprocess.run(
            ["make", "--no-print-directory", "-f", str(self.repo / "Makefile"),
             # Test the package gate without recursively invoking this test suite.
             "-o", "test", "check", "AGENT=", "SKILLS_DIR=", "PROJECT=",
             f"PYTHON={shlex.quote(sys.executable)}"],
            cwd=self.root, env=env, text=True, capture_output=True, timeout=10,
        )

    def assert_missing_template(self, result, name):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(f"MISS required templates/{name}", result.stderr)
        self.assertNotIn("check ok", result.stdout)

    def test_complete_package_passes(self):
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("check ok", result.stdout)

    def test_each_missing_template_fails(self):
        for name in TEMPLATES:
            with self.subTest(template=name):
                path = self.templates / name
                original = path.read_bytes()
                path.unlink()
                try:
                    self.assert_missing_template(self.run_check(), name)
                finally:
                    path.write_bytes(original)

    def test_missing_templates_directory_fails(self):
        shutil.rmtree(self.templates)
        result = self.run_check()
        for name in TEMPLATES:
            with self.subTest(template=name):
                self.assert_missing_template(result, name)

    def test_directory_in_place_of_template_fails(self):
        for name in TEMPLATES:
            with self.subTest(template=name):
                path = self.templates / name
                original = path.read_bytes()
                path.unlink()
                path.mkdir()
                try:
                    self.assert_missing_template(self.run_check(), name)
                finally:
                    path.rmdir()
                    path.write_bytes(original)


if __name__ == "__main__":
    unittest.main()
