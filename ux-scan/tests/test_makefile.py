"""Exercise public Make targets from checkout and install paths containing spaces."""
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which("make"), "GNU Make is required")
class MakefileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.repo = self.base / "checkout with spaces"
        self.repo.mkdir()
        shutil.copy2(ROOT / "Makefile", self.repo / "Makefile")
        # Copy only the sources the targets use: TMPDIR may itself be inside ROOT.
        for name in ("scripts", "skills", "examples"):
            shutil.copytree(ROOT / name, self.repo / name,
                            ignore=shutil.ignore_patterns("__pycache__"))

    def make(self, *args, cwd=None):
        result = subprocess.run(
            ["make", "--no-print-directory", *map(str, args), f"PYTHON={sys.executable}"],
            cwd=cwd or self.repo, text=True, capture_output=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def test_demo_and_external_makefile_resolve_checkout_with_spaces(self):
        help_result = self.make("-f", self.repo / "Makefile", "help", cwd=self.base)
        self.assertIn(str(self.repo / "skills" / "ux-scan"), help_result.stdout)
        out = self.base / "demo output"
        result = self.make("demo", "NO_PDF=1", "LANG_OUT=en", f"DEMO_OUT={out}")
        self.assertIn("contract ok:", result.stdout)
        inventory = self.base / "external inventory.json"
        self.make("-f", self.repo / "Makefile", "inventory",
                  f"TARGET={self.repo / 'examples' / 'tasklane'}",
                  f"FLOWS={out / 'flows.json'}", f"OUT={inventory}", cwd=self.base)
        data = json.loads(inventory.read_text(encoding="utf-8"))
        self.assertEqual([r["route"] for r in data["routes"]],
                         ["/", "/signup", "/settings", "/archive"])

    def test_literal_and_project_install_paths_ignore_unused_agent(self):
        for variable in ("SKILLS_DIR", "PROJECT"):
            with self.subTest(variable=variable):
                target = self.base / f"{variable} user's directory"
                target.mkdir()
                args = (f"{variable}={target}", "AGENT=unused-host")
                installed = (target if variable == "SKILLS_DIR"
                             else target / ".claude" / "skills") / "ux-scan"
                self.make("link", *args)
                self.assertTrue(installed.is_symlink())
                self.assertEqual(installed.resolve(), self.repo / "skills" / "ux-scan")
                self.assertIn("symlink", self.make("status", *args).stdout)
                self.assertIn("already linked", self.make("link", *args).stdout)
                self.make("unlink", *args)
                self.assertFalse(installed.is_symlink())
                self.assertFalse(installed.exists())

    def test_unknown_agent_is_rejected_when_selecting_hosts(self):
        result = subprocess.run(
            ["make", "--no-print-directory", "status", "AGENT=unknown-host"],
            cwd=self.repo, text=True, capture_output=True, timeout=30,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unknown AGENT", result.stderr)


if __name__ == "__main__":
    unittest.main()
