"""Exercise public Make targets with literal checkout, interpreter and output paths."""
import json
import os
import shlex
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
        self.base = Path(self.tmp.name).resolve()  # macOS: $TMPDIR under /var is a symlink to /private/var
        self.repo = self.base / "checkout with spaces"
        self.repo.mkdir()
        shutil.copy2(ROOT / "Makefile", self.repo / "Makefile")
        # Copy only the sources the targets use: TMPDIR may itself be inside ROOT.
        for name in ("scripts", "skills", "examples"):
            shutil.copytree(ROOT / name, self.repo / name,
                            ignore=shutil.ignore_patterns("__pycache__"))

    def make(self, *args, cwd=None, python=None):
        result = subprocess.run(
            ["make", "--no-print-directory", *map(str, args), f"PYTHON={python or shlex.quote(sys.executable)}"],
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

    def test_demo_rejects_output_inside_fixture_before_writing(self):
        fixture = self.repo / "examples" / "tasklane"
        alias = self.base / "fixture alias"
        alias.symlink_to(fixture, target_is_directory=True)

        def snapshot():
            return {str(p.relative_to(fixture)): p.read_bytes() if p.is_file() else None
                    for p in fixture.rglob("*")}

        before = snapshot()
        for out in (fixture, fixture / "new output", alias / "new output"):
            with self.subTest(out=out):
                result = subprocess.run(
                    ["make", "--no-print-directory", "demo", "NO_PDF=1",
                     f"DEMO_OUT={out}", f"PYTHON={shlex.quote(sys.executable)}"],
                    cwd=self.repo, text=True, capture_output=True, timeout=30,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("read-only", result.stderr)
                self.assertEqual(snapshot(), before)

    def test_literal_and_project_install_paths_ignore_unused_agent(self):
        for variable in ("SKILLS_DIR", "PROJECT"):
            with self.subTest(variable=variable):
                target = self.base / f"{variable} user's \"quoted\" | directory"
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

    def test_shell_characters_in_paths_are_never_evaluated(self):
        self.repo = self.repo.rename(
            self.base / "checkout 'single' \"double\" `touch CHECKOUT_EVALUATED` | path"
        )
        interpreter = self.base / "python 'single' \"double\""
        interpreter.symlink_to(sys.executable)
        python_command = shlex.quote(str(interpreter))
        help_result = self.make("-f", self.repo / "Makefile", "help", cwd=self.base)
        self.assertIn(str(self.repo / "skills" / "ux-scan"), help_result.stdout)
        out = self.base / "output 'single' \"double\" `touch OUTPUT_EVALUATED` | path"
        self.make("demo", "NO_PDF=1", f"DEMO_OUT={out}", python=python_command)
        self.assertTrue((out / "report.html").is_file())
        inventory = out / "external 'quoted' inventory.json"
        self.make("-f", self.repo / "Makefile", "inventory",
                  f"TARGET={self.repo / 'examples' / 'tasklane'}",
                  f"FLOWS={out / 'flows.json'}", f"OUT={inventory}",
                  cwd=self.base, python=python_command)
        self.assertTrue(inventory.is_file())
        target = self.base / "skills 'single' \"double\" `touch INSTALL_EVALUATED` | path"
        target.mkdir()
        self.make("link", f"SKILLS_DIR={target}")
        self.assertEqual((target / "ux-scan").resolve(), self.repo / "skills" / "ux-scan")
        self.assertIn("already linked", self.make("link", f"SKILLS_DIR={target}").stdout)
        self.assertIn("symlink", self.make("status", f"SKILLS_DIR={target}").stdout)
        self.make("unlink", f"SKILLS_DIR={target}")
        self.assertFalse((target / "ux-scan").is_symlink())
        for directory in (self.base, self.repo):
            for name in ("CHECKOUT_EVALUATED", "OUTPUT_EVALUATED", "INSTALL_EVALUATED"):
                self.assertFalse((directory / name).exists(), str(directory / name))

    def test_relative_install_path_starting_with_dash_is_literal(self):
        target = self.repo / "-skills"
        target.mkdir()
        self.make("link", "SKILLS_DIR=-skills")
        self.assertEqual((target / "ux-scan").resolve(), self.repo / "skills" / "ux-scan")
        self.assertIn("already linked", self.make("link", "SKILLS_DIR=-skills").stdout)
        self.assertIn("symlink", self.make("status", "SKILLS_DIR=-skills").stdout)
        self.make("unlink", "SKILLS_DIR=-skills")
        self.assertFalse((target / "ux-scan").is_symlink())

    def test_unlink_failure_does_not_report_success(self):
        target = self.base / "installed skills"
        target.mkdir()
        self.make("link", f"SKILLS_DIR={target}")
        commands = self.base / "commands"
        commands.mkdir()
        remove = commands / "rm"
        remove.write_text("#!/bin/sh\necho 'simulated unlink failure' >&2\nexit 1\n", encoding="utf-8")
        remove.chmod(0o755)
        result = subprocess.run(
            ["make", "--no-print-directory", "unlink", f"SKILLS_DIR={target}"],
            cwd=self.repo, text=True, capture_output=True, timeout=30,
            env={**os.environ, "PATH": str(commands) + os.pathsep + os.environ.get("PATH", "")},
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("simulated unlink failure", result.stderr)
        self.assertNotIn("unlinked", result.stdout)
        self.assertTrue((target / "ux-scan").is_symlink())

    def test_python_command_can_include_interpreter_options(self):
        out = self.base / "inventory with options.json"
        self.make("inventory", f"TARGET={self.repo / 'examples' / 'tasklane'}",
                  f"OUT={out}", python=f"{shlex.quote(sys.executable)} -B")
        self.assertEqual(json.loads(out.read_text(encoding="utf-8"))["tool"], "inventory.py")

    def test_unknown_agent_is_rejected_when_selecting_hosts(self):
        result = subprocess.run(
            ["make", "--no-print-directory", "status", "AGENT=unknown-host"],
            cwd=self.repo, text=True, capture_output=True, timeout=30,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unknown AGENT", result.stderr)


if __name__ == "__main__":
    unittest.main()
