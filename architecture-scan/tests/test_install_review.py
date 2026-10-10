"""Keep install and demo targets usable from literal checkout paths."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from test_architecture_scan import make_env


REPO = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which("make"), "make is required for installation tests")
class CheckoutPathTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="architecture-scan-checkout-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def run_make(self, repo, invocation, target, preload=None, **variables):
        command = ["make", "--no-print-directory"]
        if preload == "argument":
            command.extend(["-f", str(self.root / "defaults.mk")])
        if invocation == "normal":
            cwd = repo
        elif invocation == "directory":
            cwd = self.root
            command.extend(["-C", str(repo)])
        else:
            cwd = self.root
            makefile = repo / "Makefile"
            if invocation == "relative":
                makefile = makefile.relative_to(cwd)
            command.extend(["-f", str(makefile)])
        settings = {"AGENT": "agy", "SKILLS_DIR": "", "PROJECT": ""}
        settings.update(variables)
        env = make_env()
        if preload == "environment":
            env["MAKEFILES"] = str(self.root / "defaults.mk")
        return subprocess.run(
            command + [target] + [f"{name}={value}" for name, value in settings.items()],
            cwd=cwd, env=env, text=True, capture_output=True, timeout=10,
        )

    def assert_success(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_checkout_paths_preserved_by_all_makefile_invocations(self):
        for case, name in enumerate(("checkout with spaces", "checkout's $cached `printf marker` files")):
            repo = self.root / name
            shutil.copytree(REPO, repo, ignore=shutil.ignore_patterns(".git", "__pycache__"))
            skill = repo / "skills" / "architecture-scan"
            for invocation in ("normal", "directory", "absolute", "relative"):
                with self.subTest(checkout=name, invocation=invocation):
                    destination = self.root / f"skills-{case}-{invocation}"
                    destination.mkdir(exist_ok=True)
                    link = destination / "architecture-scan"
                    self.assert_success(self.run_make(repo, invocation, "link", SKILLS_DIR=destination))
                    self.assertTrue(link.is_symlink())
                    self.assertEqual(link.readlink(), skill)
                    self.assertTrue((link / "SKILL.md").is_file())

                    status = self.run_make(repo, invocation, "status", SKILLS_DIR=destination)
                    self.assert_success(status)
                    self.assertIn(f"symlink  {link} -> {skill}", status.stdout)
                    self.assert_success(self.run_make(repo, invocation, "unlink", SKILLS_DIR=destination))
                    self.assertFalse(link.is_symlink())

                    help_result = self.run_make(repo, invocation, "help")
                    self.assert_success(help_result)
                    self.assertIn(f"skill:  {skill}", help_result.stdout)
                    self.assertIn("symlink the skill", help_result.stdout)

                    output = self.root / f"demo-{case}-{invocation}"
                    self.assert_success(self.run_make(repo, invocation, "demo", DEMO_OUT=output))
                    self.assertTrue((output / "dashboard.html").is_file())
                    self.assertTrue((output / "report.md").is_file())

    def test_pipe_paths_preserved_for_each_destination_mode(self):
        skill = REPO / "skills" / "architecture-scan"
        for mode in ("skills", "project", "host"):
            with self.subTest(mode=mode):
                base = self.root / f"{mode} path|literal destination"
                base.mkdir()
                # A truncated guard must not authorize writes to a different path.
                (self.root / f"{mode} path").mkdir()
                if mode == "skills":
                    variables = {"SKILLS_DIR": base}
                    link = base / "architecture-scan"
                elif mode == "project":
                    variables = {"PROJECT": base}
                    link = base / ".claude" / "skills" / "architecture-scan"
                else:
                    variables = {"AGY_HOME": base}
                    link = base / "skills" / "architecture-scan"

                self.assert_success(self.run_make(REPO, "absolute", "link", **variables))
                self.assertTrue(link.is_symlink())
                self.assertEqual(link.readlink(), skill)
                self.assertFalse((self.root / "literal destination").exists())
                status = self.run_make(REPO, "absolute", "status", **variables)
                self.assert_success(status)
                self.assertIn(f"symlink  {link} -> {skill}", status.stdout)
                self.assert_success(self.run_make(REPO, "absolute", "unlink", **variables))
                self.assertFalse(link.is_symlink())

    def test_preloaded_makefiles_preserve_checkout_path(self):
        (self.root / "defaults.mk").write_text("# Preloaded Make settings.\n", encoding="utf-8")
        for case, name in enumerate(("checkout", "checkout's $cached `printf marker` files")):
            repo = self.root / name
            shutil.copytree(REPO, repo, ignore=shutil.ignore_patterns(".git", "__pycache__"))
            skill = repo / "skills" / "architecture-scan"
            for preload in ("argument", "environment"):
                with self.subTest(checkout=name, preload=preload):
                    destination = self.root / f"skills-{case}-{preload}"
                    destination.mkdir()
                    result = self.run_make(
                        repo, "absolute", "link", preload=preload, SKILLS_DIR=destination,
                    )
                    self.assert_success(result)
                    link = destination / "architecture-scan"
                    self.assertEqual(link.readlink(), skill)
                    self.assertTrue((link / "SKILL.md").is_file())
                    help_result = self.run_make(repo, "absolute", "help", preload=preload)
                    self.assert_success(help_result)
                    self.assertIn(f"skill:  {skill}", help_result.stdout)
                    self.assertIn("symlink the skill", help_result.stdout)


if __name__ == "__main__":
    unittest.main()
