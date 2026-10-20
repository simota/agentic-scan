"""Keep install and demo targets usable from literal checkout paths."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from test_architecture_scan import make_env


REPO = Path(__file__).resolve().parents[1]


def make_keeps_dollar_in_makefile_path(root):
    """GNU Make 3.81 expands a `$` in a -f path before recording MAKEFILE_LIST."""
    probe = root / "probe $keep"
    probe.mkdir()
    (probe / "probe.mk").write_text("$(info [$(MAKEFILE_LIST)])\nall: ;\n", encoding="utf-8")
    result = subprocess.run(
        ["make", "--no-print-directory", "-f", str(probe / "probe.mk")],
        cwd=root, env=make_env(), text=True, capture_output=True, timeout=10,
    )
    return "$keep" in result.stdout


@unittest.skipUnless(shutil.which("make"), "make is required for installation tests")
class CheckoutPathTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="architecture-scan-checkout-")
        self.addCleanup(temporary.cleanup)
        # Links name the checkout's physical path, so expect it (macOS: /var -> /private/var).
        self.root = Path(temporary.name).resolve()
        self.keeps_dollar = make_keeps_dollar_in_makefile_path(self.root)

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

    def assert_unlocatable(self, result, link):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("cannot locate this Makefile", result.stderr)
        self.assertFalse(link.is_symlink())

    def unlocatable(self, name, invocation):
        return "$" in name and invocation in ("absolute", "relative") and not self.keeps_dollar

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
                    result = self.run_make(repo, invocation, "link", SKILLS_DIR=destination)
                    if self.unlocatable(name, invocation):
                        self.assert_unlocatable(result, link)
                        continue
                    self.assert_success(result)
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
                    link = destination / "architecture-scan"
                    if self.unlocatable(name, "absolute"):
                        self.assert_unlocatable(result, link)
                        continue
                    self.assert_success(result)
                    self.assertEqual(link.readlink(), skill)
                    self.assertTrue((link / "SKILL.md").is_file())
                    help_result = self.run_make(repo, "absolute", "help", preload=preload)
                    self.assert_success(help_result)
                    self.assertIn(f"skill:  {skill}", help_result.stdout)
                    self.assertIn("symlink the skill", help_result.stdout)


    def test_symlinked_checkout_links_one_target_for_every_invocation(self):
        real = self.root / "real"
        shutil.copytree(REPO, real, ignore=shutil.ignore_patterns(".git", "__pycache__"))
        alias = self.root / "alias"
        alias.symlink_to(real)
        skill = real / "skills" / "architecture-scan"
        destination = self.root / "skills"
        destination.mkdir()
        link = destination / "architecture-scan"
        # A shell inside the alias exports the logical PWD that `pwd` reports.
        env = {**make_env(), "PWD": str(alias)}
        command = ["make", "--no-print-directory"]
        settings = [f"SKILLS_DIR={destination}", "AGENT=agy", "PROJECT="]
        self.assert_success(subprocess.run(
            command + ["link"] + settings, cwd=alias, env=env, text=True, capture_output=True, timeout=10,
        ))
        self.assertEqual(link.readlink(), skill)
        self.assert_success(self.run_make(alias, "directory", "unlink", SKILLS_DIR=destination))
        self.assertFalse(link.is_symlink())

    def test_link_made_through_a_symlinked_checkout_still_counts_as_ours(self):
        real = self.root / "real"
        shutil.copytree(REPO, real, ignore=shutil.ignore_patterns(".git", "__pycache__"))
        alias = self.root / "alias"
        alias.symlink_to(real)
        destination = self.root / "skills"
        destination.mkdir()
        link = destination / "architecture-scan"
        link.symlink_to(alias / "skills" / "architecture-scan")  # made before links were physical
        result = self.run_make(real, "directory", "link", SKILLS_DIR=destination)
        self.assert_success(result)
        self.assertIn("already linked", result.stdout)
        self.assert_success(self.run_make(real, "directory", "unlink", SKILLS_DIR=destination))
        self.assertFalse(link.is_symlink())


    def test_link_to_a_users_own_link_is_not_ours(self):
        skill = REPO / "skills" / "architecture-scan"
        switcher = self.root / "current"
        switcher.symlink_to(skill)  # e.g. a version switcher the user maintains
        destination = self.root / "skills"
        destination.mkdir()
        link = destination / "architecture-scan"
        link.symlink_to(switcher)
        result = self.run_make(REPO, "directory", "link", SKILLS_DIR=destination)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("refusing", result.stderr)
        result = self.run_make(REPO, "directory", "unlink", SKILLS_DIR=destination)
        self.assert_success(result)
        self.assertIn("left", result.stdout)
        self.assertEqual(link.readlink(), switcher)


if __name__ == "__main__":
    unittest.main()
