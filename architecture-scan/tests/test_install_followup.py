"""Guard literal install paths and destinations created concurrently."""
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

from test_architecture_scan import make_env


REPO = Path(__file__).resolve().parents[1]
SKILL = REPO / "skills" / "architecture-scan"


@unittest.skipUnless(shutil.which("make"), "make is required for installation tests")
class InstallFollowupTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="architecture-scan-relative-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def run_make(self, target, repo=REPO, commands=None, **variables):
        settings = {"AGENT": "agy", "SKILLS_DIR": "", "PROJECT": ""}
        settings.update(variables)
        env = make_env()
        if commands is not None:
            env["PATH"] = str(commands) + os.pathsep + env.get("PATH", "")
        return subprocess.run(
            ["make", "--no-print-directory", "-f", str(repo / "Makefile"), target]
            + [f"{name}={value}" for name, value in settings.items()],
            cwd=self.root, env=env, text=True, capture_output=True, timeout=10,
        )

    def destination(self, mode):
        base = Path(f"-{mode}")
        (self.root / base).mkdir()
        if mode == "skills":
            return base / "architecture-scan", {"SKILLS_DIR": base}
        if mode == "project":
            return base / ".claude" / "skills" / "architecture-scan", {"PROJECT": base}
        return base / "skills" / "architecture-scan", {"AGY_HOME": base}

    def assert_success(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def existing_link(self, mode):
        relative, variables = self.destination(mode)
        link = self.root / relative
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(SKILL)
        return relative, link, variables

    def test_link_accepts_relative_destinations_starting_with_dash(self):
        for mode in ("skills", "project", "host"):
            with self.subTest(mode=mode):
                relative, variables = self.destination(mode)
                link = self.root / relative
                self.assert_success(self.run_make("link", **variables))
                self.assertEqual(link.readlink(), SKILL)

                repeated = self.run_make("link", **variables)
                self.assert_success(repeated)
                self.assertIn(f"{relative} already linked", repeated.stdout)

    def test_status_reads_relative_symlinks_starting_with_dash(self):
        for mode in ("skills", "project", "host"):
            with self.subTest(mode=mode):
                relative, link, variables = self.existing_link(mode)
                result = self.run_make("status", **variables)
                self.assert_success(result)
                self.assertIn(f"symlink  {relative} -> {SKILL}", result.stdout)
                self.assertEqual(result.stderr, "")
                self.assertEqual(link.readlink(), SKILL)

    def test_unlink_removes_relative_symlinks_starting_with_dash(self):
        for mode in ("skills", "project", "host"):
            with self.subTest(mode=mode):
                relative, link, variables = self.existing_link(mode)
                result = self.run_make("unlink", **variables)
                self.assert_success(result)
                self.assertIn(f"unlinked {relative}", result.stdout)
                self.assertFalse(link.is_symlink())

    def test_link_refuses_destinations_created_after_existence_check(self):
        repo = self.root / "checkout"
        shutil.copytree(REPO, repo, ignore=shutil.ignore_patterns(".git", "__pycache__"))
        skill = repo / "skills" / "architecture-scan"
        skill_text = (skill / "SKILL.md").read_bytes()
        for kind in ("symlink", "directory"):
            with self.subTest(kind=kind):
                destination = self.root / kind / "skills"
                destination.mkdir(parents=True)
                link = destination / "architecture-scan"
                commands = self.root / kind / "commands"
                commands.mkdir()
                if kind == "symlink":
                    create = "import os,sys; os.symlink(sys.argv[1], sys.argv[2])"
                else:
                    create = (
                        "from pathlib import Path; import sys; "
                        "path=Path(sys.argv[2]); path.mkdir(); "
                        "(path/'keep.txt').write_text('keep', encoding='utf-8')"
                    )
                # Make a concurrent destination appear after the installer's
                # existence check and before its attempt to create the link.
                shim = commands / "mkdir"
                shim.write_text(
                    "#!/bin/sh\n" + shlex.quote(shutil.which("mkdir"))
                    + ' "$@" || exit "$?"\n'
                    + " ".join(shlex.quote(arg) for arg in (
                        sys.executable, "-c", create, str(skill), str(link),
                    )) + "\n",
                    encoding="utf-8",
                )
                shim.chmod(0o755)

                result = self.run_make("link", repo=repo, commands=commands, SKILLS_DIR=destination)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertNotIn("linked   ", result.stdout)
                self.assertNotIn("invoke it with", result.stdout)
                self.assertFalse((skill / "architecture-scan").is_symlink())
                self.assertEqual((skill / "SKILL.md").read_bytes(), skill_text)
                if kind == "symlink":
                    self.assertEqual(link.readlink(), skill)
                else:
                    self.assertFalse(link.is_symlink())
                    self.assertEqual((link / "keep.txt").read_text(encoding="utf-8"), "keep")
                    self.assertFalse((link / "architecture-scan").is_symlink())


if __name__ == "__main__":
    unittest.main()
