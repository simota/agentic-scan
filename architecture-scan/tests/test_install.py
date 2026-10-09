"""Exercise installation targets only inside temporary directories."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[1]
SKILL = REPO / "skills" / "architecture-scan"


@unittest.skipUnless(shutil.which("make"), "make is required for installation tests")
class InstallTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="architecture-scan-install-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def run_make(self, target, **variables):
        # Explicit overrides keep every write away from the real host directories.
        settings = {"AGENT": "agy", "SKILLS_DIR": "", "PROJECT": ""}
        settings.update(variables)
        env = os.environ.copy()
        for name in ("MAKEFLAGS", "MFLAGS"):
            env.pop(name, None)
        return subprocess.run(
            ["make", "--no-print-directory", "-f", str(REPO / "Makefile"), target]
            + [f"{name}={value}" for name, value in settings.items()],
            cwd=self.root, env=env, text=True, capture_output=True, timeout=10,
        )

    def destination(self, mode):
        base = self.root / mode / "path with spaces"
        if mode == "skills":
            return base, base / "architecture-scan", {"SKILLS_DIR": base}
        if mode == "project":
            return base, base / ".claude" / "skills" / "architecture-scan", {"PROJECT": base}
        return base, base / "skills" / "architecture-scan", {"AGY_HOME": base}

    def assert_success(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_space_paths_support_link_status_and_unlink(self):
        for mode in ("skills", "project", "host"):
            with self.subTest(mode=mode):
                base, link, variables = self.destination(mode)
                base.mkdir(parents=True)
                self.assert_success(self.run_make("link", **variables))
                self.assertTrue(link.is_symlink())
                self.assertEqual(link.readlink(), SKILL)

                repeated = self.run_make("link", **variables)
                self.assert_success(repeated)
                self.assertIn(f"{link} already linked", repeated.stdout)

                status = self.run_make("status", **variables)
                self.assert_success(status)
                self.assertIn(f"symlink  {link} -> {SKILL}", status.stdout)

                self.assert_success(self.run_make("unlink", **variables))
                self.assertFalse(link.is_symlink())
                status = self.run_make("status", **variables)
                self.assert_success(status)
                self.assertIn(f"absent   {link}", status.stdout)

    def test_foreign_symlinks_are_refused_and_preserved(self):
        for existing in (False, True):
            with self.subTest(existing_target=existing):
                base = self.root / f"skills {existing}"
                base.mkdir()
                foreign = self.root / f"foreign {existing}"
                if existing:
                    foreign.mkdir()
                link = base / "architecture-scan"
                link.symlink_to(foreign)

                result = self.run_make("link", SKILLS_DIR=base)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f"refusing {link}", result.stderr)
                result = self.run_make("unlink", SKILLS_DIR=base)
                self.assert_success(result)
                self.assertIn(f"left     {link}", result.stdout)
                self.assertEqual(link.readlink(), foreign)

    def test_regular_files_and_directories_are_preserved(self):
        for kind in ("file", "directory"):
            with self.subTest(kind=kind):
                base = self.root / f"skills {kind}"
                base.mkdir()
                entry = base / "architecture-scan"
                if kind == "directory":
                    entry.mkdir()
                    sentinel = entry / "keep.txt"
                else:
                    sentinel = entry
                sentinel.write_text("keep", encoding="utf-8")

                result = self.run_make("link", SKILLS_DIR=base)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f"refusing {entry}", result.stderr)
                result = self.run_make("unlink", SKILLS_DIR=base)
                self.assert_success(result)
                self.assertIn(f"left     {entry}", result.stdout)
                self.assertEqual(sentinel.read_text(encoding="utf-8"), "keep")

    def test_missing_parent_directories_are_skipped(self):
        for mode in ("skills", "project", "host"):
            with self.subTest(mode=mode):
                base, link, variables = self.destination(mode)
                result = self.run_make("link", **variables)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f"skip     {link} - {base} does not exist", result.stdout)
                result = self.run_make("status", **variables)
                self.assert_success(result)
                self.assertIn(f"skip     {link} - host not installed", result.stdout)
                self.assertFalse(base.exists())


if __name__ == "__main__":
    unittest.main()
