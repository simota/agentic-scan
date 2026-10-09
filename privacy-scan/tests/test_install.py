"""Offline regression tests for literal install paths and existing entries."""
from pathlib import Path
import subprocess
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[1]
SKILL = REPO / "skills" / "privacy-scan"


class InstallTests(unittest.TestCase):
    def run_make(self, cwd, target, **variables):
        options = {"AGENT": "agy", "PROJECT": "", "SKILLS_DIR": ""}
        options.update(variables)
        return subprocess.run(
            ["make", "--no-print-directory", "-f", str(REPO / "Makefile"), target,
             *[f"{key}={value}" for key, value in options.items()]],
            cwd=cwd, capture_output=True, text=True, timeout=10,
        )

    def assert_success(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def check_install_path(self, variable, suffix):
        for name in ("custom skills", "custom's skills"):
            with self.subTest(variable=variable, name=name), tempfile.TemporaryDirectory() as d:
                root = Path(d)
                requested = root / name
                prefix = root / name.split(" ", 1)[0]
                requested.mkdir()
                prefix.mkdir()
                destination = requested.joinpath(*suffix) / "privacy-scan"
                unrelated = prefix / "privacy-scan"
                variables = {variable: str(requested)}

                linked = self.run_make(root, "link", **variables)
                self.assert_success(linked)
                self.assertTrue(destination.is_symlink(), linked.stdout + linked.stderr)
                self.assertEqual(destination.readlink(), SKILL)
                self.assertEqual(list(prefix.iterdir()), [])
                self.assert_success(self.run_make(root, "link", **variables))

                # A same-repo link elsewhere must remain outside this operation's scope.
                unrelated.symlink_to(SKILL, target_is_directory=True)
                status = self.run_make(root, "status", **variables)
                self.assert_success(status)
                self.assertEqual(status.stdout.strip(), f"symlink  {destination} -> {SKILL}")

                self.assert_success(self.run_make(root, "unlink", **variables))
                self.assertFalse(destination.is_symlink())
                self.assertFalse(destination.exists())
                self.assertTrue(unrelated.is_symlink())
                self.assertEqual(unrelated.readlink(), SKILL)
                status = self.run_make(root, "status", **variables)
                self.assert_success(status)
                self.assertEqual(status.stdout.strip(), f"absent   {destination}")

    def test_custom_skills_paths_are_literal(self):
        self.check_install_path("SKILLS_DIR", ())

    def test_project_paths_are_literal(self):
        self.check_install_path("PROJECT", (".claude", "skills"))

    def test_host_paths_are_literal(self):
        self.check_install_path("AGY_HOME", ("skills",))

    def test_existing_entries_are_preserved(self):
        for kind in ("symlink", "directory"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as d:
                root = Path(d)
                requested = root / "custom skills"
                requested.mkdir()
                (root / "custom").mkdir()
                destination = requested / "privacy-scan"
                original = root / "another-skill"
                original.mkdir()
                if kind == "symlink":
                    destination.symlink_to(original, target_is_directory=True)
                else:
                    destination.mkdir()
                    (destination / "keep.txt").write_text("keep", encoding="utf-8")

                linked = self.run_make(root, "link", SKILLS_DIR=str(requested))
                self.assertNotEqual(linked.returncode, 0, linked.stdout + linked.stderr)
                self.assertIn("refusing", linked.stderr)
                self.assert_success(self.run_make(root, "unlink", SKILLS_DIR=str(requested)))
                if kind == "symlink":
                    self.assertTrue(destination.is_symlink())
                    self.assertEqual(destination.readlink(), original)
                else:
                    self.assertFalse(destination.is_symlink())
                    self.assertEqual((destination / "keep.txt").read_text(encoding="utf-8"), "keep")
                self.assertEqual(list((root / "custom").iterdir()), [])


if __name__ == "__main__":
    unittest.main()
