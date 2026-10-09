"""Leading-hyphen relative install paths are paths throughout the lifecycle."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[1]
SKILL = REPO / "skills" / "privacy-scan"
INSTALL_PATHS = (
    ("SKILLS_DIR", (), "agy"),
    ("PROJECT", (".claude", "skills"), "agy"),
    ("CODEX_HOME", ("skills",), "codex"),
    ("AGY_HOME", ("skills",), "agy"),
    ("HOME", (".claude", "skills"), "claude"),
    ("HOME", (".codex", "skills"), "codex"),
    ("HOME", (".gemini", "antigravity-cli", "skills"), "agy"),
)
RELATIVE_ROOT = "-requested 'with spaces'$X"


class OptionPathInstallTests(unittest.TestCase):
    def run_make(self, root, target, variable, agent, mode):
        environment = dict(os.environ)
        for name in ("SKILLS_DIR", "PROJECT", "CODEX_HOME", "AGY_HOME", "CLAUDE_CONFIG_DIR",
                     "MAKEFILES", "MAKEFLAGS", "GNUMAKEFLAGS", "MFLAGS"):
            environment.pop(name, None)
        # Confine every host-discovery path to this fixture, even on failure.
        environment["HOME"] = str(root / "uninstalled-hosts")
        environment["X"] = ""
        command = ["make", "--no-print-directory", "-f", str(REPO / "Makefile"),
                   target, f"AGENT={agent}"]
        if mode == "environment":
            environment[variable] = RELATIVE_ROOT
        else:
            command.append(f"{variable}={RELATIVE_ROOT.replace('$', '$$')}")
        return subprocess.run(
            command, cwd=root, env=environment, capture_output=True, text=True, timeout=10,
        )

    def assert_success(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stderr, "", result.stdout + result.stderr)

    def test_link_status_and_unlink_with_relative_option_paths(self):
        for variable, suffix, agent in INSTALL_PATHS:
            for mode in ("environment", "command_line"):
                with self.subTest(variable=variable, agent=agent, mode=mode), \
                        tempfile.TemporaryDirectory() as directory:
                    root = Path(directory).resolve()
                    requested = root / RELATIVE_ROOT
                    guard = requested.joinpath(*suffix[:-1]) if variable == "HOME" else requested
                    guard.mkdir(parents=True)
                    destination = requested.joinpath(*suffix) / "privacy-scan"

                    linked = self.run_make(root, "link", variable, agent, mode)
                    self.assert_success(linked)
                    self.assertTrue(destination.is_symlink())
                    self.assertEqual(destination.readlink(), SKILL)
                    self.assertTrue((destination / "SKILL.md").is_file())
                    again = self.run_make(root, "link", variable, agent, mode)
                    self.assert_success(again)
                    self.assertIn("already linked", again.stdout)
                    status = self.run_make(root, "status", variable, agent, mode)
                    self.assert_success(status)
                    self.assertIn(f" -> {SKILL}\n", status.stdout)
                    self.assert_success(self.run_make(root, "unlink", variable, agent, mode))
                    self.assertFalse(destination.is_symlink())

    def test_existing_relative_option_links_can_be_inspected_and_removed(self):
        for variable, suffix, agent in INSTALL_PATHS:
            for mode in ("environment", "command_line"):
                with self.subTest(variable=variable, agent=agent, mode=mode), \
                        tempfile.TemporaryDirectory() as directory:
                    root = Path(directory).resolve()
                    destination = (root / RELATIVE_ROOT).joinpath(*suffix) / "privacy-scan"
                    destination.parent.mkdir(parents=True)
                    destination.symlink_to(SKILL, target_is_directory=True)
                    unrelated = root / "unrelated"
                    unrelated.symlink_to(SKILL, target_is_directory=True)

                    status = self.run_make(root, "status", variable, agent, mode)
                    self.assert_success(status)
                    self.assertIn(f" -> {SKILL}\n", status.stdout)
                    self.assert_success(self.run_make(root, "unlink", variable, agent, mode))
                    self.assertFalse(destination.is_symlink())
                    self.assertEqual(unrelated.readlink(), SKILL)

    def test_unlink_existing_relative_option_link_without_status(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            destination = root / RELATIVE_ROOT / "privacy-scan"
            destination.parent.mkdir()
            destination.symlink_to(SKILL, target_is_directory=True)

            result = self.run_make(root, "unlink", "SKILLS_DIR", "agy", "environment")
            self.assert_success(result)
            self.assertFalse(destination.is_symlink())

    def test_foreign_entries_under_relative_option_paths_are_preserved(self):
        for kind in ("symlink", "dangling_symlink", "directory"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                destination = root / RELATIVE_ROOT / "privacy-scan"
                destination.parent.mkdir()
                original = root / "other-skill"
                if kind == "directory":
                    destination.mkdir()
                    (destination / "keep.txt").write_text("keep", encoding="utf-8")
                else:
                    if kind == "symlink":
                        original.mkdir()
                    destination.symlink_to(original, target_is_directory=True)

                linked = self.run_make(root, "link", "SKILLS_DIR", "agy", "environment")
                self.assertNotEqual(linked.returncode, 0, linked.stdout + linked.stderr)
                self.assertIn("refusing", linked.stderr)
                if kind != "directory":
                    self.assertIn(f"is a symlink to {original}", linked.stderr)
                self.assert_success(self.run_make(root, "unlink", "SKILLS_DIR", "agy", "environment"))
                if kind == "directory":
                    self.assertEqual((destination / "keep.txt").read_text(encoding="utf-8"), "keep")
                else:
                    self.assertTrue(destination.is_symlink())
                    self.assertEqual(destination.readlink(), original)


if __name__ == "__main__":
    unittest.main()
