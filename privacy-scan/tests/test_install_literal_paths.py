"""Environment paths stay literal while command-line Make syntax still works."""
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


class LiteralEnvironmentPathTests(unittest.TestCase):
    def make_environment(self, root):
        environment = dict(os.environ)
        for name in ("SKILLS_DIR", "PROJECT", "CODEX_HOME", "AGY_HOME",
                     "MAKEFILES", "MAKEFLAGS", "GNUMAKEFLAGS", "MFLAGS"):
            environment.pop(name, None)
        # All host discovery is confined to the fixture, including on failure.
        environment["HOME"] = str(root / "uninstalled-hosts")
        environment["X"] = ""
        return environment

    def run_make(self, root, target, agent, environment, *variables, options=()):
        return subprocess.run(
            ["make", "--no-print-directory", *options, "-f", str(REPO / "Makefile"),
             target, f"AGENT={agent}", *variables],
            cwd=root, env=environment, capture_output=True, text=True, timeout=10,
        )

    def assert_success(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_environment_link_and_status_use_the_literal_path(self):
        for variable, suffix, agent in INSTALL_PATHS:
            for options in ((), ("-e",)):
                with self.subTest(variable=variable, agent=agent, options=options), \
                        tempfile.TemporaryDirectory() as directory:
                    root = Path(directory).resolve()
                    requested = root / "requested 'with spaces'$X"
                    expanded = root / "requested 'with spaces'"
                    destination = requested.joinpath(*suffix) / "privacy-scan"
                    unrelated = expanded.joinpath(*suffix) / "privacy-scan"
                    destination.parent.mkdir(parents=True)
                    unrelated.parent.mkdir(parents=True)
                    environment = self.make_environment(root)
                    environment[variable] = str(requested)

                    linked = self.run_make(root, "link", agent, environment, options=options)
                    self.assert_success(linked)
                    self.assertTrue(destination.is_symlink(), linked.stdout + linked.stderr)
                    self.assertEqual(destination.readlink(), SKILL)
                    self.assertFalse(unrelated.is_symlink())
                    status = self.run_make(root, "status", agent, environment, options=options)
                    self.assert_success(status)
                    self.assertEqual(status.stdout.strip(), f"symlink  {destination} -> {SKILL}")
                    self.assert_success(self.run_make(root, "link", agent, environment, options=options))

    def test_environment_unlink_preserves_the_other_directory(self):
        for variable, suffix, agent in INSTALL_PATHS:
            for options in ((), ("-e",)):
                with self.subTest(variable=variable, agent=agent, options=options), \
                        tempfile.TemporaryDirectory() as directory:
                    root = Path(directory).resolve()
                    requested = root / "requested$X"
                    expanded = root / "requested"
                    destination = requested.joinpath(*suffix) / "privacy-scan"
                    unrelated = expanded.joinpath(*suffix) / "privacy-scan"
                    for path in (destination, unrelated):
                        path.parent.mkdir(parents=True)
                        path.symlink_to(SKILL, target_is_directory=True)
                    environment = self.make_environment(root)
                    environment[variable] = str(requested)

                    unlinked = self.run_make(root, "unlink", agent, environment, options=options)
                    self.assert_success(unlinked)
                    self.assertFalse(destination.is_symlink(), unlinked.stdout + unlinked.stderr)
                    self.assertTrue(unrelated.is_symlink())
                    self.assertEqual(unrelated.readlink(), SKILL)

    def test_command_line_dollar_escaping_is_unchanged(self):
        for variable, suffix, agent in INSTALL_PATHS:
            with self.subTest(variable=variable, agent=agent), \
                    tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                requested = root / "requested$X"
                destination = requested.joinpath(*suffix) / "privacy-scan"
                destination.parent.mkdir(parents=True)
                environment = self.make_environment(root)
                assignment = f"{variable}={str(requested).replace('$', '$$')}"

                linked = self.run_make(root, "link", agent, environment, assignment)
                self.assert_success(linked)
                self.assertTrue(destination.is_symlink(), linked.stdout + linked.stderr)
                self.assertEqual(destination.readlink(), SKILL)
                self.assert_success(self.run_make(root, "unlink", agent, environment, assignment))
                self.assertFalse(destination.is_symlink())

    def test_command_line_make_variable_references_are_unchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            requested = root / "requested$X"
            requested.mkdir()
            environment = self.make_environment(root)
            variables = (
                f"fixture_root={str(requested).replace('$', '$$')}",
                "SKILLS_DIR=$(fixture_root)",
            )

            linked = self.run_make(root, "link", "agy", environment, *variables)
            self.assert_success(linked)
            destination = requested / "privacy-scan"
            self.assertTrue(destination.is_symlink(), linked.stdout + linked.stderr)
            self.assertEqual(destination.readlink(), SKILL)
            self.assert_success(self.run_make(root, "unlink", "agy", environment, *variables))
            self.assertFalse(destination.is_symlink())


if __name__ == "__main__":
    unittest.main()
