"""Exercise installer failure reporting and explicit destination overrides."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from test_architecture_scan import make_env


REPO = Path(__file__).resolve().parents[1]
SKILL = REPO / "skills" / "architecture-scan"


@unittest.skipUnless(shutil.which("make"), "make is required for installation tests")
class InstallIntegrityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="architecture-scan-integrity-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.destination = self.root / "skills"
        self.destination.mkdir()
        self.link = self.destination / "architecture-scan"

    def run_make(self, target, path=None, **variables):
        settings = {
            "AGENT": "agy", "AGY_HOME": self.root / "absent-host",
            "SKILLS_DIR": self.destination, "PROJECT": "",
        }
        settings.update(variables)
        env = make_env()
        if path is not None:
            env["PATH"] = str(path) + os.pathsep + env.get("PATH", "")
        return subprocess.run(
            ["make", "--no-print-directory", "-f", str(REPO / "Makefile"), target]
            + [f"{name}={value}" for name, value in settings.items()],
            cwd=self.root, env=env, text=True, capture_output=True, timeout=10,
        )

    def assert_success(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_unlink_failure_is_reported_and_does_not_claim_success(self):
        self.assert_success(self.run_make("link"))
        # Simulate a failed removal without relying on this process's privileges.
        commands = self.root / "commands"
        commands.mkdir()
        remover = commands / "rm"
        remover.write_text(
            "#!/bin/sh\nprintf 'rm: simulated permission denied\\n' >&2\nexit 1\n",
            encoding="utf-8",
        )
        remover.chmod(0o755)

        result = self.run_make("unlink", path=commands)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("simulated permission denied", result.stderr)
        self.assertNotIn("unlinked", result.stdout)
        self.assertEqual(self.link.readlink(), SKILL)

        self.assert_success(self.run_make("unlink"))
        self.assertFalse(self.link.is_symlink())

    def test_explicit_destination_ignores_unused_agent(self):
        for mode in ("skills", "project"):
            variables = {"AGENT": "custom-host"}
            link = self.link
            if mode == "project":
                variables.update(SKILLS_DIR="", PROJECT=self.destination)
                link = self.destination / ".claude" / "skills" / "architecture-scan"
            for target in ("link", "status", "unlink"):
                with self.subTest(mode=mode, target=target):
                    result = self.run_make(target, **variables)
                    self.assert_success(result)
                    if target != "unlink":
                        self.assertEqual(link.readlink(), SKILL)
                    else:
                        self.assertFalse(link.is_symlink())

    def test_unknown_agent_without_override_still_fails(self):
        result = self.run_make("link", AGENT="custom-host", SKILLS_DIR="")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unknown AGENT", result.stderr)
        self.assertFalse(self.link.is_symlink())


if __name__ == "__main__":
    unittest.main()
