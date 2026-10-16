"""Command-line narrowing wins over the environment; AGENT is checked only where used."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[1]
SKILL = REPO / "skills" / "privacy-scan"


def make(root, *arguments, **environment):
    env = dict(os.environ)
    for name in ("SKILLS_DIR", "PROJECT", "AGENT", "CODEX_HOME", "AGY_HOME", "DEMO_OUT",
                 "MAKEFILES", "MAKEFLAGS", "GNUMAKEFLAGS", "MFLAGS", "MAKELEVEL"):
        env.pop(name, None)
    env["HOME"] = str(root / "home")
    env.update(environment)
    return subprocess.run(["make", "--no-print-directory", "-f", str(REPO / "Makefile"), *arguments],
                          cwd=root, env=env, capture_output=True, text=True, timeout=30)


class PrecedenceTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name).resolve()
        for path in ("home/.claude", "project/.claude/skills", "skills-dir"):
            (self.root / path).mkdir(parents=True)
        self.claude = self.root / "home" / ".claude" / "skills" / "privacy-scan"
        self.project = self.root / "project" / ".claude" / "skills" / "privacy-scan"
        self.skills_dir = self.root / "skills-dir" / "privacy-scan"

    def assert_linked(self, result, linked, *untouched):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(linked.readlink(), SKILL)
        for path in untouched:
            self.assertFalse(os.path.lexists(path), path)

    def test_command_line_agent_wins_over_environment_project(self):
        # Before: an exported PROJECT silently redirected `make link AGENT=claude`.
        result = make(self.root, "link", "AGENT=claude", PROJECT=str(self.root / "project"))
        self.assert_linked(result, self.claude, self.project)
        result = make(self.root, "unlink", "AGENT=claude", PROJECT=str(self.root / "project"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(os.path.lexists(self.claude))

    def test_command_line_project_wins_over_environment_skills_dir(self):
        result = make(self.root, "link", f"PROJECT={self.root / 'project'}",
                      SKILLS_DIR=str(self.root / "skills-dir"))
        self.assert_linked(result, self.project, self.skills_dir, self.claude)

    def test_environment_narrowing_still_applies_without_command_line_narrowing(self):
        result = make(self.root, "link", PROJECT=str(self.root / "project"), AGENT="claude")
        self.assert_linked(result, self.project, self.claude)

    def test_command_line_order_is_unchanged(self):
        result = make(self.root, "link", "AGENT=claude", f"PROJECT={self.root / 'project'}",
                      f"SKILLS_DIR={self.root / 'skills-dir'}")
        self.assert_linked(result, self.skills_dir, self.project, self.claude)

    def test_failure_names_the_narrowing_that_was_tried(self):
        missing = self.root / "no such project"
        result = make(self.root, "link", PROJECT=str(missing))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(f"nothing linked - no skills directory found for: PROJECT {missing}",
                      result.stderr)

    def test_unrelated_environment_agent_only_matters_where_agent_is_used(self):
        # Before: AGENT=ci-runner-3 in the environment stopped every target.
        out = self.root / "demo"
        result = make(self.root, "demo", f"DEMO_OUT={out}", AGENT="ci-runner-3")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((out / "report.md").is_file())
        result = make(self.root, "link", f"SKILLS_DIR={self.root / 'skills-dir'}", AGENT="ci-runner-3")
        self.assert_linked(result, self.skills_dir)
        result = make(self.root, "link", AGENT="ci-runner-3")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unknown AGENT 'ci-runner-3' (environment)", result.stderr)
        self.assertFalse(os.path.lexists(self.claude))


if __name__ == "__main__":
    unittest.main()
