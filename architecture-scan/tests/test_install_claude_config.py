"""Keep Claude installation in the active configuration directory."""
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[1]
SKILL = REPO / "skills" / "architecture-scan"


@unittest.skipUnless(shutil.which("make"), "make is required for installation tests")
class ClaudeConfigTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="architecture-scan-claude-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def run_make(self, target, *, dry_run, env_config=None, **variables):
        settings = {
            "AGENT": "claude", "SKILLS_DIR": "", "PROJECT": "",
            "PYTHON": shlex.quote(sys.executable),
        }
        settings.update(variables)
        env = os.environ.copy()
        for name in ("MAKEFLAGS", "MFLAGS", "MAKEFILES", "CLAUDE_CONFIG_DIR"):
            env.pop(name, None)
        if env_config is not None:
            env["CLAUDE_CONFIG_DIR"] = str(env_config)
        command = ["make", "--no-print-directory", "-f", str(REPO / "Makefile")]
        if dry_run:
            command.append("-n")
        return subprocess.run(
            command + [target] + [f"{name}={value}" for name, value in settings.items()],
            cwd=self.root, env=env, text=True, capture_output=True, timeout=10,
        )

    def assert_success(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def assert_targets(self, result, guard, skills):
        self.assert_success(result)
        for line in result.stdout.splitlines():
            _, separator, arguments = line.partition("set -- ")
            if separator:
                self.assertEqual(
                    shlex.split(arguments.removesuffix("; \\")),
                    [str(guard), str(skills)],
                )
                return
        self.fail("dry-run did not show the installation targets: " + result.stdout)

    def safe_make(self, target, guard, skills, **settings):
        # A regression must fail before a live command can touch the real HOME.
        self.assertTrue(guard.is_relative_to(self.root))
        self.assertTrue(skills.is_relative_to(self.root))
        self.assert_targets(
            self.run_make(target, dry_run=True, **settings), guard, skills,
        )
        return self.run_make(target, dry_run=False, **settings)

    def assert_lifecycle(self, guard, skills, **settings):
        link = skills / "architecture-scan"
        self.assert_success(self.safe_make("link", guard, skills, **settings))
        self.assertEqual(link.readlink(), SKILL)
        repeated = self.safe_make("link", guard, skills, **settings)
        self.assert_success(repeated)
        self.assertIn(f"{link} already linked", repeated.stdout)
        status = self.safe_make("status", guard, skills, **settings)
        self.assert_success(status)
        self.assertIn(f"symlink  {link} -> {SKILL}", status.stdout)
        self.assert_success(self.safe_make("unlink", guard, skills, **settings))
        self.assertFalse(link.is_symlink())
        status = self.safe_make("status", guard, skills, **settings)
        self.assert_success(status)
        self.assertIn(f"absent   {link}", status.stdout)

    def test_custom_config_from_environment_and_make_argument(self):
        for source in ("environment", "argument"):
            with self.subTest(source=source):
                config = self.root / source / "claude's work profile"
                config.mkdir(parents=True)
                settings = {"env_config" if source == "environment" else "CLAUDE_CONFIG_DIR": config}
                self.assert_lifecycle(config, config / "skills", **settings)

    def test_make_argument_takes_precedence_over_environment(self):
        environment_config = self.root / "environment profile"
        argument_config = self.root / "argument profile"
        environment_config.mkdir()
        argument_config.mkdir()
        self.assert_lifecycle(
            argument_config, argument_config / "skills",
            env_config=environment_config, CLAUDE_CONFIG_DIR=argument_config,
        )
        self.assertEqual(list(environment_config.iterdir()), [])

    def test_missing_custom_config_is_skipped_without_creating_it(self):
        config = self.root / "missing profile"
        skills = config / "skills"
        settings = {"env_config": config}
        result = self.safe_make("link", config, skills, **settings)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(f"{config} does not exist", result.stdout)
        status = self.safe_make("status", config, skills, **settings)
        self.assert_success(status)
        self.assertIn("host not installed", status.stdout)
        self.assert_success(self.safe_make("unlink", config, skills, **settings))
        self.assertFalse(config.exists())

    def test_explicit_destinations_take_precedence_over_config(self):
        config = self.root / "unused Claude profile"
        config.mkdir()
        for mode in ("project", "skills"):
            with self.subTest(mode=mode):
                project = self.root / f"{mode} project"
                project.mkdir()
                settings = {"env_config": config, "PROJECT": project}
                if mode == "project":
                    guard = project
                    skills = project / ".claude" / "skills"
                else:
                    guard = skills = self.root / "literal skills"
                    skills.mkdir()
                    settings["SKILLS_DIR"] = skills
                self.assert_lifecycle(guard, skills, **settings)
                if mode == "skills":
                    self.assertEqual(list(project.iterdir()), [])
        self.assertEqual(list(config.iterdir()), [])

    def test_unset_and_empty_config_fall_back_to_default_in_dry_run_only(self):
        default_config = os.environ.get("HOME", "") + "/.claude"
        cases = (
            {},
            {"env_config": ""},
            {"CLAUDE_CONFIG_DIR": ""},
            {"env_config": self.root / "ignored profile", "CLAUDE_CONFIG_DIR": ""},
        )
        for settings in cases:
            for target in ("link", "status", "unlink"):
                with self.subTest(settings=settings, target=target):
                    self.assert_targets(
                        self.run_make(target, dry_run=True, **settings),
                        default_config, default_config + "/skills",
                    )


if __name__ == "__main__":
    unittest.main()
