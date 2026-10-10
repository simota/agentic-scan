"""Exercise installation only in temporary directories, including spaceful paths."""
import importlib.util
import io
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout


REPO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("skill_install", REPO / "scripts" / "install.py")
install = importlib.util.module_from_spec(spec)
spec.loader.exec_module(install)


STUB_TEST = """\
import os
import sys
import unittest


class StubTests(unittest.TestCase):
    def test_stub(self):
        print(f"stub suite ran in {os.getcwd()} with {sys.executable}")
"""


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="performance-install-")
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.skill = self.root / "repo with spaces" / "skills" / "performance-scan"
        self.skill.mkdir(parents=True)
        self.hosts = {name: self.root / f"{name} home" for name in ("claude", "codex", "agy")}

    def run_install(self, action, *args):
        # Explicit helper arguments isolate every host without changing HOME or CODEX_HOME.
        host_args = [value for name, path in self.hosts.items()
                     for value in (f"--{name}-home", str(path))]
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            result = install.main([action, "--skill", str(self.skill), *host_args, *args])
        return result, stdout.getvalue(), stderr.getvalue()

    def test_multiple_hosts_link_idempotently_and_unlink(self):
        for host in self.hosts.values():
            host.mkdir()
        result, _, errors = self.run_install("link")
        self.assertEqual(result, 0, errors)
        for host in self.hosts.values():
            link = host / "skills" / self.skill.name
            self.assertEqual(link.readlink(), self.skill)
            self.assertTrue(link.is_dir())
        result, output, errors = self.run_install("link")
        self.assertEqual(result, 0, errors)
        self.assertEqual(output.count("already linked"), 3)
        result, output, errors = self.run_install("status")
        self.assertEqual(result, 0, errors)
        self.assertEqual(output.count("symlink  "), 3)
        result, _, errors = self.run_install("unlink")
        self.assertEqual(result, 0, errors)
        for host in self.hosts.values():
            self.assertFalse((host / "skills" / self.skill.name).is_symlink())

    def test_missing_hosts_are_skipped_and_nothing_linked_fails(self):
        self.hosts["claude"].mkdir()
        result, output, errors = self.run_install("link")
        self.assertEqual(result, 0, errors)
        self.assertEqual(output.count("skip     "), 2)
        self.assertFalse(self.hosts["codex"].exists())
        self.assertFalse(self.hosts["agy"].exists())
        result, _, errors = self.run_install("link", "--agents", "codex")
        self.assertEqual(result, 1)
        self.assertIn("nothing linked", errors)
        self.assertFalse(self.hosts["codex"].exists())

    def test_agent_selection_does_not_touch_other_installed_hosts(self):
        for host in self.hosts.values():
            host.mkdir()
        result, _, errors = self.run_install("link", "--agents", "agy")
        self.assertEqual(result, 0, errors)
        self.assertTrue((self.hosts["agy"] / "skills" / self.skill.name).is_symlink())
        self.assertFalse((self.hosts["claude"] / "skills").exists())
        self.assertFalse((self.hosts["codex"] / "skills").exists())

    def test_foreign_symlinks_directories_and_files_are_preserved(self):
        foreign = self.root / "another skill"
        foreign.mkdir()
        for kind in ("symlink", "dangling symlink", "directory", "file"):
            with self.subTest(kind=kind):
                directory = self.root / kind
                directory.mkdir()
                destination = directory / self.skill.name
                if kind == "directory":
                    destination.mkdir()
                elif kind == "file":
                    destination.write_text("existing", encoding="utf-8")
                else:
                    target = foreign if kind == "symlink" else self.root / "missing skill"
                    destination.symlink_to(target, target_is_directory=True)
                result, _, errors = self.run_install("link", "--skills-dir", str(directory))
                self.assertEqual(result, 1)
                self.assertIn("refusing", errors)
                result, output, errors = self.run_install("unlink", "--skills-dir", str(directory))
                self.assertEqual(result, 0, errors)
                self.assertIn("left     ", output)
                if "symlink" in kind:
                    self.assertEqual(destination.readlink(), target)
                elif kind == "directory":
                    self.assertTrue(destination.is_dir())
                else:
                    self.assertEqual(destination.read_text(encoding="utf-8"), "existing")

    def test_a_conflict_on_one_host_links_none(self):
        for host in self.hosts.values():
            host.mkdir()
        (self.hosts["codex"] / "skills" / self.skill.name).mkdir(parents=True)
        result, _, errors = self.run_install("link")
        self.assertEqual(result, 1)
        self.assertIn("refusing", errors)
        for name in ("claude", "agy"):
            self.assertFalse((self.hosts[name] / "skills").exists())

    def test_a_skills_dir_inside_the_skill_is_refused(self):
        for directory in (self.skill, self.skill / "nested"):
            with self.subTest(directory=directory):
                directory.mkdir(exist_ok=True)
                result, _, errors = self.run_install("link", "--skills-dir", str(directory))
                self.assertEqual(result, 1)
                self.assertIn("inside the skill", errors)
                self.assertFalse((directory / self.skill.name).is_symlink())

    def test_a_link_through_a_checkout_alias_is_recognised(self):
        alias = self.root / "alias"
        alias.symlink_to(self.skill.parents[1], target_is_directory=True)
        directory = self.root / "custom skills"
        directory.mkdir()
        destination = directory / self.skill.name
        destination.symlink_to(alias / "skills" / self.skill.name, target_is_directory=True)
        result, output, errors = self.run_install("link", "--skills-dir", str(directory))
        self.assertEqual(result, 0, errors)
        self.assertIn("already linked", output)
        # Older Makefiles linked through unresolved paths; unlink still removes them.
        result, output, errors = self.run_install("unlink", "--skills-dir", str(directory))
        self.assertEqual(result, 0, errors)
        self.assertIn("unlinked ", output)
        self.assertFalse(destination.is_symlink())

    def test_relative_links_are_removed_but_dotfiles_chains_are_left(self):
        directory = self.root / "custom skills"
        directory.mkdir()
        destination = directory / self.skill.name
        destination.symlink_to(os.path.relpath(self.skill, directory), target_is_directory=True)
        result, output, errors = self.run_install("unlink", "--skills-dir", str(directory))
        self.assertEqual(result, 0, errors)
        self.assertIn("unlinked ", output)
        dotfiles = self.root / "dotfiles" / self.skill.name
        dotfiles.parent.mkdir()
        dotfiles.symlink_to(self.skill, target_is_directory=True)
        destination.symlink_to(dotfiles, target_is_directory=True)
        result, output, errors = self.run_install("link", "--skills-dir", str(directory))
        self.assertIn("already linked", output)
        result, output, errors = self.run_install("unlink", "--skills-dir", str(directory))
        self.assertIn("through another symlink", output)
        self.assertTrue(destination.is_symlink())

    def test_an_unusable_skills_dir_on_one_host_links_none(self):
        for host in self.hosts.values():
            host.mkdir()
        (self.hosts["codex"] / "skills").write_text("not a directory", encoding="utf-8")
        (self.hosts["agy"] / "skills").symlink_to("skills")
        for agents in ("claude codex", "claude agy"):
            with self.subTest(agents=agents):
                result, _, errors = self.run_install("link", "--agents", agents)
                self.assertEqual(result, 1)
                self.assertRegex(errors, "not a usable directory|[Ll]oop")
                self.assertFalse((self.hosts["claude"] / "skills").exists())

    def test_messages_name_what_was_searched_and_refuse_an_empty_agent(self):
        missing = self.root / "no such dir"
        result, _, errors = self.run_install("link", "--skills-dir", str(missing))
        self.assertEqual(result, 1)
        self.assertIn(f"no skills directory found for: {missing}", errors)
        for action in ("link", "status", "unlink"):
            result, _, errors = self.run_install(action, "--agents", "")
            self.assertEqual(result, 1, action)
            self.assertIn("AGENT is empty", errors)

    def test_missing_source_and_unknown_agent_do_not_create_links(self):
        directory = self.root / "custom skills"
        directory.mkdir()
        result, _, errors = self.run_install("link", "--agents", "unknown")
        self.assertEqual(result, 1)
        self.assertIn("unknown AGENT", errors)
        self.skill.rmdir()
        result, _, errors = self.run_install("link", "--skills-dir", str(directory))
        self.assertEqual(result, 1)
        self.assertIn("skill directory does not exist", errors)
        self.assertEqual(list(directory.iterdir()), [])


@unittest.skipUnless(shutil.which("make"), "make is not installed")
class MakefilePathTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="performance-make-")
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.repo = self.root / "repo with spaces"
        self.repo.mkdir()
        for name in ("Makefile", "README.md"):
            shutil.copy2(REPO / name, self.repo / name)
        for name in ("skills", "examples", "scripts"):
            shutil.copytree(REPO / name, self.repo / name, ignore=shutil.ignore_patterns("__pycache__"))
        # make test/check run "unittest discover -s tests" from the checkout. What is
        # under test is the Makefile's path quoting, not the suite itself (which runs
        # on its own), so a one-file stub stands in and reports where it ran and with
        # which interpreter.
        (self.repo / "tests").mkdir()
        (self.repo / "tests" / "test_stub.py").write_text(STUB_TEST, encoding="utf-8")
        self.skill = self.repo / "skills" / "performance-scan"

    def run_make(self, target, *variables, external=False, preceding=(), preload=None,
                 environment=None, expect=0):
        args = ["make", "--no-print-directory"]
        for makefile in preceding:
            args += ["-f", str(makefile)]
        if external or preceding:
            args += ["-f", str(self.repo / "Makefile") if external else "Makefile"]
        env = os.environ.copy()
        env.pop("MAKEFLAGS", None)
        env.pop("MFLAGS", None)
        env.pop("MAKEOVERRIDES", None)
        env.pop("MAKEFILES", None)
        if preload is not None:
            env["MAKEFILES"] = str(preload)
        env.update(environment or {})
        result = subprocess.run(
            [*args, target, f"PYTHON={sys.executable}", *variables],
            cwd=self.root if external else self.repo, env=env,
            text=True, capture_output=True, timeout=30,
        )
        if expect == 0:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        return result.stdout

    def test_a_failing_suite_fails_test_and_check(self):
        (self.repo / "tests" / "test_stub.py").write_text(
            "import unittest\n\n\nclass Failing(unittest.TestCase):\n"
            "    def test_fails(self):\n        self.fail('expected')\n", encoding="utf-8")
        self.run_make("test", expect=1)
        self.assertNotIn("check ok", self.run_make("check", expect=1))

    def test_spaceful_checkout_and_skills_dir_link_status_unlink(self):
        directory = self.root / "custom skills"
        directory.mkdir()
        variable = f"SKILLS_DIR={directory}"
        self.run_make("link", variable)
        destination = directory / self.skill.name
        self.assertEqual(destination.readlink(), self.skill)
        self.assertTrue(destination.is_dir())
        self.assertIn(f"symlink  {destination} -> {self.skill}", self.run_make("status", variable))
        self.run_make("unlink", variable)
        self.assertFalse(destination.is_symlink())

    def test_spaceful_project_path_and_absolute_makefile_invocation(self):
        project = self.root / "project with spaces"
        project.mkdir()
        variable = f"PROJECT={project}"
        self.run_make("link", variable, external=True)
        destination = project / ".claude" / "skills" / self.skill.name
        self.assertEqual(destination.readlink(), self.skill)
        self.assertTrue(destination.is_dir())
        self.assertIn(str(destination), self.run_make("status", variable, external=True))
        self.run_make("unlink", variable, external=True)
        self.assertFalse(destination.is_symlink())

    def test_exported_selection_variables_are_ignored(self):
        home = self.root / "home"
        (home / ".claude").mkdir(parents=True)
        project = self.root / "unrelated project"
        project.mkdir()
        environment = {"PROJECT": str(project), "SKILLS_DIR": str(project), "AGENT": "unknown"}
        for flags in ((), ("-e",)):  # -e makes the environment override the makefile
            with self.subTest(flags=flags):
                output = self.run_make(*flags, "link", f"HOME={home}", environment=environment)
                link = home / ".claude" / "skills" / self.skill.name
                self.assertEqual(link.readlink(), self.skill)
                self.assertNotIn(str(project), output)
                self.assertEqual(list(project.iterdir()), [])

    def test_preceding_makefiles_preserve_spaceful_checkout_paths(self):
        settings = self.root / "settings.mk"
        settings.write_text("# Preloaded configuration.\n", encoding="utf-8")
        directory = self.root / "custom skills"
        directory.mkdir()
        variable = f"SKILLS_DIR={directory}"
        for external in (False, True):
            for source in ("-f", "MAKEFILES"):
                with self.subTest(external=external, source=source):
                    options = {"external": external}
                    if source == "-f":
                        options["preceding"] = (settings,)
                    else:
                        options["preload"] = settings
                    self.run_make("link", variable, **options)
                    destination = directory / self.skill.name
                    self.assertEqual(destination.readlink(), self.skill)
                    self.assertTrue(destination.is_dir())
                    self.assertIn(str(self.skill), self.run_make("status", variable, **options))
                    self.run_make("unlink", variable, **options)
                    self.assertFalse(destination.is_symlink())

    def test_development_targets_in_spaceful_checkout(self):
        self.assertIn(str(self.skill), self.run_make("help", external=True))
        output = self.root / "demo output"
        self.run_make("demo", f"DEMO_OUT={output}")
        self.assertTrue((output / "dashboard.html").is_file())
        self.assertTrue((output / "report.md").is_file())
        ran = f"stub suite ran in {self.repo.resolve()} with "
        self.assertIn(ran, self.run_make("test", external=True))
        scratch = self.root / "check scratch"
        scratch.mkdir()
        output = self.run_make("check", f"TMPDIR={scratch}")
        self.assertIn(ran, output)  # check depends on test
        self.assertIn("check ok", output)
        self.assertEqual(list(scratch.iterdir()), [])

    def test_spaceful_python_path_for_installer_and_development_targets(self):
        python = self.root / "python tools" / "python3"
        python.parent.mkdir()
        python.symlink_to(sys.executable)
        variable = f"PYTHON={python}"
        self.assertIn(str(self.skill), self.run_make("help", variable, external=True))
        directory = self.root / "custom skills"
        status = self.run_make("status", variable, f"SKILLS_DIR={directory}", external=True)
        self.assertIn(str(directory / self.skill.name), status)

        output = self.root / "demo output"
        self.run_make("demo", variable, f"DEMO_OUT={output}", external=True)
        self.assertTrue((output / "dashboard.html").is_file())
        self.assertTrue((output / "report.md").is_file())
        scratch = self.root / "check scratch"
        scratch.mkdir()
        output = self.run_make("check", variable, f"TMPDIR={scratch}", external=True)
        self.assertIn(f"stub suite ran in {self.repo.resolve()} with {python}\n", output)
        self.assertIn("check ok", output)
        self.assertEqual(list(scratch.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
