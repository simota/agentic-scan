"""Offline regression tests for literal install paths and existing entries."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[1]
SKILL = REPO / "skills" / "privacy-scan"


class InstallTests(unittest.TestCase):
    def run_make(self, cwd, target, *, makefile=REPO / "Makefile", extra_makefiles=(), env=None, **variables):
        options = {"AGENT": "agy", "PROJECT": "", "SKILLS_DIR": ""}
        options.update(variables)
        command = ["make", "--no-print-directory"]
        for extra in extra_makefiles:
            command.extend(["-f", str(extra)])
        if makefile is not None:
            command.extend(["-f", str(makefile)])
        return subprocess.run(
            [*command, target,
             *[f"{key}={value}" for key, value in options.items()]],
            cwd=cwd, env=env, capture_output=True, text=True, timeout=10,
        )

    def assert_success(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def check_install_path(self, variable, suffix):
        for name in ("custom skills", "custom's skills", "custom|skills"):
            with self.subTest(variable=variable, name=name), tempfile.TemporaryDirectory() as d:
                root = Path(d).resolve()
                requested = root / name
                prefix = root / name.split(" ", 1)[0].split("|", 1)[0]
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

    def test_checkout_paths_are_literal(self):
        for name in ("checkout space", "checkout's space", 'checkout "quoted"',
                     "checkout`literal`", "checkout|literal"):
            for explicit_makefile in (False, True):
                with self.subTest(name=name, explicit_makefile=explicit_makefile), tempfile.TemporaryDirectory() as d:
                    root = Path(d).resolve()
                    checkout = root / name
                    skill = checkout / "skills" / "privacy-scan"
                    skill.mkdir(parents=True)
                    (skill / "SKILL.md").write_text("fixture skill", encoding="utf-8")
                    shutil.copyfile(REPO / "Makefile", checkout / "Makefile")
                    caller = root / "caller"
                    caller.mkdir()
                    requested = root / "custom skills"
                    requested.mkdir()
                    destination = requested / "privacy-scan"
                    cwd = caller if explicit_makefile else checkout
                    makefile = checkout / "Makefile" if explicit_makefile else None

                    linked = self.run_make(cwd, "link", makefile=makefile, SKILLS_DIR=str(requested))
                    self.assert_success(linked)
                    self.assertTrue(destination.is_symlink(), linked.stdout + linked.stderr)
                    self.assertEqual(destination.readlink(), skill)
                    self.assertTrue((destination / "SKILL.md").is_file())
                    self.assert_success(self.run_make(cwd, "link", makefile=makefile, SKILLS_DIR=str(requested)))
                    status = self.run_make(cwd, "status", makefile=makefile, SKILLS_DIR=str(requested))
                    self.assert_success(status)
                    self.assertEqual(status.stdout.strip(), f"symlink  {destination} -> {skill}")
                    self.assert_success(self.run_make(cwd, "unlink", makefile=makefile, SKILLS_DIR=str(requested)))
                    self.assertFalse(destination.is_symlink())

    def test_pipe_paths_do_not_unlink_outside_the_requested_directory(self):
        for variable, suffix in (("SKILLS_DIR", ()), ("PROJECT", (".claude", "skills")),
                                 ("AGY_HOME", ("skills",))):
            with self.subTest(variable=variable), tempfile.TemporaryDirectory() as d:
                root = Path(d).resolve()
                requested = root / "requested|elsewhere"
                destination = requested.joinpath(*suffix) / "privacy-scan"
                destination.parent.mkdir(parents=True)
                destination.symlink_to(SKILL, target_is_directory=True)
                unrelated = (root / "elsewhere").joinpath(*suffix) / "privacy-scan"
                unrelated.parent.mkdir(parents=True)
                unrelated.symlink_to(SKILL, target_is_directory=True)

                result = self.run_make(root, "unlink", **{variable: str(requested)})
                self.assert_success(result)
                self.assertFalse(destination.is_symlink(), result.stdout + result.stderr)
                self.assertTrue(unrelated.is_symlink(), result.stdout + result.stderr)
                self.assertEqual(unrelated.readlink(), SKILL)

    def test_link_requires_the_source_skill(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d).resolve()
            checkout = root / "checkout"
            checkout.mkdir()
            shutil.copyfile(REPO / "Makefile", checkout / "Makefile")
            requested = root / "skills"
            requested.mkdir()

            result = self.run_make(root, "link", makefile=checkout / "Makefile", SKILLS_DIR=str(requested))
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("SKILL.md", result.stderr)
            self.assertEqual(list(requested.iterdir()), [])

    def test_prior_makefiles_do_not_change_the_source(self):
        for mode in ("environment", "multiple_f", "include"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as d:
                root = Path(d).resolve()
                checkout = root / "checkout"
                skill = checkout / "skills" / "privacy-scan"
                skill.mkdir(parents=True)
                (skill / "SKILL.md").write_text("fixture skill", encoding="utf-8")
                makefile = checkout / "Makefile"
                shutil.copyfile(REPO / "Makefile", makefile)
                defaults = root / "defaults.mk"
                defaults.write_text("# earlier makefile\n", encoding="utf-8")
                options = {"makefile": makefile}
                if mode == "environment":
                    options["env"] = dict(os.environ, MAKEFILES=str(defaults))
                elif mode == "multiple_f":
                    options["extra_makefiles"] = (defaults,)
                else:
                    outer = root / "outer.mk"
                    outer.write_text(f"include {makefile}\n", encoding="utf-8")
                    options["makefile"] = outer
                requested = root / "skills"
                requested.mkdir()
                destination = requested / "privacy-scan"

                linked = self.run_make(root, "link", **options, SKILLS_DIR=str(requested))
                self.assert_success(linked)
                self.assertEqual(destination.readlink(), skill)
                self.assert_success(self.run_make(root, "unlink", **options, SKILLS_DIR=str(requested)))
                self.assertFalse(destination.is_symlink())

    def test_symlinked_checkout_keeps_existing_link_targets(self):
        for explicit_makefile in (False, True):
            with self.subTest(explicit_makefile=explicit_makefile), tempfile.TemporaryDirectory() as d:
                root = Path(d).resolve()
                checkout = root / "real"
                skill = checkout / "skills" / "privacy-scan"
                skill.mkdir(parents=True)
                (skill / "SKILL.md").write_text("fixture skill", encoding="utf-8")
                shutil.copyfile(REPO / "Makefile", checkout / "Makefile")
                alias = root / "alias"
                alias.symlink_to(checkout, target_is_directory=True)
                requested = root / "skills"
                requested.mkdir()
                destination = requested / "privacy-scan"
                expected = alias / "skills" / "privacy-scan" if explicit_makefile else skill
                destination.symlink_to(expected, target_is_directory=True)
                cwd = root if explicit_makefile else alias
                makefile = alias / "Makefile" if explicit_makefile else None
                environment = dict(os.environ, PWD=str(cwd))

                linked = self.run_make(cwd, "link", makefile=makefile, env=environment, SKILLS_DIR=str(requested))
                self.assert_success(linked)
                self.assertIn("already linked", linked.stdout)
                self.assertEqual(destination.readlink(), expected)
                self.assert_success(self.run_make(cwd, "unlink", makefile=makefile, env=environment,
                                                 SKILLS_DIR=str(requested)))
                self.assertFalse(destination.is_symlink())

    def test_existing_entries_are_preserved(self):
        for kind in ("symlink", "directory"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as d:
                root = Path(d).resolve()
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
