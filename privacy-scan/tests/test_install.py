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
    def run_make(self, cwd, target, *, makefile=REPO / "Makefile", env=None, **variables):
        options = {"AGENT": "agy", "PROJECT": "", "SKILLS_DIR": ""}
        options.update(variables)
        command = ["make", "--no-print-directory"]
        if makefile is not None:
            command += ["-f", str(makefile)]
        command += [target, *[f"{key}={value}" for key, value in options.items()]]
        return subprocess.run(
            command,
            cwd=cwd, env=env, capture_output=True, text=True, timeout=10,
        )

    def assert_success(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def copy_checkout(self, root, name):
        checkout = root / name
        checkout.mkdir()
        shutil.copyfile(REPO / "Makefile", checkout / "Makefile")
        source = checkout / "skills" / "privacy-scan"
        shutil.copytree(SKILL, source)
        return checkout, source

    def test_checkout_paths_are_literal(self):
        for name in ("checkout with spaces", "checkout's files", 'checkout "quoted" files',
                     "checkout $(touch injected) `touch injected`"):
            for invocation in ("default", "absolute"):
                with self.subTest(name=name, invocation=invocation), tempfile.TemporaryDirectory() as d:
                    root = Path(d)
                    checkout, source = self.copy_checkout(root, name)
                    requested = root / "host's skills"
                    requested.mkdir()
                    destination = requested / "privacy-scan"
                    cwd = checkout if invocation == "default" else root
                    makefile = None if invocation == "default" else checkout / "Makefile"
                    options = {"makefile": makefile, "SKILLS_DIR": str(requested)}

                    linked = self.run_make(cwd, "link", **options)
                    self.assert_success(linked)
                    self.assertTrue(destination.is_symlink(), linked.stdout + linked.stderr)
                    self.assertEqual(destination.readlink(), source)
                    self.assertTrue((destination / "SKILL.md").is_file())
                    self.assert_success(self.run_make(cwd, "link", **options))
                    status = self.run_make(cwd, "status", **options)
                    self.assert_success(status)
                    self.assertEqual(status.stdout.strip(), f"symlink  {destination} -> {source}")
                    self.assert_success(self.run_make(cwd, "unlink", **options))
                    self.assertFalse(destination.is_symlink())
                    self.assertFalse((cwd / "injected").exists())

    def test_existing_links_keep_checkout_alias_semantics(self):
        for invocation in ("default", "absolute_alias"):
            with self.subTest(invocation=invocation), tempfile.TemporaryDirectory() as d:
                root = Path(d)
                checkout, source = self.copy_checkout(root, "checkout")
                alias = root / "alias"
                alias.symlink_to(checkout, target_is_directory=True)
                requested = root / "skills"
                requested.mkdir()
                destination = requested / "privacy-scan"
                cwd = alias if invocation == "default" else root
                makefile = None if invocation == "default" else alias / "Makefile"
                expected = source if invocation == "default" else alias / "skills" / "privacy-scan"
                options = {"makefile": makefile, "SKILLS_DIR": str(requested),
                           "env": {**os.environ, "PWD": str(cwd)}}

                # Match the link target created by the original abspath-based installer.
                destination.symlink_to(expected, target_is_directory=True)
                self.assert_success(self.run_make(cwd, "link", **options))
                self.assertEqual(destination.readlink(), expected)
                self.assert_success(self.run_make(cwd, "unlink", **options))
                self.assertFalse(destination.is_symlink())
                self.assert_success(self.run_make(cwd, "link", **options))
                self.assertEqual(destination.readlink(), expected)
                self.assertTrue((destination / "SKILL.md").is_file())

    def test_makefile_list_prefixes_do_not_change_source(self):
        for prefix in ("preload", "include"):
            with self.subTest(prefix=prefix), tempfile.TemporaryDirectory() as d:
                root = Path(d)
                checkout, source = self.copy_checkout(root, "checkout with spaces")
                requested = root / "skills"
                requested.mkdir()
                options = {"makefile": checkout / "Makefile", "SKILLS_DIR": str(requested)}
                wrapper = root / "wrapper.mk"
                if prefix == "preload":
                    wrapper.write_text("PRELOADED := yes\n", encoding="utf-8")
                    options["MAKEFILES"] = str(wrapper)
                else:
                    escaped = str(checkout / "Makefile").replace(" ", "\\ ")
                    wrapper.write_text(f"include {escaped}\n", encoding="utf-8")
                    options["makefile"] = wrapper

                self.assert_success(self.run_make(root, "link", **options))
                self.assertEqual((requested / "privacy-scan").readlink(), source)

    def test_missing_source_is_refused_before_linking(self):
        for missing in ("directory", "manifest", "previously linked"):
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as d:
                root = Path(d)
                checkout, source = self.copy_checkout(root, "checkout's files")
                requested = root / "skills"
                requested.mkdir()
                destination = requested / "privacy-scan"
                options = {"makefile": checkout / "Makefile", "SKILLS_DIR": str(requested)}
                if missing == "previously linked":
                    self.assert_success(self.run_make(root, "link", **options))
                if missing == "manifest":
                    (source / "SKILL.md").unlink()
                else:
                    shutil.rmtree(source)

                linked = self.run_make(root, "link", **options)
                self.assertNotEqual(linked.returncode, 0, linked.stdout + linked.stderr)
                self.assertIn("refusing", linked.stderr)
                if missing == "previously linked":
                    self.assertEqual(destination.readlink(), source)
                    self.assert_success(self.run_make(root, "unlink", **options))
                self.assertFalse(destination.is_symlink())
                self.assertFalse(destination.exists())

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
