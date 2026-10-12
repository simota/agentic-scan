"""Exercise installation and CLI helpers from paths containing shell punctuation."""
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAKE = shutil.which("make")


@unittest.skipUnless(MAKE, "make is required")
class MakefilePathTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.repo = self.root / "repo with spaces and 'quotes'"
        self.repo.mkdir()
        shutil.copyfile(ROOT / "Makefile", self.repo / "Makefile")
        self.skill = self.repo / "skills" / "prune-scan"
        self.skill.mkdir(parents=True)
        self.destination = self.root / "installed skills with 'quotes'"
        self.destination.mkdir()

    def make(self, *args, external=False):
        command = [MAKE]
        if external:
            command.extend(["-f", str(self.repo / "Makefile")])
        return subprocess.run(command + list(args), cwd=self.root if external else self.repo,
                              capture_output=True, text=True, timeout=20)

    def assert_ok(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_install_status_and_unlink_use_the_real_checkout_path(self):
        target = f"SKILLS_DIR={self.destination}"
        link = self.destination / "prune-scan"
        self.assert_ok(self.make("link", target))
        self.assertTrue(link.is_symlink())
        self.assertEqual(link.readlink(), self.skill)
        self.assertTrue(link.is_dir())
        repeated = self.make("link", target)
        self.assert_ok(repeated)
        self.assertIn("already linked", repeated.stdout)
        status = self.make("status", target)
        self.assert_ok(status)
        self.assertIn(str(self.skill), status.stdout)
        self.assert_ok(self.make("unlink", target))
        self.assertFalse(link.is_symlink())
        self.assertTrue(self.skill.is_dir())

    def test_absolute_makefile_path_works_from_another_directory(self):
        help_result = self.make("help", external=True)
        self.assert_ok(help_result)
        self.assertIn(str(self.skill), help_result.stdout)
        self.assertIn("symlink the skill", help_result.stdout)
        self.assertEqual(help_result.stderr, "")
        self.assert_ok(self.make("link", f"SKILLS_DIR={self.destination}", external=True))
        self.assertEqual((self.destination / "prune-scan").readlink(), self.skill)

    def test_pipe_in_install_path_cannot_redirect_the_link(self):
        prefix = self.root / "installed"
        prefix.mkdir()
        destination = self.root / "installed|unexpected"
        destination.mkdir()
        target = f"SKILLS_DIR={destination}"
        self.assert_ok(self.make("link", target))
        link = destination / "prune-scan"
        self.assertEqual(link.readlink(), self.skill)
        self.assertFalse((self.repo / "unexpected").exists())
        self.assert_ok(self.make("unlink", target))
        self.assertFalse(link.is_symlink())

    def test_foreign_link_is_never_replaced_or_unlinked(self):
        other = self.root / "another skill"
        other.mkdir()
        link = self.destination / "prune-scan"
        link.symlink_to(other)
        target = f"SKILLS_DIR={self.destination}"
        refused = self.make("link", target)
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("refusing", refused.stderr)
        self.assertEqual(link.readlink(), other)
        self.assert_ok(self.make("unlink", target))
        self.assertEqual(link.readlink(), other)

    def test_preloaded_makefiles_do_not_change_the_checkout_path(self):
        config = self.root / "config.mk"
        config.write_text("# Host-specific make settings.\n", encoding="utf-8")
        for preloaded in ("argument", "environment"):
            with self.subTest(preloaded=preloaded):
                command = [MAKE]
                env = os.environ.copy()
                if preloaded == "argument":
                    command.extend(["-f", str(config)])
                else:
                    env["MAKEFILES"] = str(config)
                command.extend(["-f", str(self.repo / "Makefile"), "link",
                                f"SKILLS_DIR={self.destination}"])
                result = subprocess.run(command, cwd=self.root, env=env,
                                        capture_output=True, text=True, timeout=20)
                self.assert_ok(result)
                link = self.destination / "prune-scan"
                self.assertEqual(link.readlink(), self.skill)
                self.assertTrue(link.is_dir())
                link.unlink()

    def test_inventory_helper_preserves_quoted_input_and_output_paths(self):
        shutil.copytree(ROOT / "skills" / "prune-scan" / "scripts", self.skill / "scripts")
        target = self.root / "reviewed app with 'quotes'"
        target.mkdir()
        (target / "unused.py").write_text("def unused_helper():\n    return 1\n", encoding="utf-8")
        output = self.root / "inventory with 'quotes'.json"
        result = self.make("inventory", f"TARGET={target}", f"OUT={output}")
        self.assert_ok(result)
        data = json.loads(output.read_text(encoding="utf-8"))
        self.assertIn("unused_helper", [row["name"] for row in data["unreferenced_symbols"]])


if __name__ == "__main__":
    unittest.main()
