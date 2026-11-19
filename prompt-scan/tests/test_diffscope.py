"""diffscope.py: the change a diff-scoped review covers (reference/diff-mode.md)."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "skills" / ROOT.name / "scripts" / "diffscope.py"
ENV = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
       "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
       "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}


def run(*args, cwd=None):
    return subprocess.run([sys.executable, str(SCRIPT), *map(str, args)], capture_output=True,
                          text=True, cwd=cwd, env={**ENV, "PYTHONDONTWRITEBYTECODE": "1"})


class DiffScopeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name) / "repo"
        self.repo.mkdir()
        self.git("init", "-q", "-b", "main")
        self.write("app/orders.py", "".join(f"line {n}\n" for n in range(1, 11)))
        self.write("app/old.py", "gone\n")
        self.write("app/name.py", "".join(f"keep {n}\n" for n in range(1, 21)))
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "base")
        self.git("checkout", "-q", "-b", "feature")
        lines = (self.repo / "app/orders.py").read_text().splitlines(keepends=True)
        lines[2] = "changed 3\n"
        del lines[7]
        self.write("app/orders.py", "".join(lines))
        self.write("app/new.py", "a\nb\n")
        self.git("rm", "-q", "app/old.py")
        self.git("mv", "app/name.py", "app/renamed.py")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "feature")
        self.git("checkout", "-q", "main")
        self.write("README.md", "main moved on\n")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "main")
        self.git("checkout", "-q", "feature")
        self.out = Path(self.tmp.name) / "diff.json"

    def tearDown(self):
        self.tmp.cleanup()

    def git(self, *args):
        subprocess.run(["git", "-C", str(self.repo), *args], check=True, env=ENV, capture_output=True)

    def write(self, rel, text):
        path = self.repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def scope(self, *extra):
        proc = run("scope", self.repo, "--out", self.out, *extra)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return json.loads(self.out.read_text()), proc.stdout

    def test_branch_diff_is_taken_from_the_merge_base(self):
        diff, stdout = self.scope("--base", "main")
        files = {f["path"]: f for f in diff["files"]}
        self.assertNotIn("README.md", files)  # changed on the base only
        self.assertEqual(files["app/new.py"]["status"], "added")
        self.assertEqual(files["app/new.py"]["changed"], [[1, 2]])
        self.assertEqual(files["app/old.py"]["status"], "deleted")
        self.assertEqual(files["app/renamed.py"]["status"], "renamed")
        self.assertEqual(files["app/renamed.py"]["old_path"], "app/name.py")
        self.assertEqual(files["app/renamed.py"]["changed"], [])
        self.assertEqual(files["app/orders.py"]["changed"], [[3, 3]])
        self.assertEqual(files["app/orders.py"]["removed_at"], [7])
        self.assertTrue(diff["scope"].startswith("Diff main...HEAD (merge base "))
        self.assertIn(diff["scope"], stdout)

    def test_default_base_is_main(self):
        diff, _ = self.scope()
        self.assertEqual(diff["base"], "main")

    def test_worktree_includes_unstaged_and_untracked_changes(self):
        self.write("app/orders.py", (self.repo / "app/orders.py").read_text() + "tail\n")
        self.write("app/scratch.py", "x\ny\nz\n")
        diff, _ = self.scope("--base", "main", "--worktree")
        files = {f["path"]: f for f in diff["files"]}
        self.assertEqual(files["app/scratch.py"]["status"], "untracked")
        self.assertEqual(files["app/scratch.py"]["changed"], [[1, 3]])
        self.assertIn([10, 10], files["app/orders.py"]["changed"])
        self.assertIsNone(diff["head_commit"])
        self.assertIn("working tree", diff["scope"])

    def test_pathspec_limits_the_diff(self):
        diff, _ = self.scope("--base", "main", "--path", "app/new.py")
        self.assertEqual([f["path"] for f in diff["files"]], ["app/new.py"])
        self.assertIn("limited to app/new.py", diff["scope"])

    def test_locate_places_each_location(self):
        self.scope("--base", "main")
        proc = run("locate", self.out, "app/orders.py:3", "app/orders.py:5", "app/orders.py:8",
                   "app/old.py:1", "app/other.py:1", "app/new.py", "--json")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(proc.stdout), {
            "app/orders.py:3": "changed", "app/orders.py:5": "file", "app/orders.py:8": "changed",
            "app/old.py:1": "deleted", "app/other.py:1": "outside", "app/new.py": "file"})
        near = run("locate", self.out, "app/orders.py:5", "--near", "2")
        self.assertEqual(near.stdout.split("\t")[0], "changed")

    def test_errors_exit_2(self):
        proc = run("scope", self.repo, "--base", "no-such-ref", "--out", self.out)
        self.assertEqual(proc.returncode, 2)
        self.assertIn("no-such-ref", proc.stderr)
        self.out.write_text("{}")
        self.assertEqual(run("locate", self.out, "a.py:1").returncode, 2)

    def test_empty_diff_says_so(self):
        diff, stdout = self.scope("--base", "HEAD")
        self.assertEqual(diff["files"], [])
        self.assertIn("no changes", stdout)


if __name__ == "__main__":
    unittest.main()
