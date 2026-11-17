"""Offline tests for scripts/recon.py, against throwaway git repositories."""
import contextlib
from datetime import date
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parent.parent / "skills" / "logic-scan" / "scripts"
sys.path.insert(0, str(SCRIPTS))
sys.dont_write_bytecode = True

import recon  # noqa: E402

TODAY = date(2026, 11, 17)
GIT_ENV = {"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}


class Repo:
    def __init__(self, path):
        self.path = path
        path.mkdir()
        self.git("init", "-q", "-b", "main")

    def git(self, *args, env=None):
        return subprocess.run(["git", "-C", str(self.path), *args], check=True, capture_output=True,
                              text=True, env={**os.environ, **GIT_ENV, **(env or {})}).stdout

    def commit(self, day, message, *paths):
        for p in paths:
            f = self.path / p
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(f"{f.read_text() if f.exists() else ''}{message}\n")
        self.git("add", "-A")
        stamp = f"{day}T12:00:00"
        self.git("commit", "-q", "-m", message,
                 env={"GIT_AUTHOR_DATE": stamp, "GIT_COMMITTER_DATE": stamp})


class Rule(unittest.TestCase):
    def test_test_file_rule_is_the_union_of_the_scans(self):
        self.assertEqual(recon.TEST_DIRS,
                         ("test", "tests", "__tests__", "__mocks__", "spec", "e2e", "Tests"))
        self.assertEqual(recon.TEST_DIR_SUFFIXES, (".Tests",))
        self.assertEqual(recon.TEST_NAMES,
                         ("*_test.*", "*.test.*", "*.spec.*", "*.test-d.*", "*.cy.*", "*_spec.rb",
                          "test_*.py", "conftest.py", "*Test.java", "*Test.kt", "*Tests.swift"))

    def test_classifies_paths(self):
        tests = ["tests/a.py", "pkg/__tests__/x.ts", "e2e/login.ts", "Shop.Tests/A.cs",
                 "pay_test.go", "a.test.ts", "b.spec.js", "c.test-d.ts", "d.cy.ts", "e_spec.rb",
                 "test_pay.py", "conftest.py", "src/PayTest.java", "PayTest.kt", "AppTests.swift",
                 "ios/Tests/A.swift", "src/test/java/A.java"]
        sources = ["test_utils/x.py", "src/latest.py", "contest.py", "src/testing.go",
                   "specs.md", "src/Contest.java", "app/e2e_config.py"]
        for p in tests:
            self.assertTrue(recon.is_test_file(p), p)
        for p in sources:
            self.assertFalse(recon.is_test_file(p), p)

    def test_glob_keeps_star_inside_a_segment(self):
        self.assertTrue(recon.excluded("packages/a/dist/x.js", [recon.glob_regex("**/dist")]))
        self.assertTrue(recon.excluded("vendor/lib/x.go", [recon.glob_regex("vendor")]))
        self.assertFalse(recon.excluded("src/vendor.go", [recon.glob_regex("vendor")]))
        self.assertFalse(recon.excluded("a/b/c.js", [recon.glob_regex("a/*.js")]))

    def test_months_before_clamps_the_day(self):
        self.assertEqual(recon.months_before(date(2026, 3, 31), 1), date(2026, 2, 28))
        self.assertEqual(recon.months_before(TODAY, 12), date(2025, 11, 17))


class RepoCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.repo = Repo(self.root / "r")

    def tearDown(self):
        self.tmp.cleanup()

    def run_recon(self, *args, repo=None):
        out = self.root / "recon.json"
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = recon.main([str(repo or self.repo.path), "--out", str(out),
                               "--today", TODAY.isoformat(), *args])
        self.assertEqual(code, 0)
        return json.loads(out.read_text(encoding="utf-8"))


class History(RepoCase):
    def build(self):
        r = self.repo
        r.commit("2024-01-10", "init", "src/pay.py", "src/cart.py")
        r.commit("2026-01-05", "feat: pay", "src/pay.py", "tests/test_pay.py")
        r.commit("2026-02-05", "fix: rounding in pay", "src/pay.py")
        r.commit("2026-03-05", "fix(cart): empty cart", "src/cart.py", "tests/test_cart.py")
        r.commit("2026-04-05", "chore: tidy\n\nThis closes bug 12.", "src/pay.py", "package-lock.json")
        r.commit("2026-05-05", "build: prefix debug fixture", "dist/app.js", "src/util.py")

    def test_window_hotspots_and_fixes(self):
        self.build()
        doc = self.run_recon()
        self.assertEqual(doc["window"], {"start": "2025-11-17", "end": "2026-11-17",
                                         "value": "2025-11-17..2026-11-17", "whole_history": False})
        self.assertEqual((doc["commits"], doc["merges"], doc["shallow"]), (5, 0, False))
        self.assertEqual([(h["path"], h["commits"]) for h in doc["hotspots"]],
                         [("src/pay.py", 3), ("dist/app.js", 1), ("src/cart.py", 1), ("src/util.py", 1)])
        self.assertEqual([h["path"] for h in doc["hotspots"] if h["top_decile"]], ["src/pay.py"])
        fixes = {f["subject"]: f for f in doc["fixes"]}
        self.assertEqual(set(fixes), {"fix: rounding in pay", "fix(cart): empty cart", "chore: tidy"})
        self.assertFalse(fixes["fix: rounding in pay"]["touched_tests"])
        self.assertTrue(fixes["fix(cart): empty cart"]["touched_tests"])
        self.assertEqual(fixes["chore: tidy"]["matched_in"], "body")
        self.assertEqual(fixes["fix: rounding in pay"]["matched_in"], "subject")
        self.assertEqual(doc["warnings"], [])

    def test_exclude_and_source_root(self):
        self.build()
        doc = self.run_recon("--exclude", "**/dist", "--source-root", "src/")
        self.assertEqual([h["path"] for h in doc["hotspots"]], ["src/pay.py", "src/cart.py", "src/util.py"])
        self.assertEqual(doc["source_roots"], ["src"])

    def test_young_repository_uses_whole_history(self):
        self.repo.commit("2026-09-01", "init", "a.py")
        self.repo.commit("2026-10-01", "feat", "a.py")
        doc = self.run_recon()
        self.assertTrue(doc["window"]["whole_history"])
        self.assertEqual(doc["window"]["start"], "2026-09-01")
        self.assertEqual(doc["commits"], 2)
        self.assertIn("younger than the window", doc["warnings"][0])

    def test_shallow_clone_is_flagged(self):
        self.build()
        clone = self.root / "clone"
        subprocess.run(["git", "clone", "-q", "--depth", "1", f"file://{self.repo.path}", str(clone)],
                       check=True, capture_output=True, env={**os.environ, **GIT_ENV})
        doc = self.run_recon(repo=clone)
        self.assertTrue(doc["shallow"])
        self.assertTrue(any(w.startswith("shallow clone") for w in doc["warnings"]))

    def test_not_a_repository_exits_2(self):
        plain = self.root / "plain"
        plain.mkdir()
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = recon.main([str(plain), "--out", str(self.root / "x.json")])
        self.assertEqual(code, 2)
        self.assertIn("recon:", err.getvalue())
        self.assertFalse((self.root / "x.json").exists())


class Cases(RepoCase):
    """The cases recon.md's shell commands were tested against, now run through recon.py."""

    def put(self, message, files):
        for name, text in files.items():
            path = self.repo.path / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        self.repo.git("add", "-A")
        self.repo.git("commit", "-q", "-m", message)

    def test_churn_leaves_out_tests_locks_and_generated_files(self):
        kept = ["src/app.ts", "src/test_utils/helpers.py", "src/latest/x.ts",
                "src/respec/spec.ts", "src/Shop.Testing/a.cs"]
        left_out = [
            "packages/core/dist/index.d.ts", "pnpm-lock.yaml", "package-lock.json",
            "yarn.lock", "Cargo.lock", "go.sum", "packages/core/test/cart.ts",
            "src/cart.test-d.ts", "src/__mocks__/api.ts", "e2e/login.cy.ts",
            "src/cart.test.ts", "src/cart.spec.ts", "src/__tests__/a.ts", "tests/test_a.py",
            "pkg/a_test.go", "app/src/test/java/ATest.java", "spec/models/user_spec.rb",
            "lib/cart_spec.rb", "src/Shop.Tests/CartTests.cs", "cypress/checkout.cy.ts",
            "tests/conftest.py", "src/a_test.py"]
        self.put("one", {name: "1" for name in kept + left_out})
        doc = self.run_recon("--since", "2000-01-01", "--exclude", "**/dist")
        self.assertEqual(sorted(h["path"] for h in doc["hotspots"]), sorted(kept))

    def test_bug_fix_grep_matches_whole_words(self):
        fixes = ["fix: rounding", "Fixed crash on save", "fixing the parser", "hotfix login",
                 "bugfix: parser", "Bugs in the parser", "Bug 12: empty cart", "fixes #4"]
        others = ["refactor: prefix legacy helpers", "chore: add debug logging",
                  "test: add fixtures", "docs: suffix rules"]
        for i, message in enumerate(fixes + others):
            self.put(message, {"f.txt": str(i)})
        self.repo.git("checkout", "-q", "-b", "fix/side")
        self.put("docs: side note", {"side.txt": "1"})
        self.repo.git("checkout", "-q", "-")
        self.repo.git("merge", "-q", "--no-ff", "-m", "Merge branch 'fix/side'", "fix/side")
        doc = self.run_recon("--since", "2000-01-01")
        self.assertEqual(sorted(f["subject"] for f in doc["fixes"]), sorted(fixes))
        self.assertTrue(all(f["matched_in"] == "subject" for f in doc["fixes"]))

    def test_fixes_that_touched_no_test_are_listed(self):
        self.put("feat: refunds", {"src/refund.py": "1", "tests/test_refund.py": "1"})
        self.put("fix: rounding", {"src/refund.py": "2"})
        self.put("fix: partial refunds", {"src/refund.py": "3", "tests/test_refund.py": "2"})
        self.put("bugfix: cart", {"src/cart.ts": "1", "src/cart.test.ts": "1"})
        self.put("hotfix: login", {"pkg/login.go": "1"})
        self.put("fix: login test", {"pkg/login_test.go": "1"})
        self.put("chore: fixture", {"src/refund.py": "4"})
        self.put("fix: e2e login", {"src/login.ts": "1", "e2e/login.cy.ts": "1"})
        self.put("fix: checkout", {"src/checkout.ts": "1", "cypress/checkout.cy.ts": "1"})
        self.put("fix: user model", {"app/models/user.rb": "1", "spec/models/user_spec.rb": "1"})
        self.put("fix: cart totals", {"src/Cart.cs": "1", "src/Shop.Tests/CartTests.cs": "1"})
        self.put("fix: inspector", {"src/respec/spec.ts": "1"})
        doc = self.run_recon("--since", "2000-01-01")
        self.assertEqual(sorted(f["subject"] for f in doc["fixes"] if not f["touched_tests"]),
                         ["fix: inspector", "fix: rounding", "hotfix: login"])


if __name__ == "__main__":
    unittest.main()
