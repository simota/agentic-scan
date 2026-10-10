"""Defects from a strict pre-PR review: renumber joins, `--`, odd paths, hand edits."""
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from test_architecture_scan import SKILL, complete_doc, finding, findings, render


class RenumberJoinTests(unittest.TestCase):
    def test_ids_joined_by_slash_or_dash_are_each_rewritten(self):
        mapping = {"A-001": "A-002", "A-002": "A-001"}
        rewrite = lambda text: findings._rewrite_ids(text, mapping)  # noqa: E731
        self.assertEqual(rewrite("Fix A-002/A-001 together"), "Fix A-001/A-002 together")
        self.assertEqual(rewrite("A-002-A-001 range"), "A-001-A-002 range")
        three = {"A-001": "A-003", "A-002": "A-001", "A-003": "A-004", "A-004": "A-002"}
        self.assertEqual(findings._rewrite_ids("A-001-A-002-A-003 and A-001/A-002/A-003/A-004",
                                               three),
                         "A-003-A-001-A-004 and A-003/A-001/A-004/A-002")
        self.assertEqual(findings._rewrite_ids("A-001-A-002-A-003.md", three),
                         "A-001-A-002-A-003.md")
        for literal in ("docs/A-001.md", "JIRA-A-001", "A-001/notes", "x-A-001", "A-001-x",
                        "A-001-A-002.md", "A-001/A-002/", "foo/A-001/A-002 bar",
                        "JIRA-A-001-A-002"):
            with self.subTest(literal=literal):
                self.assertEqual(rewrite(literal), literal)


class SafeOutputTests(unittest.TestCase):
    def test_a_closed_or_plain_stream_is_left_alone(self):
        closed = io.TextIOWrapper(io.BytesIO())
        closed.close()
        with redirect_stdout(closed), redirect_stderr(io.StringIO()):
            findings.safe_output()


class DashItemTests(unittest.TestCase):
    def test_a_dash_item_never_becomes_a_rule(self):
        for item in ("--", "-- ", "--\t", "-x", "- -"):
            with self.subTest(item=item):
                self.assertTrue(render.block_safe(render.markdown_inline(item)).startswith("&#45;"))


class OddPathTests(unittest.TestCase):
    @unittest.skipIf(sys.platform == "win32", "POSIX byte paths")
    def test_non_utf8_paths_print_instead_of_crashing_after_the_work(self):
        with tempfile.TemporaryDirectory() as d:
            base = os.fsencode(d)
            out = os.fsdecode(base + b"/o\xff")
            fragment = Path(d) / "f.json"
            fragment.write_text(json.dumps(complete_doc()), encoding="utf-8")
            env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
            scripts = SKILL / "scripts"
            for args in (["findings.py", "merge", f"{out}/findings.json", str(fragment)],
                         ["render.py", f"{out}/findings.json", "--out", out],
                         ["findings.py", "check", out]):
                with self.subTest(command=args[:2]):
                    result = subprocess.run([sys.executable, str(scripts / args[0]), *args[1:]],
                                            capture_output=True, env=env, timeout=30)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertNotIn(b"Traceback", result.stderr)


class HandEditTests(unittest.TestCase):
    def test_deep_nesting_is_a_schema_error(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "findings.json"
            path.write_text('{"meta": {"x": ' + "[" * 100000 + "]" * 100000 + "}}", encoding="utf-8")
            with self.assertRaises(findings.SchemaError):
                findings.read_json(path)

    def test_huge_line_numbers_are_refused_by_the_schema(self):
        with self.assertRaisesRegex(findings.SchemaError, "location"):
            findings.validate({"findings": [finding(location="a.py:1-" + "9" * 5000)]})
        findings.validate({"findings": [finding(location="a.py:999999999")]})


class BatchErrorTests(unittest.TestCase):
    def test_the_failing_fragment_is_named(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            paths = []
            for i, frag in enumerate(({"limitations": ["x"]},
                                      {"findings": [finding(severity="Hihg")]},
                                      {"limitations": ["y"]})):
                paths.append(tmp / f"b{i}.json")
                paths[-1].write_text(json.dumps(frag), encoding="utf-8")
            err = io.StringIO()
            with redirect_stdout(io.StringIO()), redirect_stderr(err):
                self.assertEqual(findings.main(["merge", str(tmp / "out" / "findings.json"),
                                                *map(str, paths)]), 1)
            self.assertIn("b1.json", err.getvalue())


class TemporaryFileTests(unittest.TestCase):
    def test_a_leftover_temporary_file_is_named_as_such(self):
        out = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, out)
        target = out / "findings.json"
        target.write_text(json.dumps(complete_doc()), encoding="utf-8")
        with redirect_stdout(io.StringIO()):
            render.main([str(target), "--out", str(out)])
        (out / f".findings-{'a' * 32}.tmp").write_text("partial", encoding="utf-8")
        problems = findings.contract_problems(out)
        self.assertEqual(len(problems), 1)
        self.assertIn("interrupted write", problems[0])
        self.assertNotIn("--allow", problems[0])


class EvidenceHostTests(unittest.TestCase):
    def test_host_ports_versions_and_abbreviations_are_not_lines(self):
        for evidence, ok in (("db.internal:5432 refused", False), ("api.example.com:443", False),
                             ("e.g.:3", False), ("v1.2:3", False), ("//host/x.py:3", False),
                             ("README:4", True), ("job.py:58", True), ("src/x:9", True),
                             (r"C:\repo\a.py:3", True), ("app.config.ts:3", True),
                             ("Dockerfile.dev:3", True), ("Containerfile.dev:1", True),
                             (".env.local:3", True), ("Makefile.local:2", True),
                             ("docker-compose.local:2", True), ("Service.svc:4", True),
                             ("notes.org:3", True), ("api.example.io:443", False),
                             ("README.com:443", False), ("Dockerfile.com:443", False),
                             ("notafile.internal:443", False), (".env.com:3", False),
                             ("src/README.com:3", True)):
            with self.subTest(evidence=evidence):
                self.assertEqual(findings.cites_line(evidence), ok)


class HostInLocationTests(unittest.TestCase):
    def test_a_host_like_name_from_the_finding_location_still_counts(self):
        self.assertTrue(findings.cites_line("README.com:4", ["README.com:4"]))


class ProtocolRelativeTests(unittest.TestCase):
    def test_another_host_is_never_a_relative_link(self):
        for url in ("//evil.example/x", " //evil.example/x", r"\\host\share", "/\\evil.com",
                    "\\/evil.com"):
            with self.subTest(url=url):
                self.assertFalse(render.is_safe_link(url))
                self.assertNotIn("](<", render.markdown_reference({"url": url}))


if __name__ == "__main__":
    unittest.main()
