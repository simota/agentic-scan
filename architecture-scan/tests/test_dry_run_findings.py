"""Defects found by running the skill end to end on a small app."""
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest
import unittest.mock
from contextlib import redirect_stderr, redirect_stdout

from test_architecture_scan import complete_doc, finding, findings, render


class CollisionAtOneLocationTests(unittest.TestCase):
    def test_another_finding_at_the_same_location_is_refused(self):
        existing = finding("A-001", "High")
        other = finding("A-001", "Low", title="A different design note")
        self.assertTrue(findings._collides(existing, other))
        moved = finding("A-001", "High", location="worker/refunds/job.py:60")
        self.assertTrue(findings._collides(existing, moved))
        self.assertFalse(findings._collides(existing, finding("A-001", "Medium")))
        self.assertFalse(findings._collides(existing, {"id": "A-001", "title": "x"}))

    def test_merge_keeps_the_first_finding(self):
        with tempfile.TemporaryDirectory() as d:
            target, fragment = Path(d) / "findings.json", Path(d) / "f.json"
            target.write_text(json.dumps({"findings": [finding("A-202", "High")]}), encoding="utf-8")
            fragment.write_text(json.dumps({"findings": [finding("A-202", "Low", title="Other")]}),
                                encoding="utf-8")
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(findings.main(["merge", str(target), str(fragment)]), 1)
            self.assertEqual(findings.read_json(target)["findings"][0]["severity"], "High")


class UntracedFindingTests(unittest.TestCase):
    def setUp(self):
        self.out = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.out)

    def problems(self, doc):
        target = self.out / "findings.json"
        target.write_text(json.dumps(doc), encoding="utf-8")
        with redirect_stdout(io.StringIO()):
            render.main([str(target), "--out", str(self.out)])
        return findings.contract_problems(self.out)

    def test_unverified_high_or_medium_fails_even_with_evidence(self):
        for severity, ok in (("High", False), ("Medium", False), ("Low", True)):
            with self.subTest(severity=severity):
                doc = complete_doc()
                doc["findings"] = [finding("A-001", severity, rule="R-01")]
                doc["findings"][0]["validation"] = {"verdict": "Unverified", "method": "static",
                                                    "evidence": "some text"}
                problems = self.problems(doc)
                self.assertEqual(problems == [], ok, problems)
                if not ok:
                    self.assertIn("trace it end to end", problems[0])
                    self.assertNotIn("lower", problems[0])  # severity is never the remedy

    def test_stale_message_names_both_causes(self):
        doc = complete_doc()
        self.problems(doc)
        (self.out / "report.md").write_text("old", encoding="utf-8")
        problems = findings.contract_problems(self.out)
        self.assertIn("changed after the last render", problems[0])


class RenderReadabilityTests(unittest.TestCase):
    def test_code_keeps_paths_readable_and_inline_syntax_inert(self):
        self.assertEqual(render.markdown_code("worker/refunds.py:12"),
                         "<code>worker/refunds.py:12</code>")
        code = render.markdown_code("a*b_c|d `e` http://x www.y u@h  two")
        for raw in ("*", "_", "|", "`", "http:", "www.", "@", "  "):
            self.assertNotIn(raw, code)

    def test_rules_show_family_and_mark_inferred_rules(self):
        doc = complete_doc()
        doc["rules"][0].update(family="OWN", inferred=True)
        for lang, marker in (("en", "inferred, to confirm"), ("ja", "推定・要確認")):
            with self.subTest(lang=lang):
                self.assertIn(f"| R-01 · OWN | one writer ({marker}) |",
                              render.render_markdown(doc, lang))
                self.assertIn(f"<td>R-01 · OWN</td><td>one writer ({marker})</td>",
                              render.render_html(doc, lang))

    def test_japanese_labels_separate_source_evidence_and_method(self):
        t = render.LABELS["ja"]
        self.assertEqual(len({t["source"], t["evidence"], t["method"]}), 3)


if __name__ == "__main__":
    unittest.main()


class AdversarialEdgeTests(unittest.TestCase):
    def test_ids_beside_japanese_text_are_mentions_but_path_segments_are_not(self):
        mapping = {"A-001": "A-002", "A-002": "A-001"}
        rewrite = lambda text: findings._rewrite_ids(text, mapping)  # noqa: E731
        self.assertEqual(rewrite("A-001を先に修正し、指摘A-002の対応"), "A-002を先に修正し、指摘A-001の対応")
        self.assertEqual(rewrite("(A-001), A-001. A-001's"), "(A-002), A-002. A-002's")
        for literal in ("docs/A-001.md:3", r"adr\A-001.md", "dir/A-001/x", "A-001.md"):
            self.assertEqual(rewrite(literal), literal)

    def test_evidence_after_a_label_counts_and_bare_words_do_not(self):
        for evidence, ok in (("根拠:job.py:58", True), ("evidence:job.py:58", True),
                             ("Makefile:12", True), ("Dockerfile:3", True),
                             ("Ticket ABC:123", False), ("see ratio:3", False), ("v1:2", False),
                             ("https://h.example:443/x", False), ("BUILD:12", True),
                             ("WORKSPACE:4", True), ("CODEOWNERS:7", True)):
            with self.subTest(evidence=evidence):
                self.assertEqual(findings.cites_line(evidence), ok)

    def test_extensionless_file_from_the_finding_location_counts(self):
        self.assertTrue(findings.cites_line("server:9 swallows the error", ["bin/server:9"]))
        self.assertTrue(findings.cites_line("bin/server:9", "bin/server:9"))
        self.assertFalse(findings.cites_line("server:9", ["api/app.py:3"]))

    def test_collision_ignores_whitespace_and_location_shape(self):
        existing = finding("A-001", "High", location=["worker/refunds/job.py:58"])
        resent = finding("A-001", "High", title="Refund job writes invoices directly  ",
                         location="worker/refunds/job.py:58")
        self.assertFalse(findings._collides(existing, resent))

    def test_a_spurious_rule_is_removed_by_id(self):
        doc = complete_doc()
        doc["rules"].append({"id": "R-02", "statement": "x", "source": "baseline",
                             "status": "holds"})
        findings.merge(doc, {"remove": {"rules": ["R-02"]}}, "f")
        self.assertEqual([r["id"] for r in doc["rules"]], ["R-01"])
        for removals in ({"rules": ["R-09"]}, {"findings": ["A-001"]}):
            with self.subTest(removals=removals):
                with self.assertRaises(findings.SchemaError):
                    findings.merge(complete_doc(), {"remove": removals}, "f")

    def test_unreadable_directory_merges_unlocked_with_a_warning(self):
        with tempfile.TemporaryDirectory() as d:
            target, fragment = Path(d) / "findings.json", Path(d) / "f.json"
            fragment.write_text(json.dumps({"limitations": ["x"]}), encoding="utf-8")
            real_open = findings.os.open

            def deny_directories(path, flags, *args):
                if Path(path).is_dir():
                    raise PermissionError(13, "Permission denied", str(path))
                return real_open(path, flags, *args)

            err = io.StringIO()
            with unittest.mock.patch.object(findings.os, "open", deny_directories), \
                    redirect_stdout(io.StringIO()), redirect_stderr(err):
                self.assertEqual(findings.main(["merge", str(target), str(fragment)]), 0)
            self.assertIn("cannot lock", err.getvalue())
            self.assertEqual(findings.read_json(target)["limitations"], ["x"])

    def test_dollar_signs_cannot_open_math(self):
        rendered = render.markdown_inline("$HOME/$USER and ${X}")
        self.assertNotIn("$", rendered)
        self.assertNotIn("$", render.markdown_code("echo $HOME"))
