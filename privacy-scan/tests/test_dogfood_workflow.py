"""Regressions for friction found by running the skill end to end on a synthetic app."""
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from test_privacy_scan import complete_doc, finding, findings, render


def write_outputs(out, doc):
    out.mkdir()
    (out / "findings.json").write_text(json.dumps(doc), encoding="utf-8")
    (out / "report.md").write_text(render.render_markdown(doc, "en"), encoding="utf-8")
    (out / "dashboard.html").write_text(render.render_html(doc, "en"), encoding="utf-8")


class RenumberTests(unittest.TestCase):
    def doc(self):
        doc = complete_doc()
        doc["findings"] = [
            finding("PV-001", "Low", title="Low first", location="web/low.py:1"),
            finding("PV-002", "High", title="High second",
                    validation={"verdict": "FalsePositive", "method": "static",
                                "evidence": "scrubber at app.py:30"}),
            finding("PV-003", "High", title="High third", impact="Same root as PV-001",
                    location="api/high.py:1"),
        ]
        doc["next_steps"] = ["Fix PV-003, then PV-001; keep PV-002 excluded"]
        return doc

    def test_renumber_orders_by_severity_and_rewrites_references(self):
        doc = self.doc()
        moves = findings.renumber(doc)
        self.assertEqual([(f["id"], f["title"]) for f in doc["findings"]],
                         [("PV-001", "High third"), ("PV-002", "Low first"),
                          ("PV-003", "High second")])
        self.assertEqual(moves, {"PV-001": "PV-002", "PV-002": "PV-003", "PV-003": "PV-001"})
        self.assertEqual(doc["findings"][0]["impact"], "Same root as PV-002")
        self.assertEqual(doc["next_steps"], ["Fix PV-001, then PV-002; keep PV-003 excluded"])
        findings.validate(doc, complete=True)

    def test_check_names_the_order_and_the_command_then_renumber_fixes_it(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "out"
            write_outputs(out, self.doc())
            problems = "\n".join(findings.contract_problems(out))
            self.assertIn("PV-001 Low, PV-003 High", problems)
            self.assertIn("findings.py renumber", problems)
            with redirect_stdout(io.StringIO()) as stdout:
                self.assertEqual(findings.main(["renumber", str(out / "findings.json")]), 0)
            self.assertIn("PV-003 -> PV-001", stdout.getvalue())
            with redirect_stdout(io.StringIO()):
                render.main([str(out / "findings.json"), "--out", str(out), "--lang", "en"])
            self.assertEqual(findings.contract_problems(out), [])

    def test_refused_renumber_writes_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "findings.json"
            path.write_text('{"findings": [{"id": "PV-001"}]}', encoding="utf-8")
            before = path.read_bytes()
            with redirect_stderr(io.StringIO()):
                self.assertEqual(findings.main(["renumber", str(path)]), 1)
            self.assertEqual(path.read_bytes(), before)


    def test_equal_severities_are_ordered_by_path(self):
        doc = complete_doc()
        doc["findings"] = [finding("PV-001", "High", location=["web/z.py:1"]),
                           finding("PV-002", "High", location="api/a.py:9")]
        findings.renumber(doc)
        self.assertEqual([f["location"] for f in doc["findings"]], ["api/a.py:9", ["web/z.py:1"]])

    def test_technical_values_keep_text_shaped_like_ids(self):
        doc = complete_doc()
        doc["findings"] = [
            finding("PV-001", "Low", location=["docs/PV-001.md:10"],
                    references=[{"title": "See PV-001", "url": "https://example.com/PV-001"}]),
            finding("PV-002", "High")]
        doc["findings"][0]["validation"]["method"] = "analysed"
        doc["findings"][0]["analysis"] = {"tool": "rg", "command": "rg PV-001 docs",
                                          "result": "PV-001 cited twice"}
        doc["meta"]["commit"] = "PV-001"
        findings.renumber(doc)
        moved = doc["findings"][1]
        self.assertEqual(moved["id"], "PV-002")
        self.assertEqual(moved["location"], ["docs/PV-001.md:10"])
        self.assertEqual(moved["references"], [{"title": "See PV-002",
                                                "url": "https://example.com/PV-001"}])
        self.assertEqual(moved["analysis"]["command"], "rg PV-001 docs")
        self.assertEqual(moved["analysis"]["result"], "PV-002 cited twice")
        self.assertEqual(doc["meta"]["commit"], "PV-001")


class MergeAndSchemaTests(unittest.TestCase):
    def test_nested_validation_merges_key_by_key(self):
        doc = complete_doc()
        findings.merge(doc, {"findings": [{"id": "PV-001", "validation": {"verdict": "Likely"}}]},
                       "fragment")
        self.assertEqual(doc["findings"][0]["validation"],
                         {"verdict": "Likely", "method": "static", "evidence": "app.py:22"})
        findings.validate(doc, complete=True)

    def test_merge_does_not_alias_fragment_objects(self):
        doc = complete_doc()
        fragment = {"findings": [{"id": "PV-001", "validation": {"verdict": "Likely"}}]}
        findings.merge(doc, fragment, "fragment")
        fragment["findings"][0]["validation"]["verdict"] = "Valid"
        self.assertEqual(doc["findings"][0]["validation"]["verdict"], "Likely")

    def test_excluded_findings_need_no_fix_or_guard(self):
        excluded = finding(validation={"verdict": "NotApplicable", "method": "static",
                                       "evidence": "dead code, no route reaches app.py:22"})
        del excluded["fix"], excluded["guard"]
        findings.validate({"findings": [excluded]})
        markdown = render.render_markdown({**complete_doc(), "findings": [excluded]}, "en")
        self.assertNotIn("**fix direction:**", markdown)
        reported = copy.deepcopy(excluded)
        reported["validation"]["verdict"] = "Valid"
        with self.assertRaises(findings.SchemaError):
            findings.validate({"findings": [reported]})

    def test_environment_dependent_findings_name_their_conditions(self):
        doc = complete_doc()
        doc["findings"][0]["confidence"] = "Environment-dependent"
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "out"
            write_outputs(out, doc)
            self.assertTrue(any(p.startswith("findings[0].conditions")
                                for p in findings.contract_problems(out)))
        doc["findings"][0]["conditions"] = "LOG_LEVEL is debug in production"
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "out"
            write_outputs(out, doc)
            self.assertEqual(findings.contract_problems(out), [])
            self.assertIn("**conditions:** LOG\\_LEVEL is debug in production",
                          (out / "report.md").read_text(encoding="utf-8"))

    def test_timestamped_migration_paths_are_accepted(self):
        for location in ("db/migrations/20261009123045_create_users.py:12",
                         "prisma/migrations/20240101000000_init/migration.sql:3"):
            with self.subTest(location=location):
                findings.validate({"findings": [finding(location=location)]})
        # An impossible date-time is not masked.
        with self.assertRaises(findings.SchemaError):
            findings.validate({"findings": [finding(location="db/20261399123045_x.py:1")]})
        # The exemption is for path segments only: in prose the same digits
        # could be an account number.
        with self.assertRaises(findings.SchemaError):
            findings.validate({"findings": [finding(title="Account 20261009123045 is exposed")]})
        with self.assertRaises(findings.SchemaError):
            findings.validate({"findings": [finding(location="db/x_20261009123045.py:1")]})


class DisclaimerTests(unittest.TestCase):
    def test_both_reports_state_it_is_not_legal_advice(self):
        doc = complete_doc()
        self.assertIn("not legal advice", render.render_markdown(doc, "en"))
        self.assertIn("not legal advice", render.render_html(doc, "en"))
        self.assertIn("法的見解ではない", render.render_markdown(doc, "ja"))
        self.assertIn("法的見解ではない", render.render_html(doc, "ja"))


if __name__ == "__main__":
    unittest.main()


class DraftWarningTests(unittest.TestCase):
    def test_render_warns_about_what_check_will_refuse(self):
        doc = complete_doc()
        doc["limitations"] = []
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "findings.json"
            path.write_text(json.dumps(doc), encoding="utf-8")
            stderr = io.StringIO()
            with redirect_stdout(io.StringIO()), redirect_stderr(stderr):
                self.assertEqual(render.main([str(path), "--out", directory]), 0)
            self.assertIn("warning: findings.py check will refuse: limitations:", stderr.getvalue())
            stderr = io.StringIO()
            doc["limitations"] = ["Not legal advice"]
            path.write_text(json.dumps(doc), encoding="utf-8")
            with redirect_stdout(io.StringIO()), redirect_stderr(stderr):
                render.main([str(path), "--out", directory])
            self.assertEqual(stderr.getvalue(), "")

    def test_partly_applied_perspectives_may_hold_findings(self):
        doc = complete_doc()
        for p in doc["perspectives"]:
            if p["name"] == doc["findings"][0]["category"]:
                p.update(status="partly applied", note="LT2 applied; LT3 not reached")
        findings.validate(doc, complete=True)
        self.assertEqual(findings.record_problems(doc), [])

    def test_check_orders_equal_severities_by_path(self):
        doc = complete_doc()
        doc["findings"] = [finding("PV-001", "High", location="web/z.py:1"),
                           finding("PV-002", "High", location="api/a.py:1")]
        self.assertTrue(any("then by path" in p for p in findings.record_problems(doc)))
        findings.renumber(doc)
        self.assertEqual(findings.record_problems(doc), [])


class BlindRunTests(unittest.TestCase):
    """Rules added after a blind run split one fix into two findings and mixed steps."""

    def test_two_reported_findings_cannot_share_a_fix_location(self):
        doc = complete_doc()
        doc["findings"][1]["location"] = copy.deepcopy(doc["findings"][0]["location"])
        self.assertTrue(any("share their first location" in p for p in findings.record_problems(doc)))
        doc["findings"][1]["validation"] = {"verdict": "FalsePositive", "method": "static",
                                            "evidence": "scrubber at app.py:30"}
        self.assertEqual(findings.record_problems(doc), [])

    def test_steps_must_belong_to_the_category(self):
        doc = complete_doc()
        doc["findings"][0]["category"] = "Identifiers and pseudonymisation"
        problems = findings.record_problems(doc)
        self.assertTrue(any(p.startswith("PV-001.step: LT2 is not a step of Identifiers") for p in problems),
                        problems)
        doc["findings"][0]["step"] = "ID2"
        self.assertEqual(findings.record_problems(doc), [])

    def test_step_prefixes_match_the_reference_headings(self):
        text = (Path(findings.__file__).parents[1] / "reference" / "perspectives.md").read_text(
            encoding="utf-8")
        for name, prefix in findings.STEP_PREFIXES.items():
            self.assertIn(f"### {name} ({prefix})", text)
