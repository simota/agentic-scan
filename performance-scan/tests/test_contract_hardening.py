"""Second-review regressions: escaping, permissions, contract rules and messages."""
import contextlib
import io
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from test_performance_scan import complete_doc, finding, findings, render


def run(main, *args):
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = main([str(arg) for arg in args])
    return code, stdout.getvalue(), stderr.getvalue()


def write_outputs(out, doc):
    (out / "findings.json").write_text(json.dumps(doc), encoding="utf-8")
    for name in ("report.md", "dashboard.html"):
        (out / name).write_text("x", encoding="utf-8")


class EscapingTests(unittest.TestCase):
    def test_step_and_perspective_notes_are_escaped_in_both_outputs(self):
        doc = complete_doc()
        doc["findings"][0]["step"] = "<b>DB1</b>*"
        doc["perspectives"][0]["note"] = "</td><img src=x onerror=alert(1)>"
        html = render.render_html(doc, "en")
        report = render.render_markdown(doc, "en")
        self.assertNotIn("<b>DB1</b>", html)
        self.assertNotIn("<img", html)
        self.assertIn("&lt;b&gt;DB1&lt;/b&gt;*", html)
        self.assertIn("(&lt;b&gt;DB1&lt;/b&gt;\\*)", report)
        self.assertNotIn("<img", report)

    def test_emoji_shortcodes_are_split(self):
        self.assertEqual(render.markdown_text("ratio :100: ok"), "ratio :<!-- -->100: ok")
        self.assertEqual(render.markdown_text("app/x.py:42"), "app/x.py:42")
        self.assertEqual(render.markdown_text(":white_check_mark:"),
                         ":<!-- -->white\\_check\\_mark:")
        doc = complete_doc()
        doc["findings"][0]["step"] = " "
        self.assertIn("**perspective:** Database access\n", render.render_markdown(doc, "en"))

    def test_dashboard_perspective_table_has_headers_and_no_blank_evidence(self):
        doc = complete_doc()
        doc["findings"][1]["validation"] = {"verdict": "Likely", "method": "static"}
        html = render.render_html(doc, "ja")
        self.assertIn("<th scope='col'>状態</th><th scope='col'>メモ</th>", html)
        self.assertEqual(html.count("<dt>evidence</dt>") + html.count("<dt>根拠</dt>"), 1)


class RenderMessageTests(unittest.TestCase):
    def test_schema_errors_name_the_input_file(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "findings.json"
            source.write_text("[]", encoding="utf-8")
            code, _, err = run(render.main, source, "--out", directory)
            self.assertEqual(code, 2)
            self.assertEqual(err, f"schema: {source}: top level: must be an object\n")


class PermissionTests(unittest.TestCase):
    def test_new_record_and_outputs_start_private(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fragment = root / "fragment.json"
            fragment.write_text(json.dumps(complete_doc()), encoding="utf-8")
            old = os.umask(0o022)
            try:
                code, _, err = run(findings.main, "merge", root / "findings.json", fragment)
                self.assertEqual(code, 0, err)
                code, _, err = run(render.main, root / "findings.json", "--out", root)
                self.assertEqual(code, 0, err)
            finally:
                os.umask(old)
            for name in ("findings.json", "report.md", "dashboard.html"):
                self.assertEqual(stat.S_IMODE((root / name).stat().st_mode), 0o600, name)


class ContractTests(unittest.TestCase):
    def problems(self, doc):
        with tempfile.TemporaryDirectory() as directory:
            write_outputs(Path(directory), doc)
            return findings.contract_problems(directory)

    def test_excluded_findings_come_last_and_are_not_ranked(self):
        excluded = {"verdict": "FalsePositive", "method": "static", "evidence": "x.py:1"}
        doc = complete_doc()
        doc["findings"] = [finding("P-001", "Low"), finding("P-002", "High", validation=excluded)]
        self.assertEqual(self.problems(doc), [])
        doc["findings"] = [finding("P-001", "Low", validation=excluded), finding("P-002", "High")]
        self.assertEqual(self.problems(doc), [
            "P-002: excluded findings (P-001) must be numbered after all others"])
        doc["findings"] = [finding("P-001", "Low"), finding("P-002", "High")]
        self.assertEqual(self.problems(doc), [
            "findings must be numbered in severity order (High first): P-002 (High) follows "
            "P-001 (Low)"])

    def test_definitive_evidence_suspected_valid_and_holding_budgets(self):
        doc = complete_doc()
        doc["findings"][0]["validation"]["evidence"] = "looks fine"
        doc["findings"][1].update(confidence="Suspected")
        doc["findings"][0]["budget"] = "B-01"
        doc["budgets"][0]["status"] = "holds"
        self.assertEqual(self.problems(doc), [
            "P-001.validation.evidence: Valid evidence must cite a path:line",
            "P-002: a Suspected finding cannot be Valid; confirm the code link "
            "(Confirmed or Environment-dependent) or record Likely",
            "B-01: status holds, but P-001 is a Valid, unfixed violation of it"])
        doc["findings"][0]["status"] = "Accepted"  # an accepted cost still violates it
        self.assertIn("B-01: status holds, but P-001 is a Valid, unfixed violation of it",
                      self.problems(doc))
        doc["findings"][0]["status"] = "Fixed"
        doc["findings"][0]["validation"]["evidence"] = "C:\\app\\x.py:12 shows it"
        doc["findings"][1]["validation"]["verdict"] = "Likely"
        self.assertEqual(self.problems(doc), [])

    def test_required_lists_and_unique_ids(self):
        doc = complete_doc()
        doc["limitations"], doc["checked_ok"] = [], []
        self.assertEqual(self.problems(doc), [
            "limitations: state what static reading cannot show",
            "checked_ok: list what was examined and held"])
        doc = complete_doc()
        doc["findings"][1]["id"] = "P-001"
        with self.assertRaisesRegex(findings.SchemaError, r"duplicate P-001"):
            findings.validate(doc)

    def test_check_names_a_path_that_is_not_a_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "findings.json"
            path.write_text("{}", encoding="utf-8")
            for target in (path, Path(directory) / "missing"):
                self.assertEqual(findings.contract_problems(target), [f"not a directory: {target}"])


class MergeMessageTests(unittest.TestCase):
    def test_errors_name_the_finding_and_the_invalid_existing_record(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target, fragment = root / "findings.json", root / "b.json"
            target.write_text(json.dumps(complete_doc()), encoding="utf-8")
            record = finding("P-099")
            del record["workload"]
            fragment.write_text(json.dumps({"findings": [record]}), encoding="utf-8")
            code, _, err = run(findings.main, "merge", target, fragment)
            self.assertEqual(code, 1)
            self.assertIn("b.json: findings[2]: missing workload (finding 'P-099')", err)

            target.write_text(json.dumps({"findings": [{"id": "P-001"}]}), encoding="utf-8")
            fragment.write_text("{}", encoding="utf-8")
            code, _, err = run(findings.main, "merge", target, fragment)
            self.assertEqual(code, 1)
            self.assertIn(f"refused: {target}: findings[0]: missing title", err)

    def test_list_items_are_checked_before_deduplication(self):
        doc = {"checked_ok": ["a"]}
        findings.merge(doc, {"checked_ok": ["a", "b", "b"]}, "f.json")
        self.assertEqual(doc["checked_ok"], ["a", "b"])
        with self.assertRaisesRegex(findings.SchemaError, r"^f\.json\.checked_ok\[0\]"):
            findings.merge(doc, {"checked_ok": [["unhashable"]]}, "f.json")



class ReportLayoutTests(unittest.TestCase):
    def test_index_excluded_section_method_and_budget_links(self):
        doc = complete_doc()
        doc["meta"]["method"] = "Static review"
        doc["findings"][0]["budget"] = "B-01"
        doc["findings"].append(finding("P-003", "High", budget="B-01", validation={
            "verdict": "NotApplicable", "method": "static", "evidence": "x.py:3"}))
        report = render.render_markdown(doc, "en")
        self.assertIn("| Method | Static review |", report)
        self.assertIn("| ID | Severity | Confidence | Verdict | Title | Location |", report)
        self.assertIn("| P-003 | High | Confirmed | NotApplicable |", report)
        findings_part, excluded_part = report.split("## Excluded findings")
        self.assertNotIn("### P-003", findings_part)
        self.assertIn("### P-003 [NotApplicable] ", excluded_part)
        self.assertNotIn("**status:**", excluded_part.split("## Performance budgets")[0])
        budget = next(line for line in report.splitlines() if line.startswith("| B-01 |"))
        self.assertTrue(budget.endswith(" | P-001 |"))
        html = render.render_html(doc, "en")
        self.assertIn("<td>P-001</td>", html)
        self.assertEqual(html.count("<dt>status</dt>"), 2)


class LanguageNoteTests(unittest.TestCase):
    def test_overriding_the_record_language_is_noted(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "findings.json"
            source.write_text(json.dumps(complete_doc()), encoding="utf-8")
            code, _, err = run(render.main, source, "--out", directory, "--lang", "ja")
            self.assertEqual(code, 0)
            self.assertEqual(err, "render: note: labels in ja, but the record's text is in en\n")
            code, _, err = run(render.main, source, "--out", directory, "--lang", "en")
            self.assertEqual((code, err), (0, ""))


class CitationTests(unittest.TestCase):
    def test_evidence_must_name_a_file_position(self):
        cites = ["app/orders/views.py:18 lacks prefetch", "app/orders/views.py#L18",
                 "views.py：18", "C:\\app\\x.py:12", "Makefile:12 sets -O0", "src/main:40"]
        not_cites = ["confirmed against https://staging.example:8080/api/orders",
                     "measured locally at 12:30", "ratio 1:10", "redis at localhost:6379",
                     "views.py line 18"]
        for text in cites:
            self.assertTrue(findings.cites_location(text), text)
        for text in not_cites:
            self.assertFalse(findings.cites_location(text), text)


class AllExcludedLayoutTests(unittest.TestCase):
    def test_an_all_excluded_record_does_not_say_none_under_its_index(self):
        doc = complete_doc()
        for f in doc["findings"]:
            f["validation"] = {"verdict": "NotApplicable", "method": "static", "evidence": "a.py:1"}
        doc["findings"][0]["location"] = ["a.py:3", "c.py:4"]
        report = render.render_markdown(doc, "en")
        findings_part = report.split("## Findings")[1].split("## Excluded findings")[0]
        self.assertNotIn("None.", findings_part)
        self.assertIn("| a.py:3 (+1) |", findings_part)


if __name__ == "__main__":
    unittest.main()
