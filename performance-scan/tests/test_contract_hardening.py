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

    def test_dashboard_perspective_table_has_headers_and_no_blank_evidence(self):
        doc = complete_doc()
        doc["findings"][1]["validation"] = {"verdict": "Likely", "method": "static"}
        html = render.render_html(doc, "ja")
        self.assertIn("<th scope='col'>状態</th><th scope='col'>メモ</th>", html)
        self.assertEqual(html.count("<dt>evidence</dt>") + html.count("<dt>根拠</dt>"), 1)


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

    def test_excluded_findings_are_not_ranked_but_included_ones_are(self):
        doc = complete_doc()
        doc["findings"] = [finding("P-001", "Low", validation={
            "verdict": "FalsePositive", "method": "static", "evidence": "x.py:1"}),
            finding("P-002", "High")]
        self.assertEqual(self.problems(doc), [])
        doc["findings"][0]["validation"] = {"verdict": "Valid", "method": "static", "evidence": "x"}
        self.assertEqual(self.problems(doc),
                         ["findings must be numbered in severity order (High first)"])

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


if __name__ == "__main__":
    unittest.main()
