"""Cross-field consistency of the record and agreement between the record and its outputs."""
import base64
import hashlib
import io
import json
from pathlib import Path
import re
import shutil
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from test_architecture_scan import complete_doc, finding, findings, render


class SchemaConsistencyTests(unittest.TestCase):
    def assert_refused(self, doc, pattern):
        with self.assertRaisesRegex(findings.SchemaError, pattern):
            findings.validate(doc)

    def test_ids_and_lines_accept_ascii_digits_only(self):
        for fid in ("A-٠٠١", "A-００１"):
            with self.subTest(fid=fid):
                self.assert_refused({"findings": [finding(fid)]}, r"\.id")
        doc = complete_doc()
        doc["rules"][0]["id"] = "R-٠١"
        self.assert_refused(doc, r"rules\[0\]\.id")
        self.assert_refused({"findings": [finding(location="src/a.py:٥")]}, "location")

    def test_location_lines_start_at_one_and_ranges_ascend(self):
        for location in ("src/a.py:0", "src/a.py:0-4", "src/a.py:12-5"):
            with self.subTest(location=location):
                self.assert_refused({"findings": [finding(location=location)]}, "location")
        findings.validate({"findings": [finding(location=["src/a.py:5-5", "src/a.py:1-40"])]})

    def test_step_is_a_hunt_step_of_the_finding_category(self):
        for step in ("dm1", "DM", "DM0", "XX1", "DM1 DM2", 1, None):
            with self.subTest(step=step):
                self.assert_refused({"findings": [finding(step=step)]}, r"\.step")
        self.assert_refused({"findings": [finding(step="BL1")]}, "not a Domain model")
        findings.validate({"findings": [finding(step="DM12"),
                                        finding("A-002", category="Coupling", step="CP3")]})
        self.assertEqual(len(findings.STEP_PREFIXES), len(findings.PERSPECTIVES))

    def test_step_prefixes_match_the_perspectives_reference(self):
        text = (Path(findings.__file__).parents[1] / "reference" / "perspectives.md").read_text(
            encoding="utf-8")
        headings = re.findall(r"^### (.+?) \(([A-Z]{2})\)", text, re.MULTILINE)
        self.assertEqual(tuple(name for name, _ in headings), findings.PERSPECTIVES)
        self.assertEqual(tuple(prefix for _, prefix in headings), findings.STEP_PREFIXES)

    def test_rule_family_and_inferred_are_checked_when_present(self):
        for key, value in (("family", "LAYERS"), ("family", 1), ("inferred", "false"),
                           ("inferred", 0)):
            with self.subTest(key=key, value=value):
                doc = complete_doc()
                doc["rules"][0][key] = value
                self.assert_refused(doc, rf"rules\[0\]\.{key}")
        doc = complete_doc()
        doc["rules"][0].update(family="OWN", inferred=True)
        findings.validate(doc, complete=True)


class ContractConsistencyTests(unittest.TestCase):
    def setUp(self):
        self.out = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.out)

    def build(self, doc, *args):
        target = self.out / "findings.json"
        target.write_text(json.dumps(doc), encoding="utf-8")
        with redirect_stdout(io.StringIO()):
            self.assertEqual(render.main([str(target), "--out", str(self.out), *args]), 0)
        return target

    def test_cited_rule_must_exist(self):
        doc = complete_doc()
        doc["findings"][0]["rule"] = "R-09"
        self.build(doc)
        problems = findings.contract_problems(self.out)
        self.assertTrue(any("A-001" in p and "R-09" in p for p in problems), problems)
        doc["findings"][0]["rule"] = "R-01"
        self.build(doc)
        self.assertEqual(findings.contract_problems(self.out), [])

    def test_finding_under_a_not_applicable_perspective_fails(self):
        doc = complete_doc()
        for p in doc["perspectives"]:
            if p["name"] == "Domain model and data ownership":
                p.update(status="N/A", note="no stores")
        self.build(doc)
        problems = findings.contract_problems(self.out)
        self.assertTrue(any("A-001" in p and "N/A" in p for p in problems), problems)

    def test_finding_under_a_not_checked_perspective_fails_unless_excluded(self):
        doc = complete_doc()
        for p in doc["perspectives"]:
            if p["name"] == "Domain model and data ownership":
                p.update(status="not checked", note="no access")
        doc["findings"][1]["validation"].update(verdict="NotApplicable", evidence="dead.py:1")
        self.build(doc)
        problems = findings.contract_problems(self.out)
        self.assertEqual([p.split(":")[0] for p in problems], ["A-001"], problems)

    def test_high_and_medium_findings_need_evidence(self):
        for severity in ("High", "Medium"):
            with self.subTest(severity=severity):
                doc = complete_doc()
                doc["findings"][0].update(severity=severity,
                                          validation={"verdict": "Unverified", "method": "static"})
                self.build(doc)
                problems = findings.contract_problems(self.out)
                self.assertTrue(any("A-001" in p and "evidence" in p for p in problems), problems)
        doc = complete_doc()
        doc["findings"][1]["validation"] = {"verdict": "Unverified", "method": "static"}
        self.build(doc)
        self.assertEqual(findings.contract_problems(self.out), [])

    def test_definitive_evidence_cites_a_line(self):
        doc = complete_doc()
        doc["findings"][0]["validation"]["evidence"] = "trust me"
        self.build(doc)
        problems = findings.contract_problems(self.out)
        self.assertTrue(any("A-001" in p and "path:line" in p for p in problems), problems)
        doc = complete_doc()
        doc["findings"][1]["validation"].update(verdict="FalsePositive", evidence="delegates")
        self.build(doc)
        problems = findings.contract_problems(self.out)
        self.assertTrue(any("A-002" in p and "path:line" in p for p in problems), problems)

    def test_outputs_rendered_before_the_last_merge_are_stale(self):
        target = self.build(complete_doc())
        self.assertEqual(findings.contract_problems(self.out), [])
        fragment = self.out.parent / f"{self.out.name}-fragment.json"
        self.addCleanup(fragment.unlink, missing_ok=True)
        fragment.write_text(json.dumps({"limitations": ["added after rendering"]}), encoding="utf-8")
        with redirect_stdout(io.StringIO()):
            self.assertEqual(findings.main(["merge", str(target), str(fragment)]), 0)
        problems = findings.contract_problems(self.out)
        self.assertEqual(sorted(p.split()[0] for p in problems), ["dashboard.html", "report.md"])
        with redirect_stdout(io.StringIO()):
            render.main([str(target), "--out", str(self.out)])
        self.assertEqual(findings.contract_problems(self.out), [])

    def test_hand_edited_output_is_named(self):
        self.build(complete_doc(), "--lang", "ja")
        report = self.out / "report.md"
        report.write_bytes(report.read_bytes() + b"\nedited\n")
        self.assertEqual([p.split()[0] for p in findings.contract_problems(self.out)],
                         ["report.md"])

    def test_either_language_passes_when_both_outputs_agree(self):
        for lang in ("ja", "en"):
            with self.subTest(lang=lang):
                self.build(complete_doc(), "--lang", lang)
                self.assertEqual(findings.contract_problems(self.out), [])

    def test_missing_output_directory_is_one_clear_problem(self):
        problems = findings.contract_problems(self.out / "absent")
        self.assertEqual(len(problems), 1)
        self.assertIn("not a directory", problems[0])

    def test_merge_creates_the_output_directory(self):
        fragment = self.out / "fragment.json"
        fragment.write_text(json.dumps({"findings": [finding()]}), encoding="utf-8")
        target = self.out / "new" / "findings.json"
        with redirect_stdout(io.StringIO()):
            self.assertEqual(findings.main(["merge", str(target), str(fragment)]), 0)
        self.assertEqual(findings.read_json(target)["findings"][0]["id"], "A-001")


class RenderConsistencyTests(unittest.TestCase):
    def test_report_names_each_finding_perspective_and_step(self):
        doc = complete_doc()
        del doc["findings"][1]["step"]
        for lang in ("en", "ja"):
            with self.subTest(lang=lang):
                label = render.LABELS[lang]["category"]
                markdown = render.render_markdown(doc, lang)
                self.assertIn(f"- **{label}:** Domain model and data ownership (DM1)\n", markdown)
                self.assertIn(f"- **{label}:** Domain model and data ownership\n", markdown)
                self.assertIn("(DM1)", render.render_html(doc, lang))

    def test_table_headers_are_localized_in_both_outputs(self):
        doc = complete_doc()
        markdown = render.render_markdown(doc, "ja")
        self.assertIn("| ID | ルール | 根拠 | 状態 |", markdown)
        self.assertIn("| 観点 | 状態 | メモ |", markdown)
        self.assertNotIn("| Source |", markdown)
        html = render.render_html(doc, "ja")
        self.assertIn("<th>ルール</th>", html)
        self.assertIn("<th>観点</th>", html)

    def test_both_outputs_list_perspectives_in_reference_order_with_gaps(self):
        doc = complete_doc()
        doc["perspectives"] = list(reversed(doc["perspectives"]))[:-1]
        missing = findings.PERSPECTIVES[0]
        markdown = render.render_markdown(doc, "en")
        rows = re.findall(r"^\| ([A-Z][^|]+?) \| (\S+) \|", markdown.split("## Perspective coverage")[1],
                          re.MULTILINE)
        self.assertEqual(tuple(name for name, _ in rows[1:]), findings.PERSPECTIVES)
        self.assertEqual(rows[1], (missing, "—"))
        html = render.render_html(doc, "en")
        self.assertIn(f"<tr><td>{missing}</td><td>—</td><td>not recorded</td></tr>", html)

    def test_blank_commit_and_method_fall_back(self):
        doc = complete_doc()
        doc["meta"].update(commit="  ", method=" \n")
        markdown = render.render_markdown(doc, "en")
        self.assertIn("| Revision | UNKNOWN |", markdown)
        self.assertIn(render.LABELS["en"]["static_note"], markdown)
        self.assertIn(" · UNKNOWN · ", render.render_html(doc, "en"))

    def test_only_web_references_become_links(self):
        doc = complete_doc()
        doc["findings"][0]["references"] = [
            {"title": "ADR <4>", "url": "https://example.com/adr?a=1&b='2'"},
            {"url": "javascript:alert(1)"},
            {"url": "HTTP://EXAMPLE.COM/x"},
            {"url": "https://example.com/a b"},
            {"url": "docs/adr/0004.md"},
        ]
        html = render.render_html(doc, "en")
        hrefs = re.findall(r"<a href='([^']*)'", html)
        self.assertEqual(hrefs, ["https://example.com/adr?a=1&amp;b=&#x27;2&#x27;",
                                 "HTTP://EXAMPLE.COM/x"])
        self.assertIn("ADR &lt;4&gt;: https://example.com/adr", html)
        self.assertIn("javascript:alert(1)", html)
        self.assertNotIn("href='javascript", html)

    def test_dashboard_policy_allows_only_its_own_style_and_script(self):
        html = render.render_html(complete_doc(), "en")
        policy = re.search(r"Content-Security-Policy' content=\"([^\"]+)\"", html)[1]
        self.assertIn("default-src 'none'", policy)
        for tag in ("style", "script"):
            body = re.search(rf"<{tag}>(.*?)</{tag}>", html, re.DOTALL)[1]
            digest = base64.b64encode(hashlib.sha256(body.encode("utf-8")).digest()).decode()
            self.assertIn(f"{tag}-src 'sha256-{digest}'", policy)

    def test_excluded_findings_are_marked_in_the_dashboard(self):
        doc = complete_doc()
        doc["findings"][1]["validation"].update(verdict="FalsePositive", evidence="delegates")
        html = render.render_html(doc, "en")
        self.assertEqual(html.count("class='excluded'"), 1)
        self.assertIn("<details data-sev='Low' class='excluded'>", html)

    def test_list_items_cannot_open_markdown_blocks(self):
        items = {
            "[Confirmed]: https://evil.example/x": "&#91;Confirmed]: https://evil.example/x",
            "---": "&#45;--", "***": "&#42;**", "# Not a heading": "&#35; Not a heading",
            "1) numbered": "1&#41; numbered", "12. twelve": "12&#46; twelve",
            "[x] looks done": "&#91;x] looks done", "    indented": "&#32;&#32;&#32;&#32;indented",
            "+ plus": "&#43; plus", "~~~": "&#126;~~", "=": "&#61;",
            "plain [link](https://a.example)": "plain [link](https://a.example)",
        }
        doc = complete_doc()
        doc["checked_ok"] = list(items)
        markdown = render.render_markdown(doc, "en")
        for expected in items.values():
            self.assertIn(f"\n- {expected}\n", markdown)

    def test_unclosed_backtick_fence_is_encoded(self):
        self.assertTrue(render.block_safe(render.markdown_inline("```")).startswith("&#96;"))
        self.assertEqual(render.block_safe(render.markdown_inline("`x`")), render.markdown_code("x"))

    def test_text_after_a_label_keeps_its_numbering_readable(self):
        doc = complete_doc()
        doc["findings"][0]["trace"] = "1. job.py:58 updates invoices"
        self.assertIn("- **trace:** 1. job.py:58", render.render_markdown(doc, "en"))

    def test_heading_keeps_a_trailing_hash(self):
        doc = complete_doc()
        doc["meta"]["project"] = "Proj ##"
        doc["findings"][0]["title"] = "Uses C #"
        markdown = render.render_markdown(doc, "en")
        self.assertIn("# Architecture assessment: Proj #&#35;\n", markdown)
        self.assertIn("[Valid] Uses C &#35;\n", markdown)

    def test_report_links_only_safe_reference_targets(self):
        doc = complete_doc()
        doc["findings"][0]["references"] = [
            {"url": "javascript:alert(1)"}, {"title": "data", "url": " data:text/html,x"},
            {"title": "ADR", "url": "docs/adr/1.md"}, {"url": "https://example.com/a"}]
        markdown = render.render_markdown(doc, "en")
        self.assertNotIn("(<javascript", markdown)
        self.assertNotIn("(< data", markdown)
        self.assertIn(render.markdown_code("javascript:alert(1)"), markdown)
        self.assertIn("data: " + render.markdown_code(" data:text/html,x"), markdown)
        self.assertIn("[ADR](<docs/adr/1.md>)", markdown)
        self.assertIn("(<https://example.com/a>)", markdown)

    def test_title_names_the_project(self):
        self.assertIn("<title>Architecture assessment: demo</title>",
                      render.render_html(complete_doc(), "en"))

    def test_unwritable_output_exits_1_and_keeps_previous_files(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            target = tmp / "findings.json"
            target.write_text(json.dumps(complete_doc()), encoding="utf-8")
            blocker = tmp / "out"
            blocker.write_text("a file, not a directory", encoding="utf-8")
            errors = io.StringIO()
            with redirect_stdout(io.StringIO()), redirect_stderr(errors):
                self.assertEqual(render.main([str(target), "--out", str(blocker)]), 1)
            self.assertIn("write failed", errors.getvalue())
            self.assertEqual(blocker.read_text(encoding="utf-8"), "a file, not a directory")
            out = tmp / "rendered"
            with redirect_stdout(io.StringIO()):
                self.assertEqual(render.main([str(target), "--out", str(out)]), 0)
            self.assertEqual(sorted(p.name for p in out.iterdir()), ["dashboard.html", "report.md"])

    def test_render_keeps_symlinked_outputs_and_their_mode(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            target = tmp / "findings.json"
            target.write_text(json.dumps(complete_doc()), encoding="utf-8")
            out, real = tmp / "out", tmp / "real.md"
            out.mkdir()
            real.write_text("old", encoding="utf-8")
            real.chmod(0o640)
            (out / "report.md").symlink_to(real)
            with redirect_stdout(io.StringIO()):
                self.assertEqual(render.main([str(target), "--out", str(out)]), 0)
            self.assertTrue((out / "report.md").is_symlink())
            self.assertIn("# Architecture assessment", real.read_text(encoding="utf-8"))
            self.assertEqual(real.stat().st_mode & 0o777, 0o640)

    def test_outputs_use_lf_line_endings(self):
        data = render.rendered_outputs(complete_doc(), "en")["report.md"]
        self.assertNotIn(b"\r\n", data)
        self.assertTrue(data.endswith(b"\n"))


if __name__ == "__main__":
    unittest.main()
