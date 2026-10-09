"""Regression checks for literal record content and complete budget output."""
from contextlib import redirect_stdout
from html.parser import HTMLParser
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "perf_render_regressions", ROOT / "skills" / "performance-scan" / "scripts" / "render.py")
render = importlib.util.module_from_spec(spec)
spec.loader.exec_module(render)


class HtmlTableReader(HTMLParser):
    def __init__(self):
        super().__init__()
        self.rows = []
        self.tags = []
        self.row = []
        self.cell = None

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        if tag == "tr":
            self.row = []
        if tag in ("td", "th"):
            self.cell = ""

    def handle_data(self, data):
        if self.cell is not None:
            self.cell += data

    def handle_endtag(self, tag):
        if tag in ("td", "th"):
            self.row.append(self.cell)
            self.cell = None
        if tag == "tr":
            self.rows.append(self.row)


class RenderRegressions(unittest.TestCase):
    def setUp(self):
        self.doc = json.loads((ROOT / "examples" / "findings.sample.json").read_text(encoding="utf-8"))

    def test_sample_request_placeholders_remain_literal(self):
        report = render.render_markdown(self.doc, "en")
        self.assertIn("GET /api/orders?page=&lt;n&gt;", report)
        self.assertIn("GET /api/orders/&lt;id&gt;", report)
        self.assertIn("GET /admin/products?sku=&lt;sku&gt;", report)
        self.assertNotIn("<n>", report)
        self.assertNotIn("<sku>", report)

    def test_table_data_cannot_change_columns_or_create_blocks(self):
        self.doc["meta"]["scope"] = "API | worker\r\n# forged scope"
        self.doc["budgets"][0]["source"] = "baseline | tests/query.py:30\n| forged | row |"
        self.doc["budgets"][0]["statement"] = r"p95 < 200 ms; literal \| and &lt;"
        self.doc["perspectives"][0]["note"] = "DB1 | DB2\r---"
        report = render.render_markdown(self.doc, "en")

        scope = next(line for line in report.splitlines() if line.startswith("| Scope |"))
        self.assertEqual(scope.count("|"), 3)
        self.assertIn("API &#124; worker<br>\\# forged scope", scope)
        budget = next(line for line in report.splitlines() if line.startswith("| B-01 |"))
        self.assertEqual(budget.count("|"), 7)
        self.assertIn("baseline &#124; tests/query.py:30<br>&#124; forged &#124; row &#124;", budget)
        self.assertIn(r"literal \\&#124; and &amp;lt;", budget)
        self.assertIn(" | violated | ", budget)
        coverage = next(line for line in report.splitlines() if line.startswith("| Database access |"))
        self.assertEqual(coverage.count("|"), 4)
        self.assertIn("DB1 &#124; DB2<br>\\---", coverage)
        self.assertNotIn("\n# forged scope", report)
        self.assertNotIn("\n| forged", report)

    def test_titles_evidence_and_lists_cannot_add_markup(self):
        self.doc["meta"]["project"] = "demo\n# forged project"
        finding = self.doc["findings"][0]
        finding["title"] = "**bold** [click](https://example.test)\n### forged finding"
        finding["validation"]["evidence"] = "<script>bad()</script> & <n>"
        finding["workload"] = "a_backtick` and ~~strike~~"
        self.doc["limitations"] = ["first\n- forged item\n<!-- hidden -->"]
        report = render.render_markdown(self.doc, "en")

        self.assertIn(r"\*\*bold\*\* \[click\](https&#58;//example.test)", report)
        self.assertIn("<br>\\#\\#\\# forged finding", report)
        self.assertIn("&lt;script&gt;bad()&lt;/script&gt; &amp; &lt;n&gt;", report)
        self.assertIn(r"a\_backtick\` and \~\~strike\~\~", report)
        self.assertIn("first<br>\\- forged item<br>&lt;\\!-- hidden --&gt;", report)
        self.assertNotIn("\n# forged project", report)
        self.assertNotIn("\n### forged finding", report)
        self.assertNotIn("\n- forged item", report)
        self.assertNotIn("<script>", report)
        self.assertNotIn("<!-- hidden -->", report)

    def test_plain_text_list_items_cannot_become_nested_blocks(self):
        self.doc["checked_ok"] = ["- nested", "+ nested", "1. numbered", "2) numbered",
                                  "---", "    indented code", "\tindented code", "- [ ] task"]
        report = render.render_markdown(self.doc, "en")
        checked = report.split("## Checked and sound\n\n", 1)[1].split("\n\n", 1)[0]
        self.assertEqual(checked.splitlines(), [
            r"- \- nested", r"- \+ nested", r"- 1\. numbered", r"- 2\) numbered",
            r"- \---", "- &#32;&#32;&#32;&#32;indented code", "- &#9;indented code",
            r"- \- \[ \] task",
        ])

    def test_reference_labels_and_urls_use_separate_escaping(self):
        self.doc["findings"][0]["references"] = [{
            "title": "Docs [v2] <guide>\n![fake](x)",
            "url": "https://example.test/a(b)>c?x=one two&y=<n>",
        }]
        report = render.render_markdown(self.doc, "en")
        reference = next(line for line in report.splitlines() if line.startswith("- **references:**"))
        self.assertEqual(reference, "- **references:** [Docs \\[v2\\] &lt;guide&gt;<br>"
                         "\\!\\[fake\\](x)](<https://example.test/a%28b%29%3Ec?"
                         "x=one%20two&amp;y=%3Cn%3E>)")

    def test_plain_text_urls_do_not_use_gfm_autolinks(self):
        self.doc["findings"][0]["workload"] = "https://example.test www.example.test a@example.test"
        report = render.render_markdown(self.doc, "en")
        self.assertIn("- **workload:** https&#58;//example.test www&#46;example.test a&#64;example.test", report)

    def test_unsafe_or_malformed_urls_stay_visible_without_active_links(self):
        self.doc["findings"][0]["references"] = [
            {"title": "Unsafe", "url": "javascript:alert(1)"},
            {"title": "Malformed", "url": "https://[bad"},
            {"title": "Data", "url": "data:text/html,<script>bad()</script>"},
        ]
        report = render.render_markdown(self.doc, "en")
        references = [line for line in report.splitlines() if line.startswith("- **references:**")]
        self.assertEqual(len(references), 3)
        self.assertIn("Unsafe (javascript:alert(1))", references[0])
        self.assertIn(r"Malformed (https&#58;//\[bad)", references[1])
        self.assertIn("Data (data:text/html,&lt;script&gt;bad()&lt;/script&gt;)", references[2])
        self.assertTrue(all("](" not in line for line in references))

    def test_measurement_command_keeps_backticks_and_line_breaks(self):
        finding = self.doc["findings"][0]
        finding["validation"]["method"] = "measured"
        finding["measurement"] = {
            "result": "1 < 2 & **literal**",
            "environment": "local\n<throwaway>",
            "command": "printf '`<n>`'\n# not a heading\n\n`",
        }
        report = render.render_markdown(self.doc, "en")
        measurement = next(line for line in report.splitlines() if line.startswith("- **measurement:**"))
        self.assertEqual(measurement, "- **measurement:** 1 &lt; 2 &amp; \\*\\*literal\\*\\* "
                         "(``printf '`<n>`'``<br>`# not a heading`<br><br>`` ` ``, "
                         "local<br>&lt;throwaway&gt;)")
        self.assertNotIn("\n# not a heading", report)

    def test_code_delimiters_do_not_remove_command_edge_spaces(self):
        finding = self.doc["findings"][0]
        finding["validation"]["method"] = "measured"
        finding["measurement"] = {"result": "ok", "environment": "local", "command": ""}
        for command, expected in (
            ("  command  ", "`   command   `"),
            ("  command", "`  command`"),
            ("command  ", "`command  `"),
            ("print('``')", "```print('``')```"),
            ("`command`", "`` `command` ``"),
        ):
            with self.subTest(command=command):
                finding["measurement"]["command"] = command
                report = render.render_markdown(self.doc, "en")
                self.assertIn(f"- **measurement:** ok ({expected}, local)", report)

    def test_cli_preserves_budget_reason_and_inference_in_both_languages(self):
        reason = "Supplier API | <latency> is unknown\nConfirm the contract"
        self.doc["budgets"][2]["reason"] = reason
        self.doc["budgets"][1].pop("inferred")
        self.doc["findings"][0]["title"] = "<script>bad()</script>"
        for lang, yes, no, reason_label in (
            ("en", "Yes — confirm with owner", "No", "Reason not checked"),
            ("ja", "推定・要確認", "いいえ", "未確認の理由"),
        ):
            with self.subTest(lang=lang), tempfile.TemporaryDirectory() as directory:
                out = Path(directory)
                source = out / "findings.json"
                source.write_text(json.dumps(self.doc), encoding="utf-8")
                with redirect_stdout(io.StringIO()):
                    self.assertEqual(render.main([str(source), "--out", str(out), "--lang", lang]), 0)
                report = (out / "report.md").read_text(encoding="utf-8")
                dashboard = (out / "dashboard.html").read_text(encoding="utf-8")
                self.assertIn(reason_label, report)
                self.assertIn("Supplier API &#124; &lt;latency&gt; is unknown<br>Confirm the contract", report)
                rows = [line for line in report.splitlines() if line.startswith("| B-")]
                self.assertEqual(len(rows), 3)
                self.assertTrue(all(line.count("|") == 7 for line in rows))
                self.assertIn(f" | {no} | ", rows[0])
                self.assertIn(" | — | ", rows[1])
                self.assertIn(f" | {yes} | ", rows[2])

                parsed = HtmlTableReader()
                parsed.feed(dashboard)
                self.assertEqual(parsed.tags.count("script"), 1)  # Only the dashboard's own filter script.
                self.assertIn(reason_label, parsed.rows[0])
                budgets = {row[0]: row for row in parsed.rows if row and row[0].startswith("B-")}
                self.assertEqual(budgets["B-01"][4], no)
                self.assertEqual(budgets["B-02"][4], "—")
                self.assertEqual(budgets["B-03"][4:], [yes, reason])
                self.assertNotIn("<script>bad()</script>", dashboard)


if __name__ == "__main__":
    unittest.main()
