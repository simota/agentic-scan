"""Regression checks for literal record content and complete budget output."""
from contextlib import redirect_stdout
from copy import deepcopy
from html.parser import HTMLParser
import importlib.util
import io
import json
from pathlib import Path
import re
import tempfile
import unittest
from xml.etree.ElementTree import Element, SubElement


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


class HtmlTreeReader(HTMLParser):
    """Read rendered elements and decoded text without a browser dependency."""
    VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link",
            "meta", "param", "source", "track", "wbr"}

    def __init__(self, html):
        super().__init__()
        self.root = Element("document")
        self.stack = [self.root]
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        element = SubElement(self.stack[-1], tag, dict(attrs))
        if tag not in self.VOID:
            self.stack.append(element)

    def handle_endtag(self, tag):
        for i in range(len(self.stack) - 1, 0, -1):
            if self.stack[i].tag == tag:
                del self.stack[i:]
                break

    def handle_data(self, data):
        element = self.stack[-1]
        if len(element):
            element[-1].tail = (element[-1].tail or "") + data
        else:
            element.text = (element.text or "") + data


def element_text(element):
    return "".join(element.itertext())


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
        self.assertEqual(budget.count("|"), 8)
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
        self.assertIn("- **workload:** https&#58;//example.test www&#46;example.test a@<!-- -->example.test", report)

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

    def test_html_measurement_keeps_an_exact_separate_command_block(self):
        command = "python - <<'PY'\n  print('<script>bad()</script> & `')\n\nPY\n"
        finding = self.doc["findings"][0]
        finding["validation"]["method"] = "measured"
        finding["measurement"] = {
            "result": "1 < 2\nresult marker",
            "environment": "local\n<throwaway>",
            "command": command,
        }
        render.validate(self.doc, complete=True)
        for lang in ("ja", "en"):
            with self.subTest(lang=lang):
                root = HtmlTreeReader(render.render_html(self.doc, lang)).root
                codes = root.findall(".//details/dl/dd/pre/code")
                self.assertEqual(len(codes), 1)
                self.assertEqual(element_text(codes[0]), command)
                cells = [element_text(dd) for dd in root.findall(".//details/dl/dd")]
                self.assertIn(finding["measurement"]["result"], cells)
                self.assertIn(finding["measurement"]["environment"], cells)
                self.assertIn(command, cells)
                self.assertEqual(len(root.findall(".//script")), 1)

    def test_html_plain_text_preserves_line_breaks_without_creating_markup(self):
        self.doc["meta"]["project"] = "Project\n<script>bad()</script>"
        self.doc["meta"]["scope"] = "API\nworker"
        self.doc["findings"][0]["title"] = "Title\n<b>literal</b>"
        self.doc["findings"][0]["request"] = "1. Create fixtures\n2. GET /api/orders"
        self.doc["findings"][0]["validation"]["evidence"] = "First trace\n<pre>literal</pre>"
        self.doc["budgets"][0]["source"] = "baseline\nsource marker"
        self.doc["limitations"] = ["First line\n<img src=x onerror=bad()>"]
        render.validate(self.doc, complete=True)
        for lang in ("ja", "en"):
            with self.subTest(lang=lang):
                root = HtmlTreeReader(render.render_html(self.doc, lang)).root
                styles = element_text(root.find(".//style"))
                preserves_lines = set()
                for selectors, declarations in re.findall(r"([^{}]+)\{([^{}]*)\}", styles):
                    if re.search(r"white-space\s*:\s*(?:pre-wrap|pre-line|pre|break-spaces)\b",
                                 declarations):
                        preserves_lines.update(selector.strip() for selector in selectors.split(","))
                for tag in ("h1", "p", "summary", "dd", "td", "li"):
                    self.assertIn(tag, preserves_lines, f"{tag} must display recorded line breaks")
                cells = [element_text(dd) for dd in root.findall(".//details/dl/dd")]
                self.assertIn(self.doc["findings"][0]["request"], cells)
                self.assertIn(self.doc["findings"][0]["validation"]["evidence"], cells)
                self.assertEqual(len(root.findall(".//script")), 1)
                self.assertEqual(root.findall(".//img"), [])
                self.assertEqual(root.findall(".//pre"), [])

    def test_html_severity_filters_match_counts_and_mark_excluded_summaries(self):
        base = self.doc["findings"][0]
        cases = [("High", "Valid"), ("Medium", "Likely"), ("Low", "Unverified"),
                 ("Info", "Unlikely"), ("High", "FalsePositive"), ("Medium", "NotApplicable")]
        records = []
        for i, (severity, verdict) in enumerate(cases, 1):
            finding = deepcopy(base)
            finding.update(id=f"P-{i:03d}", title=f"Finding {i}", severity=severity)
            finding["validation"]["verdict"] = verdict
            records.append(finding)
        for selected in (records, records[-2:], []):
            self.doc["findings"] = selected
            render.validate(self.doc, complete=True)
            for lang, excluded_label in (("ja", "除外"), ("en", "Excluded")):
                with self.subTest(lang=lang, findings=len(selected)):
                    root = HtmlTreeReader(render.render_html(self.doc, lang)).root
                    buttons = {button.get("data-filter"): element_text(button)
                               for button in root.findall(".//button")}
                    self.assertEqual(set(buttons), {"all", "High", "Medium", "Low", "Info", "excluded"})
                    self.assertEqual(buttons["excluded"], excluded_label)
                    cards = {element_text(card.find("span")): int(card.findtext("b"))
                             for card in root.findall(".//div[@class='card']")}
                    details = root.findall(".//details")
                    self.assertEqual(len(details), len(selected))
                    for severity in ("High", "Medium", "Low", "Info"):
                        expected = 1 if selected is records else 0
                        self.assertEqual(cards[severity], expected)
                        self.assertEqual(sum(d.get("data-sev") == severity for d in details), expected)
                    expected_excluded = 2 if selected else 0
                    self.assertEqual(cards[excluded_label], expected_excluded)
                    self.assertEqual(sum(d.get("data-sev") == "excluded" for d in details), expected_excluded)
                    for detail, finding in zip(details, selected):
                        if finding["validation"]["verdict"] in ("FalsePositive", "NotApplicable"):
                            summary = element_text(detail.find("summary"))
                            self.assertIn(excluded_label, summary)
                            self.assertIn(finding["validation"]["verdict"], summary)

    def test_html_references_escape_link_attributes_and_keep_title_fallback(self):
        references = [
            {"title": "Docs [v2] <guide>\n![fake](x)",
             "url": "https://example.test/a(b)>c?x=one two&y=<n>&q='\" onmouseover=\"bad()"},
            {"url": "mailto:person@example.test"},
            {"title": "Local document", "url": "docs/performance notes.md#counters"},
        ]
        self.doc["findings"][0]["references"] = references
        render.validate(self.doc, complete=True)
        expected_urls = [
            "https://example.test/a%28b%29%3Ec?x=one%20two&y=%3Cn%3E&q='%22%20onmouseover=%22bad%28%29",
            "mailto:person@example.test", "docs/performance%20notes.md#counters",
        ]
        for lang in ("ja", "en"):
            with self.subTest(lang=lang):
                root = HtmlTreeReader(render.render_html(self.doc, lang)).root
                links = root.findall(".//details/dl/dd/a")
                self.assertEqual(len(links), len(references))
                self.assertEqual([link.attrib for link in links], [{"href": url} for url in expected_urls])
                self.assertEqual([element_text(link) for link in links],
                                 [ref.get("title", ref["url"]) for ref in references])
                self.assertEqual(len(root.findall(".//script")), 1)
                self.assertEqual(root.findall(".//img"), [])

    def test_html_unsafe_or_malformed_references_are_visible_without_links(self):
        references = [
            {"title": "Unsafe", "url": "javascript:alert(1)"},
            {"title": "Mixed case", "url": "JaVaScRiPt:alert(1)"},
            {"title": "Control character", "url": "java\nscript:alert(1)"},
            {"title": "Malformed", "url": "https://[bad"},
            {"title": "Data", "url": "data:text/html,<script>bad()</script>"},
            {"title": "VBScript", "url": "vbscript:msgbox(1)"},
        ]
        self.doc["findings"][0]["references"] = references
        render.validate(self.doc, complete=True)
        for lang in ("ja", "en"):
            with self.subTest(lang=lang):
                root = HtmlTreeReader(render.render_html(self.doc, lang)).root
                self.assertEqual(root.findall(".//a"), [])
                cells = [element_text(dd) for dd in root.findall(".//details/dl/dd")]
                for ref in references:
                    self.assertIn(f"{ref['title']} ({ref['url']})", cells)
                self.assertEqual(len(root.findall(".//script")), 1)

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
                self.assertEqual(len(rows), len(self.doc["budgets"]))
                self.assertTrue(all(line.count("|") == 8 for line in rows))
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
                self.assertEqual(budgets["B-03"][4:6], [yes, reason])
                self.assertNotIn("<script>bad()</script>", dashboard)


if __name__ == "__main__":
    unittest.main()
