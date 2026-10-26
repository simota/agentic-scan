"""Regression checks for literal record content and complete budget output."""
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import io
import json
from pathlib import Path
import re
import tempfile
import unittest

from support import REPO, HtmlTableReader, HtmlTreeReader, complete_doc, element_text, render


class RenderRegressions(unittest.TestCase):
    def setUp(self):
        self.doc = json.loads((REPO / "examples" / "findings.sample.json").read_text(encoding="utf-8"))

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
        self.assertEqual(budget.count("|"), 9)
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

    def measure(self, before, after=None):
        finding = self.doc["findings"][0]
        finding["validation"]["method"] = "measured"
        finding["measurement"] = {"environment": "local\n<throwaway>", "before": before,
                                  "after": after or {"command": "c", "result": "ok", "log": "l"}}
        return finding

    def test_measurement_command_keeps_backticks_and_line_breaks(self):
        self.measure({"result": "1 < 2 & **literal**", "log": "l",
                      "command": "printf '`<n>`'\n# not a heading\n\n`"})
        report = render.render_markdown(self.doc, "en")
        lines = report.splitlines()
        at = lines.index("- **measurement:** local<br>&lt;throwaway&gt;")
        self.assertEqual(lines[at + 1], "  - **before:** 1 &lt; 2 &amp; \\*\\*literal\\*\\* "
                         "(``printf '`<n>`'``<br>`# not a heading`<br><br>`` ` ``)")
        self.assertNotIn("\n# not a heading", report)

    def test_code_delimiters_do_not_remove_command_edge_spaces(self):
        finding = self.measure({"result": "ok", "command": "", "log": "l"})
        for command, expected in (
            ("  command  ", "`   command   `"),
            ("  command", "`  command`"),
            ("command  ", "`command  `"),
            ("print('``')", "```print('``')```"),
            ("`command`", "`` `command` ``"),
        ):
            with self.subTest(command=command):
                finding["measurement"]["before"]["command"] = command
                report = render.render_markdown(self.doc, "en")
                self.assertIn(f"  - **before:** ok ({expected})", report)

    def test_markdown_log_is_a_literal_fence_inside_the_finding(self):
        log = "```\n# not a heading\n<script>bad()</script>\n\n- not a list"
        self.measure({"command": "c", "result": "ok", "log": log})
        lines = render.render_markdown(self.doc, "en").splitlines()
        at = lines.index("    ````text")
        self.assertEqual(lines[at + 1:at + 7], ["    ```", "    # not a heading",
                                                "    <script>bad()</script>", "", "    - not a list",
                                                "    ````"])
        self.assertEqual(lines[at - 1].split(":**")[0], "  - **before")
        self.assertTrue(lines[at + 7].startswith("  - **after:** ok"))

    def test_html_measurement_keeps_exact_separate_command_and_log_blocks(self):
        command = "python - <<'PY'\n  print('<script>bad()</script> & `')\n\nPY\n"
        log = "orders=50 queries=52\n<b>raw</b> & `"
        finding = self.measure({"result": "1 < 2\nresult marker", "command": command, "log": log},
                               {"result": "after marker", "command": "after-cmd", "log": "after-log"})
        render.validate(self.doc, complete=True)
        for lang in ("ja", "en"):
            with self.subTest(lang=lang):
                root = HtmlTreeReader(render.render_html(self.doc, lang)).root
                codes = [element_text(code) for code in root.findall(".//details/dl/dd/pre/code")]
                self.assertEqual(codes, [command, log, "after-cmd", "after-log"])
                cells = [element_text(dd) for dd in root.findall(".//details/dl/dd")]
                for value in ("1 < 2\nresult marker", "after marker",
                              finding["measurement"]["environment"]):
                    self.assertIn(value, cells)
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
                for tag in ("h1", "p", "summary", "dd", "td", ".lists li"):
                    self.assertIn(tag, preserves_lines, f"{tag} must display recorded line breaks")
                cells = [element_text(dd) for dd in root.findall(".//details/dl/dd")]
                self.assertIn(self.doc["findings"][0]["request"], cells)
                self.assertIn(self.doc["findings"][0]["validation"]["evidence"], cells)
                self.assertEqual(len(root.findall(".//script")), 1)
                self.assertEqual(root.findall(".//img"), [])
                self.assertEqual(root.findall(".//pre"), [])

    def test_contents_links_keep_the_kits_single_line(self):
        # The kit lays the contents out as one scrolling row on narrow screens
        # (white-space:nowrap); a bare li rule broke "Summary" into "Sum/mar/y".
        root = HtmlTreeReader(render.render_html(self.doc, "en")).root
        styles = element_text(root.find(".//style"))
        own = re.sub(r"/\*.*?\*/", "", styles[len(render.kit_style.dashboard_css()):], flags=re.S)
        for selectors, declarations in re.findall(r"([^{}]+)\{([^{}]*)\}", own):
            if re.search(r"white-space|overflow-wrap|word-break", declarations):
                for selector in selectors.split(","):
                    self.assertNotIn(selector.strip(), ("li", "a", "ol"),
                                     "scope list rules to record text such as .lists li")
        self.assertTrue(root.findall(".//nav[@id='nav']/ol/li/a"))
        self.assertFalse(root.findall(".//*[@class='lists']//nav"))

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
                               for button in root.findall(".//button[@data-filter]")}
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
                self.assertEqual(root.findall(".//details//a"), [])
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
            ("en", "Yes — confirm with owner", "No", "Reason (partly read or not checked)"),
            ("ja", "推定・要確認", "いいえ", "未確認・一部確認の理由"),
        ):
            with self.subTest(lang=lang), tempfile.TemporaryDirectory() as directory:
                out = Path(directory)
                source = out / "findings.json"
                source.write_text(json.dumps(self.doc), encoding="utf-8")
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    self.assertEqual(render.main([str(source), "--out", str(out), "--lang", lang]), 0)
                report = (out / "report.md").read_text(encoding="utf-8")
                dashboard = (out / "dashboard.html").read_text(encoding="utf-8")
                self.assertIn(reason_label, report)
                self.assertIn("Supplier API &#124; &lt;latency&gt; is unknown<br>Confirm the contract", report)
                rows = [line for line in report.splitlines() if line.startswith("| B-")]
                self.assertEqual(len(rows), len(self.doc["budgets"]))
                self.assertTrue(all(line.count("|") == 9 for line in rows))
                self.assertIn(f" | {no} | ", rows[0])
                self.assertIn(" | — | ", rows[1])
                self.assertIn(f" | {yes} | ", rows[2])

                parsed = HtmlTableReader()
                parsed.feed(dashboard)
                self.assertEqual(parsed.tags.count("script"), 1)  # Only the dashboard's own filter script.
                self.assertIn(reason_label, parsed.rows[0])
                budgets = {row[0]: row for row in parsed.rows if row and row[0].startswith("B-")}
                self.assertEqual(budgets["B-01"][5], no)
                self.assertEqual(budgets["B-02"][5], "—")
                self.assertEqual(budgets["B-03"][5:7], [yes, reason])
                self.assertNotIn("<script>bad()</script>", dashboard)



class RenderRoundEightTests(unittest.TestCase):
    def setUp(self):
        self.doc = complete_doc()

    def test_reference_urls_are_normalised_before_linking(self):
        for url in (" https://example.com/doc", "https://example.com/doc\n", "https://exa\tmple.com/doc"):
            with self.subTest(url=repr(url)):
                destination = render.link_destination(url)
                self.assertTrue(destination.startswith("https://exa"), destination)
                self.assertNotIn("%", destination)
        self.assertEqual(render.link_destination(" docs/a.md"), "%20docs/a.md")
        self.assertEqual(render.link_destination("docs/a\tb.md"), "docs/a%09b.md")

    def test_an_invisible_reference_title_falls_back_to_the_url(self):
        for title in ("​", "⁠﻿", "­ ", "  "):
            with self.subTest(title=repr(title)):
                ref = {"title": title, "url": "https://example.com/"}
                self.assertEqual(render.reference_title(ref), "https://example.com/")
        self.assertEqual(render.reference_title({"title": "Docs​", "url": "u"}), "Docs​")

    def test_budget_family_is_shown(self):
        self.doc["budgets"][0]["family"] = "QRY"
        self.assertIn("| B-01 | QRY |", render.render_markdown(self.doc, "en"))
        self.assertIn("<td>QRY</td>", render.render_html(self.doc, "en"))

    def test_blank_evidence_is_hidden(self):
        self.doc["findings"][1]["validation"] = {"verdict": "Likely", "method": "static", "evidence": "   "}
        report = render.render_markdown(self.doc, "en")
        dashboard = render.render_html(self.doc, "en")
        self.assertNotIn("**evidence:** &#32;", report)
        self.assertNotIn("<dt>evidence</dt><dd>   </dd>", dashboard)

    def test_dashboard_shows_one_location_per_line(self):
        self.doc["findings"][0]["location"] = ["a.py:1", "b.py:2"]
        self.assertIn("<dd>a.py:1\nb.py:2</dd>", render.render_html(self.doc, "en"))

    def test_html_lang_follows_the_record(self):
        self.doc["meta"]["lang"] = "ja"
        self.assertIn("<html lang='ja' class='app-shell'>", render.render_html(self.doc, "en"))

    def test_an_empty_out_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "findings.json"
            source.write_text(json.dumps(self.doc), encoding="utf-8")
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as exit:
                    render.main([str(source), "--out", " "])
            self.assertEqual(exit.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
