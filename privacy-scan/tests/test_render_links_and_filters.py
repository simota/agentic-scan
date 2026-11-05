"""Regressions for prose URLs in report.md and the dashboard's filters and layout."""
import copy
import re
import unittest

from test_privacy_scan import complete_doc, findings, render


class ProseUrlTests(unittest.TestCase):
    def test_prose_urls_become_links_that_keep_their_spelling(self):
        cases = {
            "see https://example.com/x_y.": "see [https://example.com/x\\_y](<https://example.com/x_y>).",
            "(https://example.com/a?b=1&c=2#d_e)":
                "([https://example.com/a?b=1&amp;c=2\\#d\\_e](<https://example.com/a?b=1&amp;c=2#d_e>))",
            "www.example.com/a_b, ok": "[www.example.com/a\\_b](<http://www.example.com/a_b>), ok",
            "go https://e.com/a|b": "go [https://e.com/a](<https://e.com/a>)\\|b",
            "http:// alone": "http\\:// alone",  # displays as typed, never autolinked
            "javascript:alert(1)": "javascript:alert(1)",
        }
        for text, expected in cases.items():
            with self.subTest(text=text):
                self.assertEqual(render.markdown_text(text), expected)

    def test_reference_labels_are_not_nested_links(self):
        ref = {"title": "https://example.com/a_b", "url": "https://example.com/a_b"}
        self.assertEqual(render.markdown_reference(ref),
                         "[https://example.com/a\\_b](<https://example.com/a_b>)")

    def test_list_items_starting_with_a_url_stay_list_items(self):
        self.assertEqual(render.markdown_item("https://example.com/a"),
                         "[https://example.com/a](<https://example.com/a>)")


class ExcludedFindingTests(unittest.TestCase):
    def doc(self):
        doc = complete_doc()
        excluded = copy.deepcopy(doc["findings"][0])
        excluded["id"] = "PV-003"
        excluded["validation"] = {"verdict": "FalsePositive", "method": "static",
                                  "evidence": "scrubber at app.py:30"}
        doc["findings"].append(excluded)
        return doc

    def test_excluded_findings_have_their_own_filter_and_label(self):
        html = render.render_html(self.doc(), "en")
        self.assertEqual(html.count("<details data-sev='High'>"), 1)
        self.assertIn("<details data-sev='excluded'>", html)
        self.assertIn("<button type='button' data-filter='excluded' aria-pressed='false'>"
                      "Excluded <span class='n'>1</span></button>", html)
        self.assertIn("· FalsePositive (Excluded)", html)
        markdown = render.render_markdown(self.doc(), "ja")
        self.assertIn("### PV-003 [High][Confirmed] Error tracker receives request bodies (除外)",
                      markdown)

    def test_excluded_filter_appears_only_when_needed(self):
        self.assertNotIn("data-filter='excluded'", render.render_html(complete_doc(), "en"))

    def test_empty_state_is_present_and_toggled_by_the_filter(self):
        html = render.render_html(complete_doc(), "en")
        self.assertIn("<p data-empty hidden>None.</p>", html)
        self.assertIn("empty.hidden=shown>0", html)
        doc = complete_doc()
        doc["findings"] = []
        self.assertIn("<p data-empty>None.</p>", render.render_html(doc, "en"))


class LayoutTests(unittest.TestCase):
    def test_cells_wrap_and_keep_line_breaks(self):
        css = render.CSS
        # Cells wrap between words; a table too wide scrolls inside .tablewrap.
        self.assertRegex(css, r"(?:td,th|th,td)\{[^}]*overflow-wrap:break-word")
        self.assertIn(".tablewrap{overflow-x:auto", css)
        for selector in ("dd", "li", "td"):
            self.assertRegex(css, selector + r"\{[^}]*white-space:pre-line")
        # Light and dark themes come from scan-report-kit: the system setting and the toggle.
        self.assertIn("color-scheme:light", css)
        self.assertIn('@media(prefers-color-scheme:dark){:root:not([data-theme="light"]){color-scheme:dark', css)
        self.assertIn(':root[data-theme="dark"]{color-scheme:dark', css)

    def test_title_names_the_project_and_analysis_precedes_status(self):
        doc = complete_doc()
        doc["findings"][0]["analysis"] = {"tool": "rg", "command": "rg email", "result": "2 hits"}
        doc["findings"][0]["validation"]["method"] = "analysed"
        html = render.render_html(doc, "en")
        self.assertIn("<title>Privacy assessment: demo</title>", html)
        first = html.split("</details>", 1)[0]
        self.assertLess(first.index("<dt>analysis</dt>"), first.index("<dt>status</dt>"))
        findings.validate(doc, complete=True)


class DashboardControlTests(unittest.TestCase):
    """What the filters, status messages, ledger marks and page policy promise."""

    def test_filters_are_a_named_group_that_state_their_counts(self):
        doc = complete_doc()
        html = render.render_html(doc, "en")
        self.assertIn("<div class='filter-buttons' role='group' "
                      "aria-label='Filter findings by severity'>", html)
        by_sev, _ = render.counts(doc["findings"])
        for severity, n in by_sev.items():
            self.assertIn(f"<button type='button' data-filter='{severity}' aria-pressed='false'>"
                          f"{severity} <span class='n'>{n}</span></button>", html)
        total = len(doc["findings"])
        self.assertIn(f"data-filter='all' aria-pressed='true'>All <span class='n'>{total}</span>", html)
        self.assertNotIn("<button data", html)  # every button is type=button

    def test_shown_count_is_a_status_message_updated_by_the_filter(self):
        for lang in ("en", "ja"):
            with self.subTest(lang=lang):
                doc = complete_doc()
                html = render.render_html(doc, lang)
                template = render.LABELS[lang]["showing"]
                n = str(len(doc["findings"]))
                self.assertIn(f"id='register-count' role='status' data-template='{template}'>"
                              + template.replace("{shown}", n).replace("{total}", n) + "</p>", html)
        self.assertIn("count.dataset.template.replace('{shown}',shown)", render.JS)
        doc = complete_doc()
        doc["findings"] = []
        self.assertRegex(render.render_html(doc, "en"), r"id='register-count'[^>]* hidden>")

    def test_ledger_statuses_that_need_action_are_marked(self):
        doc = complete_doc()
        doc["commitments"].append({"id": "C-02", "statement": "regions", "source": "policy",
                                   "status": "not checked", "reason": "outside the repository"})
        doc["perspectives"][0]["status"] = "not checked"
        doc["perspectives"].pop()  # left out of the record: shown as —
        html = render.render_html(doc, "ja")
        self.assertIn("<span class='status' data-status='violated'>違反</span>", html)
        self.assertIn("<span class='status' data-status='not checked'>未確認</span>"
                      " — 理由: outside the repository</td>", html)
        self.assertIn('.status[data-status="violated"]{color:var(--high);font-weight:700}', render.CSS)
        # Perspectives the record leaves out stay plain text.
        self.assertIn("<td data-label='ステータス'>—</td>", html)

    def test_theme_choice_is_remembered_with_the_kit_key(self):
        self.assertIn("localStorage.getItem('scan-report-kit.theme')", render.JS)
        self.assertIn("localStorage.setItem('scan-report-kit.theme'", render.JS)
        # Storage can throw (private windows, blocked site data); the page still works.
        self.assertEqual(render.JS.count("localStorage"), render.JS.count("try{localStorage")
                         + render.JS.count("try{const t=localStorage"))

    def test_content_security_policy_allows_only_the_pages_own_style_and_script(self):
        from base64 import b64encode
        from hashlib import sha256
        html = render.render_html(complete_doc(), "en")
        policy = re.search(r"<meta http-equiv='Content-Security-Policy' content=\"([^\"]+)\">", html)
        self.assertIsNotNone(policy)
        self.assertLess(html.index("Content-Security-Policy"), html.index("<style>"))
        style = re.search(r"<style>(.*?)</style>", html, re.S).group(1)
        script = re.search(r"<script>(.*?)</script>", html, re.S).group(1)

        def source(code):
            return "'sha256-" + b64encode(sha256(code.encode()).digest()).decode() + "'"
        directives = dict(d.strip().split(" ", 1) for d in policy.group(1).split(";"))
        self.assertEqual(directives["default-src"], "'none'")
        self.assertIn(source(style), directives["style-src"].split())
        self.assertIn(source(script), directives["script-src"].split())
        self.assertEqual(directives["base-uri"], "'none'")
        self.assertEqual(directives["form-action"], "'none'")
        self.assertNotRegex(html, r" style=")  # hashes do not cover style attributes


if __name__ == "__main__":
    unittest.main()
