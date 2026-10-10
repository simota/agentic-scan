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
            "http:// alone": "http:// alone",
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
        self.assertIn("<button data-filter='excluded' aria-pressed='false'>Excluded</button>", html)
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
        self.assertRegex(css, r"td,th\{[^}]*overflow-wrap:anywhere")
        for selector in ("dd", "li", "td"):
            self.assertRegex(css, selector + r"\{[^}]*white-space:pre-line")
        self.assertIn("color-scheme:light dark", css)

    def test_title_names_the_project_and_analysis_precedes_status(self):
        doc = complete_doc()
        doc["findings"][0]["analysis"] = {"tool": "rg", "command": "rg email", "result": "2 hits"}
        doc["findings"][0]["validation"]["method"] = "analysed"
        html = render.render_html(doc, "en")
        self.assertIn("<title>Privacy assessment: demo</title>", html)
        first = html.split("</details>", 1)[0]
        self.assertLess(first.index("<dt>analysis</dt>"), first.index("<dt>status</dt>"))
        findings.validate(doc, complete=True)


if __name__ == "__main__":
    unittest.main()
