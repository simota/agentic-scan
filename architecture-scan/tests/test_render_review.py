"""Regression checks for assessment evidence retained by both renderers."""
from html import escape
import unittest

from test_architecture_scan import complete_doc, findings, render


class RenderReviewTests(unittest.TestCase):
    def test_dashboard_retains_reference_titles_and_urls(self):
        doc = complete_doc()
        references = [
            {"title": 'Billing <ADR> & "ownership"',
             "url": "https://example.com/adr?rule=OWN&version=2"},
            {"url": "docs/adr/0004-billing.md"},
            {"title": "Literal reference", "url": "<script>alert('ref')</script>"},
        ]
        doc["findings"][0]["references"] = references
        findings.validate(doc, complete=True)
        for lang in ("en", "ja"):
            with self.subTest(lang=lang):
                html = render.render_html(doc, lang)
                finding_html = html.split("<details ", 1)[1].split("</details>", 1)[0]
                self.assertIn(f"<dt>{render.LABELS[lang]['references']}</dt>", finding_html)
                for reference in references:
                    self.assertIn(escape(reference["url"]), finding_html)
                    if "title" in reference:
                        self.assertIn(escape(reference["title"]), finding_html)
                self.assertNotIn("<ADR>", finding_html)
                self.assertNotIn("<script>", finding_html)

    def test_recorded_assessment_method_survives_without_findings(self):
        doc = complete_doc()
        doc["findings"] = []
        method = "Read-only git history: 12 months; import-linter: 0 broken contracts"
        doc["meta"]["method"] = method
        findings.validate(doc, complete=True)
        for lang in ("en", "ja"):
            with self.subTest(lang=lang):
                markdown = render.render_markdown(doc, lang)
                html = render.render_html(doc, lang)
                self.assertIn(method, markdown)
                self.assertIn(escape(method), html)
                self.assertNotIn(render.LABELS[lang]["static_note"], markdown)

    def test_fallback_method_accounts_for_recorded_static_analysis(self):
        doc = complete_doc()
        doc["findings"][0]["analysis"] = {
            "tool": "git", "command": "git log --since=1.year -- worker/",
            "result": "12 changes to worker/ in the assessed history window",
        }
        findings.validate(doc, complete=True)
        for lang in ("en", "ja"):
            with self.subTest(lang=lang):
                note = render.LABELS[lang]["analysed_note"]
                self.assertIn(note, render.render_markdown(doc, lang))
                self.assertIn(escape(note), render.render_html(doc, lang))

    def test_fallback_method_remains_static_without_analysis(self):
        doc = complete_doc()
        for lang in ("en", "ja"):
            with self.subTest(lang=lang):
                note = render.LABELS[lang]["static_note"]
                self.assertIn(note, render.render_markdown(doc, lang))
                self.assertIn(escape(note), render.render_html(doc, lang))


if __name__ == "__main__":
    unittest.main()
