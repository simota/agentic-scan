"""Regressions for recorded review methods and executable analysis commands."""
from html.parser import HTMLParser
import unittest

from test_privacy_scan import complete_doc, findings, render


class ReportHTML(HTMLParser):
    def __init__(self, source):
        super().__init__()
        self.tags = []
        self.stack = []
        self.code_blocks = []
        self.descriptions = []
        self.term = ""
        self.value = ""
        self.code = ""
        self.feed(source)

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        if tag in ("meta", "br"):
            return
        self.stack.append(tag)
        if tag == "dt":
            self.term = ""
        elif tag == "dd":
            self.value = ""
        elif tag == "code" and "pre" in self.stack:
            self.code = ""

    def handle_endtag(self, tag):
        if tag == "code" and "pre" in self.stack:
            self.code_blocks.append(self.code)
        elif tag == "dd":
            self.descriptions.append((self.term, self.value))
        if self.stack and self.stack[-1] == tag:
            self.stack.pop()

    def handle_data(self, data):
        if "dt" in self.stack:
            self.term += data
        if "dd" in self.stack:
            self.value += data
        if "pre" in self.stack and "code" in self.stack:
            self.code += data


class ReviewRenderingTests(unittest.TestCase):
    def test_html_analysis_command_preserves_lines_indentation_and_literal_markup(self):
        doc = complete_doc()
        command = 'git status\n  git diff --stat\n\tprintf "<email> & </code><script>literal</script>"'
        doc["findings"][0]["validation"]["method"] = "analysed"
        doc["findings"][0]["analysis"] = {
            "tool": "git <read-only>", "command": command, "result": "No <email> field",
        }
        findings.validate(doc, complete=True)
        for lang in ("ja", "en"):
            with self.subTest(lang=lang):
                source = render.render_html(doc, lang)
                parsed = ReportHTML(source)
                self.assertEqual(parsed.code_blocks, [command])
                self.assertEqual(parsed.tags.count("script"), 2)  # Data script + fixed dashboard script.
                self.assertNotIn("email", parsed.tags)
                self.assertNotIn("read-only", parsed.tags)
                self.assertIn("No &lt;email&gt; field", source)
                self.assertIn("git &lt;read-only&gt;", source)

    def test_recorded_method_survives_zero_findings_in_both_languages(self):
        doc = complete_doc()
        doc["findings"] = []
        method = "Read-only schema scan; no issues found"
        doc["meta"]["method"] = method
        findings.validate(doc, complete=True)
        for lang, label in (("en", "Review method"), ("ja", "診断方法")):
            with self.subTest(lang=lang):
                markdown = render.render_markdown(doc, lang)
                html = render.render_html(doc, lang)
                self.assertIn(f"| {label} | {method} |", markdown)
                self.assertIn((label, method), ReportHTML(html).descriptions)
                self.assertNotIn(render.LABELS[lang]["static_note"], markdown)
                self.assertNotIn(render.LABELS[lang]["static_note"], html)

    def test_recorded_method_is_literal_and_keeps_each_finding_verification(self):
        doc = complete_doc()
        method = "Custom <method> & [scope]\nsecond line"
        doc["meta"]["method"] = method
        doc["findings"][1]["validation"]["method"] = "analysed"
        doc["findings"][1]["analysis"] = {
            "tool": "git", "command": "git status", "result": "No source changes",
        }
        findings.validate(doc, complete=True)
        for lang, label in (("en", "Review method"), ("ja", "診断方法")):
            with self.subTest(lang=lang):
                markdown = render.render_markdown(doc, lang)
                html = render.render_html(doc, lang)
                parsed = ReportHTML(html)
                self.assertIn(
                    f"| {label} | Custom &lt;method&gt; &amp; \\[scope\\]<br>second line |",
                    markdown,
                )
                self.assertIn((label, method), parsed.descriptions)
                self.assertNotIn("method", parsed.tags)
                verification = render.LABELS[lang]["method"]
                self.assertIn(f"**{verification}:** static", markdown)
                self.assertIn(f"**{verification}:** analysed", markdown)
                verdict = render.LABELS[lang]["verdict"]
                self.assertIn((verdict, "Valid (static)"), parsed.descriptions)
                self.assertIn((verdict, "Valid (analysed)"), parsed.descriptions)

    def test_unspecified_or_blank_method_keeps_default_verification_note(self):
        for method in (None, "", "   "):
            for analysed in (False, True):
                doc = complete_doc()
                if method is not None:
                    doc["meta"]["method"] = method
                if analysed:
                    doc["findings"][0]["validation"]["method"] = "analysed"
                    doc["findings"][0]["analysis"] = {
                        "tool": "git", "command": "git status", "result": "No source changes",
                    }
                findings.validate(doc, complete=True)
                for lang in ("ja", "en"):
                    with self.subTest(method=method, analysed=analysed, lang=lang):
                        expected = render.LABELS[lang]["analysed_note" if analysed else "static_note"]
                        self.assertIn(expected, render.render_markdown(doc, lang))
                        self.assertIn(expected, render.render_html(doc, lang))


if __name__ == "__main__":
    unittest.main()
