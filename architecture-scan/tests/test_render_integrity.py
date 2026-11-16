"""Regression checks for literal evidence and Markdown output structure."""
from html import unescape
from html.parser import HTMLParser
import re
import unittest

from test_architecture_scan import complete_doc, findings, render


class VisibleText(HTMLParser):
    def __init__(self, source):
        super().__init__()
        self.text = ""
        self.codes = []
        self.in_code = False
        self.feed(source)

    def handle_starttag(self, tag, attrs):
        if tag == "code":
            self.in_code = True
            self.codes.append("")
        elif tag == "br":
            self.handle_data("\n")

    def handle_endtag(self, tag):
        if tag == "code":
            self.in_code = False

    def handle_data(self, value):
        self.text += value
        if self.in_code:
            self.codes[-1] += value


class RenderIntegrityTests(unittest.TestCase):
    def test_markdown_retains_literal_html_in_recorded_text(self):
        doc = complete_doc()
        doc["meta"].update(project="Shop <Core>", method="Read <source> & history")
        finding = doc["findings"][0]
        finding["title"] = "List<Invoice> crosses a module boundary"
        for key in ("scenario", "blast_radius", "trace", "contrast", "impact", "rule", "fix", "guard"):
            finding[key] = f"{key}: <Invoice> & <Refund>"
        finding["validation"]["evidence"] = "Result<Invoice> has no owner"
        finding["analysis"] = {
            "tool": "scanner <local>", "command": "scan invoices",
            "result": "Found <Invoice> without an owner",
        }
        for key in ("checked_ok", "limitations", "decisions", "next_steps"):
            doc[key] = [f"{key}: <Invoice> remains visible"]
        findings.validate(doc, complete=True)
        expected = [doc["meta"]["project"], doc["meta"]["method"], finding["title"],
                    finding["validation"]["evidence"], finding["analysis"]["tool"],
                    finding["analysis"]["result"]]
        expected += [finding[key] for key in
                     ("scenario", "blast_radius", "trace", "contrast", "impact", "rule", "fix", "guard")]
        expected += [doc[key][0] for key in ("checked_ok", "limitations", "decisions", "next_steps")]
        for lang in ("en", "ja"):
            with self.subTest(lang=lang):
                visible = VisibleText(render.render_markdown(doc, lang)).text
                for value in expected:
                    self.assertIn(value, visible)

    def test_multiline_values_do_not_create_report_sections_or_findings(self):
        doc = complete_doc()
        values = ("project", "method", "title", "trace", "evidence", "limitations")
        for field in values:
            value = f"{field} first\r\n## nested heading\r### A-999 fake finding\n- continuation"
            if field in ("project", "method"):
                doc["meta"][field] = value
            elif field == "evidence":
                doc["findings"][0]["validation"][field] = value
            elif field == "limitations":
                doc[field] = [value]
            else:
                doc["findings"][0][field] = value
        findings.validate(doc, complete=True)
        for lang in ("en", "ja"):
            with self.subTest(lang=lang):
                markdown = render.render_markdown(doc, lang)
                self.assertEqual(len(re.findall(r"^# ", markdown, re.MULTILINE)), 1)
                # Nine sections (the level legend among them) plus the architecture diagrams.
                self.assertEqual(len(re.findall(r"^## ", markdown, re.MULTILINE)), 10)
                # Two findings plus before, after and the changes between them.
                self.assertEqual(len(re.findall(r"^### ", markdown, re.MULTILINE)), 5)
                visible = VisibleText(markdown).text
                for field in values:
                    self.assertIn(f"{field} first\n## nested heading\n### A-999 fake finding\n- continuation",
                                  visible)

    def test_analysis_command_keeps_backticks_and_multiline_shell_text(self):
        doc = complete_doc()
        command = "rg '`Invoice`' api/ \\\r\n  --glob '*.py'"
        doc["findings"][0]["analysis"] = {
            "tool": "rg", "command": command, "result": "Found 2 references",
        }
        findings.validate(doc, complete=True)
        for lang in ("en", "ja"):
            with self.subTest(lang=lang):
                parsed = VisibleText(render.render_markdown(doc, lang))
                self.assertIn(command.replace("\r\n", "\n"), parsed.codes)

    def test_markdown_references_keep_brackets_and_parentheses(self):
        doc = complete_doc()
        references = [
            {"title": "Billing ] notes [draft", "url": "https://example.com/adr_(draft?x=1&y=2"},
            {"url": "docs/adr/billing).md"},
        ]
        doc["findings"][0]["references"] = references
        findings.validate(doc, complete=True)
        for lang in ("en", "ja"):
            with self.subTest(lang=lang):
                markdown = render.render_markdown(doc, lang)
                prefix = f"- **{render.LABELS[lang]['references']}:** "
                links = [line[len(prefix):] for line in markdown.splitlines()
                         if line.startswith(prefix)]
                self.assertEqual(len(links), len(references))
                for link, reference in zip(links, references):
                    # A label cannot contain an unescaped closing bracket, and an
                    # angle destination permits otherwise unbalanced parentheses.
                    match = re.fullmatch(r"\[([^\[\]]*)\]\(<([^<>]*)>\)", link)
                    self.assertIsNotNone(match, link)
                    self.assertEqual(VisibleText(match[1]).text,
                                     reference.get("title", reference["url"]))
                    self.assertEqual(unescape(match[2]), reference["url"])

    def test_inline_code_and_emphasis_remain_available(self):
        doc = complete_doc()
        doc["findings"][0]["trace"] = "Call **BillingService** with `List<Invoice>`"
        for lang in ("en", "ja"):
            with self.subTest(lang=lang):
                markdown = render.render_markdown(doc, lang)
                self.assertIn("**BillingService**", markdown)
                if "`List<Invoice>`" not in markdown:
                    self.assertIn("List<Invoice>", VisibleText(markdown).codes)


if __name__ == "__main__":
    unittest.main()
