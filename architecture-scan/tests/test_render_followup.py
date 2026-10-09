"""Regression checks for visible multiline evidence and reference labels."""
from html import unescape
from html.parser import HTMLParser
import re
import unittest

from test_architecture_scan import complete_doc, findings, render


class DisplayedText(HTMLParser):
    """Read text with normal HTML whitespace folding and explicit line breaks."""

    def __init__(self, source):
        super().__init__()
        self.text = ""
        self.ignored = False
        self.feed(source)

    def handle_starttag(self, tag, attrs):
        if tag in ("style", "script"):
            self.ignored = True
        elif tag == "br":
            self.text += "\n"

    def handle_endtag(self, tag):
        if tag in ("style", "script"):
            self.ignored = False

    def handle_data(self, value):
        if not self.ignored:
            self.text += re.sub(r"[ \t\r\n\f]+", " ", value)


class RenderFollowupTests(unittest.TestCase):
    def test_dashboard_preserves_recorded_line_breaks(self):
        doc = complete_doc()
        doc["meta"]["scope"] = "api/\r\nworker/\rweb/"
        finding = doc["findings"][0]
        finding["trace"] = "1. Read <Invoice>\r\n2. Update invoice\n3. Return result"
        finding["validation"]["evidence"] = "First writer <billing>\nSecond writer <refunds>"
        finding["analysis"] = {
            "tool": "rg",
            "command": "rg '<Invoice>' api/ \\\n--glob '*.py'",
            "result": "api/billing.py:10\r\nworker/refunds.py:20",
        }
        doc["rules"][0].update(statement="Only billing writes invoices\nRefunds must delegate",
                                status="not checked", reason="No <manifest>\rNo deployment access")
        doc["perspectives"][0]["note"] = "api/ checked\nworker/ not checked"
        for key in ("checked_ok", "limitations", "decisions", "next_steps"):
            doc[key] = [f"{key}: first line\nsecond <line>"]
        findings.validate(doc, complete=True)
        expected = [doc["meta"]["scope"], finding["trace"],
                    finding["validation"]["evidence"], finding["analysis"]["command"],
                    finding["analysis"]["result"], doc["rules"][0]["statement"],
                    doc["rules"][0]["reason"], doc["perspectives"][0]["note"]]
        expected += [doc[key][0] for key in ("checked_ok", "limitations", "decisions", "next_steps")]
        for lang in ("en", "ja"):
            with self.subTest(lang=lang):
                html = render.render_html(doc, lang)
                displayed = DisplayedText(html).text
                for value in expected:
                    self.assertIn(value.replace("\r\n", "\n").replace("\r", "\n"), displayed)
                for literal in ("<Invoice>", "<billing>", "<refunds>", "<manifest>", "<line>"):
                    self.assertNotIn(literal, html)

    def test_references_without_a_title_display_the_url(self):
        url = "docs/adr/billing.md?draft=1&version=2"
        for title in (None, ""):
            doc = complete_doc()
            ref = {"url": url}
            if title is not None:
                ref["title"] = title
            doc["findings"][0]["references"] = [ref]
            findings.validate(doc, complete=True)
            for lang in ("en", "ja"):
                with self.subTest(lang=lang, title=title):
                    markdown = render.render_markdown(doc, lang)
                    prefix = f"- **{render.LABELS[lang]['references']}:** "
                    line = next(line[len(prefix):] for line in markdown.splitlines()
                                if line.startswith(prefix))
                    link = re.fullmatch(r"\[([^\[\]]+)\]\(<([^<>]+)>\)", line)
                    self.assertIsNotNone(link, line)
                    self.assertEqual(DisplayedText(link[1]).text, url)
                    self.assertEqual(unescape(link[2]), url)
                    html = render.render_html(doc, lang)
                    prefix = f"<dt>{render.LABELS[lang]['references']}</dt><dd>"
                    cell = html.split(prefix, 1)[1].split("</dd>", 1)[0]
                    self.assertEqual(DisplayedText(cell).text, url)


if __name__ == "__main__":
    unittest.main()
