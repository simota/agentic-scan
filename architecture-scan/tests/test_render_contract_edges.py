"""Regression checks for literal source locations in the findings report."""
from html.parser import HTMLParser
import unittest

from test_architecture_scan import complete_doc, findings, render


class LocationText(HTMLParser):
    """Read literal code spans without treating Markdown markers as text."""

    def __init__(self, source):
        super().__init__()
        self.codes = []
        self.in_code = False
        self.feed(source)

    def handle_starttag(self, tag, attrs):
        if tag == "code":
            self.in_code = True
            self.codes.append("")

    def handle_endtag(self, tag):
        if tag == "code":
            self.in_code = False

    def handle_data(self, value):
        if self.in_code:
            self.codes[-1] += value


class RenderContractEdgeTests(unittest.TestCase):
    def test_source_locations_preserve_markdown_punctuation(self):
        locations = ["pkg/__init__.py:1", "src/_internal_.py:42", "pkg/a`b`c.py:3-5"]
        for value in (locations[0], locations):
            doc = complete_doc()
            doc["findings"][0]["location"] = value
            findings.validate(doc, complete=True)
            for lang in ("en", "ja"):
                with self.subTest(value=value, lang=lang):
                    markdown = render.render_markdown(doc, lang)
                    prefix = f"- **{render.LABELS[lang]['location']}:** "
                    line = next(line[len(prefix):] for line in markdown.splitlines()
                                if line.startswith(prefix))
                    expected = value if isinstance(value, list) else [value]
                    self.assertEqual(LocationText(line).codes, expected)


if __name__ == "__main__":
    unittest.main()
