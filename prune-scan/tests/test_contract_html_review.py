"""Contract metadata must stay inside the actual document head."""

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "prune-scan" / "scripts"))

import contract_check  # noqa: E402


class ContractHtmlReviewTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.out = Path(tmp.name)
        data = json.loads((ROOT / "examples" / "findings.sample.json").read_text(encoding="utf-8"))
        data["limitations"].append("report.pdf not produced: this test checks HTML")
        sources = {
            "findings.json": json.dumps(data).encode("utf-8"),
            "units.json": (ROOT / "examples" / "units.sample.json").read_bytes(),
            "inventory.json": b'{"tool": "inventory.py"}\n',
        }
        for name, source in sources.items():
            (self.out / name).write_bytes(source)
        self.stamps = "".join(
            f'<meta name="{stamp}" content="sha256:{hashlib.sha256(sources[name]).hexdigest()}">'
            for stamp, name in ((contract_check.STAMP, "findings.json"),
                                (contract_check.UNITS_STAMP, "units.json"))
        )
        self.page = f'<html lang="en"><head>{self.stamps}</head><body>Report</body></html>'
        for name in ("dashboard.html", "report.html"):
            (self.out / name).write_text(self.page, encoding="utf-8")
        self.assertEqual(list(contract_check.problems(self.out, no_pdf=True)), [])

    def assert_rejected(self, page):
        for name in ("dashboard.html", "report.html"):
            with self.subTest(page=name):
                path = self.out / name
                path.write_text(page, encoding="utf-8")
                try:
                    errors = list(contract_check.problems(self.out, no_pdf=True))
                    self.assertTrue(any(error.startswith(f"{name}: invalid or incomplete HTML")
                                        for error in errors), errors)
                finally:
                    path.write_text(self.page, encoding="utf-8")

    def test_self_closing_non_void_head_elements_cannot_validate_inert_stamps(self):
        for tag in ("style", "script", "title", "template", "textarea", "iframe", "div"):
            for opening in (f"<{tag}/>", f"<{tag.upper()} />"):
                with self.subTest(opening=opening):
                    self.assert_rejected(self.page.replace("<head>", "<head>" + opening, 1))

    def test_self_closing_body_cannot_supply_a_missing_end_tag(self):
        self.assert_rejected(self.page.replace("<body>Report</body>", "<body/>"))

    def test_self_closing_envelope_elements_are_invalid(self):
        for page in ('<html lang="en"/>',
                     '<html lang="en"><head/><body></body></html>',
                     '<html lang="en"><head></head><body/></html>'):
            with self.subTest(page=page):
                metadata = contract_check.PageMetadata(page)
                self.assertTrue(metadata.invalid)
                self.assertFalse(metadata.complete)

    def test_void_self_closing_elements_preserve_valid_stamps(self):
        for ending in ("/>", " />"):
            with self.subTest(ending=ending):
                head = '<link rel="stylesheet" href="report.css"' + ending
                head += self.stamps.replace(">", ending)
                page = f'<html lang="en"><head>{head}</head><body><br/><img src="icon.png" /></body></html>'
                for name in ("dashboard.html", "report.html"):
                    (self.out / name).write_text(page, encoding="utf-8")
                self.assertEqual(list(contract_check.problems(self.out, no_pdf=True)), [])

    def test_self_closing_text_in_comments_and_scripts_is_not_markup(self):
        content = '<!-- <head/> --><script>const example = "<style/>";</script>'
        page = self.page.replace("<head>", "<head>" + content, 1)
        for name in ("dashboard.html", "report.html"):
            (self.out / name).write_text(page, encoding="utf-8")
        self.assertEqual(list(contract_check.problems(self.out, no_pdf=True)), [])

    def test_script_double_escape_cannot_validate_stamps_in_script_text(self):
        for nested in ("<script>", "<ScRiPt/>", "<script \tdata-example>", "<script\n>"):
            with self.subTest(nested=nested):
                content = "<script><!-- " + nested + "</script>"
                self.assert_rejected(self.page.replace("<head>", "<head>" + content, 1))

    def test_script_markup_without_double_escape_preserves_real_stamps(self):
        for script in ('const example = "<script>";',
                       '<!-- const example = "<style/>"; // -->',
                       '<!-- const example = "<scripture>"; // -->'):
            with self.subTest(script=script):
                page = self.page.replace("<head>", "<head><script>" + script + "</script>", 1)
                for name in ("dashboard.html", "report.html"):
                    (self.out / name).write_text(page, encoding="utf-8")
                self.assertEqual(list(contract_check.problems(self.out, no_pdf=True)), [])

    def test_non_whitespace_head_text_cannot_leave_stamps_in_a_browser_body(self):
        for text in ("unexpected text", "&amp;", "&#65;", "&#x41;", "&nbsp;", "&#160;", "\u00a0",
                     "\v", "&#11;", "&#x0b;", "&#31;", "\u2003", "&unknown;", "&Tab", "&NewLine"):
            with self.subTest(text=text):
                self.assert_rejected(self.page.replace("<head>", "<head>" + text, 1))

    def test_body_elements_and_stray_br_end_tags_cannot_implicitly_close_head(self):
        for content in ("<div></div>", "<div>body text</div>", "<br>", "</br>",
                        '<img src="icon.png">', "<iframe></iframe>", "<custom-element></custom-element>"):
            with self.subTest(content=content):
                self.assert_rejected(self.page.replace("<head>", "<head>" + content, 1))

    def test_text_or_body_markup_before_head_cannot_validate_later_stamps(self):
        for content in ("unexpected text", "&#11;", "<div></div>", "</br>"):
            for position in ("before-html", "before-head"):
                with self.subTest(content=content, position=position):
                    page = (content + self.page if position == "before-html"
                            else self.page.replace("<head>", content + "<head>", 1))
                    self.assert_rejected(page)

    def test_discarded_numeric_references_cannot_forge_stamp_attributes(self):
        for entity in ("&#11;", "&#x0b;", "&#31;", "&#xFFFF;", "&#xFDD0;"):
            for attribute in ("name", "content"):
                with self.subTest(entity=entity, attribute=attribute):
                    if attribute == "name":
                        page = self.page.replace('name="prune-scan-', 'name="' + entity + 'prune-scan-', 1)
                    else:
                        page = self.page.replace('content="sha256:', 'content="sha256:' + entity, 1)
                    self.assert_rejected(page)

    def test_html_whitespace_and_valid_character_references_preserve_head(self):
        for content in (" \t\n\f\r", "&#9;&#10;&#12;&#13;&#32;", "&Tab;&NewLine;",
                        "<!-- text, &nbsp; and <div> inside a comment -->"):
            with self.subTest(content=content):
                page = self.page.replace("<head>", "<head>" + content, 1)
                page = " \n<!doctype html>\n" + page
                for name in ("dashboard.html", "report.html"):
                    (self.out / name).write_text(page, encoding="utf-8")
                self.assertEqual(list(contract_check.problems(self.out, no_pdf=True)), [])

    def test_normal_head_elements_keep_text_in_their_own_context(self):
        content = ('<base href="https://example.com/"><link rel="stylesheet" href="report.css">'
                   '<meta charset="utf-8"><title>Report &amp; details &#160; </br> &lt;body&gt;</title>'
                   '<style>body::before { content: "<div> &nbsp;"; }</style>'
                   '<script>const example = "<div> &nbsp; &#11;";</script>'
                   '<template><div>Template text &nbsp;</div></template>')
        page = self.page.replace("<head>", "<head>" + content, 1)
        # Ordinary entity spelling of an ASCII stamp is identical in a browser.
        page = page.replace('name="prune-scan-', 'name="&#112;rune-scan-')
        page = page.replace('content="sha256:', 'content="&#x73;ha256:')
        for name in ("dashboard.html", "report.html"):
            (self.out / name).write_text(page, encoding="utf-8")
        self.assertEqual(list(contract_check.problems(self.out, no_pdf=True)), [])


if __name__ == "__main__":
    unittest.main()
