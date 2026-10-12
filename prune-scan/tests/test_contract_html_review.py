"""Regression tests for browser-incompatible contract HTML."""

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

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

    def assert_accepted(self, page):
        for name in ("dashboard.html", "report.html"):
            (self.out / name).write_text(page, encoding="utf-8")
        self.assertEqual(list(contract_check.problems(self.out, no_pdf=True)), [])

    def test_direct_head_text_invalidates_the_envelope_before_or_after_stamps(self):
        for text in ("unexpected text", "日本語", "<", "\ntext\t"):
            for position in ("<head>", "</head>"):
                with self.subTest(text=text, position=position):
                    inserted = position + text if position == "<head>" else text + position
                    self.assert_rejected(self.page.replace(position, inserted, 1))

    def test_only_html_ascii_whitespace_can_remain_directly_in_head(self):
        for text in ("\v", "\x1c", "\x85", "\xa0", "\u2003", "\u2028", "\u202f", "\u3000", "\ufeff"):
            with self.subTest(text=repr(text)):
                self.assert_rejected(self.page.replace("<head>", "<head>" + text, 1))

    def test_non_whitespace_references_cannot_keep_the_head_open(self):
        for text in ("&amp;", "&nbsp;", "&emsp;", "&#65;", "&#x3000;", "&#11;", "&#x1f;",
                     "&#127;", "&#xFFFF;", "&#0;", "&#x110000;", "&unknown;", "&Tab", "&NewLine"):
            with self.subTest(text=text):
                self.assert_rejected(self.page.replace("<head>", "<head>" + text, 1))

    def test_html_whitespace_and_its_references_preserve_valid_stamps(self):
        for text in (" \t\n\r\f", "&#9;&#10;&#12;&#13;&#32;", "&#x09;&#x0a;&#x0C;&#x0D;&#x20;",
                     "&#00032;", "&#32", "&Tab;&NewLine;", "\n&Tab;\n&NewLine;\n"):
            with self.subTest(text=text):
                self.assert_accepted(self.page.replace("<head>", "<head>" + text, 1))

    def test_head_text_elements_keep_their_text_and_comments_out_of_direct_head_data(self):
        for content in ('<title>Report &amp; analysis &nbsp; &#11;</title>',
                        '<style>body::before { content: "text &nbsp; &#11;"; }</style>',
                        '<script>const example = "text &nbsp; &#11;";</script>',
                        '<!-- text &nbsp; &#11; <br> -->'):
            with self.subTest(content=content):
                self.assert_accepted(self.page.replace("<head>", "<head>" + content, 1))

    def test_script_legacy_comments_cannot_make_stamps_or_closing_tags_inert(self):
        for script in ('<script><!--<script></script>',
                       '<SCRIPT><!--\n<ScRiPt data-demo="x">\n</SCRIPT>',
                       '<script type="application/json"><!--<script></script>'):
            for position in ("<head>", "<body>"):
                with self.subTest(script=script, position=position):
                    self.assert_rejected(self.page.replace(position, position + script, 1))

    def test_normal_scripts_and_escaped_html_comments_preserve_the_contract(self):
        for script in ('<script>const marker = "<script>";</script>',
                       '<script>// ordinary line comment\n/* ordinary block comment */\nconst x = 1;</script>',
                       '<script>const marker = "\\u003c!--";</script>',
                       '<script type="application/json">{"marker": "\\u003c!--"}</script>',
                       '<script>const marker = "&lt;!--";</script>',
                       '<style>/* <!-- <script> */</style><!-- <script><!-- text </script> -->'):
            for position in ("<head>", "<body>"):
                with self.subTest(script=script, position=position):
                    self.assert_accepted(self.page.replace(position, position + script, 1))

    def test_script_boundaries_survive_fragmented_data_callbacks(self):
        handle_data = contract_check.PageMetadata.handle_data

        def fragmented(parser, data):
            for character in data:
                handle_data(parser, character)

        with mock.patch.object(contract_check.PageMetadata, "handle_data", fragmented):
            for position in ("<head>", "<body>"):
                with self.subTest(position=position):
                    script = '<script><!-- <ScRiPt\t></script>'
                    self.assert_rejected(self.page.replace(position, position + script, 1))
                    script = '<script><!-- const example = "<scripture>"; // --></script>'
                    self.assert_accepted(self.page.replace(position, position + script, 1))

    def test_body_only_elements_cannot_restore_the_head_for_later_stamps(self):
        for content in ("<br>", "<hr/>", '<img src="icon.png">', '<input type="hidden">',
                        "<div></div>", "<p></p>", "<textarea></textarea>", "<svg></svg>"):
            with self.subTest(content=content):
                self.assert_rejected(self.page.replace("<head>", "<head>" + content, 1))

    def test_br_end_tag_cannot_keep_the_head_open(self):
        self.assert_rejected(self.page.replace("<head>", "<head></br>", 1))

    def test_text_outside_the_explicit_head_and_body_cannot_supply_a_false_envelope(self):
        for page in ("text" + self.page, self.page.replace("<head>", "text<head>", 1),
                     self.page.replace("<body>", "text<body>", 1), self.page + "text"):
            with self.subTest(page=page):
                self.assert_rejected(page)

    def test_body_elements_before_the_head_cannot_supply_head_metadata(self):
        for content in ("<br>", "</br>", "<div></div>", "<template></template>"):
            for page in (content + self.page, self.page.replace("<head>", content + "<head>", 1)):
                with self.subTest(content=content, page=page):
                    self.assert_rejected(page)

    def test_unclosed_head_children_cannot_hide_in_a_complete_envelope(self):
        for tag in ("title", "style", "script", "template", "noscript", "noframes"):
            with self.subTest(tag=tag):
                self.assert_rejected(self.page.replace("</head>", f"<{tag}></head>", 1))

    def test_control_references_cannot_be_dropped_from_stamp_attributes(self):
        for reference in ("&#11;", "&#x1f;", "&#127;", "&#xFFFF;"):
            for value in (contract_check.STAMP, "sha256:"):
                with self.subTest(reference=reference, value=value):
                    self.assert_rejected(self.page.replace(value, value + reference, 1))

    def test_valid_numeric_references_in_stamp_attributes_still_match_the_digest(self):
        page = self.page.replace(contract_check.STAMP, contract_check.STAMP.replace("-", "&#45;"), 1)
        page = page.replace("sha256:", "sh&#97;256&#x3a;", 1)
        self.assert_accepted(page)

    def test_document_whitespace_bom_comments_and_closed_head_children_remain_valid(self):
        content = '<template><div>Text &nbsp; &#11;</div></template>'
        page = self.page.replace("<head>", "<head>" + content, 1)
        self.assert_accepted('\ufeff\n<!doctype html><!-- document -->\n' + page + '\n<!-- end -->')

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
