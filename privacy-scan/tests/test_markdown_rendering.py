"""Regression coverage for literal report prose, references and commands."""
from html import unescape
import unittest

from test_privacy_scan import complete_doc, render


class MarkdownRenderingTests(unittest.TestCase):
    def test_quotes_and_literal_character_references_are_preserved(self):
        doc = complete_doc()
        doc["findings"][0]["validation"]["evidence"] = (
            "worker's filter uses 'always' and \"never\"; literal &copy; and &#x27;")
        markdown = render.render_markdown(doc, "en")
        self.assertIn(
            "- **evidence:** worker's filter uses 'always' and \"never\"; "
            "literal &amp;copy; and &amp;\\#x27;", markdown)

    def test_placeholders_and_markup_remain_literal_in_prose(self):
        doc = complete_doc()
        doc["meta"]["project"] = "Audit #1\n<email> & [draft]"
        doc["findings"][0]["title"] = "<email> *field* `quoted`\n# second line"
        doc["findings"][0]["data"] = "Only <email> reaches the sink"
        doc["findings"][0]["validation"]["evidence"] = "request <email> & token_*"
        doc["checked_ok"] = ["<email> _never_ **stored**\n- next line"]
        markdown = render.render_markdown(doc, "en")
        self.assertIn(
            "# Privacy assessment: Audit \\#1<br>&lt;email&gt; &amp; \\[draft\\]", markdown)
        self.assertIn(
            "### PV-001 [High][Confirmed] &lt;email&gt; \\*field\\* \\`quoted\\`<br>\\# second line",
            markdown)
        self.assertIn("- **personal data:** Only &lt;email&gt; reaches the sink", markdown)
        self.assertIn("- **evidence:** request &lt;email&gt; &amp; token\\_\\*", markdown)
        self.assertIn("- &lt;email&gt; \\_never\\_ \\*\\*stored\\*\\*<br>- next line", markdown)
        self.assertNotIn("\n# second line", markdown)
        self.assertNotIn("\n- next line", markdown)

    def test_pipes_and_line_breaks_stay_inside_each_table_cell(self):
        doc = complete_doc()
        doc["meta"]["scope"] = "API | worker\r\nbatch\rfooter"
        doc["commitments"][0]["statement"] = "No email | phone is logged\n<email>"
        doc["commitments"][0]["source"] = "policy | text"
        doc["perspectives"][0]["note"] = "PC1 | PC2\nfollow-up"
        markdown = render.render_markdown(doc, "en")
        self.assertIn("| Scope | API \\| worker<br>batch<br>footer |", markdown)
        self.assertIn(
            "| C-01 | No email \\| phone is logged<br>&lt;email&gt; |  | policy \\| text | violated |",
            markdown)
        self.assertIn(
            "| Data inventory and minimisation | applied | PC1 \\| PC2<br>follow-up |", markdown)

    def test_headings_and_list_items_preserve_block_markers(self):
        doc = complete_doc()
        doc["meta"]["project"] = "Hash #"
        doc["findings"][0]["title"] = "Literal #"
        doc["checked_ok"] = ["- literal", "+ literal", "1. literal", "1) literal", "---"]
        markdown = render.render_markdown(doc, "en")
        self.assertIn("# Privacy assessment: Hash \\#\n", markdown)
        self.assertIn("### PV-001 [High][Confirmed] Literal \\#\n", markdown)
        for line in ("- \\- literal", "- \\+ literal", "- 1\\. literal", "- 1\\) literal", "- \\---"):
            self.assertIn(line + "\n", markdown)

    def test_indented_list_prose_keeps_whitespace_without_starting_code_blocks(self):
        for field in ("checked_ok", "limitations", "decisions", "next_steps"):
            for lang in ("en", "ja"):
                for indent in ("    ", "\t", " \t "):
                    with self.subTest(field=field, lang=lang, indent=repr(indent)):
                        value = indent + "No <email> reaches logging\nReview <config> & settings."
                        doc = complete_doc()
                        doc[field] = [value]
                        markdown = render.render_markdown(doc, lang)
                        heading = f"## {render.LABELS[lang][field]}\n\n"
                        section = markdown.split(heading, 1)[1].split("\n## ", 1)[0].rstrip("\n")
                        self.assertTrue(section.startswith("- "))
                        body = section[2:]
                        # Raw indentation after the list marker can start a code
                        # block before HTML entities and line breaks are parsed.
                        self.assertNotRegex(body, r"^[ \t]")
                        self.assertNotIn("\n", body)
                        self.assertEqual(unescape(body.replace("<br>", "\n")), value)

    def test_indented_list_markers_remain_literal(self):
        cases = (("- literal", r"\- literal"), ("+ literal", r"\+ literal"),
                 ("1. literal", r"1\. literal"), ("1) literal", r"1\) literal"),
                 ("---", r"\---"))
        for indent in ("    ", "\t", " \t "):
            for value, escaped in cases:
                with self.subTest(indent=repr(indent), value=value):
                    item = render.markdown_item(indent + value)
                    self.assertNotRegex(item, r"^[ \t]")
                    self.assertTrue(item.endswith(escaped))
                    self.assertEqual(unescape(item[:-len(escaped)]), indent)

    def test_reference_label_and_destination_keep_their_content(self):
        doc = complete_doc()
        doc["findings"][0]["references"] = [{
            "title": "SDK [docs] <email> *privacy*",
            "url": "https://example.invalid/docs/(privacy policy)?literal=&copy;&q=<email>#frag",
        }]
        markdown = render.render_markdown(doc, "en")
        self.assertIn(
            "- **references:** [SDK \\[docs\\] &lt;email&gt; \\*privacy\\*]"
            "(<https://example.invalid/docs/(privacy%20policy)?literal=&amp;copy;&amp;q=%3Cemail%3E#frag>)",
            markdown)

    def test_relative_and_fragment_references_remain_links(self):
        doc = complete_doc()
        doc["findings"][0]["references"] = [
            {"title": "Policy", "url": "docs/privacy (policy).md#scope"},
            {"title": "Scope", "url": "#scope"},
        ]
        markdown = render.render_markdown(doc, "en")
        self.assertIn("[Policy](<docs/privacy%20(policy).md#scope>)", markdown)
        self.assertIn("[Scope](<#scope>)", markdown)

    def test_unsupported_or_malformed_reference_uris_remain_visible_as_text(self):
        cases = (
            ("javascript:alert(1)", "Reference — javascript:alert(1)"),
            ("java\nscript:alert(1)", "Reference — java<br>script:alert(1)"),
            ("data:text/html,<email>", "Reference — data:text/html,&lt;email&gt;"),
            ("https://[broken", "Reference — https://\\[broken"),
        )
        for url, expected in cases:
            with self.subTest(url=url):
                doc = complete_doc()
                doc["findings"][0]["references"] = [{"title": "Reference", "url": url}]
                markdown = render.render_markdown(doc, "en")
                self.assertIn("- **references:** " + expected, markdown)
                self.assertNotIn("[Reference](", markdown)

    def test_commands_preserve_backticks_spaces_and_line_breaks(self):
        cases = (
            ("git log --format=`%h`", "`` git log --format=`%h` ``"),
            ('printf "``" && git status', '```printf "``" && git status```'),
            (" git status ", "`  git status  `"),
            ("git status\n# <email>", "`git status`<br>`# <email>`"),
            ("``", "``` `` ```"),
        )
        for command, expected in cases:
            with self.subTest(command=command):
                doc = complete_doc()
                doc["findings"][0]["validation"]["method"] = "analysed"
                doc["findings"][0]["analysis"] = {
                    "tool": "git [read-only]", "command": command, "result": "<email> *checked*",
                }
                markdown = render.render_markdown(doc, "en")
                self.assertIn(
                    "- **analysis:** &lt;email&gt; \\*checked\\* (git \\[read-only\\]: " + expected + ")",
                    markdown)


if __name__ == "__main__":
    unittest.main()
