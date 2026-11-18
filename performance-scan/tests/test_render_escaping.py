"""Record text reaches both outputs as literal text, never as markup."""
import re
import unittest

from support import complete_doc, render


class EscapingTests(unittest.TestCase):
    def test_step_and_perspective_notes_are_escaped_in_both_outputs(self):
        doc = complete_doc()
        doc["findings"][0]["step"] = "<b>DB1</b>*"
        doc["perspectives"][0]["note"] = "</td><img src=x onerror=alert(1)>"
        html = render.render_html(doc, "en")
        report = render.render_markdown(doc, "en")
        self.assertNotIn("<b>DB1</b>", html)
        self.assertNotIn("<img", html)
        self.assertIn("&lt;b&gt;DB1&lt;/b&gt;*", html)
        self.assertIn("(&lt;b&gt;DB1&lt;/b&gt;\\*)", report)
        self.assertNotIn("<img", report)

    def test_emoji_shortcodes_are_split(self):
        self.assertEqual(render.markdown_text("ratio :100: ok"), "ratio :<!-- -->100: ok")
        self.assertEqual(render.markdown_text("app/x.py:42"), "app/x.py:42")
        self.assertEqual(render.markdown_text(":white_check_mark:"),
                         ":<!-- -->white\\_check\\_mark:")
        doc = complete_doc()
        doc["findings"][0]["step"] = " "
        self.assertIn("**perspective:** Database access\n", render.render_markdown(doc, "en"))

    def test_dollar_signs_cannot_start_math(self):
        self.assertEqual(render.markdown_text("$x+y$"), "\\$x+y\\$")



class UntrustedTextTests(unittest.TestCase):
    def test_control_and_bidi_characters_become_visible_escapes(self):
        doc = complete_doc()
        doc["findings"][0]["title"] = "ok\u202etxt.exe \x1b]52;c;cGF5bG9hZA==\x07 end"
        report, html = render.render_markdown(doc, "en"), render.render_html(doc, "en")
        for output in (report, html):
            self.assertNotIn("\u202e", output)
            self.assertNotIn("\x1b", output)
            self.assertNotIn("\x07", output)
        self.assertIn("ok\\u202etxt.exe \\u001b]52;c;cGF5bG9hZA==\\u0007 end", html)
        # Markdown escapes the backslashes so the escape stays visible when rendered.
        self.assertIn("ok\\\\u202etxt.exe \\\\u001b\\]52", report)

    def test_protocol_relative_and_unc_references_are_not_linked(self):
        for url in ("//evil.example/share/x", " //evil.example/x", "\\\\evil\\share"):
            with self.subTest(url=url):
                self.assertIsNone(render.link_destination(url))
                doc = complete_doc()
                doc["findings"][0]["references"] = [{"title": "Share", "url": url}]
                # Only the in-page contents links remain.
                links = re.findall(r"href=['\"]([^'\"]*)", render.render_html(doc, "en"))
                self.assertEqual([href for href in links if not href.startswith("#")], [])
                self.assertNotIn("](<", render.render_markdown(doc, "en"))
        self.assertEqual(render.link_destination("docs/notes.md#x"), "docs/notes.md#x")

class LocationTests(unittest.TestCase):
    def test_locations_are_copyable_code_spans(self):
        doc = complete_doc()
        doc["findings"][0]["location"] = ["app/order_serializer.rb:9-12", "a`b.py:3"]
        report = render.render_markdown(doc, "en")
        self.assertIn("- **location:** `app/order_serializer.rb:9-12`, ``a`b.py:3``", report)

if __name__ == "__main__":
    unittest.main()
