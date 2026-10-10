"""Record text reaches both outputs as literal text, never as markup."""
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


if __name__ == "__main__":
    unittest.main()
