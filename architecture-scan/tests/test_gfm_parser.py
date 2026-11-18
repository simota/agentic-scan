"""Rendered report.md through a real GFM parser, where one is installed.

String checks cannot see what a parser does after decoding entities (an
e-mail autolink, `$` math), so hostile recorded text is parsed with pandoc's
GFM reader when available and the result must hold no link, image, math or
emphasis the record did not ask for.
"""
import re
import shutil
import subprocess
import unittest

from test_architecture_scan import complete_doc, render

HOSTILE = [
    "mail bob@example.com or ssh deploy@host.example",
    "_https://evil.example and 参照https://evil.example and _www.e.example_",
    "[click](javascript:alert(1)) ![i](https://evil.example/i.png) <https://x.example>",
    "path $HOME/$USER/cache and ${DB_URL}/${DB_NAME}",
    r"api/\*/models.py and web/\*/models.py",
    "www.example.com/x http://e.example/a HTTPS://E.example ftp://f.example",
]


@unittest.skipUnless(shutil.which("pandoc"), "pandoc is not installed")
class PandocGfmTests(unittest.TestCase):
    def html(self, markdown):
        return subprocess.run(["pandoc", "-f", "gfm", "-t", "html"], input=markdown,
                              capture_output=True, text=True, encoding="utf-8", check=True,
                              timeout=60).stdout

    def test_hostile_text_stays_text_in_every_position(self):
        doc = complete_doc()
        f = doc["findings"][0]
        doc["checked_ok"] = list(HOSTILE)
        doc["rules"][0]["statement"] = " ".join(HOSTILE)
        f["trace"] = "\n".join(HOSTILE)
        f["location"] = ["deploy@host.example/$HOME/a_b_c.py:3"]
        f["analysis"] = {"tool": "ssh", "command": "ssh deploy@host.example 'echo $HOME'",
                         "result": HOSTILE[0]}
        f["validation"]["method"] = "analysed"
        html = self.html(render.render_markdown(doc, "en"))
        # Emphasis the author wrote (`_www.e.example_`) is kept on purpose.
        # pandoc anchors each line of a highlighted code block (the Mermaid
        # diagrams) with `<a href="#cb1-1" aria-hidden="true">`; that is no link.
        self.assertNotRegex(html, r"<a (?!href=\"#cb[0-9]+-[0-9]+\" aria-hidden)|<img |class=\"math")
        for text in ("bob@example.com", "$HOME/$USER/cache", "${DB_URL}/${DB_NAME}",
                     r"api/\*/models.py", "javascript:alert(1)"):
            self.assertIn(text, re.sub(r"<[^>]+>", "", html).replace("&amp;", "&"))

    def test_intended_emphasis_and_code_survive(self):
        doc = complete_doc()
        doc["findings"][0]["fix"] = "keep *this* and `code`"
        html = self.html(render.render_markdown(doc, "en"))
        self.assertIn("<em>this</em>", html)
        self.assertIn("<code>code</code>", html)


if __name__ == "__main__":
    unittest.main()
