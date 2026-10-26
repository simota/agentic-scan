"""Backslash-escaped schemes, C1 controls in URLs, dashboard whitespace and facets."""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from test_architecture_scan import complete_doc, render


def node_has_playwright():
    if not shutil.which("node"):
        return False
    return subprocess.run(["node", "-e", "require('playwright')"], capture_output=True).returncode == 0


class EscapedSchemeTests(unittest.TestCase):
    def test_a_backslash_before_punctuation_never_makes_a_link(self):
        # cmark-gfm decodes `&#92;` and then unescapes `\:`, linking `ftp://…`.
        for url in ("ftp\\://evil.example/x", "javascript\\:alert(1)", "mailto\\:a@x.example",
                    "a\\#b", "docs\\.github/x.md"):
            with self.subTest(url=url):
                self.assertFalse(render.is_safe_link(url))
                self.assertNotIn("](<", render.markdown_reference({"url": url, "title": "t"}))

    def test_a_windows_relative_path_still_links(self):
        self.assertTrue(render.is_safe_link("docs\\adr\\0004.md"))
        self.assertIn("](<docs&#92;adr&#92;0004.md>)",
                      render.markdown_reference({"url": "docs\\adr\\0004.md", "title": "ADR"}))

    def test_a_c1_control_is_a_control(self):
        for url in ("https://example.com/a\x85b", "https://example.com/\x9b", "docs/a\x80.md"):
            with self.subTest(url=repr(url)):
                self.assertFalse(render.is_web_url(url))
                self.assertFalse(render.is_safe_link(url))


class DashboardWhitespaceTests(unittest.TestCase):
    def test_recorded_spaces_and_tabs_are_kept_in_finding_details(self):
        self.assertRegex(render.CSS, r"(?:^|[}\s])\.detail dd\{[^}]*white-space:pre-wrap")


@unittest.skipUnless(node_has_playwright(), "node with playwright is not installed")
class FacetTests(unittest.TestCase):
    SCRIPT = """
const { chromium } = require('playwright');
(async () => {
  const b = await chromium.launch(); const p = await b.newPage();
  await p.goto('file://' + process.argv[1]);
  await p.selectOption('#f-verdict', 'FalsePositive');
  await p.click('.facet[data-sev=High]');
  console.log(JSON.stringify(await p.evaluate(() => ({
    verdict: document.getElementById('f-verdict').value,
    shown: Array.from(document.querySelectorAll('.finding')).filter(d => !d.hidden).length}))));
  await b.close();
})();
"""

    def test_a_severity_facet_clears_an_excluded_verdict(self):
        doc = complete_doc()
        doc["findings"][1]["validation"] = {"verdict": "FalsePositive", "method": "static",
                                            "evidence": "job.py:3 delegates to billing"}
        with tempfile.TemporaryDirectory() as d:
            page = Path(d) / "dashboard.html"
            page.write_text(render.render_html(doc, "en"), encoding="utf-8")
            result = subprocess.run(["node", "-e", self.SCRIPT, str(page)], capture_output=True,
                                    text=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {"verdict": "", "shown": 1})
