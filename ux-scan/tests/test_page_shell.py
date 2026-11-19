"""The shell evidence.html and mockups.html share, and the dashboard's links to them."""

import contextlib
import copy
import io
import json
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "ux-scan" / "scripts"))

import evidence  # noqa: E402
import findings  # noqa: E402
import mockups  # noqa: E402
import page_shell  # noqa: E402
import render  # noqa: E402

SAMPLE = json.loads((ROOT / "examples" / "findings.sample.json").read_text(encoding="utf-8"))
FLOWS = json.loads((ROOT / "examples" / "flows.sample.json").read_text(encoding="utf-8"))


def toolbar(page):
    marker = '<div class="cx-tools">' if '<div class="cx-tools">' in page else '<div class="tools">'
    start = page.index(marker)
    return page[start:page.index("</div>", start)]


class DashboardLinkTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.out = Path(temp.name) / "out"
        self.out.mkdir()
        self.data = copy.deepcopy(SAMPLE)
        self.data["limitations"].append("report.pdf not produced: no engine in this test")

    def render(self, data, lang="en"):
        (self.out / "findings.json").write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        (self.out / "flows.json").write_text(json.dumps(FLOWS), encoding="utf-8")
        shutil.copytree(ROOT / "examples" / "evidence", self.out / "evidence", dirs_exist_ok=True)
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as err:
            code = render.main([str(self.out / "findings.json"), "--out", str(self.out), "--lang", lang, "--no-pdf"])
        self.assertEqual(code, 0, err.getvalue())
        return (self.out / "dashboard.html").read_text(encoding="utf-8")

    def test_dashboard_links_evidence_then_mockups_once_each(self):
        for lang in ("en", "ja"):
            tools = toolbar(self.render(self.data, lang))
            evidence_at, mockups_at = tools.index('href="evidence.html"'), tools.index('href="mockups.html"')
            self.assertLess(tools.index('href="report.html"'), evidence_at)
            self.assertLess(evidence_at, mockups_at)
            self.assertEqual((tools.count("evidence.html"), tools.count("mockups.html")), (1, 1))

    def test_links_sit_in_the_band_tools_and_add_no_stylesheet(self):
        page = self.render(self.data)
        self.assertIn('href="evidence.html"', toolbar(page))
        # The band's tools wrap by themselves; no rule re-raises the sticky offset under the band.
        self.assertNotIn("--appbar-h:80px", page)
        # Without companion pages the kit's dashboard is left exactly as rendered.
        common = render.report.validate(render.to_common(self.data, "en", FLOWS))
        page = render.report.render_dashboard(common, "en", render.console_model(self.data, common, "en", FLOWS))
        self.assertEqual(page_shell.link_dashboard(page, []), page)

    def test_a_changed_dashboard_template_is_refused(self):
        with self.assertRaisesRegex(RuntimeError, "dashboard template changed"):
            page_shell.link_dashboard("<html><head></head><body></body></html>", [("evidence.html", "Evidence")])
        page = f"<head></head>{page_shell.DASHBOARD_REPORT_LINK}{page_shell.DASHBOARD_REPORT_LINK}"
        with self.assertRaisesRegex(RuntimeError, "dashboard template changed"):
            page_shell.link_dashboard(page, [("evidence.html", "Evidence")])


class ShellTests(unittest.TestCase):
    CHROME = {"kind": "UX <review>", "report_link": "Report", "theme": "Theme"}

    def test_page_escapes_its_text_and_runs_the_theme_toggle_first(self):
        page = page_shell.page(lang="en", title="T <1>", policy="default-src 'none'", css=".x{}",
                               chrome=self.CHROME, project="P & Q", dashboard="Dashboard",
                               body="<p>body</p>", script="/* page */")
        self.assertIn("<title>T &lt;1&gt;</title>", page)
        self.assertIn("UX &lt;review&gt;", page)
        self.assertIn("P &amp; Q", page)
        self.assertIn("<main>\n<p>body</p>\n</main>", page)
        self.assertLess(page.index("THEME_KEY"), page.index("/* page */"))
        self.assertIn('content="default-src &#x27;none&#x27;"', page)

    def test_both_companion_pages_use_the_shell(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        out = Path(temp.name)
        data = copy.deepcopy(SAMPLE)
        (out / "findings.json").write_text(json.dumps(data), encoding="utf-8")
        (out / "flows.json").write_text(json.dumps(FLOWS), encoding="utf-8")
        (out / "inventory.json").write_text(json.dumps({"flows_sha256": findings.canonical_digest(FLOWS)}))
        shutil.copytree(ROOT / "examples" / "evidence", out / "evidence")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(render.main([str(out / "findings.json"), "--out", str(out), "--no-pdf"]), 0)
        for name in ("evidence.html", "mockups.html"):
            page = (out / name).read_text(encoding="utf-8")
            self.assertEqual(page.count("THEME_KEY = 'scan-report-kit.theme'"), 1, name)
            self.assertIn('<button id="theme" type="button">', page)
            self.assertIn('<a class="button" href="dashboard.html">Dashboard</a>', toolbar(page))


# Set per element in the markup (style="--split:…"), not by any stylesheet.
INLINE_PROPERTIES = {"--columns", "--split", "--stages"}
# A fallback hides a misspelt or missing name, so it does not excuse one.
VAR = re.compile(r"var\((--[\w-]+)")
DEFINED = re.compile(r"(--[\w-]+)\s*:")


class StylesheetTests(unittest.TestCase):
    """A var() naming a property the page never defines drops its declaration or falls back silently."""

    def assert_defined(self, css, base, name):
        defined = set(DEFINED.findall(base + css)) | INLINE_PROPERTIES
        self.assertEqual(sorted(set(VAR.findall(css)) - defined), [], name)

    def test_companion_page_css_uses_only_properties_the_dashboard_css_defines(self):
        base = render.report.style.dashboard_css()
        for name, css in (("evidence.PAGE_CSS", evidence.PAGE_CSS), ("mockups.CSS", mockups.CSS)):
            self.assert_defined(css, base, name)

    def test_the_split_slider_is_a_24px_target(self):
        # WCAG 2.5.8: the browser's range input is 16px tall, too small to drag by touch.
        self.assertRegex(mockups.CSS, r"\.split\{[^}]*height:24px")

    def test_report_evidence_css_uses_only_properties_the_document_css_defines(self):
        self.assert_defined(evidence.REPORT_CSS, render.report.style.document_css("UX REVIEW"), "evidence.REPORT_CSS")


if __name__ == "__main__":
    unittest.main()
