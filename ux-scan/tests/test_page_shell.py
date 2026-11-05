"""The shell evidence.html and mockups.html share, and the dashboard's links to them."""

import contextlib
import copy
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "ux-scan" / "scripts"))

import findings  # noqa: E402
import page_shell  # noqa: E402
import render  # noqa: E402

SAMPLE = json.loads((ROOT / "examples" / "findings.sample.json").read_text(encoding="utf-8"))
FLOWS = json.loads((ROOT / "examples" / "flows.sample.json").read_text(encoding="utf-8"))


def toolbar(page):
    start = page.index('<div class="tools">')
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

    def test_narrow_toolbar_wraps_only_when_links_were_added(self):
        page = self.render(self.data)
        self.assertEqual(page.count(page_shell.NARROW_TOOLBAR_CSS), 1)
        # After the kit's CSS, so its equally specific no-wrap rule does not win.
        self.assertLess(page.rindex("--appbar-h:56px"), page.index(page_shell.NARROW_TOOLBAR_CSS))
        self.assertLess(page.index(page_shell.NARROW_TOOLBAR_CSS), page.index("</head>"))
        # Without companion pages the kit's dashboard is left exactly as rendered.
        page = render.report.render_dashboard(render.report.validate(render.to_common(self.data, "en", FLOWS)), "en")
        self.assertEqual(page_shell.link_dashboard(page, []), page)

    def test_a_changed_dashboard_template_is_refused(self):
        with self.assertRaisesRegex(RuntimeError, "dashboard template changed"):
            page_shell.link_dashboard("<html><head></head><body></body></html>", [("evidence.html", "Evidence")])
        page = f"<head></head>{page_shell.DASHBOARD_REPORT_LINK}{page_shell.DASHBOARD_REPORT_LINK}"
        with self.assertRaisesRegex(RuntimeError, "dashboard template changed"):
            page_shell.link_dashboard(page, [("evidence.html", "Evidence")])

    def test_record_text_cannot_move_the_toolbar_rule_out_of_the_head(self):
        self.data["findings"][0]["title"] = "Stray </head> in a title"
        page = self.render(self.data)
        self.assertLess(page.index(page_shell.NARROW_TOOLBAR_CSS), page.index("<body"))


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


if __name__ == "__main__":
    unittest.main()
