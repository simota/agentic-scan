"""Dashboard printing, empty filters, contrast, wrapping and bidi; Makefile edges."""
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

from test_architecture_scan import REPO, complete_doc, make_env, render


def page_style(doc=None):
    """The stylesheet the rendered dashboard inlines (scan-report-kit's, then this skill's)."""
    html = render.render_html(doc or complete_doc(), "en")
    return re.search(r"<style>(.*?)</style>", html, re.S)[1]


class DashboardTests(unittest.TestCase):
    def test_printing_opens_every_finding_and_hides_the_filter(self):
        self.assertIn("beforeprint", render.JS)
        self.assertIn("f.hidden=false;d.open=true", render.JS)
        # The last print block is this skill's; it hides the whole filter panel.
        printed = page_style().rsplit("@media print{", 1)[1]
        self.assertRegex(printed, r"\.filters-panel[^{]*\{display:none!important")

    def test_printing_hides_the_empty_message_and_restores_collapsed_findings(self):
        self.assertIn("if(m)m.hidden=true", render.JS)
        self.assertIn("shut.forEach(function(d){d.open=false;})", render.JS)

    def test_a_url_with_a_bidi_control_is_never_a_link(self):
        doc = complete_doc()
        doc["findings"][0]["references"] = [{"title": "t", "url": "https://e.example/\u202egpj.exe"},
                                            {"url": "docs/\u2066a.md"}]
        for output in (render.render_html(doc, "en"), render.render_markdown(doc, "en")):
            self.assertNotRegex(output, "[\u202a-\u202e\u2066-\u2069]")
            # Only same-page anchors (permalinks) may link from a finding.
            self.assertNotRegex(output.split("<details", 1)[-1], r"href=['\"](?!#)")
            self.assertNotIn("](<", output)
            self.assertIn("U+202E", output)

    def test_the_tab_title_shows_bidi_controls_too(self):
        doc = complete_doc()
        doc["meta"]["project"] = "acme\u202eloc.exe"
        title = re.search(r"<title>(.*?)</title>", render.render_html(doc, "en"))[1]
        self.assertIn("[U+202E]", title)

    def test_a_filter_with_no_match_has_a_message(self):
        html = render.render_html(complete_doc(), "en")
        self.assertIn(f"<p class='empty' data-empty hidden>{render.DASH['en']['no_matches']}</p>", html)
        self.assertNotIn("<p data-empty", render.render_html({**complete_doc(), "findings": []}, "en"))

    def test_excluded_findings_keep_full_contrast(self):
        self.assertNotIn("opacity", page_style())

    def test_long_titles_and_project_names_wrap(self):
        style = page_style()
        # Titles and register rows inherit the body rule; the hero title also sets it.
        self.assertRegex(style, r"(?m)^body\{[^}]*overflow-wrap:anywhere")
        self.assertRegex(style, r"\.hero h1\{[^}]*overflow-wrap:anywhere")

    def test_bidi_controls_are_shown_not_applied(self):
        doc = complete_doc()
        doc["findings"][0]["title"] = "Refund ‮evil⁦x"
        for output in (render.render_html(doc, "en"), render.render_markdown(doc, "en")):
            self.assertNotRegex(output, "[‪-‮⁦-⁩]")
            self.assertIn("U+202E", output)


    def test_the_dashboard_opts_into_the_kits_application_shell(self):
        # The kit scopes its app bar, sidebar and pinned filters to html.app-shell.
        html = render.render_html(complete_doc(), "en")
        self.assertIn("<html lang='en' class='app-shell'>", html)
        self.assertIn("<header class='appbar'>", html)
        nav = re.search(r"<nav class='sidebar'.*?</nav>", html, re.S)[0]
        targets = re.findall(r'href="#([^"]+)"', nav)
        self.assertIn("findings", targets)
        for target in targets:
            self.assertIn(f"id='{target}'", html)
        self.assertEqual(len(re.findall(r"<button type='button' class='facet'", nav)), len(render.SEVERITIES))
        empty = render.render_html({**complete_doc(), "findings": []}, "en")
        self.assertNotIn("class='facet'", empty)

class MakefileEdgeTests(unittest.TestCase):
    def make(self, *args):
        return subprocess.run(["make", "--no-print-directory", "-f", str(REPO / "Makefile"), *args],
                              env=make_env(), capture_output=True, text=True, timeout=30)

    def test_lang_out_cannot_run_a_shell_command(self):
        with tempfile.TemporaryDirectory() as d:
            marker = Path(d) / "pwned"
            self.make("demo", f"DEMO_OUT={d}/out", f"LANG_OUT=en;touch {marker}")
            self.assertFalse(marker.exists())

    def test_a_file_given_as_skills_dir_is_named_as_such(self):
        with tempfile.NamedTemporaryFile() as f:
            result = self.make("link", f"SKILLS_DIR={f.name}", "AGENT=", "PROJECT=")
        self.assertIn("is not a directory", result.stdout)

    def test_goals_keep_their_order_under_jobs(self):
        self.assertRegex((REPO / "Makefile").read_text(encoding="utf-8"),
                         re.compile(r"^\.NOTPARALLEL:", re.M))


if __name__ == "__main__":
    unittest.main()
