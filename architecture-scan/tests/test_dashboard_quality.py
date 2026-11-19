"""Dashboard printing, empty filters, contrast, wrapping and bidi; Makefile edges."""
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

from test_architecture_scan import REPO, complete_doc, findings, make_env, render


def page_style(doc=None):
    """The stylesheet the rendered dashboard inlines (the bundled report kit's, then this skill's)."""
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
        # The console layer fades only two verdict swatches (Likely, Unlikely), never a record.
        style = page_style().replace(render.report_style.console_css(), "")
        self.assertNotIn("opacity", style)
        faded = re.findall(r"([^{}]+)\{[^}]*opacity", render.report_style.console_css())
        self.assertEqual([selector.strip() for selector in faded], [".cx-t-mid", ".cx-t-weak"])

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
        # The kit scopes its sidebar and pinned filters to html.app-shell; the console band
        # replaces its app bar and holds the page's one h1.
        html = render.render_html(complete_doc(), "en")
        self.assertIn("<html lang='en' class='app-shell'>", html)
        self.assertIn("<header class='cx-band'>", html)
        self.assertNotIn("class='appbar'", html)
        self.assertEqual(len(re.findall(r"<h1[ >]", html)), 1)
        nav = re.search(r"<nav class='sidebar'.*?</nav>", html, re.S)[0]
        targets = re.findall(r'href="#([^"]+)"', nav)
        self.assertIn("findings", targets)
        for target in targets:
            self.assertIn(f"id='{target}'", html)
        self.assertEqual(len(re.findall(r"<button type='button' class='facet'", nav)), len(render.SEVERITIES))
        empty = render.render_html({**complete_doc(), "findings": []}, "en")
        self.assertNotIn("class='facet'", empty)

    def test_a_broken_rule_and_a_coverage_gap_are_marked_beside_their_word(self):
        doc = complete_doc()
        doc["rules"][0]["status"] = "partly read"
        doc["perspectives"][0]["status"] = "not checked"
        doc["perspectives"][1]["status"] = "N/A"
        html = render.render_html(doc, "en")
        rules = html.split("id='rules-section'", 1)[1].split("</table>", 1)[0]
        coverage = html.split("class='coverage-table'", 1)[1].split("</table>", 1)[0]
        self.assertIn("<span class='state gap'>partly read</span>", rules)
        self.assertIn("<span class='state gap'>not checked</span>", coverage)
        self.assertIn("<span class='state na'>N/A</span>", coverage)
        self.assertIn("<span class='state'>applied</span>", coverage)
        self.assertEqual(render.html_state("violated"), "<span class='state bad'>violated</span>")
        self.assertEqual(render.html_state("holds"), "<span class='state'>holds</span>")
        # The word carries the meaning; colour and weight only reinforce it.
        style = page_style()
        self.assertRegex(style, r"\.state\.bad\{color:var\(--high\);font-weight:700\}")
        self.assertRegex(style, r"\.state\.gap\{font-weight:700;font-style:italic\}")
        # Every status either schema allows is plain or has a style.
        for status in findings.RULE_STATUSES + findings.PERSPECTIVE_STATUSES + ("—",):
            cls = render.STATE_CLASS.get(status)
            self.assertTrue(cls is None or f".state.{cls}{{" in style, status)

    def test_wide_filter_values_are_given_room(self):
        style = page_style()
        # On a wide screen the count and reset move under the filters, which keep the full width.
        self.assertRegex(style, r"@media\(min-width:1100px\)\{\.app-shell \.filters-panel\{display:block\}")
        # On a phone the perspective and order controls take a whole row.
        self.assertIn("@media(max-width:480px){.app-shell .filters .wide{grid-column:1/-1}}", style)
        html = render.render_html(complete_doc(), "en")
        self.assertRegex(html, r"<label class='wide'><span>[^<]*</span><select id='f-cat'>")
        self.assertRegex(html, r"<label class='wide'><span>[^<]*</span><select id='f-sort'>")

    def test_the_diagram_text_list_is_a_full_size_target_apart_from_the_next_heading(self):
        style = page_style()
        self.assertIn(".arch-text>summary{padding:4px 0;cursor:pointer}", style)
        self.assertIn(".arch>h3{margin-top:24px}", style)

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
