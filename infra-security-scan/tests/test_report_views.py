"""Dashboard and assessment views: print, counts, links, language and LLM copy."""
import contextlib
import io
import json
from pathlib import Path
import re
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "skills" / "infra-security-scan" / "scripts"))
import render  # noqa: E402

SAMPLE = REPO / "examples" / "findings.sample.json"
SAMPLE_JA = REPO / "examples" / "findings.sample.ja.json"


def pages(source, lang):
    with tempfile.TemporaryDirectory() as tmp:
        with contextlib.redirect_stdout(io.StringIO()):
            code = render.main([str(source), "--out", tmp, "--lang", lang, "--no-pdf"])
        if code != 0:
            raise AssertionError(f"render.main returned {code}")
        return [(Path(tmp) / n).read_text(encoding="utf-8") for n in ("dashboard.html", "assessment.html")]


class ReportViewTest(unittest.TestCase):
    def test_print_css_wraps_excerpts_and_forces_light_colors(self):
        dash, report = pages(SAMPLE, "en")
        # Printed excerpts wrap: inside the dashboard's print block; always in the paper document.
        self.assertRegex(dash, r"@media print\{[^@]*\.snippet\{white-space:pre-wrap;overflow:visible\}")
        self.assertRegex(report, r"\.snippet\{[^}]*white-space:pre-wrap;[^}]*overflow:visible")
        # Print is light: the kit forces light tokens and the console skips the document in both dark modes.
        self.assertIn('@media print{html:root:not([data-theme="light"]),html:root[data-theme]{color-scheme:light', dash)
        self.assertIn('<html lang="en" class="cx-doc">', report)
        for dark_selector in (':root:not([data-theme="light"])', ':root[data-theme="dark"]'):
            self.assertIn(dark_selector + ':not(.cx-doc)', report)
            self.assertNotIn(dark_selector + ' {', report)
        self.assertIn("tr.row:not([hidden])+tr.detail{display:table-row!important}", dash)
        self.assertNotIn("tr.detail{display:table-row!important}}", dash.replace("+tr.detail", ""))
        self.assertIn(".ap{break-inside:avoid-page}", report)
        for page in (dash, report):
            opacity_rules = re.findall(r"([^\n{}]+)\s*\{[^{}]*\bopacity:", page.split("</style>")[0])
            self.assertEqual([rule.strip() for rule in opacity_rules], [".cx-t-mid", ".cx-t-weak"])

    def test_dashboard_opts_into_the_kit_application_shell(self):
        # The kit scopes its sidebar and pinned register to html.app-shell.
        dash, _ = pages(SAMPLE, "en")
        data = json.loads(SAMPLE.read_text(encoding="utf-8"))
        self.assertIn('<html lang="en" class="app-shell">', dash)
        self.assertIn('<header class="cx-band">', dash)
        self.assertNotIn('class="masthead"', dash)
        nav = dash.split('<nav class="sidebar"')[1].split("</nav>")[0]
        hrefs = re.findall(r'<a href="#([^"]+)">', nav)
        self.assertEqual(len(hrefs), 8)
        self.assertEqual(hrefs[:2], ["triage", "findings"])
        for href in hrefs:
            self.assertIn(f'id="{href}"', dash, href)
        # Facets count what the severity cards count.
        counts = render.counts(data)
        for s in render.SEVERITIES:
            self.assertIn(f'data-sev="{s}" aria-controls="findings" aria-pressed="false">'
                          f'<span class="facet-name {s}">{s}</span><span class="facet-n">{counts[s]}</span>', dash)
        ja, _ = pages(SAMPLE_JA, "ja")
        self.assertIn('aria-label="目次"', ja)
        self.assertIn("<kbd>Enter</kbd> 詳細の表示・非表示", ja)

    def test_japanese_pages_translate_perspectives_and_inputs(self):
        dash, report = pages(SAMPLE_JA, "ja")
        for name in render.perspective_names():
            if name != "Kubernetes":
                self.assertNotIn(f">{name}<", dash + report, name)
        self.assertIn("プラン JSON:", report)

    def test_dashboard_shows_scope_inventory_and_links_reveal_rows(self):
        dash, _ = pages(SAMPLE, "en")
        data = json.loads(SAMPLE.read_text(encoding="utf-8"))
        self.assertIn("Scope and method", dash)
        for item in data["inventory"]["not_run"]:
            self.assertIn(item, dash)
        self.assertIn("addEventListener('hashchange',reveal)", dash)
        # A second press of the same link fires no hashchange; the click handler reveals the row.
        self.assertIn("a.hash===location.hash&&reveal()", dash)
        self.assertIn('aria-controls="F-001-detail"', dash)
        self.assertIn('id="F-001-detail"', dash)
        # The kit's fixed 7-column widths and mobile card layout apply only to .register.
        self.assertEqual(dash.count('<table class="register"'), 1)

    def test_markdown_keeps_fields_out_of_multiline_sections(self):
        data = json.loads(SAMPLE.read_text(encoding="utf-8"))
        f = next(x for x in data["findings"] if x["id"] == "F-001")
        f["validation"]["evidence"] = "Read at main.tf:3 and confirmed:"
        md = render.finding_markdown(f, render.LABELS["en"], "en")
        head, _, rest = md.partition("### Attack path")
        self.assertIn("- Impact:", head)
        self.assertIn("- Fix direction:", head)
        self.assertNotIn("- Impact:", rest)
        self.assertIn("### References", md)
        self.assertIn("confirmed:", md)
        self.assertIn("- Attack paths: " + ", ".join(f["attack_paths"]), md)
        ja = render.finding_markdown(f, render.LABELS["ja"], "ja")
        self.assertIn("深刻度: 高", ja)
        self.assertNotIn(": High", ja)

    def test_english_pages_spell_out_camel_case_verdicts(self):
        dash, report = pages(SAMPLE, "en")
        row = re.search(r'<tr class="row excluded" id="F-003"[^>]*>(.*?)</tr>', dash).group(1)
        self.assertIn('data-label="Verdict">False positive</td>', row)
        self.assertIn('data-ver="FalsePositive"', dash)  # the filter still matches the canonical value
        self.assertIn('<option value="NotApplicable">Not applicable</option>', dash)
        self.assertNotIn(">FalsePositive<", dash + report)

    def test_filters_that_hide_every_finding_offer_one_step_back(self):
        dash, _ = pages(SAMPLE, "en")
        self.assertRegex(dash, r'<tr class="no-match" hidden><td colspan="7" class="empty"><p>No findings match these filters\.</p>'
                               r'<button class="clear-filters" type="button">Clear filters</button></td></tr></tbody>')
        self.assertIn("noMatch.hidden=n+xe+xc>0", dash)
        data = render.empty_record()
        data["meta"] = json.loads(SAMPLE.read_text(encoding="utf-8"))["meta"]
        with tempfile.TemporaryDirectory() as tmp:
            empty = Path(tmp) / "findings.json"
            empty.write_text(json.dumps(data), encoding="utf-8")
            dash, _ = pages(empty, "ja")
        # An empty register says so once; there is nothing to clear.
        self.assertNotIn('class="no-match"', dash)
        self.assertIn('<td colspan="7" class="empty">記録なし。</td>', dash)

    def test_theme_toggle_exposes_its_state(self):
        dash, _ = pages(SAMPLE, "en")
        self.assertIn('<button id="theme" type="button" aria-pressed="false">Toggle color theme</button>', dash)
        self.assertIn("themeBtn.setAttribute('aria-pressed',String(dark()))", dash)

    def test_unchecked_perspectives_stand_out_and_the_counts_corner_heads_nothing(self):
        dash, report = pages(SAMPLE, "en")
        self.assertIn('Governance and guardrails<span class="st gap">Not checked</span>', dash)
        self.assertIn('Network exposure<span class="st">Applied</span>', dash)
        self.assertIn('<td>Governance and guardrails</td><td class="gap">Not checked</td>', report)
        self.assertIn('<thead><tr><td></td><th scope="col" class="High">', report)
        self.assertNotIn('<th scope="col"></th>', report)


class LevelLegendTest(unittest.TestCase):
    """Both pages say what each severity and confidence level means, in both languages."""

    def test_every_level_has_a_legend_line_in_both_languages(self):
        for lang in render.LABELS:
            for level in (*render.SEVERITIES, *render.CONFIDENCES, "separate", "assumed"):
                with self.subTest(lang=lang, level=level):
                    self.assertTrue(render.LEGEND[lang].get(level, "").strip())

    def test_legend_appears_in_both_pages_for_the_samples(self):
        for source, lang in ((SAMPLE, "en"), (SAMPLE_JA, "ja")):
            L, lines = render.LABELS[lang], render.LEGEND[lang]
            for name, page in zip(("dashboard", "assessment"), pages(source, lang)):
                with self.subTest(lang=lang, page=name):
                    self.assertIn(f"<h2>{L['legend']}</h2>", page)
                    for level in (*render.SEVERITIES, *render.CONFIDENCES):
                        self.assertIn(render.esc(render.shown(level, lang)) + "</", page)
                        self.assertIn(render.esc(lines[level]), page)
                    self.assertIn(render.esc(lines["separate"]), page)
        self.assertIn("How to read the levels", pages(SAMPLE, "en")[1])
        self.assertIn("レベルの読み方", pages(SAMPLE_JA, "ja")[0])

    def test_assumed_line_only_when_the_axis_is_assumed(self):
        for source, lang in ((SAMPLE, "en"), (SAMPLE_JA, "ja")):
            data = json.loads(source.read_text(encoding="utf-8"))
            assumed = render.esc(render.LEGEND[lang]["assumed"])
            for axis in ("confirmed", "assumed", None):
                if axis is None:
                    data["meta"].pop("axis", None)
                else:
                    data["meta"]["axis"] = axis
                with tempfile.TemporaryDirectory() as tmp:
                    src = Path(tmp) / "f.json"
                    src.write_text(json.dumps(data), encoding="utf-8")
                    for name, page in zip(("dashboard", "assessment"), pages(src, lang)):
                        with self.subTest(lang=lang, axis=axis, page=name):
                            (self.assertIn if axis == "assumed" else self.assertNotIn)(assumed, page)


if __name__ == "__main__":
    unittest.main()
