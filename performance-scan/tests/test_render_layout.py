"""Report and dashboard structure: sections, tables, fallbacks and language labels."""
import json
import tempfile
import unittest
from pathlib import Path

from support import REPO, HtmlTreeReader, complete_doc, element_text, finding, findings, render, run_main


class ReportLayoutTests(unittest.TestCase):
    def test_index_excluded_section_method_and_budget_links(self):
        doc = complete_doc()
        doc["meta"]["method"] = "Static review"
        doc["findings"][0]["budget"] = "B-01"
        doc["findings"].append(finding("P-003", "High", budget="B-01", validation={
            "verdict": "NotApplicable", "method": "static", "evidence": "x.py:3"}))
        report = render.render_markdown(doc, "en")
        self.assertIn("| Method | Static review |", report)
        self.assertIn("| ID | Severity | Confidence | Verdict | Title | Location |", report)
        self.assertIn("| P-003 | High | Confirmed | NotApplicable |", report)
        findings_part, excluded_part = report.split("## Excluded findings")
        self.assertNotIn("### P-003", findings_part)
        self.assertIn("### P-003 [NotApplicable] ", excluded_part)
        self.assertNotIn("**status:**", excluded_part.split("## Performance budgets")[0])
        budget = next(line for line in report.splitlines() if line.startswith("| B-01 |"))
        self.assertTrue(budget.endswith(" | P-001 |"))
        html = render.render_html(doc, "en")
        self.assertIn("<td>P-001</td>", html)
        self.assertEqual(html.count("<dt>status</dt>"), 2)

    def test_report_lists_every_perspective_in_canonical_order(self):
        doc = complete_doc()
        doc["perspectives"] = list(reversed(doc["perspectives"][1:]))
        report = render.render_markdown(doc, "en")
        rows = [line.split(" | ")[0][2:] for line in report.splitlines()
                if line.startswith("| ") and line.split(" | ")[0][2:] in findings.PERSPECTIVES]
        self.assertEqual(rows, list(findings.PERSPECTIVES))
        self.assertIn("| Database access | — |  |", report)

    def test_dashboard_perspective_table_has_headers_and_no_blank_evidence(self):
        doc = complete_doc()
        doc["findings"][1]["validation"] = {"verdict": "Likely", "method": "static"}
        html = render.render_html(doc, "ja")
        self.assertIn("<th scope='col'>状態</th><th scope='col'>メモ</th>", html)
        self.assertEqual(html.count("<dt>evidence</dt>") + html.count("<dt>根拠</dt>"), 1)

    def test_blank_reference_titles_and_commits_fall_back_to_visible_text(self):
        doc = complete_doc()
        doc["meta"]["commit"] = ""
        doc["findings"][0]["references"] = [{"title": " ", "url": "https://example.test/doc"}]
        report = render.render_markdown(doc, "en")
        html = render.render_html(doc, "en")
        self.assertIn("| Revision | UNKNOWN |", report)
        self.assertIn("[https&#58;//example.test/doc](<https://example.test/doc>)", report)
        self.assertIn(" · UNKNOWN · ", html)
        self.assertIn(">https://example.test/doc</a>", html)

    def test_report_labels_follow_the_language_and_name_the_perspective(self):
        doc = complete_doc()
        report = render.render_markdown(doc, "ja")
        self.assertIn("| 範囲 | repo root |", report)
        self.assertIn("| 観点 | 状態 | メモ |", report)
        self.assertNotIn("| Scope |", report)
        self.assertIn("- **観点:** Database access (DB1)", report)
        del doc["findings"][0]["step"]
        report = render.render_markdown(doc, "en")
        self.assertIn("| Scope | repo root |", report)
        self.assertIn("- **perspective:** Database access\n", report)
        self.assertIn("· Database access (DB1)</span>", render.render_html(complete_doc(), "en"))


class AppShellTests(unittest.TestCase):
    def test_dashboard_opts_into_the_kit_shell_with_contents_and_facets(self):
        doc = complete_doc()
        doc["findings"].append(finding("P-003", "High", validation={
            "verdict": "NotApplicable", "method": "static", "evidence": "x.py:3"}))
        for budgets in (doc.get("budgets", []), []):
            doc["budgets"] = budgets
            with self.subTest(budgets=bool(budgets)):
                root = HtmlTreeReader(render.render_html(doc, "en")).root
                self.assertEqual(root.find("html").get("class"), "app-shell")
                self.assertIsNotNone(root.find(".//header[@class='cx-band']"))
                targets = [a.get("href")[1:] for a in root.findall(".//nav[@id='nav']//a")]
                expected = ["triage", "findings", "overview"] + (["budgets"] if budgets else []) + ["coverage", "lists"]
                self.assertEqual(targets, expected)
                for target in targets:
                    self.assertIsNotNone(root.find(f".//*[@id='{target}']"), target)
                # Facets count what their filter shows: included findings only.
                facets = {b.get("data-sev"): int(b.findtext("span[@class='facet-n']"))
                          for b in root.findall(".//button[@class='facet']")}
                shown = {s: sum(d.get("data-sev") == s for d in root.findall(".//details"))
                         for s in ("High", "Medium", "Low", "Info")}
                self.assertEqual(facets, shown)


class DashboardFeedbackTests(unittest.TestCase):
    """Keyboard reach, filter feedback and exclusion marks on the dashboard."""

    def doc_with_excluded(self):
        doc = complete_doc()
        doc["findings"].append(finding("P-003", "Medium", validation={
            "verdict": "FalsePositive", "method": "static", "evidence": "x.py:3"}))
        return doc

    def test_tables_are_named_focusable_regions(self):
        for lang in ("en", "ja"):
            with self.subTest(lang=lang):
                labels = render.LABELS[lang]
                root = HtmlTreeReader(render.render_html(complete_doc(), lang)).root
                wraps = root.findall(".//div[@class='tablewrap']")
                self.assertTrue(wraps)
                for wrap in wraps:
                    # A sideways-scrolling table must be reachable without a pointer.
                    self.assertEqual((wrap.get("role"), wrap.get("tabindex")), ("region", "0"))
                self.assertEqual({w.get("aria-label") for w in wraps},
                                 {labels["perspectives"]} | ({labels["budgets"]} if complete_doc().get("budgets") else set()))

    def test_filter_status_counts_findings_and_names_an_empty_result(self):
        doc = self.doc_with_excluded()
        for lang in ("en", "ja"):
            with self.subTest(lang=lang):
                labels = render.LABELS[lang]
                root = HtmlTreeReader(render.render_html(doc, lang)).root
                status = root.find(".//*[@id='result-count']")
                self.assertEqual(status.get("role"), "status")
                total = len(doc["findings"])
                self.assertEqual(element_text(status), labels["filter_shown"].format(shown=total, total=total))
                self.assertEqual(status.get("data-shown"), labels["filter_shown"])
                self.assertEqual(status.get("data-empty"), labels["filter_empty"])
        doc["findings"] = []
        root = HtmlTreeReader(render.render_html(doc, "en")).root
        # With nothing to filter, the section already says None.
        self.assertIsNone(root.find(".//*[@id='result-count']"))

    def test_copy_results_have_a_polite_announcer(self):
        root = HtmlTreeReader(render.render_html(complete_doc(), "en")).root
        announcer = root.find(".//*[@id='announce']")
        self.assertEqual((announcer.get("role"), announcer.get("class")), ("status", "sr-only"))
        self.assertIn("getElementById('announce')", render.JS)

    def test_an_excluded_summary_is_badged_as_excluded_not_by_severity(self):
        root = HtmlTreeReader(render.render_html(self.doc_with_excluded(), "en")).root
        badges = {d.get("data-sev"): d.find("summary/span").get("class")
                  for d in root.findall(".//details")}
        self.assertEqual(badges["High"], "badge High")
        self.assertEqual(badges["excluded"], "badge excluded")
        excluded = next(d for d in root.findall(".//details") if d.get("data-sev") == "excluded")
        # The recorded severity and verdict stay readable beside the exclusion mark.
        self.assertEqual(element_text(excluded.find("summary/span[@class='small']")),
                         "· FalsePositive · Medium · Confirmed · Database access (DB1)")


class AllExcludedLayoutTests(unittest.TestCase):
    def test_an_all_excluded_record_does_not_say_none_under_its_index(self):
        doc = complete_doc()
        for f in doc["findings"]:
            f["validation"] = {"verdict": "NotApplicable", "method": "static", "evidence": "a.py:1"}
        doc["findings"][0]["location"] = ["a.py:3", "c.py:4"]
        report = render.render_markdown(doc, "en")
        findings_part = report.split("## Findings")[1].split("## Excluded findings")[0]
        self.assertNotIn("None.", findings_part)
        self.assertIn("| a.py:3 (+1) |", findings_part)


class LanguageNoteTests(unittest.TestCase):
    def test_overriding_the_record_language_is_noted(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "findings.json"
            source.write_text(json.dumps(complete_doc()), encoding="utf-8")
            code, _, err = run_main(render.main, source, "--out", directory, "--lang", "ja")
            self.assertEqual(code, 0)
            self.assertEqual(err, "render: note: labels in ja, but the record's text is in en\n")
            code, _, err = run_main(render.main, source, "--out", directory, "--lang", "en")
            self.assertEqual((code, err), (0, ""))



class BlankOptionalFieldTests(unittest.TestCase):
    def test_blank_optional_fields_and_commit_are_not_rendered_blank(self):
        doc = complete_doc()
        doc["meta"]["commit"] = "   "
        doc["findings"][0].update(contrast="", budget=" ")
        report, html = render.render_markdown(doc, "en"), render.render_html(doc, "en")
        self.assertIn("| Revision | UNKNOWN |", report)
        self.assertIn(" · UNKNOWN · ", html)
        self.assertNotIn("**contrast:**", report)
        self.assertNotIn("**budget:**", report)
        self.assertNotIn("<dt>contrast</dt>", html)


class LevelLegendTests(unittest.TestCase):
    """The "How to read the levels" legend: one line per level, on both pages, in both languages."""

    def test_every_severity_and_confidence_has_a_legend_line_in_each_language(self):
        for lang in ("en", "ja"):
            legend = render.LABELS[lang]["legend"]
            for level in findings.SEVERITIES + findings.CONFIDENCES + ("separate", "assumed"):
                with self.subTest(lang=lang, level=level):
                    self.assertTrue(legend.get(level, "").strip())

    def test_the_sample_report_and_dashboard_carry_the_legend(self):
        sample = REPO / "examples" / "findings.sample.json"
        for lang in ("en", "ja"):
            t = render.LABELS[lang]
            with self.subTest(lang=lang), tempfile.TemporaryDirectory() as directory:
                code, _, _ = run_main(render.main, sample, "--out", directory, "--lang", lang)
                self.assertEqual(code, 0)
                report = (Path(directory) / "report.md").read_text(encoding="utf-8")
                html = (Path(directory) / "dashboard.html").read_text(encoding="utf-8")
                self.assertIn(f"## {t['levels']}\n", report)
                self.assertIn(f"<h2>{t['levels']}</h2>", html)
                for level in findings.SEVERITIES + findings.CONFIDENCES:
                    self.assertIn(f"- **{level}:** {t['legend'][level]}\n", report)
                    self.assertIn(f"<dt>{level}</dt><dd>{render.html_text(t['legend'][level])}</dd>", html)
                self.assertIn(t["legend"]["separate"], report)
                self.assertIn(render.html_text(t["legend"]["separate"]), html)

    def test_the_assumed_axis_line_appears_only_when_the_axis_is_assumed(self):
        doc = complete_doc()
        for axis in ("confirmed", "assumed", None):
            if axis is None:
                del doc["meta"]["axis"]
            else:
                doc["meta"]["axis"] = axis
            for lang in ("en", "ja"):
                note = render.LABELS[lang]["legend"]["assumed"]
                with self.subTest(axis=axis, lang=lang):
                    report, html = render.render_markdown(doc, lang), render.render_html(doc, lang)
                    self.assertEqual(note in report, axis == "assumed")
                    self.assertEqual(render.html_text(note) in html, axis == "assumed")
        self.assertEqual(render.LABELS["en"]["legend"]["assumed"],
                         "Severity rests on an assumed list; see decisions.")


if __name__ == "__main__":
    unittest.main()
