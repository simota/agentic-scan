"""The "How to read the levels" legend: one line per level, in both outputs and languages."""
from html import escape
import json
import unittest

from test_architecture_scan import REPO, complete_doc, findings, render

LANGS = ("en", "ja")


def sample() -> dict:
    return json.loads((REPO / "examples" / "findings.sample.json").read_text(encoding="utf-8"))


class LevelLegendTests(unittest.TestCase):
    def test_every_severity_and_confidence_has_a_legend_line_in_both_languages(self):
        for lang in LANGS:
            labels = render.LABELS[lang]
            for level in (*findings.SEVERITIES, *findings.CONFIDENCES):
                with self.subTest(lang=lang, level=level):
                    self.assertTrue(labels.get("level_" + level, "").strip())
            for key in ("levels", "levels_separate", "levels_assumed"):
                with self.subTest(lang=lang, key=key):
                    self.assertTrue(labels.get(key, "").strip())

    def test_the_sample_report_and_dashboard_carry_the_legend(self):
        doc = sample()
        for lang in LANGS:
            labels = render.LABELS[lang]
            markdown = render.render_markdown(doc, lang)
            html = render.render_html(doc, lang)
            with self.subTest(lang=lang):
                self.assertIn(f"\n## {labels['levels']}\n", markdown)
                self.assertIn(f"<h2>{escape(labels['levels'])}</h2>", html)
                self.assertIn("<a href=\"#levels\">", html)
                for level in (*findings.SEVERITIES, *findings.CONFIDENCES):
                    meaning = labels["level_" + level]
                    self.assertIn(f"- **{level}:** {render.markdown_inline(meaning)}\n", markdown)
                    self.assertIn(f"<dt>{level}</dt><dd>{escape(meaning)}</dd>", html)
                self.assertIn(escape(labels["levels_separate"]), html)
                self.assertIn(render.markdown_inline(labels["levels_separate"]), markdown)

    def test_the_assumed_axis_line_appears_only_when_the_axis_is_assumed(self):
        for lang in LANGS:
            assumed = render.LABELS[lang]["levels_assumed"]
            for axis in ("confirmed", "assumed", None):
                doc = complete_doc()
                if axis is None:
                    del doc["meta"]["axis"]
                else:
                    doc["meta"]["axis"] = axis
                with self.subTest(lang=lang, axis=axis):
                    markdown = render.render_markdown(doc, lang)
                    html = render.render_html(doc, lang)
                    self.assertEqual(render.markdown_inline(assumed) in markdown, axis == "assumed")
                    self.assertEqual(escape(assumed) in html, axis == "assumed")


if __name__ == "__main__":
    unittest.main()
