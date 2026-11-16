"""The rendered pages explain every severity and confidence level, in both languages."""

import contextlib
import io
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "prune-scan" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import render  # noqa: E402
from findings import CONFIDENCES, SEVERITIES  # noqa: E402
from scan_report_kit.report import esc  # noqa: E402

SAMPLES = {"en": ROOT / "examples" / "findings.sample.json", "ja": ROOT / "examples" / "findings.sample.ja.json"}


class LevelsLegendTests(unittest.TestCase):
    def test_every_level_has_a_legend_line_in_both_languages(self):
        for lang in ("en", "ja"):
            levels = render.LABELS[lang]["levels"]
            for level in (*SEVERITIES, *CONFIDENCES, "title", "severity", "confidence", "closing"):
                with self.subTest(lang=lang, level=level):
                    self.assertTrue(levels.get(level, "").strip())

    def test_closing_line_sends_inferred_purpose_findings_to_decisions(self):
        for lang, decisions in (("en", "decisions"), ("ja", "判断事項")):
            with self.subTest(lang=lang):
                closing = render.LABELS[lang]["levels"]["closing"]
                self.assertIn("Purpose-dependent", closing)
                self.assertIn(decisions, closing)

    def test_sample_report_and_dashboard_show_the_legend(self):
        for lang, sample in SAMPLES.items():
            with tempfile.TemporaryDirectory() as tmp:
                out = Path(tmp)
                shutil.copy(sample, out / "findings.json")
                shutil.copy(ROOT / "examples" / "units.sample.json", out / "units.json")
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(render.main([str(out / "findings.json"), "--out", str(out),
                                                  "--lang", lang, "--no-pdf"]), 0)
                levels = render.LABELS[lang]["levels"]
                for page in ("report.html", "dashboard.html"):
                    html = (out / page).read_text(encoding="utf-8")
                    with self.subTest(lang=lang, page=page):
                        self.assertEqual(html.count("id='levels'"), 1)
                        section = html[html.index("id='levels'"):]
                        for key in ("title", *SEVERITIES, *CONFIDENCES, "closing"):
                            self.assertIn(esc(levels[key]), section)


if __name__ == "__main__":
    unittest.main()
