"""How to read the levels: the severity and confidence legend on both report pages."""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import tempfile
import unittest

from test_report_outputs import ReportHTML
from test_security_scan import import_module

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills/security-scan/scripts"
SAMPLES = {"en": ROOT / "examples/findings.sample.json", "ja": ROOT / "examples/findings.sample.ja.json"}


class LevelLegendTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.renderer = import_module(SCRIPTS / "render.py", "tested_renderer_legend")

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="security-scan-legend-")).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def lines(self, lang):
        L = self.renderer.LABELS[lang]
        return ([L["legend_sev_" + s] for s in self.renderer.SEVERITIES] +
                [L["legend_conf_" + c] for c in self.renderer.CONFIDENCES] + [L["legend_separate"]])

    def legends(self, lang, axis):
        data = json.loads(SAMPLES[lang].read_text(encoding="utf-8"))
        data["meta"]["axis"] = axis
        findings = self.tmp / f"{lang}-{axis}.json"
        findings.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        out = self.tmp / f"{lang}-{axis}"
        self.assertEqual(self.renderer.main([str(findings), "--out", str(out), "--lang", lang, "--no-pdf"]), 0)
        # Parsed markup only: the dashboard's JSON payload also carries every label.
        return {page: ReportHTML((out / page).read_text(encoding="utf-8")).root.find(id="level-legend").text()
                for page in ("assessment.html", "dashboard.html")}

    def test_every_severity_and_confidence_has_a_legend_line_in_every_language(self):
        for lang, L in self.renderer.LABELS.items():
            keys = (["legend", "legend_severity", "legend_confidence", "legend_separate", "legend_assumed"] +
                    ["legend_sev_" + s for s in self.renderer.SEVERITIES] +
                    ["legend_conf_" + c for c in self.renderer.CONFIDENCES])
            for key in keys:
                with self.subTest(lang=lang, key=key):
                    self.assertTrue(L.get(key, "").strip())

    def test_the_hand_filled_report_templates_copy_the_legend_unchanged(self):
        for lang in SAMPLES:
            template = (ROOT / f"skills/security-scan/templates/report.{lang}.md").read_text(encoding="utf-8")
            L = self.renderer.LABELS[lang]
            for line in [L["legend"], L["legend_assumed"]] + self.lines(lang):
                with self.subTest(lang=lang, line=line[:30]):
                    self.assertIn(line, template)

    def test_the_legend_appears_in_the_assessment_and_the_dashboard(self):
        for lang in SAMPLES:
            L = self.renderer.LABELS[lang]
            for page, text in self.legends(lang, "confirmed").items():
                with self.subTest(lang=lang, page=page):
                    self.assertIn(L["legend"], text)
                    for level in self.renderer.SEVERITIES + self.renderer.CONFIDENCES:
                        self.assertIn(level, text)
                    for line in self.lines(lang):
                        self.assertIn(line, text)

    def test_the_assumed_axis_line_appears_only_when_the_axis_is_assumed(self):
        for lang in SAMPLES:
            assumed = self.renderer.LABELS[lang]["legend_assumed"]
            for axis, expected in (("confirmed", False), ("assumed", True)):
                for page, text in self.legends(lang, axis).items():
                    with self.subTest(lang=lang, axis=axis, page=page):
                        self.assertEqual(assumed in text, expected)


if __name__ == "__main__":
    unittest.main()
