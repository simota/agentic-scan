"""Dashboard and assessment views: print, counts, links, language and LLM copy."""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "skills" / "infra-scan" / "scripts"))
import render  # noqa: E402

SAMPLE = REPO / "examples" / "findings.sample.json"
SAMPLE_JA = REPO / "examples" / "findings.sample.ja.json"


def pages(source, lang):
    with tempfile.TemporaryDirectory() as tmp:
        with contextlib.redirect_stdout(io.StringIO()):
            assert render.main([str(source), "--out", tmp, "--lang", lang, "--no-pdf"]) == 0
        return [(Path(tmp) / n).read_text(encoding="utf-8") for n in ("dashboard.html", "assessment.html")]


class ReportViewTest(unittest.TestCase):
    def test_print_css_wraps_excerpts_and_forces_light_colors(self):
        dash, report = pages(SAMPLE, "en")
        for page in (dash, report):
            self.assertIn("@media print{.snippet{white-space:pre-wrap;overflow:visible}}", page)
            self.assertIn("@media print{:root:not([data-print]),:root[data-theme]{color-scheme:light", page)
        self.assertIn("tr.row:not([hidden])+tr.detail{display:table-row!important}", dash)
        self.assertNotIn("tr.detail{display:table-row!important}}", dash.replace("+tr.detail", ""))
        self.assertIn(".ap{break-inside:avoid-page}", report)
        self.assertNotIn("opacity", dash + report)

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
        self.assertIn('aria-controls="F-001-detail"', dash)
        self.assertIn('id="F-001-detail"', dash)

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
        self.assertIn("- Attack paths: AP-01", md) if f.get("attack_paths") else None
        ja = render.finding_markdown(f, render.LABELS["ja"], "ja")
        self.assertIn("深刻度: 高", ja)
        self.assertNotIn(": High", ja)


if __name__ == "__main__":
    unittest.main()
