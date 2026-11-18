"""summary.py: the chat summary printed from the record."""
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

from support import REPO, complete_doc, finding, render, run_main, summary, write_record


class ChatSummary(unittest.TestCase):
    def test_counts_and_lines_match_the_report(self):
        doc = complete_doc()
        doc["findings"].append(finding("P-003", "Low", validation={
            "verdict": "FalsePositive", "method": "static", "evidence": "app/a.py:1"}))
        text = summary.render_summary(doc, "en", "/run/findings.json")
        first = text.split("\n", 1)[0]
        report_first = render.render_markdown(doc, "en").split("\n")[2]
        self.assertTrue(first.startswith(report_first.split(" · ")[0]))
        self.assertIn("Excluded 1", first)
        self.assertIn("- P-001 [High][Confirmed] Valid Order list loads items per order", text)
        self.assertIn("- P-003 [FalsePositive] Order list loads items per order", text)
        self.assertIn("## High findings\n\n### P-001", text)
        self.assertNotIn("### P-002", text)
        self.assertIn("Revision UNKNOWN · Static review", text)

    def test_baseline_line_and_rendered_files(self):
        old = complete_doc()
        new = deepcopy(old)
        del new["findings"][1]
        with tempfile.TemporaryDirectory() as directory:
            current = write_record(directory, "findings.json", new)
            baseline = write_record(directory, "old/findings.json", old)
            (Path(directory) / "report.md").write_text("x", encoding="utf-8")
            code, out, err = run_main(summary.main, current, "--baseline", baseline,
                                      "--scratch", "/tmp/scratch-1", "--lang", "ja")
        self.assertEqual(code, 0, err)
        self.assertIn("新規 0・解消 1・未再確認 0・深刻化 0", out)
        self.assertIn("スクラッチ: /tmp/scratch-1", out)
        self.assertIn("report.md`", out)
        self.assertNotIn("dashboard.html", out)

    def test_record_text_is_escaped(self):
        doc = complete_doc()
        doc["findings"][0]["title"] = "**bold** [x](https://evil.example)"
        text = summary.render_summary(doc, "en", "findings.json")
        self.assertNotIn("**bold**", text)
        self.assertNotIn("](https://", text)

    def test_the_sample_prints(self):
        code, out, err = run_main(summary.main, REPO / "examples" / "findings.sample.json")
        self.assertEqual(code, 0, err)
        self.assertTrue(out.startswith("High 1 / Medium 1 / Low 1 / Info 0"))


if __name__ == "__main__":
    unittest.main()
