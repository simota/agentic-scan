"""Dashboard printing, empty filters, contrast, wrapping and bidi; Makefile edges."""
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

from test_architecture_scan import REPO, complete_doc, make_env, render


class DashboardTests(unittest.TestCase):
    def test_printing_opens_every_finding_and_hides_the_filter(self):
        self.assertIn("beforeprint", render.JS)
        self.assertIn("d.open=true", render.JS)
        self.assertIn("@media print{[data-filter]{display:none}}", render.CSS)

    def test_a_filter_with_no_match_has_a_message(self):
        html = render.render_html(complete_doc(), "en")
        self.assertIn("<p data-empty hidden>None.</p>", html)
        self.assertNotIn("<p data-empty", render.render_html({**complete_doc(), "findings": []}, "en"))

    def test_excluded_findings_keep_full_contrast(self):
        self.assertNotIn("opacity", render.CSS)

    def test_long_titles_and_project_names_wrap(self):
        self.assertIn("h1,summary{overflow-wrap:anywhere}", render.CSS)

    def test_bidi_controls_are_shown_not_applied(self):
        doc = complete_doc()
        doc["findings"][0]["title"] = "Refund ‮evil⁦x"
        for output in (render.render_html(doc, "en"), render.render_markdown(doc, "en")):
            self.assertNotRegex(output, "[‪-‮⁦-⁩]")
            self.assertIn("U+202E", output)


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
