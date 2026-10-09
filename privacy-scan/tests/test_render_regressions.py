"""Regression checks for report contents and output preservation on failure."""
import io
import json
from contextlib import redirect_stdout
from html import escape
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_privacy_scan import complete_doc, render


class CommitmentRenderingTests(unittest.TestCase):
    def render_outputs(self, doc, lang):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            source = out / "findings.json"
            source.write_text(json.dumps(doc), encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                self.assertEqual(render.main([str(source), "--out", str(out), "--lang", lang]), 0)
            return {name: (out / name).read_text(encoding="utf-8")
                    for name in ("report.md", "dashboard.html")}

    def test_inferred_commitment_is_labeled_in_both_languages(self):
        doc = complete_doc()
        doc["commitments"][0]["inferred"] = True
        for lang, label in (("en", "inferred"), ("ja", "推定")):
            outputs = self.render_outputs(doc, lang)
            for name, output in outputs.items():
                with self.subTest(lang=lang, output=name):
                    self.assertIn(f"no PII in errors ({label})", output)

    def test_not_checked_reason_is_visible_and_html_escaped(self):
        doc = complete_doc()
        reason = "Deployment <region> & policy configuration is unavailable"
        doc["commitments"][0].update(status="not checked", reason=reason)
        for lang, label in (("en", "reason"), ("ja", "未確認の理由")):
            outputs = self.render_outputs(doc, lang)
            for name, output in outputs.items():
                with self.subTest(lang=lang, output=name):
                    expected = f"not checked — {label}: {reason}"
                    self.assertIn(escape(expected), output)
                    self.assertNotIn("<region>", output)

    def test_markdown_commitment_cells_keep_special_characters_in_one_row(self):
        for newline in ("\n", "\r\n", "\r"):
            with self.subTest(newline=repr(newline)):
                doc = complete_doc()
                reason = ("Missing IAM permission | no account access" + newline
                          + r"See C:\config\|regions <region> & policy")
                doc["commitments"][0].update(
                    statement="No PII <email> | storage", source=r"docs\policy.md:3",
                    status="not checked", reason=reason,
                )
                markdown = self.render_outputs(doc, "en")["report.md"]
                row = next(line for line in markdown.splitlines() if line.startswith("| C-01 |"))
                self.assertEqual(
                    row,
                    r"| C-01 | No PII &lt;email&gt; \| storage | docs\\policy.md:3 | "
                    r"not checked — reason: Missing IAM permission \| no account access<br>"
                    r"See C:\\config\\\|regions &lt;region&gt; &amp; policy |",
                )

    def test_optional_inferred_flag_preserves_unqualified_commitments(self):
        for inferred in (None, False):
            doc = complete_doc()
            if inferred is not None:
                doc["commitments"][0]["inferred"] = inferred
            for lang in ("en", "ja"):
                with self.subTest(inferred=inferred, lang=lang):
                    outputs = self.render_outputs(doc, lang)
                    self.assertIn("| C-01 | no PII in errors | policy | violated |", outputs["report.md"])
                    self.assertIn("<tr><td>C-01</td><td>no PII in errors</td>"
                                  "<td>policy</td><td>violated</td></tr>", outputs["dashboard.html"])


class RenderFailureTests(unittest.TestCase):
    def assert_outputs_preserved(self, failed_renderer, existing):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "findings.json"
            source.write_text(json.dumps(complete_doc()), encoding="utf-8")
            out = root / "out"
            previous = {"report.md": b"previous report\n",
                        "dashboard.html": b"previous dashboard\n"}
            if existing:
                out.mkdir()
                for name, content in previous.items():
                    (out / name).write_bytes(content)
            with patch.object(render, failed_renderer,
                              side_effect=RuntimeError("synthetic rendering failure")):
                with self.assertRaisesRegex(RuntimeError, "synthetic rendering failure"):
                    render.main([str(source), "--out", str(out)])
            for name, content in previous.items():
                if existing:
                    self.assertEqual((out / name).read_bytes(), content)
                else:
                    self.assertFalse((out / name).exists(), name)

    def test_render_failure_preserves_existing_outputs(self):
        for failed_renderer in ("render_markdown", "render_html"):
            with self.subTest(renderer=failed_renderer):
                self.assert_outputs_preserved(failed_renderer, existing=True)

    def test_render_failure_creates_no_partial_outputs(self):
        for failed_renderer in ("render_markdown", "render_html"):
            with self.subTest(renderer=failed_renderer):
                self.assert_outputs_preserved(failed_renderer, existing=False)


if __name__ == "__main__":
    unittest.main()
