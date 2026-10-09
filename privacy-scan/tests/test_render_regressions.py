"""Regression checks for report contents, references and output preservation on failure."""
import io
import json
from contextlib import redirect_stdout
from html import escape
from html.parser import HTMLParser
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_privacy_scan import complete_doc, finding, render


class ParsedHTML(HTMLParser):
    def __init__(self, source):
        super().__init__()
        self.tags = []
        self.links = []
        self.text = []
        self.summaries = []
        self._in_summary = False
        self.feed(source)

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        if tag == "a":
            self.links.append(dict(attrs))
        if tag == "summary":
            self.summaries.append("")
            self._in_summary = True

    def handle_endtag(self, tag):
        if tag == "summary":
            self._in_summary = False

    def handle_data(self, data):
        self.text.append(data)
        if self._in_summary:
            self.summaries[-1] += data


class ReportRenderingTests(unittest.TestCase):
    def render_outputs(self, doc, lang):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            source = out / "findings.json"
            source.write_text(json.dumps(doc), encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                self.assertEqual(render.main([str(source), "--out", str(out), "--lang", lang]), 0)
            return {name: (out / name).read_text(encoding="utf-8")
                    for name in ("report.md", "dashboard.html")}

    def assert_overview_counts(self, doc, severities, verdicts, excluded):
        severity_names = ("High", "Medium", "Low", "Info")
        verdict_names = ("Valid", "Likely", "Unverified", "Unlikely", "FalsePositive", "NotApplicable")
        verdict_summary = " / ".join(f"{name} {count}" for name, count in zip(verdict_names, verdicts))
        for lang, label, excluded_label in (("en", "Verdict counts", "Excluded"),
                                            ("ja", "検証判定別の件数", "除外")):
            with self.subTest(lang=lang):
                outputs = self.render_outputs(doc, lang)
                markdown_overview = outputs["report.md"].split("\n## ", 1)[0]
                html_overview = outputs["dashboard.html"].split("<h2>", 1)[0]
                overview_text = "".join(ParsedHTML(html_overview).text)
                self.assertIn(f"**{label}:** {verdict_summary}", markdown_overview)
                self.assertIn(f"{label}: {verdict_summary}", overview_text)
                self.assertIn(
                    " / ".join(f"{name} {count}" for name, count in zip(severity_names, severities))
                    + f" · {excluded_label} {excluded}", markdown_overview)
                self.assertIn(
                    "".join(f"{name}{count}" for name, count in zip(severity_names, severities))
                    + f"{excluded_label}{excluded}", overview_text)

    def test_overviews_count_all_verdicts_and_keep_severity_exclusions(self):
        doc = complete_doc()
        records = (("High", "Likely"), ("High", "Likely"), ("High", "FalsePositive"),
                   ("Medium", "Valid"), ("Medium", "NotApplicable"),
                   ("Low", "Unverified"), ("Info", "Unlikely"))
        doc["findings"] = [
            finding(f"PV-{i:03d}", severity, validation={
                "verdict": verdict, "method": "static", "evidence": "api/app.py:22"})
            for i, (severity, verdict) in enumerate(records, 1)
        ]
        self.assert_overview_counts(doc, (2, 1, 1, 1), (1, 2, 1, 1, 1, 1), 2)

    def test_empty_overviews_show_zero_counts(self):
        doc = complete_doc()
        doc["findings"] = []
        self.assert_overview_counts(doc, (0, 0, 0, 0), (0, 0, 0, 0, 0, 0), 0)

    def test_excluded_only_overviews_show_zero_active_severities(self):
        doc = complete_doc()
        doc["findings"][0]["validation"]["verdict"] = "FalsePositive"
        doc["findings"][1]["validation"]["verdict"] = "NotApplicable"
        self.assert_overview_counts(doc, (0, 0, 0, 0), (0, 0, 0, 0, 1, 1), 2)

    def test_collapsed_findings_show_every_recorded_verdict(self):
        verdicts = ("Valid", "Likely", "Unverified", "Unlikely", "FalsePositive", "NotApplicable")
        doc = complete_doc()
        doc["findings"] = [finding(f"PV-{i:03d}", validation={
            "verdict": verdict, "method": "static", "evidence": "api/app.py:22"})
            for i, verdict in enumerate(verdicts, 1)]
        for lang in ("en", "ja"):
            with self.subTest(lang=lang):
                parsed = ParsedHTML(self.render_outputs(doc, lang)["dashboard.html"])
                self.assertEqual(len(parsed.summaries), len(verdicts))
                for record, summary in zip(doc["findings"], parsed.summaries):
                    self.assertIn(record["id"], summary)
                    self.assertIn(record["validation"]["verdict"], summary)

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
                    r"| C-01 | No PII &lt;email&gt; \| storage |  | docs\\policy.md:3 | "
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
                    self.assertIn("| C-01 | no PII in errors |  | policy | violated |", outputs["report.md"])
                    self.assertIn("<tr><td>C-01</td><td>no PII in errors</td>"
                                  "<td></td><td>policy</td><td>violated</td></tr>", outputs["dashboard.html"])

    def test_references_remain_in_both_outputs_and_languages(self):
        doc = complete_doc()
        doc["findings"][0]["references"] = [
            {"title": "Vendor privacy", "url": "https://example.invalid/privacy"},
            {"title": "SDK reference", "url": "http://example.invalid/reference"},
            {"title": "Local policy", "url": "docs/privacy (policy).md#scope"},
            {"url": "#scope"},
        ]
        expected_links = [
            {"href": "https://example.invalid/privacy"},
            {"href": "http://example.invalid/reference"},
            {"href": "docs/privacy%20(policy).md#scope"},
            {"href": "#scope"},
        ]
        for lang, label in (("en", "references"), ("ja", "参考")):
            with self.subTest(lang=lang):
                outputs = self.render_outputs(doc, lang)
                parsed = ParsedHTML(outputs["dashboard.html"])
                self.assertEqual(parsed.links, expected_links)
                self.assertEqual(outputs["dashboard.html"].count(f"<dt>{label}</dt>"), 4)
                for ref in doc["findings"][0]["references"]:
                    self.assertIn(ref.get("title", ref["url"]), "".join(parsed.text))
                for reference in (
                    "[Vendor privacy](<https://example.invalid/privacy>)",
                    "[SDK reference](<http://example.invalid/reference>)",
                    "[Local policy](<docs/privacy%20(policy).md#scope>)",
                    r"[\#scope](<#scope>)",
                ):
                    self.assertIn(f"- **{label}:** {reference}", outputs["report.md"])

    def test_reference_title_and_url_cannot_add_html_elements_or_attributes(self):
        doc = complete_doc()
        title = '<img src=x onerror=alert(1)> "privacy" & <script>alert(1)</script>'
        url = 'https://example.invalid/docs?value=" onmouseover="alert(1)&kind=<email>'
        doc["findings"][0]["references"] = [{"title": title, "url": url}]
        expected_destination = (
            "https://example.invalid/docs?value=%22%20onmouseover=%22alert(1)&kind=%3Cemail%3E")
        for lang in ("en", "ja"):
            with self.subTest(lang=lang):
                outputs = self.render_outputs(doc, lang)
                parsed = ParsedHTML(outputs["dashboard.html"])
                self.assertEqual(parsed.links, [{"href": expected_destination}])
                self.assertNotIn("img", parsed.tags)
                self.assertEqual(parsed.tags.count("script"), 1)  # The dashboard's fixed script.
                self.assertIn(title, "".join(parsed.text))
                self.assertIn(escape(title), outputs["dashboard.html"])
                self.assertIn(escape(expected_destination), outputs["dashboard.html"])
                self.assertNotIn("<img", outputs["report.md"])
                self.assertNotIn("<script>alert(1)</script>", outputs["report.md"])

    def test_unsupported_or_malformed_html_references_stay_visible_without_links(self):
        urls = (
            "javascript:alert(1)",
            "java\nscript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "file:///private/report.txt",
            "https://[broken",
        )
        for lang, label in (("en", "references"), ("ja", "参考")):
            for url in urls:
                with self.subTest(lang=lang, url=url):
                    doc = complete_doc()
                    title = "Reference <untrusted>"
                    doc["findings"][0]["references"] = [{"title": title, "url": url}]
                    outputs = self.render_outputs(doc, lang)
                    parsed = ParsedHTML(outputs["dashboard.html"])
                    self.assertEqual(parsed.links, [])
                    self.assertEqual(parsed.tags.count("script"), 1)
                    self.assertNotIn("untrusted", parsed.tags)
                    self.assertIn(f"{title} — {url}", "".join(parsed.text))
                    self.assertIn(
                        f"<dt>{label}</dt><dd>{escape(title)} — {escape(url)}</dd>",
                        outputs["dashboard.html"],
                    )
                    self.assertNotIn("](<", outputs["report.md"])

    def test_unsupported_reference_without_title_keeps_its_url(self):
        doc = complete_doc()
        doc["findings"][0]["references"] = [{"url": "javascript:alert(1)"}]
        outputs = self.render_outputs(doc, "en")
        self.assertIn("<dt>references</dt><dd>javascript:alert(1)</dd>", outputs["dashboard.html"])
        self.assertIn("- **references:** javascript:alert(1)\n", outputs["report.md"])
        self.assertEqual(ParsedHTML(outputs["dashboard.html"]).links, [])


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
