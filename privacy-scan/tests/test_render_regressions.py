"""Regression checks for report contents, references and output preservation on failure."""
import io
import json
import re
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
                html_overview = re.search(r"<section id='overview'>(.*?)</section>", outputs["dashboard.html"], re.S).group(1)
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
        for lang, status, label in (("en", "not checked", "reason"), ("ja", "未確認", "理由")):
            outputs = self.render_outputs(doc, lang)
            for name, output in outputs.items():
                with self.subTest(lang=lang, output=name):
                    expected = f"{status} — {label}: {reason}"
                    # The dashboard marks the status term; compare the visible text.
                    self.assertIn(escape(expected), re.sub(r"<[^>]+>", "", output))
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
                    r"See C:\\config\\\|regions &lt;region&gt; &amp; policy | PV-001, PV-002 |",
                )

    def test_optional_inferred_flag_preserves_unqualified_commitments(self):
        for inferred in (None, False):
            doc = complete_doc()
            if inferred is not None:
                doc["commitments"][0]["inferred"] = inferred
            for lang, status in (("en", "violated"), ("ja", "違反")):
                with self.subTest(inferred=inferred, lang=lang):
                    outputs = self.render_outputs(doc, lang)
                    self.assertIn(f"| C-01 | no PII in errors |  | policy | {status} | PV-001, PV-002 |",
                                  outputs["report.md"])
                    columns = render.LABELS[lang]["commitment_columns"]
                    cells = ("C-01", "no PII in errors", "", "policy", status, "PV-001, PV-002")
                    marked = f"<span class='status' data-status='violated'>{status}</span>"
                    self.assertIn("<tr><td class='nowrap' data-label='ID'>C-01</td>"
                                  + "".join(f"<td data-label='{c}'>{v}</td>"
                                            for c, v in zip(columns[1:], cells[1:-2] + (marked, cells[-1])))
                                  + "</tr>",
                                  outputs["dashboard.html"])

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
                self.assertEqual(parsed.tags.count("script"), 2)  # Data script + fixed dashboard script.
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
                    self.assertEqual(parsed.tags.count("script"), 2)
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


class LineBreakRenderingTests(unittest.TestCase):
    """Every line boundary the personal-value guard accepts is shown as a break."""

    BREAKS = ("\v", "\f", "\x1c", "\x1d", "\x1e", "\x85", " ", " ", "\r", "\r\n")

    def test_guard_line_boundaries_are_visible_breaks_in_both_reports(self):
        for brk in self.BREAKS:
            with self.subTest(brk=ascii(brk)):
                doc = complete_doc()
                doc["checked_ok"] = [f"accounts 123456{brk}789012 rows"]
                doc["findings"][0]["flow"] = f"1. step 123456{brk}789012"
                doc["findings"][0]["references"] = [
                    {"title": f"ticket 123456{brk}789012", "url": "https://example.com/t"}]
                render.validate(doc, complete=True)
                markdown = render.render_markdown(doc, "en")
                html = render.render_html(doc, "en")
                self.assertIn("accounts 123456<br>789012 rows", markdown)
                self.assertIn("1. step 123456<br>789012", markdown)
                self.assertIn("accounts 123456\n789012 rows", html)
                self.assertIn("1. step 123456\n789012", html)
                self.assertIn(">ticket 123456\n789012</a>", html)

    def test_dashboard_text_outside_pre_line_cells_keeps_its_breaks(self):
        doc = complete_doc()
        doc["meta"]["project"] = "shop 123456\u2028789012"
        doc["meta"]["assessor"] = "team 123456\x1e789012"
        doc["findings"][0]["title"] = "Leak 123456\x85789012"
        html = render.render_html(doc, "en")
        # The finding summary, project heading, byline and footer keep line breaks.
        for selector in ("details[data-sev] summary", ".hero h2", ".hero .meta", ".footer", ".cx-band h1"):
            with self.subTest(selector=selector):
                self.assertRegex(html, r"(^|[\s},])" + re.escape(selector)
                                 + r"(,[^{]*)?\{[^}]*white-space:pre-line")
        self.assertIn("<h2>shop 123456\n789012</h2>", html)
        self.assertIn("Leak 123456\n789012", html)
        self.assertIn("team 123456\n789012", html)
        # A document title cannot hold a break; its lines are joined visibly.
        self.assertIn("<title>Privacy assessment: shop 123456 · 789012</title>", html)

    def test_commands_split_at_every_line_boundary(self):
        doc = complete_doc()
        doc["findings"][0]["validation"]["method"] = "analysed"
        doc["findings"][0]["analysis"] = {"tool": "rg", "command": "rg a rg b", "result": "none"}
        self.assertIn("`rg a`<br>`rg b`", render.render_markdown(doc, "en"))
        self.assertIn("<code>rg a\nrg b</code>", render.render_html(doc, "en"))


class EmptyLedgerTests(unittest.TestCase):
    def test_an_empty_commitments_ledger_is_shown_as_none(self):
        for lang in ("en", "ja"):
            with self.subTest(lang=lang):
                doc = complete_doc()
                doc["commitments"] = []
                for f in doc["findings"]:
                    f.pop("commitment", None)
                labels = render.LABELS[lang]
                markdown = render.render_markdown(doc, lang)
                self.assertIn(f"## {labels['commitments']}\n\n{labels['none']}\n", markdown)
                html = render.render_html(doc, lang)
                self.assertIn(f"<h2>{escape(labels['commitments'])}</h2>", html)
                self.assertIn(f"<p class='muted'>{escape(labels['none'])}</p></section>", html)


class LedgerCells(HTMLParser):
    """Column headers and each cell's data-label, per ledger table class."""

    def __init__(self, source):
        super().__init__()
        self.tables, self._table, self._cell = {}, None, None
        self.feed(source)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "table" and "ledger" in attrs.get("class", "").split():
            self._table = self.tables.setdefault(attrs["class"], {"heads": [], "rows": []})
        elif self._table is not None and tag == "tr":
            self._table["rows"].append([])
        elif self._table is not None and tag in ("th", "td"):
            self._cell = [tag, attrs.get("data-label"), ""]

    def handle_endtag(self, tag):
        if tag == "table":
            self._table = None
        elif self._cell is not None and tag == self._cell[0]:
            kind, label, text = self._cell
            if kind == "th":
                self._table["heads"].append(text)
            else:
                self._table["rows"][-1].append((label, text))
            self._cell = None

    def handle_data(self, data):
        if self._cell is not None:
            self._cell[2] += data


class NarrowLedgerTests(unittest.TestCase):
    """On narrow screens a ledger row is a card, so each cell names its column."""

    def test_every_ledger_cell_is_labelled_with_its_column(self):
        for lang in ("en", "ja"):
            with self.subTest(lang=lang):
                labels = render.LABELS[lang]
                tables = LedgerCells(render.render_html(complete_doc(), lang)).tables
                expected = {"ledger commitments": labels["commitment_columns"],
                            "ledger coverage-table": labels["perspective_columns"]}
                self.assertEqual(set(tables), set(expected))
                for name, columns in expected.items():
                    table = tables[name]
                    self.assertEqual(table["heads"], list(columns))
                    rows = [row for row in table["rows"] if row]
                    self.assertTrue(rows)
                    for row in rows:
                        self.assertEqual([label for label, _ in row], list(columns))
                # The status a reader scans for stays in the commitment card.
                commitment = tables["ledger commitments"]["rows"][1]
                self.assertEqual(commitment[-2], (labels["commitment_columns"][-2],
                                                  render.term(labels, "violated")))
                # The last cell leads from the commitment to the findings that break it.
                self.assertEqual(commitment[-1], (labels["commitment_columns"][-1],
                                                  "PV-001, PV-002"))

    def test_card_layout_applies_to_narrow_screens_but_not_print(self):
        media = re.search(r"@media screen and \(max-width:850px\)\{(.*?)\}\}", render.CSS, re.S)
        self.assertIsNotNone(media)
        self.assertIn("table.ledger>thead{position:absolute", media.group(1))
        self.assertIn("content:attr(data-label)", media.group(1))
