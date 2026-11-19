"""Japanese display names for perspectives and their statuses.

findings.json keeps the English schema values; only a Japanese rendering shows
the display names, and an English rendering is left exactly as recorded.
"""
import json
import re
import unittest
from pathlib import Path

from test_architecture_scan import REPO, SKILL, findings, import_module, render

drafts = import_module(SKILL / "scripts" / "drafts.py", "arch_drafts_labels")
compare = import_module(SKILL / "scripts" / "compare.py", "arch_compare_labels")

SAMPLE_JA = REPO / "examples" / "findings.sample.ja.json"
SAMPLE_EN = REPO / "examples" / "findings.sample.json"
JA = render.PERSPECTIVE_LABELS["ja"]
JA_STATUS = render.PERSPECTIVE_STATUS_LABELS["ja"]


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def visible(html):
    """The page text a reader sees: tags and their attribute values removed."""
    return re.sub(r"<[^>]*>", " ", html)


def console_data(html):
    return json.loads(re.search(r"<script type='application/json' id='console-data'>(.*?)</script>", html, re.S)[1])


def coverage_rows(markdown, heading):
    block = markdown.split(f"## {heading}\n", 1)[1].split("\n## ", 1)[0]
    return [line.split(" | ") for line in block.splitlines() if line.startswith("| ")][1:]


class PerspectiveLabelTable(unittest.TestCase):
    def test_covers_every_perspective(self):
        self.assertEqual(set(JA), set(findings.PERSPECTIVES))

    def test_covers_every_perspective_status(self):
        self.assertEqual(set(JA_STATUS), set(findings.PERSPECTIVE_STATUSES))
        self.assertEqual(JA_STATUS, {"applied": "適用", "not checked": "未確認", "N/A": "該当なし"})

    def test_names_are_japanese_and_distinct(self):
        self.assertEqual(len(set(JA.values())), len(JA))
        for name, label in JA.items():
            self.assertRegex(label, r"[぀-ヿ一-鿿]", name)
            self.assertNotEqual(label, name)

    def test_english_is_identity(self):
        for name in findings.PERSPECTIVES:
            self.assertEqual(render.perspective_name(name, "en"), name)
        for status in findings.PERSPECTIVE_STATUSES:
            self.assertEqual(render.perspective_status(status, "en"), status)
        for status in findings.RULE_STATUSES:
            self.assertEqual(render.rule_status(status, "en"), status)

    def test_covers_every_rule_status(self):
        self.assertEqual(set(render.RULE_STATUS_LABELS["ja"]), set(findings.RULE_STATUSES))


class JapaneseRuleStatuses(unittest.TestCase):
    """The design rules table shows Japanese statuses in a Japanese rendering only."""

    def test_rules_table_uses_japanese_statuses(self):
        doc = load(SAMPLE_JA)
        statuses = {r["status"] for r in doc["rules"]}
        markdown, html = render.render_markdown(doc, "ja"), visible(render.render_html(doc, "ja"))
        rows = coverage_rows(markdown, render.LABELS["ja"]["rules"])
        for status in statuses:
            label = render.rule_status(status, "ja")
            self.assertTrue(any(label in row[-1] for row in rows), status)
            self.assertIn(label, html)
        for row in rows:
            for status in findings.RULE_STATUSES:
                self.assertNotIn(f" {status}", f" {row[-1]}", row)

    def test_english_rules_table_keeps_the_recorded_words(self):
        doc = load(SAMPLE_EN)
        markdown = render.render_markdown(doc, "en")
        for r in doc["rules"]:
            self.assertIn(r["status"], markdown)


class JapaneseDemo(unittest.TestCase):
    """The Japanese sample rendered in Japanese shows no English-only perspective name."""

    @classmethod
    def setUpClass(cls):
        cls.doc = load(SAMPLE_JA)
        cls.markdown = render.render_markdown(cls.doc, "ja")
        cls.html = render.render_html(cls.doc, "ja")

    def assert_no_english_name(self, text, where):
        for name in findings.PERSPECTIVES:
            self.assertNotIn(name, text, f"{where} shows {name!r}")

    def test_report_md(self):
        self.assert_no_english_name(self.markdown, "report.md")
        rows = coverage_rows(self.markdown, render.LABELS["ja"]["perspectives"])
        self.assertEqual([r[0].lstrip("| ") for r in rows], [JA[n] for n in findings.PERSPECTIVES])
        recorded = {p["name"]: p["status"] for p in self.doc["perspectives"]}
        self.assertEqual([r[1] for r in rows], [JA_STATUS[recorded[n]] for n in findings.PERSPECTIVES])

    def test_dashboard_text(self):
        self.assert_no_english_name(visible(self.html), "dashboard.html")
        table = self.html.split("class='coverage-table'", 1)[1].split("</table>", 1)[0]
        for status in findings.PERSPECTIVE_STATUSES:
            self.assertNotIn(f">{status}<", table)

    def test_console_lamps(self):
        lamps = console_data(self.html)["perspectives"]
        self.assertEqual([p["name"] for p in lamps], [JA[n] for n in findings.PERSPECTIVES])
        self.assertTrue({p["result"] for p in lamps} <= set(JA_STATUS.values()) | {"—"})

    def test_filters_keep_schema_values(self):
        # The register filters match on data-cat, so the option values stay English.
        self.assertIn("<option value='Boundaries and layering'>境界と層構造</option>", self.html)
        self.assertIn("data-cat='Boundaries and layering'", self.html)

    def test_issue_drafts_and_comparison(self):
        for f in self.doc["findings"]:
            values = drafts.finding_values(f, self.doc, "ja")
            self.assertEqual(values["category"], JA[f["category"]])
        earlier = load(SAMPLE_JA)
        earlier["perspectives"][0]["status"] = "not checked"
        earlier["findings"][0]["category"] = "Coupling"
        text = compare.as_markdown(compare.compare(earlier, self.doc), earlier, self.doc, "ja")
        self.assert_no_english_name(text, "compare.py")
        self.assertIn(f"- {JA[findings.PERSPECTIVES[0]]}: 未確認 → 適用", text)


class EnglishUnchanged(unittest.TestCase):
    """An English rendering shows the recorded English names and statuses, with no Japanese label."""

    def test_english_outputs(self):
        for sample in (SAMPLE_EN, SAMPLE_JA):
            doc = load(sample)
            outputs = {name: body.decode("utf-8") for name, body in render.rendered_outputs(doc, "en").items()}
            rows = coverage_rows(outputs["report.md"], render.LABELS["en"]["perspectives"])
            recorded = {p["name"]: p["status"] for p in doc["perspectives"]}
            self.assertEqual([r[0].lstrip("| ") for r in rows], list(findings.PERSPECTIVES))
            self.assertEqual([r[1] for r in rows], [recorded[n] for n in findings.PERSPECTIVES])
            lamps = console_data(outputs["dashboard.html"])["perspectives"]
            self.assertEqual([p["name"] for p in lamps], list(findings.PERSPECTIVES))
            self.assertEqual([p["result"] for p in lamps], [recorded[n] for n in findings.PERSPECTIVES])
            if sample == SAMPLE_EN:  # the Japanese sample's own notes are Japanese text
                for body in outputs.values():
                    for label in (*JA.values(), *JA_STATUS.values()):
                        self.assertNotIn(label, body, sample.name)


if __name__ == "__main__":
    unittest.main()
