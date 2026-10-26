"""Regression checks for verification and measurement in the report overview."""
from copy import deepcopy
import unittest

from support import HtmlTreeReader, complete_doc, element_text, finding, findings, render


LANGUAGES = (
    ("en", "Verification counts", "High with incomplete verification"),
    ("ja", "検証判定別の件数", "検証未完了の High"),
)
MEASUREMENT = {
    "environment": "authorized local synthetic data",
    "before": {"command": "python3 tests/query_count.py", "result": "query count is 52 for 50 orders",
               "log": "orders=50 queries=52"},
    "after": {"command": "python3 tests/query_count.py", "result": "query count is 3 for 50 orders",
              "log": "orders=50 queries=3"},
}


def overviews(doc, lang):
    """Only inspect content visible before opening any finding."""
    markdown = render.render_markdown(doc, lang).split("\n## ", 1)[0]
    root = HtmlTreeReader(render.render_html(doc, lang)).root
    introductory = []
    for child in root.find(".//main"):
        if child.tag == "h2":
            break
        introductory.append(element_text(child))
    return markdown, "\n".join(introductory), root


class SummaryRegressions(unittest.TestCase):
    def test_verdict_counts_and_incomplete_high_are_visible_before_findings(self):
        doc = complete_doc()
        cases = (
            ("High", "Valid"), ("High", "Likely"), ("High", "Unverified"),
            ("High", "Unlikely"), ("High", "FalsePositive"),
            ("High", "NotApplicable"), ("Medium", "Valid"),
            ("Low", "Likely"), ("Low", "Unverified"),
        )
        doc["findings"] = [finding(
            f"P-{i:03d}", severity,
            validation={"verdict": verdict, "method": "static", "evidence": "trace at app.py:1"},
        ) for i, (severity, verdict) in enumerate(cases, 1)]
        findings.validate(doc, complete=True)

        for lang, label, incomplete in LANGUAGES:
            with self.subTest(lang=lang):
                markdown, html, root = overviews(doc, lang)
                expected = f"{label}: Valid 2 / Likely 2 / Unverified 2 / Unlikely 1"
                for overview in (markdown, html):
                    self.assertIn(expected, overview)
                    self.assertIn(f"{incomplete} 3", overview)
                self.assertIn(f"**{incomplete} 3**", markdown)
                self.assertIn(f"{incomplete} 3", [
                    element_text(item) for item in root.findall(".//section[@id='overview']/p/strong")])
                self.assertIn("High 4 / Medium 1 / Low 2 / Info 0", markdown)
                cards = {element_text(card.find("span")): int(card.findtext("b"))
                         for card in root.findall(".//div[@class='card']")}
                self.assertEqual([cards[s] for s in ("High", "Medium", "Low", "Info")],
                                 [4, 1, 2, 0])
                excluded = "Excluded" if lang == "en" else "除外"
                self.assertEqual(cards[excluded], 2)

    def test_zero_or_only_excluded_findings_have_no_incomplete_high(self):
        excluded = [finding(
            f"P-{i:03d}", "High",
            validation={"verdict": verdict, "method": "static", "evidence": "guard at app.py:1"},
        ) for i, verdict in enumerate(("FalsePositive", "NotApplicable"), 1)]
        for records in ([], excluded):
            doc = complete_doc()
            doc["findings"] = records
            findings.validate(doc, complete=True)
            for lang, label, incomplete in LANGUAGES:
                with self.subTest(lang=lang, findings=len(records)):
                    markdown, html, _ = overviews(doc, lang)
                    expected = f"{label}: Valid 0 / Likely 0 / Unverified 0 / Unlikely 0"
                    for overview in (markdown, html):
                        self.assertIn(expected, overview)
                        self.assertIn(f"{incomplete} 0", overview)

    def test_recorded_measurements_are_in_the_overview_for_both_methods(self):
        for method in ("static", "measured"):
            doc = complete_doc()
            doc["findings"][0]["validation"]["method"] = method
            doc["findings"][0]["measurement"] = deepcopy(MEASUREMENT)
            original = deepcopy(doc)
            findings.validate(doc, complete=True)
            for lang, _, _ in LANGUAGES:
                with self.subTest(lang=lang, method=method):
                    markdown, html, root = overviews(doc, lang)
                    note = ("Static review plus explicitly authorized local measurements."
                            if lang == "en" else
                            "静的レビューに加え、明示的に許可されたローカル計測を実施。")
                    for overview in (markdown, html):
                        self.assertIn(note, overview)
                        self.assertNotIn("静的レビューのみ。", overview)
                        self.assertNotIn("Static review;", overview)
                    self.assertIn(f"Valid ({render.shown(method, lang)})", element_text(root))
            self.assertEqual(doc, original)

    def test_static_only_note_is_visible_without_measurement(self):
        doc = complete_doc()
        for lang, _, _ in LANGUAGES:
            with self.subTest(lang=lang):
                markdown, html, _ = overviews(doc, lang)
                note = ("Static review; no load was sent to any deployed environment."
                        if lang == "en" else
                        "静的レビューのみ。稼働中の環境には負荷を一切かけていない。")
                for overview in (markdown, html):
                    self.assertIn(note, overview)


if __name__ == "__main__":
    unittest.main()
