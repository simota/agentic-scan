"""Perspective names and statuses: Japanese output shows Japanese, English output keeps the record's values."""
import copy
import unittest

from test_bug_scan import ROOT, common, render, sample

STATUSES = ("applied", "N/A", "not checked")


def english_sample():
    return tuple(common.load_json(ROOT / "examples" / f"{name}.sample.json") for name in ("findings", "surfaces", "history"))


def with_every_status(record):
    record = copy.deepcopy(record)
    for perspective, status in zip(record["perspectives"], STATUSES):
        perspective["status"] = status
    return record


class PerspectiveLabelTests(unittest.TestCase):
    def test_tables_cover_every_perspective_and_status(self):
        self.assertEqual(set(common.PERSPECTIVE_STATUS_JA), set(STATUSES))
        self.assertEqual([common.perspective_status(s, "ja") for s in STATUSES], ["適用", "該当なし", "未確認"])
        for code in common.PERSPECTIVES:
            ja, en = common.PATTERNS[code]
            self.assertRegex(ja, r"[぀-ヿ㐀-鿿]", code)
            self.assertNotEqual(ja, en, code)

    def test_japanese_output_shows_japanese_names_and_statuses(self):
        record, surfaces, history = sample()
        record = with_every_status(record)
        dashboard, document = render.build(record, surfaces, history, "ja")
        rows = render.to_common(record, surfaces, "ja")["perspectives"]
        self.assertEqual([p["name"] for p in rows], [f"{c} {common.PATTERNS[c][0]}" for c in common.PERSPECTIVES])
        self.assertEqual({p["result"] for p in rows}, {"適用", "該当なし", "未確認"})
        for code in common.PERSPECTIVES:
            english = common.PATTERNS[code][1]
            self.assertNotIn(english, dashboard + document, code)
        for status in STATUSES:
            self.assertNotIn(f"<span class='prose'>{status}</span>", document, status)
            self.assertNotIn(f'"result": "{status}"', dashboard, status)
        self.assertIn("<span class='prose'>未確認</span>", document)

    def test_english_output_keeps_recorded_names_and_statuses(self):
        record, surfaces, history = english_sample()
        record = with_every_status(record)
        dashboard, document = render.build(record, surfaces, history, "en")
        rows = render.to_common(record, surfaces, "en")["perspectives"]
        self.assertEqual([p["result"] for p in rows], [p["status"] for p in record["perspectives"]])
        for code in common.PERSPECTIVES:
            self.assertIn(f"{code} {common.PATTERNS[code][1]}", document, code)
        for status in STATUSES:
            self.assertIn(f"<span class='prose'>{status}</span>", document, status)
            self.assertIn(f'"result": "{status}"', dashboard, status)
        for word in ("適用", "該当なし", "未確認"):
            self.assertNotIn(word, dashboard + document, word)


if __name__ == "__main__":
    unittest.main()
