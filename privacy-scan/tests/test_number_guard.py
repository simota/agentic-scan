"""Regressions for digit separators, technical numbers and exempt identifiers."""
import unittest

from test_privacy_scan import complete_doc, finding, findings


def refused(text):
    try:
        findings._no_personal_values(text, "field")
    except findings.SchemaError:
        return True
    return False


class NumberGuardTests(unittest.TestCase):
    def test_unicode_dashes_separate_digits_like_hyphens(self):
        for dash in ("‐", "‑", "‒", "–", "—", "―",
                     "−", "ー", "ｰ"):
            with self.subTest(dash=ascii(dash)):
                self.assertTrue(refused(dash.join(["4111", "1111", "1111", "1111"])))
                self.assertTrue(refused(f"My Number 1234{dash}5678{dash}9012"))

    def test_card_groups_with_other_separators_are_refused(self):
        for value in ("4111.1111.1111.1111", "4111/1111/1111/1111", "4111_1111_1111_1111",
                      "4111+1111+1111+1111", "3782.822463.10005", "card 4111.1111.1111.11"):
            with self.subTest(value=value):
                self.assertTrue(refused(value))

    def test_technical_numbers_remain_allowed(self):
        for value in ("2026-10-01-2026-10-09", "2026-10-01 - 2026-10-09",
                      "123e4567-e89b-12d3-a456-426614174000",
                      "00000000-0000-0000-0000-000000000000",
                      "192.168.100.200", "10.0.0.1/24", "1.2.3.4567", "2026.10.09",
                      "2026-10-09T15:33:53Z", "api/app.py:1000-2000"):
            with self.subTest(value=value):
                self.assertFalse(refused(value))

    def test_masking_does_not_hide_an_adjacent_number(self):
        for value in ("2026-10-09 4111 1111 1111 1111", "2026-10-09-4111-1111-1111",
                      "123e4567-e89b-12d3-a456-426614174000 090 1234 5678 90"):
            with self.subTest(value=value):
                self.assertTrue(refused(value))

    def test_malformed_urls_are_also_form_decoded(self):
        doc = complete_doc()
        doc["findings"][0]["references"] = [
            {"url": "https://a℀b.example.com/?q=4111+1111+1111+1111"}]
        with self.assertRaises(findings.SchemaError):
            findings.validate(doc)


class ExemptIdentifierTests(unittest.TestCase):
    def test_long_line_numbers_and_ledger_ids_are_not_exempt(self):
        for location in ("src/a.py:4111111111111111", "src/a.py:1-4111111111111111"):
            with self.subTest(location=location), self.assertRaises(findings.SchemaError):
                findings.validate({"findings": [finding(location=location)]})
        with self.assertRaises(findings.SchemaError):
            findings.validate({"findings": [finding(commitment="C-4111111111111111")]})
        doc = complete_doc()
        doc["commitments"][0]["id"] = "C-090123456789"
        with self.assertRaises(findings.SchemaError):
            findings.validate(doc)
        findings.validate({"findings": [finding(location="src/a.py:123456789-123456789",
                                                commitment="C-123456")]})

    def test_duplicate_perspectives_in_the_record_are_not_blamed_on_the_fragment(self):
        doc = complete_doc()
        doc["perspectives"].append(dict(doc["perspectives"][0]))
        with self.assertRaises(findings.SchemaError) as raised:
            findings.merge(doc, {"perspectives": []}, "frag.json")
        self.assertTrue(str(raised.exception).startswith("perspectives["), str(raised.exception))


if __name__ == "__main__":
    unittest.main()
