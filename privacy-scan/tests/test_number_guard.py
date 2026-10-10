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


class EncodedValueTests(unittest.TestCase):
    def test_encoded_and_invisibly_split_values_are_refused(self):
        for value in ("GET /api?email=alice%40corp.com", "alice&#64;corp.com", "alice&#x40;corp.com",
                      "alice&commat;corp.com", "alice%2540corp.com",
                      "alice@corp​.com", "alice@​corp.com", "alice@corp⁠.com",
                      "alice@corp­.com", "4111​1111​1111​1111",
                      "4111%201111%201111%201111"):
            with self.subTest(value=ascii(value)):
                self.assertTrue(refused(value))
        doc = complete_doc()
        doc["findings"][0]["references"] = [
            {"url": "https://x.test/?e=alice%2540corp.com"}]
        with self.assertRaises(findings.SchemaError):
            findings.validate(doc)

    def test_encoded_placeholders_and_plain_percentages_remain_allowed(self):
        for value in ("user%40example.com", "100% of requests & 50% of jobs",
                      "a &amp; b", "&lt;email&gt;", "%ZZ not encoding"):
            with self.subTest(value=value):
                self.assertFalse(refused(value))

    def test_hex_digests_are_not_digit_runs(self):
        for value in ("commit 0a1b2c3d4e5f678901234567890abcdef1234567",
                      "sha256 " + "1234567890123a" + "0" * 50,
                      "pod-123e4567-e89b-12d3-a456-426614174000",
                      "123e4567e89b12d3a456426614174000"):
            with self.subTest(value=value):
                self.assertFalse(refused(value))
        # Without a hex letter or next to a dash-joined digit, the digits still count.
        for value in ("0" * 40, "1-123e4567-e89b-12d3-a456-426614174000",
                      "123e4567-e89b-12d3-a456-426614174000-0"):
            with self.subTest(value=value):
                self.assertTrue(refused(value))


class DateMaskTests(unittest.TestCase):
    def test_dates_cannot_split_a_longer_number(self):
        for value in ("4111-2026-01-01-1111", "1234-5678-2026-01-01", "1234-2026-01-01-5678-9012"):
            with self.subTest(value=value):
                self.assertTrue(refused(value))
        for value in ("2026-10-01-2026-10-09", "2026-10-01-2026-10-09-2026-10-12",
                      "from 2026-10-01 to 2026-10-09"):
            with self.subTest(value=value):
                self.assertFalse(refused(value))


class FinalReviewTests(unittest.TestCase):
    def test_a_date_followed_by_a_time_of_day_is_allowed(self):
        self.assertFalse(refused("backup-2024-01-01-120000.sql"))
        self.assertTrue(refused("4111-2026-01-01-111111-2222"))
        self.assertTrue(refused("2026-01-01-111111-2222"))

    def test_excluded_findings_also_need_a_valid_step(self):
        doc = complete_doc()
        doc["findings"][1]["validation"] = {"verdict": "FalsePositive", "method": "static",
                                            "evidence": "scrubber at app.py:30"}
        doc["findings"][1]["step"] = "ZZ9"
        self.assertTrue(any(p.startswith("PV-002.step") for p in findings.record_problems(doc)))


class SeparatorAdjacencyTests(unittest.TestCase):
    def test_dates_and_uuids_next_to_digits_across_any_separator_are_not_masked(self):
        for value in ("4111 2026-01-01 1111", "4111–2026-01-01–1111",
                      "4111\t2026-01-01\t1111", "4111 2026-01-01", "2026-01-01 1111 2222",
                      "1234 5678 12345678-1234-1234-1234-123456789012"):
            with self.subTest(value=ascii(value)):
                self.assertTrue(refused(value))

    def test_ranges_times_and_isolated_values_stay_masked(self):
        for value in ("2026-10-01 - 2026-10-09", "2026-10-01 – 2026-10-09",
                      "backup 2024-01-01 120000.sql", "run 123e4567-e89b-12d3-a456-426614174000 ok",
                      "on 2026-10-09, 1234 accounts"):
            with self.subTest(value=ascii(value)):
                self.assertFalse(refused(value))


class DigitRunTests(unittest.TestCase):
    def test_chained_dates_cannot_hide_extra_digits(self):
        for value in ("123 2026-01-01 2026-02-02", "2026-01-01 2026-02-02 123",
                      "2026-01-01 123 2026-02-02", "2026-01-01-120000-1234",
                      "12 2026-01-01-120000"):
            with self.subTest(value=value):
                self.assertTrue(refused(value))

    def test_runs_made_only_of_dates_and_times_stay_masked(self):
        for value in ("2026-01-01 2026-02-02 2026-03-03", "2026-01-01-120000-2026-01-02-235959",
                      "from 2026-01-01T10:00 to 2026-01-02"):
            with self.subTest(value=value):
                self.assertFalse(refused(value))

    def test_a_time_counts_only_after_a_date(self):
        self.assertTrue(refused("120000-2026-01-01"))

    def test_hex_digests_between_digit_groups_are_not_masked(self):
        digest = "0a1b2c3d4e5f678901234567890abcdef1234567"
        # Masked, this digest would hide the twelfth digit of the number beside it.
        edge = "9" + "ab" * 20
        self.assertTrue(refused(f"41111111111 {edge}"))
        for value in (f"commit {digest} merged", f"sha256 {digest}", f"{digest} utf8"):
            with self.subTest(value=value):
                self.assertFalse(refused(value))
