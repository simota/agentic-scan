"""Evidence quoted in code spans or brackets, directory locations, --allow spellings."""
import json

from test_architecture_scan import complete_doc, findings
from test_py_jvm_dry_run import Workspace


class WrappedCitationTests(Workspace):
    def test_opening_punctuation_is_not_part_of_the_cited_name(self):
        for evidence in ("`Makefile:12`", "(CODEOWNERS:4)", '"Dockerfile:3"', "[BUILD:12]",
                         "「BUILD:12」", "（Makefile:12）", "、README:2"):
            with self.subTest(evidence=evidence):
                self.assertTrue(findings.cites_line(evidence))
        for evidence in ("(server:9)", "`server:9`", "「server:9」"):
            with self.subTest(evidence=evidence):
                self.assertTrue(findings.cites_line(evidence, ["bin/server:9"]))

    def test_a_full_width_colon_ends_a_label(self):
        self.assertEqual(list(findings.evidence_paths("根拠：Makefile:12")), ["Makefile"])
        self.assertTrue(findings.cites_line("根拠：Makefile:12"))
        self.assertTrue(findings.cites_line("根拠：server:9", ["bin/server:9"]))

    def test_wrapping_does_not_turn_a_non_file_into_one(self):
        for evidence in ("`ABC:123`", "(10:30)", "「v1.2:3」", "`db.internal:5432`",
                         "(http://x.com:80/a)", "根拠：ratio:3"):
            with self.subTest(evidence=evidence):
                self.assertFalse(findings.cites_line(evidence))

    def test_a_record_citing_a_build_file_in_a_code_span_passes_check(self):
        doc = complete_doc()
        doc["findings"][0]["validation"]["evidence"] = "`Makefile:3` wires the ORM in"
        self.assertEqual(self.problems(doc), [])


class DuplicateSpacingTests(Workspace):
    def test_a_full_width_or_no_break_space_is_a_blank(self):
        doc = complete_doc()
        for evidence in ("重複：　A-001", "Duplicate of A-001", "重複: A-001　"):
            with self.subTest(evidence=repr(evidence)):
                doc["findings"][1]["validation"] = {"verdict": "NotApplicable",
                                                    "method": "static", "evidence": evidence}
                self.assertEqual(self.problems(doc), [])


class DirectoryLocationTests(Workspace):
    def test_a_location_naming_a_directory_is_refused(self):
        for location in ("worker/refunds/:58", "worker/refunds/.:58", "worker\\refunds\\:58",
                         "worker/refunds/job.py/:58", "worker/..:3"):
            with self.subTest(location=location):
                doc = complete_doc()
                doc["findings"][0]["location"] = [location]
                self.assertTrue(any("names no file" in p for p in self.problems(doc)),
                                self.problems(doc))

    def test_a_dotfile_location_is_a_file(self):
        doc = complete_doc()
        doc["findings"][0]["location"] = [".env:3"]
        self.assertEqual(self.problems(doc), [])


class AllowSpellingTests(Workspace):
    def test_a_completed_or_dotted_name_is_allowed(self):
        (self.tmp / "drafts").mkdir()
        for allow in ("drafts", "drafts/", "./drafts"):
            with self.subTest(allow=allow):
                self.assertEqual(self.problems(complete_doc(), allow), [])
        self.assertTrue(any("unexpected output: drafts" in p
                            for p in self.problems(complete_doc(), "draft")))


class InvalidRecordTests(Workspace):
    def test_merge_into_an_invalid_record_names_the_record(self):
        doc = complete_doc()
        doc["findings"][0]["severity"] = "Critical"
        self.write(doc)
        code, _, err = self.merge({"findings": [{"id": "A-001", "severity": "High"}]})
        self.assertEqual(code, 1)
        self.assertIn(f"{self.target}: existing record is invalid", err)
        self.assertEqual(json.loads(self.target.read_text(encoding="utf-8")), doc)


class MentionBoundaryTests(Workspace):
    def test_the_documented_ways_to_end_a_url_before_a_mention(self):
        mapping = {"A-001": "A-002", "A-002": "A-001"}
        for text, expected in (("https://x/adr/4 を見て A-001", "https://x/adr/4 を見て A-002"),
                               ("https://x/adr/4。A-001", "https://x/adr/4。A-002"),
                               ("https://x/adr/4を見てA-001", "https://x/adr/4を見てA-001"),
                               ("the A-001-style guard", "the A-001-style guard")):
            with self.subTest(text=text):
                self.assertEqual(findings._rewrite_ids(text, mapping), expected)
