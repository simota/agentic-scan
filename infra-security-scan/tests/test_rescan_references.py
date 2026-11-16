"""Regression tests for references surviving baseline additions and removals."""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "skills" / "infra-scan" / "scripts"))
import contract_check  # noqa: E402
import findings  # noqa: E402
import iac_scan  # noqa: E402
import render  # noqa: E402


class RescanReferencesTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.repo, self.out = self.root / "repo", self.root / "out"
        self.repo.mkdir()
        self.out.mkdir()
        self.record = self.out / "findings.json"
        self.bucket = self.repo / "z.tf"
        self.bucket.write_text('resource "aws_s3_bucket_acl" "public" {\n'
                               '  bucket = "example-bucket"\n'
                               '  acl = "public-read"\n}\n', encoding="utf-8")

    def scan(self):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as err:
            code = iac_scan.main([str(self.repo), "--out", str(self.out / "iac.json"),
                                  "--into", str(self.record)])
        self.assertEqual(code, 0, err.getvalue())
        return json.loads(self.record.read_text(encoding="utf-8"))

    def seed_path(self, data, fid):
        data["meta"].update(project="example", scope="test", date="2026-10-08", assessor="test", axis="confirmed")
        data["perspectives"] = [{"name": n, "status": "Applied"} for n in render.perspective_names()]
        data["attack_paths"] = [{"id": "AP-01", "entry": "Internet", "target": "Example bucket",
                                 "status": "open", "edges": ["Public ACL (z.tf:3)"], "findings": [fid]}]
        self.record.write_text(json.dumps(data), encoding="utf-8")

    def add_admin(self):
        (self.repo / "a.tf").write_text('resource "aws_iam_policy" "admin" {\n'
                                       '  policy = jsonencode({ Statement = [{ Effect = "Allow", '
                                       'Action = "*", Resource = "*" }] })\n}\n', encoding="utf-8")

    def seed_review(self, data, evidence):
        self.seed_path(data, "F-001")
        fragment = self.root / "review.json"
        fragment.write_text(json.dumps({"findings": [{
            "id": "F-001", "title": "Public bucket ACL", "severity": "High",
            "confidence": "Confirmed", "category": "Data protection", "provider": "aws",
            "resources": ["aws_s3_bucket_acl.public"], "location": "z.tf:3",
            "actor": "Internet", "path": "1. Public ACL (z.tf:3)",
            "impact": "Objects may be read publicly", "fix": "Use a private ACL",
            "regression": "Reject public ACLs", "contrast": "none",
            "validation": {"verdict": "Valid", "evidence": evidence},
        }]}), encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as err:
            code = findings.main(["merge", str(self.record), str(fragment)])
        self.assertEqual(code, 0, err.getvalue())

    def review_finding(self, data):
        return next(f for f in data["findings"] if f["id"] == "F-001")

    def assert_report_valid(self, data):
        render.validate(data)
        # The contract requires a verdict on every I-* and on every finding a
        # rescan reopened; triage them here, then restore the scanned record.
        original = self.record.read_bytes()
        record = render.load(self.record)
        for f in record["findings"]:
            if f["validation"]["verdict"] == "Unverified":
                f["validation"] = {"verdict": "Unlikely", "evidence": "triaged by the test"}
        self.record.write_text(json.dumps(record), encoding="utf-8")
        try:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as err:
                self.assertEqual(render.main([str(self.record), "--out", str(self.out), "--no-pdf"]), 0)
                code = contract_check.main([str(self.out), "--no-pdf"])
            self.assertEqual(code, 0, err.getvalue())
        finally:
            self.record.write_bytes(original)

    def test_added_finding_does_not_redirect_existing_attack_path(self):
        data = self.scan()
        self.seed_path(data, "I-001")
        self.add_admin()
        data = self.scan()
        self.assertEqual(data["attack_paths"][0]["findings"], ["I-002"])
        linked = next(f for f in data["findings"] if f["id"] == data["attack_paths"][0]["findings"][0])
        self.assertEqual(linked["rule"], "AWS-S3-001")
        self.assertEqual(linked["location"], "z.tf:3")
        self.assertEqual(data["attack_paths"][0]["status"], "open")
        self.assert_report_valid(data)

    def test_review_evidence_follows_baseline_after_renumbering(self):
        self.seed_review(self.scan(), "I-001 identifies the public ACL at z.tf:3.")
        self.add_admin()
        data = self.scan()
        reviewed = self.review_finding(data)
        self.assertEqual(reviewed["validation"], {
            "verdict": "Valid", "evidence": "I-002 identifies the public ACL at z.tf:3."})
        self.assertEqual(reviewed["confidence"], "Confirmed")
        self.assertEqual(data["attack_paths"][0]["status"], "open")
        self.assert_report_valid(data)
        for name in ("dashboard.html", "assessment.html"):
            page = (self.out / name).read_text(encoding="utf-8")
            self.assertIn("I-002 identifies the public ACL", page)
            self.assertNotIn("I-001 identifies the public ACL", page)

    def test_evidence_references_are_replaced_once_with_token_boundaries(self):
        self.add_admin()
        self.seed_review(self.scan(),
                         "`I-001`とI-002を確認。I-001. Keep X-I-001, I-001-suffix, I-001a, path/I-001.tf.")
        (self.repo / "0.tf").write_text('resource "aws_s3_bucket_acl" "earlier" {\n'
                                       '  acl = "public-read"\n}\n', encoding="utf-8")
        data = self.scan()
        self.assertEqual(self.review_finding(data)["validation"]["evidence"],
                         "`I-002`とI-003を確認。I-002. Keep X-I-001, I-001-suffix, I-001a, path/I-001.tf.")
        self.assert_report_valid(data)

    def test_evidence_urls_are_preserved_while_reference_tokens_are_remapped(self):
        evidence = ("Verified I-001 with https://example.com/?issue=I-001 and "
                    "https://example.com/#I-001. "
                    "https://example.com/?q=(nested(test))&issue=I-001 and "
                    "https://[2001:db8::1]/?issue=I-999 and "
                    "[I-001](https://example.com/?issue=I-001#I-999)とI-001 and "
                    "<https://example.com/#I-999>.")
        self.seed_review(self.scan(), evidence)
        self.add_admin()
        data = self.scan()
        reviewed = self.review_finding(data)
        self.assertEqual(reviewed["validation"], {
            "verdict": "Valid",
            "evidence": evidence.replace("Verified I-001", "Verified I-002")
                                .replace("[I-001]", "[I-002]")
                                .replace("とI-001", "とI-002")})
        self.assertEqual(reviewed["confidence"], "Confirmed")
        self.assert_report_valid(data)

    def test_urls_with_unmatched_ids_do_not_invalidate_review(self):
        evidence = ("Policy references https://example.com/?issue=I-999, "
                    "https://example.com/#I-999 and "
                    "[documentation](https://example.com/?issue=I-999#I-998).")
        self.seed_review(self.scan(), evidence)
        self.add_admin()
        data = self.scan()
        self.assertEqual(self.review_finding(data)["validation"], {
            "verdict": "Valid", "evidence": evidence})
        self.assertEqual(data["attack_paths"][0]["status"], "open")
        self.assert_report_valid(data)

    def test_adjacent_markdown_urls_remain_protected(self):
        evidence = ("[doc](https://example.com/#I-999)とI-001と"
                    "[doc](https://example.net/#I-998)")
        self.seed_review(self.scan(), evidence)
        self.add_admin()
        data = self.scan()
        self.assertEqual(self.review_finding(data)["validation"], {
            "verdict": "Valid", "evidence": evidence.replace("とI-001と", "とI-002と")})
        self.assertEqual(data["attack_paths"][0]["status"], "open")
        self.assert_report_valid(data)

    def test_lost_evidence_invalidates_review_and_indirect_attack_path(self):
        self.seed_review(self.scan(), "I-001 identifies the public ACL at z.tf:3.")
        self.bucket.unlink()
        self.add_admin()
        data = self.scan()
        reviewed = self.review_finding(data)
        self.assertEqual(reviewed["validation"]["verdict"], "Unverified")
        self.assertEqual(reviewed["confidence"], "Suspected")
        self.assertNotIn("I-001", reviewed["validation"]["evidence"])
        self.assertIn("AWS-S3-001 at z.tf", reviewed["validation"]["evidence"])
        self.assertIn("Recheck this finding", reviewed["validation"]["evidence"])
        self.assertEqual(data["attack_paths"][0]["findings"], ["F-001"])
        self.assertEqual(data["attack_paths"][0]["status"], "unknown")
        self.assertTrue(any("F-001" in note for note in data["limitations"]))
        self.assert_report_valid(data)
        again = self.scan()
        self.assertEqual(self.review_finding(again), reviewed)
        self.assertEqual(again["limitations"], data["limitations"])

    def test_partial_resource_removal_invalidates_review_evidence(self):
        original = self.bucket.read_text(encoding="utf-8")
        self.bucket.write_text(original + 'resource "aws_s3_bucket_acl" "other" {\n'
                               '  acl = "public-read"\n}\n', encoding="utf-8")
        self.seed_review(self.scan(), "I-001 covers both public ACLs (z.tf:3).")
        self.bucket.write_text(original, encoding="utf-8")
        data = self.scan()
        reviewed = self.review_finding(data)
        self.assertEqual(reviewed["validation"]["verdict"], "Unverified")
        self.assertIn("affected resources changed", reviewed["validation"]["evidence"])
        self.assertEqual(data["attack_paths"][0]["status"], "unknown")
        self.assert_report_valid(data)

    def test_lost_evidence_invalidates_paths_linked_from_finding(self):
        self.seed_review(self.scan(), "I-001 identifies the public ACL at z.tf:3.")
        original = json.loads(self.record.read_text(encoding="utf-8"))
        self.review_finding(original)["attack_paths"] = ["AP-01"]
        self.bucket.unlink()
        self.add_admin()
        for references in (None, [], ["F-001"]):
            with self.subTest(attack_path_findings=references):
                data = json.loads(json.dumps(original))
                if references is None:
                    data["attack_paths"][0].pop("findings")
                else:
                    data["attack_paths"][0]["findings"] = references
                render.validate(data)
                self.record.write_text(json.dumps(data), encoding="utf-8")
                data = self.scan()
                self.assertEqual(self.review_finding(data)["validation"]["verdict"], "Unverified")
                path = data["attack_paths"][0]
                self.assertEqual(path["status"], "unknown")
                self.assertEqual(path["note"].count("supporting evidence for F-001"), 1)
                self.assert_report_valid(data)
                again = self.scan()
                self.assertEqual(again["attack_paths"], data["attack_paths"])
                self.assertEqual(again["limitations"], data["limitations"])

    def test_unmatched_evidence_never_binds_to_later_reused_id(self):
        self.seed_review(self.scan(), "I-002 was cited by an earlier review (z.tf:3).")
        self.add_admin()
        data = self.scan()
        reviewed = self.review_finding(data)
        self.assertEqual(reviewed["validation"]["verdict"], "Unverified")
        self.assertIn("unmatched baseline number 002", reviewed["validation"]["evidence"])
        self.assertNotIn("I-002", reviewed["validation"]["evidence"])
        again = self.scan()
        self.assertEqual(self.review_finding(again), reviewed)
        self.assertEqual(again["limitations"], data["limitations"])
        self.assert_report_valid(again)

    def test_removed_earlier_finding_remaps_surviving_reference(self):
        self.add_admin()
        self.seed_path(self.scan(), "I-002")
        (self.repo / "a.tf").unlink()
        data = self.scan()
        self.assertEqual(data["attack_paths"][0]["findings"], ["I-001"])
        self.assertEqual(data["findings"][0]["rule"], "AWS-S3-001")
        self.assert_report_valid(data)

    def test_disappeared_finding_marks_path_unknown_before_id_reuse(self):
        self.seed_path(self.scan(), "I-001")
        self.bucket.unlink()
        self.add_admin()
        data = self.scan()
        ap = data["attack_paths"][0]
        self.assertEqual(data["findings"][0]["id"], "I-001")
        self.assertEqual(data["findings"][0]["rule"], "AWS-IAM-001")
        self.assertEqual(ap["findings"], [])
        self.assertEqual(ap["status"], "unknown")
        self.assertIn("AWS-S3-001 at z.tf", ap["note"])
        self.assertTrue(any("AP-01" in n and "Recheck" in n for n in data["limitations"]))
        self.assert_report_valid(data)
        self.assertEqual(self.scan()["limitations"], data["limitations"])

    def test_line_changes_preserve_root_cause_and_review_findings(self):
        data = self.scan()
        sample = json.loads((REPO / "examples" / "findings.sample.json").read_text(encoding="utf-8"))
        reviewed = sample["findings"][0].copy()
        reviewed.pop("attack_paths", None)
        data["findings"].insert(0, reviewed)
        self.seed_path(data, "I-001")
        data = json.loads(self.record.read_text(encoding="utf-8"))
        data["attack_paths"][0]["findings"].insert(0, reviewed["id"])
        self.record.write_text(json.dumps(data), encoding="utf-8")
        self.bucket.write_text("# moved down\n\n" + self.bucket.read_text(encoding="utf-8"), encoding="utf-8")
        data = self.scan()
        self.assertEqual(data["attack_paths"][0]["findings"], [reviewed["id"], "I-001"])
        self.assertEqual(data["findings"][0], reviewed)
        self.assertEqual(data["findings"][1]["location"], "z.tf:5")
        self.assert_report_valid(data)

    def test_unmatched_existing_reference_cannot_bind_to_a_new_id(self):
        self.seed_path(self.scan(), "I-002")
        self.add_admin()
        data = self.scan()
        self.assertEqual(data["attack_paths"][0]["findings"], [])
        self.assertEqual(data["attack_paths"][0]["status"], "unknown")
        self.assertIn("unmatched baseline number 002", data["attack_paths"][0]["note"])

    def test_same_rule_and_file_cannot_redirect_path_to_another_resource(self):
        self.seed_path(self.scan(), "I-001")
        self.bucket.write_text('resource "aws_s3_bucket_acl" "public" {\n'
                               '  acl = "private"\n}\n'
                               'resource "aws_s3_bucket_acl" "other" {\n'
                               '  acl = "public-read"\n}\n', encoding="utf-8")
        data = self.scan()
        self.assertEqual(data["findings"][0]["resources"], ["aws_s3_bucket_acl.other"])
        self.assertEqual(data["attack_paths"][0]["findings"], [])
        self.assertEqual(data["attack_paths"][0]["status"], "unknown")
        self.assertIn("affected resources changed", data["attack_paths"][0]["note"])
        self.assert_report_valid(data)

    def test_partial_resource_removal_also_requires_path_review(self):
        original = self.bucket.read_text(encoding="utf-8")
        self.bucket.write_text(original + 'resource "aws_s3_bucket_acl" "other" {\n'
                               '  acl = "public-read"\n}\n', encoding="utf-8")
        self.seed_path(self.scan(), "I-001")
        self.bucket.write_text(original, encoding="utf-8")
        data = self.scan()
        self.assertEqual(data["attack_paths"][0]["status"], "unknown")
        self.assertEqual(data["attack_paths"][0]["findings"], [])

    def test_added_resources_keep_existing_root_cause_reference(self):
        self.seed_path(self.scan(), "I-001")
        with self.bucket.open("a", encoding="utf-8") as fh:
            fh.write('resource "aws_s3_bucket_acl" "other" {\n  acl = "public-read"\n}\n')
        data = self.scan()
        self.assertEqual(data["attack_paths"][0]["status"], "open")
        self.assertEqual(data["attack_paths"][0]["findings"], ["I-001"])
        self.assertEqual(len(data["findings"][0]["resources"]), 2)

    def test_ambiguous_old_ids_leave_record_untouched(self):
        data = self.scan()
        data["findings"].append(data["findings"][0].copy())
        self.record.write_text(json.dumps(data), encoding="utf-8")
        before = self.record.read_bytes()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as err:
            code = iac_scan.main([str(self.repo), "--into", str(self.record)])
        self.assertEqual(code, 2)
        self.assertIn("duplicate IDs", err.getvalue())
        self.assertEqual(self.record.read_bytes(), before)

    # I-IDs anywhere in prose follow a rescan, and triage keeps its grade.

    def test_prose_mentions_follow_renumbering(self):
        data = self.scan()
        self.assertEqual([f["id"] for f in data["findings"]], ["I-001"])
        self.seed_path(data, "I-001")
        data = json.loads(self.record.read_text(encoding="utf-8"))
        data["decisions"] = ["Accept I-001 until the CDN lands", "I-001の判定は保留"]
        data["attack_paths"][0]["edges"] = ["Public ACL I-001 (z.tf:3)"]
        data["perspectives"][0]["note"] = "I-001 triaged"
        self.record.write_text(json.dumps(data), encoding="utf-8")
        self.add_admin()  # a.tf sorts first, so the bucket becomes I-002
        data = self.scan()
        bucket = next(f["id"] for f in data["findings"] if f["rule"] == "AWS-S3-001")
        self.assertEqual(bucket, "I-002")
        self.assertEqual(data["decisions"], ["Accept I-002 until the CDN lands", "I-002の判定は保留"])
        self.assertEqual(data["attack_paths"][0]["edges"], ["Public ACL I-002 (z.tf:3)"])
        self.assertEqual(data["perspectives"][0]["note"], "I-001 triaged".replace("I-001", "I-002"))
        self.assertEqual(render.dangling_references(data), [])

    def test_removed_baseline_in_prose_is_labelled(self):
        data = self.scan()
        data["next_steps"] = ["Fix I-001 first"]
        self.record.write_text(json.dumps(data), encoding="utf-8")
        self.bucket.write_text("# gone\n", encoding="utf-8")
        data = self.scan()
        self.assertEqual(data["next_steps"], ["Fix [removed baseline: AWS-S3-001 at z.tf] first"])

    def test_meta_prose_follows_renumbering(self):
        data = self.scan()
        data["meta"].update(scope="Bucket I-001 and its path", method="see I-001",
                            inputs=[{"path": "repo", "note": "I-001 found here"}, {"path": "plan.json"}])
        self.record.write_text(json.dumps(data), encoding="utf-8")
        self.add_admin()  # a.tf sorts first, so the bucket becomes I-002
        data = self.scan()
        self.assertEqual((data["meta"]["scope"], data["meta"]["method"]), ("Bucket I-002 and its path", "see I-002"))
        self.assertEqual(data["meta"]["inputs"], [{"path": "repo", "note": "I-002 found here"}, {"path": "plan.json"}])
        self.assertEqual(render.dangling_references(data), [])

    def test_lost_baseline_in_path_or_finding_prose_reopens_it(self):
        data = self.scan()
        self.seed_review(data, "Read the ACL at z.tf:3")
        data = json.loads(self.record.read_text(encoding="utf-8"))
        data["attack_paths"][0]["edges"] = ["Public ACL I-001 (z.tf:3)"]
        data["attack_paths"][0]["findings"] = ["F-001", "I-001"]
        self.review_finding(data)["path"] = "1. Public ACL, as I-001 shows (z.tf:3)"
        self.record.write_text(json.dumps(data), encoding="utf-8")
        self.bucket.write_text("# gone\n", encoding="utf-8")
        data = self.scan()
        ap, finding = data["attack_paths"][0], self.review_finding(data)
        self.assertEqual(ap["edges"], ["Public ACL [removed baseline: AWS-S3-001 at z.tf] (z.tf:3)"])
        self.assertEqual(ap["status"], "unknown")
        self.assertEqual(ap["note"].count("AWS-S3-001 at z.tf"), 1)
        self.assertEqual((finding["validation"]["verdict"], finding["confidence"]), ("Unverified", "Suspected"))
        self.assertIn("AWS-S3-001 at z.tf", finding["validation"]["evidence"])
        self.assertTrue(any(line.startswith("F-001: ") for line in data["limitations"]))

    def test_contract_refuses_an_inventory_from_another_scan(self):
        data = self.scan()
        self.assertEqual(contract_check.baseline_problems(data, self.out / "iac.json"), [])
        # A later --out run without --into leaves the record describing the earlier inputs.
        (self.repo / "topic.tf").write_text('resource "aws_sns_topic" "t" {\n  name = "t"\n}\n', encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(iac_scan.main([str(self.repo), "--out", str(self.out / "iac.json")]), 0)
        problems = contract_check.baseline_problems(data, self.out / "iac.json")
        self.assertEqual(problems, ["inventory: differs from iac.json (resources, by_provider, files); "
                                    "rerun iac_scan.py with both --out and --into"])

    def test_triage_keeps_confidence_and_condition(self):
        data = self.scan()
        data["findings"][0].update(confidence="Environment-dependent", condition="the bucket holds only I-001 assets",
                                   validation={"verdict": "Likely", "evidence": "read z.tf"})
        self.record.write_text(json.dumps(data), encoding="utf-8")
        self.add_admin()
        bucket = next(f for f in self.scan()["findings"] if f["rule"] == "AWS-S3-001")
        self.assertEqual((bucket["confidence"], bucket["condition"], bucket["validation"]["verdict"]),
                         ("Environment-dependent", "the bucket holds only I-002 assets", "Likely"))


if __name__ == "__main__":
    unittest.main()
