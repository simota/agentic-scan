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
        data["meta"].update(project="example", scope="test", date="2026-10-08", assessor="test")
        data["perspectives"] = [{"name": n, "status": "Applied"} for n in render.perspective_names()]
        data["attack_paths"] = [{"id": "AP-01", "entry": "Internet", "target": "Example bucket",
                                 "status": "open", "edges": ["Public ACL (z.tf:3)"], "findings": [fid]}]
        self.record.write_text(json.dumps(data), encoding="utf-8")

    def add_admin(self):
        (self.repo / "a.tf").write_text('resource "aws_iam_policy" "admin" {\n'
                                       '  policy = jsonencode({ Statement = [{ Effect = "Allow", '
                                       'Action = "*", Resource = "*" }] })\n}\n', encoding="utf-8")

    def assert_report_valid(self, data):
        render.validate(data)
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(render.main([str(self.record), "--out", str(self.out), "--no-pdf"]), 0)
            code = contract_check.main([str(self.out), "--no-pdf"])
        self.assertEqual(code, 0, err.getvalue())

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
        self.assertIn("unmatched baseline reference I-002", data["attack_paths"][0]["note"])

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


if __name__ == "__main__":
    unittest.main()
