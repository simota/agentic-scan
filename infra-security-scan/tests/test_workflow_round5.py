"""Workflow friction from a dry run: rescans reopen what changed, gates see
reopened review findings, I-* grading, neutralised S3 hits, render options."""
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
import redaction  # noqa: E402
import render  # noqa: E402

SAMPLE = REPO / "examples" / "findings.sample.json"


def call(main, *argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        code = main([str(a) for a in argv])
    return code, out.getvalue()


class WorkflowTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.out = self.root / "out"
        self.record = self.out / "findings.json"

    def tearDown(self):
        self.tmp.cleanup()

    def scan(self):
        code, out = call(iac_scan.main, self.repo, "--out", self.out / "iac.json", "--into", self.record)
        self.assertEqual(code, 0, out)
        return json.loads(self.record.read_text(encoding="utf-8"))

    def merge(self, fragment):
        path = self.root / "frag.json"
        path.write_text(json.dumps(fragment), encoding="utf-8")
        return call(findings.main, "merge", self.record, path)

    def test_changed_hit_reopens_triage_and_grading_carries(self):
        pod = ("apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n  containers:\n    - name: c\n"
               "      securityContext:\n        privileged: true\n")
        (self.repo / "pod.yaml").write_text(pod + "  volumes:\n    - name: h\n      hostPath:\n        path: /\n")
        self.scan()
        code, out = self.merge({"findings": [{"id": "I-001", "severity": "Low", "confidence": "Confirmed",
                                              "validation": {"verdict": "Valid", "evidence": "no path"}}]})
        self.assertEqual(code, 0, out)
        same = self.scan()["findings"][0]
        self.assertEqual((same["severity"], same["confidence"], same["validation"]["verdict"]),
                         ("Low", "Confirmed", "Valid"))
        (self.repo / "pod.yaml").write_text(pod)  # the hostPath is gone: the hit changed
        data = self.scan()
        self.assertEqual(data["findings"][0]["validation"]["verdict"], "Unverified")
        self.assertTrue([n for n in data["limitations"] if "the hit changed" in n])

    def test_reopened_review_finding_fails_status_and_contract(self):
        data = json.loads(SAMPLE.read_text(encoding="utf-8"))
        review = next(f for f in data["findings"] if f["id"].startswith("F-"))
        review["validation"] = {"verdict": "Unverified", "evidence": "Recheck this finding."}
        self.out.mkdir()
        self.record.write_text(json.dumps(data), encoding="utf-8")
        code, out = call(findings.main, "status", self.record)
        self.assertEqual(code, 1)
        self.assertIn(f"unverified {review['id']}", out)
        problems = contract_check.check(data, self.out, pdf=False)
        self.assertTrue([p for p in problems if "still Unverified" in p and review["id"] in p], problems)

    def test_terragrunt_paths_are_not_payloads(self):
        self.scan()
        code, out = self.merge({"limitations": ["Module source ../../../modules/app is local"]})
        self.assertEqual(code, 0, out)
        code, out = self.merge({"limitations": ["read ../../etc/passwd"]})
        self.assertEqual(code, 1)
        self.assertIn("'../../etc'", out)

    def test_public_access_block_neutralises_acl_and_policy(self):
        (self.repo / "s3.tf").write_text('''resource "aws_s3_bucket" "b" {
  bucket = "assets"
}
resource "aws_s3_bucket_acl" "b" {
  bucket = aws_s3_bucket.b.id
  acl    = "public-read"
}
resource "aws_s3_bucket_policy" "b" {
  bucket = aws_s3_bucket.b.id
  policy = jsonencode({ Statement = [{ Effect = "Allow", Principal = "*", Action = "s3:GetObject", Resource = "*" }] })
}
resource "aws_s3_bucket_public_access_block" "b" {
  bucket                  = aws_s3_bucket.b.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_acl" "other" {
  bucket = "elsewhere"
  acl    = "public-read"
}
''')
        hits = {(h["rule"], h["address"]): h for h in iac_scan.run(self.repo).hits}
        self.assertEqual(hits[("AWS-S3-001", "aws_s3_bucket_acl.b")]["severity"], "Low")
        self.assertIn("neutralised by ignore_public_acls", hits[("AWS-S3-001", "aws_s3_bucket_acl.b")]["detail"])
        self.assertEqual(hits[("AWS-S3-003", "aws_s3_bucket_policy.b")]["severity"], "Low")
        self.assertEqual(hits[("AWS-S3-001", "aws_s3_bucket_acl.other")]["severity"], "High")

    def test_render_options_and_copy_text(self):
        code, out = call(render.main, SAMPLE, "--out", self.out, "--no-pdf", "--repo", self.root / "missing")
        self.assertEqual(code, 2)
        self.assertIn("is not a directory", out)
        failed = []
        import os
        old = os.environ.get("CHROME")
        os.environ["CHROME"] = str(self.root / "no-chrome")
        try:
            self.assertIsNone(render.to_pdf(self.root / "x.html", self.root / "x.pdf", failed))
        finally:
            os.environ.pop("CHROME") if old is None else os.environ.__setitem__("CHROME", old)
        self.assertTrue(any("no-chrome" in f for f in failed))
        data = json.loads(SAMPLE.read_text(encoding="utf-8"))
        excluded = next(f for f in data["findings"] if render.is_excluded(f))
        text = render.finding_markdown(excluded, render.LABELS["en"], "en")
        self.assertTrue(text.startswith(render.LABELS["en"]["md_excluded"]))
        self.assertNotIn("Propose a minimal IaC change", text)
        page = render.render_dashboard(data, render.LABELS["en"], "en", {})
        self.assertIn('data-e="excluded"', page)

    def test_dated_names_are_not_redacted(self):
        self.assertEqual(redaction.scrub_line("Transform: AWS::Serverless-2016-10-31", "yaml"),
                         "Transform: AWS::Serverless-2016-10-31")

    def test_scan_refuses_a_malformed_record(self):
        self.out.mkdir()
        self.record.write_text(json.dumps({"checked_ok": "oops"}), encoding="utf-8")
        code, out = call(iac_scan.main, self.repo, "--out", self.out / "iac.json", "--into", self.record)
        self.assertEqual(code, 2)
        self.assertIn("checked_ok: must be a list", out)


if __name__ == "__main__":
    unittest.main()
