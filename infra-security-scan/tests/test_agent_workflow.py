"""Friction found by running the skill end to end as an agent would."""
import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
SCRIPTS = REPO / "skills" / "infra-scan" / "scripts"
sys.path.insert(0, str(SCRIPTS))
import findings  # noqa: E402
import iac_scan  # noqa: E402
import render  # noqa: E402

BUCKET = 'resource "aws_s3_bucket_acl" "b" {\n  acl = "public-read"\n}\n'


def run(main, *argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        code = main(list(argv))
    return code, out.getvalue()


class WorkflowTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.record = self.root / "out" / "findings.json"

    def tearDown(self):
        self.tmp.cleanup()

    def fragment(self, data):
        path = self.root / f"frag{len(list(self.root.glob('frag*')))}.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        return str(path)

    def test_baseline_findings_can_be_environment_dependent(self):
        (self.repo / "main.tf").write_text(BUCKET, encoding="utf-8")
        self.assertEqual(run(iac_scan.main, str(self.repo), "--into", str(self.record))[0], 0)
        code, out = run(findings.main, "merge", str(self.record), self.fragment({"findings": [{
            "id": "I-001", "confidence": "Environment-dependent",
            "condition": "No account-level public access block outside the inputs",
            "validation": {"verdict": "Likely", "evidence": "ACL read at main.tf:2"}}]}))
        self.assertEqual(code, 0, out)

    def test_status_lists_untriaged_and_dangling(self):
        (self.repo / "main.tf").write_text(BUCKET, encoding="utf-8")
        run(iac_scan.main, str(self.repo), "--into", str(self.record))
        code, out = run(findings.main, "status", str(self.record))
        self.assertEqual(code, 1)
        self.assertIn("unverified I-001 AWS-S3-001 main.tf:2", out)
        run(findings.main, "merge", str(self.record), self.fragment({
            "findings": [{"id": "I-001", "validation": {"verdict": "Valid", "evidence": "see F-007"}}]}))
        code, out = run(findings.main, "status", str(self.record))
        self.assertEqual(code, 1)
        self.assertIn("dangling  F-007 in I-001.validation.evidence", out)

    def test_scripts_run_in_isolated_mode(self):
        (self.repo / "main.tf").write_text(BUCKET, encoding="utf-8")
        for script, args in (("iac_scan.py", [str(self.repo), "--out", str(self.root / "iac.json")]),
                             ("render.py", [str(REPO / "examples" / "findings.sample.json"), "--out",
                                            str(self.root / "r"), "--no-pdf"]),
                             ("findings.py", ["status", str(REPO / "examples" / "findings.sample.json")])):
            with self.subTest(script=script):
                proc = subprocess.run([sys.executable, "-I", str(SCRIPTS / script), *args],
                                      capture_output=True, text=True, cwd=self.root)
                self.assertNotIn("ModuleNotFoundError", proc.stderr)
                self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_duplicate_declarations_in_one_module_are_noted(self):
        (self.repo / "a.tf").write_text(BUCKET, encoding="utf-8")
        (self.repo / "b.tf").write_text(BUCKET, encoding="utf-8")
        notes = iac_scan.run(self.repo).not_run
        self.assertTrue(any(n.startswith("duplicate declaration of aws_s3_bucket_acl.b") for n in notes), notes)

    def test_exports_committed_to_the_repository_get_no_excerpts(self):
        exports = {"sg.json": {"SecurityGroups": [{"GroupId": "sg-1", "Description": "owner alice@example.com"}]},
                   "iam.json": {"bindings": [{"role": "roles/viewer", "members": ["user:alice@example.com"]}],
                                "etag": "BwX"},
                   "pods.json": {"apiVersion": "v1", "kind": "List", "items": [],
                                 "metadata": {"resourceVersion": ""}},
                   "role.json": {"Role": {"RoleName": "r", "Arn": "arn:aws:iam::1:role/r"}},
                   "disk.json": {"name": "d", "selfLink": "https://www.googleapis.com/compute/v1/x"},
                   # Shapes the scanner reads as exports (describe-trails, get-public-access-block).
                   "trails.json": {"trailList": [{"Name": "t", "S3BucketName": "acme-trail-logs",
                                                  "IsMultiRegionTrail": False}]},
                   "pab.json": {"PublicAccessBlockConfiguration": {"BlockPublicAcls": False}}}
        for name, doc in exports.items():
            with self.subTest(name=name):
                path = self.repo / name
                path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
                self.assertIsNone(render.source_lines(path))

    def test_hand_written_configuration_keeps_its_excerpts(self):
        for name, doc in (("lifecycle.json", {"Rules": [{"ID": "expire", "Status": "Enabled"}]}),
                          ("list.json", {"apiVersion": "v1", "kind": "List", "items": []})):
            with self.subTest(name=name):
                path = self.repo / name
                path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
                self.assertIsNotNone(render.source_lines(path))

    def test_every_baseline_title_has_a_japanese_title(self):
        for rule, (title, *_rest) in iac_scan.RULES.items():
            with self.subTest(rule=rule):
                self.assertNotEqual(render.shown(title, "ja"), title)


if __name__ == "__main__":
    unittest.main()
