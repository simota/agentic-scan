"""iac_scan input handling: encodings, line breaks, unreadable inputs, CLI, rescans."""
import codecs
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "skills" / "infra-scan" / "scripts"))
import findings  # noqa: E402
import iac_scan  # noqa: E402

SG = {"SecurityGroups": [{"GroupId": "sg-1", "IpPermissions": [
    {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}]}
BUCKET = 'resource "aws_s3_bucket_acl" "b" {\n  acl = "public-read"\n}\n'


def quiet(fn, *args):
    err = io.StringIO()
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
        code = fn(*args)
    return code, err.getvalue()


class ScanTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.out = self.root / "out"
        self.out.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, text, encoding="utf-8"):
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text if isinstance(text, bytes) else text.encode(encoding))
        return path

    def scan(self, *extra):
        code, err = quiet(iac_scan.main, [str(self.repo), "--out", str(self.out / "iac.json"), *extra])
        self.assertEqual(code, 0, err)
        return json.loads((self.out / "iac.json").read_text(encoding="utf-8"))

    def rules(self, result):
        return sorted({(h["rule"], h["file"], h["line"]) for h in result["hits"]})

    def test_utf16_export_with_bom_is_read(self):
        self.write("aws-sg.json", codecs.BOM_UTF16_LE + json.dumps(SG).encode("utf-16-le"))
        self.assertIn(("AWS-NET-001", "aws-sg.json", 1), self.rules(self.scan()))

    def test_binary_input_is_listed_not_silent(self):
        self.write("weird.json", b"{\0}")
        self.write("image.png", b"\x89PNG\0\0")
        not_run = self.scan()["not_run"]
        self.assertIn("binary or not UTF-8, skipped: weird.json", not_run)
        self.assertFalse(any("image.png" in n for n in not_run))

    def test_form_feed_does_not_shift_line_numbers(self):
        self.write("pod.yaml", "apiVersion: v1\nkind: Pod\n# page\x0cbreak\nmetadata:\n  name: p\n"
                               "spec:\n  hostNetwork: true\n  containers:\n  - name: c\n    image: x\n")
        self.write("main.tf", "# a\x0cb\n" + BUCKET)
        hits = self.rules(self.scan())
        pod = [line for _, f, line in hits if f == "pod.yaml"]
        self.assertTrue(pod)
        self.assertEqual(set(pod), {7}, hits)
        self.assertEqual({line for _, f, line in hits if f == "main.tf"}, {3}, hits)

    def test_deep_json_is_listed_not_a_crash(self):
        self.write("deep.json", "[" * 100000 + "]" * 100000)
        self.assertIn("JSON nested too deeply, skipped: deep.json", self.scan()["not_run"])

    def test_terraform_json_is_listed(self):
        self.write("main.tf.json", json.dumps({"resource": {}}))
        self.assertIn("Terraform JSON syntax not evaluated; review by hand: main.tf.json",
                      self.scan()["not_run"])

    def test_tofu_files_are_read_and_shadow_tf(self):
        self.write("main.tofu", BUCKET)
        self.write("other.tf", BUCKET.replace('"b"', '"c"'))
        self.write("other.tofu", "")
        result = self.scan()
        self.assertIn(("AWS-S3-001", "main.tofu", 2), self.rules(result))
        self.assertFalse(any(f == "other.tf" for _, f, _ in self.rules(result)))
        self.assertIn("OpenTofu reads other.tofu instead; not evaluated: other.tf", result["not_run"])

    @unittest.skipIf(not hasattr(os, "geteuid") or os.geteuid() == 0, "root reads mode-000 files")
    def test_unreadable_file_is_listed_not_a_crash(self):
        path = self.write("main.tf", BUCKET)
        os.chmod(path, 0)
        try:
            self.assertTrue(any(n.startswith("unreadable, skipped: main.tf") for n in self.scan()["not_run"]))
        finally:
            os.chmod(path, 0o644)

    def test_out_failure_is_exit_2_and_leaves_findings_untouched(self):
        self.write("main.tf", BUCKET)
        blocker = self.root / "afile"
        blocker.write_text("x", encoding="utf-8")
        record = self.out / "findings.json"
        code, err = quiet(iac_scan.main, [str(self.repo), "--out", str(blocker / "iac.json"),
                                          "--into", str(record)])
        self.assertEqual(code, 2)
        self.assertNotIn("Traceback", err)
        self.assertFalse(record.exists())

    def test_duplicate_keys_in_record_are_refused(self):
        record = self.out / "findings.json"
        record.write_text('{"schema_version": 1, "limitations": ["a"], "limitations": []}', encoding="utf-8")
        code, err = quiet(iac_scan.main, [str(self.repo), "--into", str(record)])
        self.assertEqual(code, 2)
        self.assertIn("duplicate JSON key", err)

    def test_snapshots_join_the_repository_baseline(self):
        self.write("main.tf", BUCKET)
        exports = self.root / "exports"
        exports.mkdir()
        (exports / "aws-sg.json").write_text(json.dumps(SG), encoding="utf-8")
        record = self.out / "findings.json"
        result = self.scan("--snapshots", str(exports), "--into", str(record))
        files = {f for _, f, _ in self.rules(result)}
        self.assertEqual(files, {"main.tf", "@snapshots/exports/aws-sg.json"})
        locations = [f["location"] for f in json.loads(record.read_text(encoding="utf-8"))["findings"]]
        self.assertIn("@snapshots/exports/aws-sg.json:1", locations)

    def test_snapshots_inside_the_repository_are_refused(self):
        (self.repo / "exports").mkdir()
        code, err = quiet(iac_scan.main, [str(self.repo), "--snapshots", str(self.repo / "exports")])
        self.assertEqual(code, 2)
        self.assertIn("overlaps the repository", err)

    def test_rescan_keeps_triage_of_unchanged_findings(self):
        self.write("main.tf", BUCKET)
        record = self.out / "findings.json"
        self.scan("--into", str(record))
        fragment = self.root / "triage.json"
        fragment.write_text(json.dumps({"findings": [{"id": "I-001", "validation": {
            "verdict": "FalsePositive", "evidence": "Overridden by the account block at main.tf:9"}}]}),
            encoding="utf-8")
        code, err = quiet(findings.main, ["merge", str(record), str(fragment)])
        self.assertEqual(code, 0, err)
        self.write("extra.tf", BUCKET.replace('"b"', '"c"'))
        self.scan("--into", str(record))
        data = json.loads(record.read_text(encoding="utf-8"))
        kept = next(f for f in data["findings"] if f["location"].startswith("main.tf"))
        new = next(f for f in data["findings"] if f["location"].startswith("extra.tf"))
        self.assertEqual(kept["validation"]["verdict"], "FalsePositive")
        self.assertEqual(new["validation"]["verdict"], "Unverified")

    def test_rescan_with_changed_resources_drops_triage_visibly(self):
        self.write("main.tf", BUCKET)
        record = self.out / "findings.json"
        self.scan("--into", str(record))
        fragment = self.root / "triage.json"
        fragment.write_text(json.dumps({"findings": [{"id": "I-001", "validation": {
            "verdict": "NotApplicable", "evidence": "Public asset bucket at main.tf:1"}}]}), encoding="utf-8")
        self.assertEqual(quiet(findings.main, ["merge", str(record), str(fragment)])[0], 0)
        self.write("main.tf", BUCKET + BUCKET.replace('"b"', '"c"'))
        self.scan("--into", str(record))
        data = json.loads(record.read_text(encoding="utf-8"))
        self.assertEqual(data["findings"][0]["validation"]["verdict"], "Unverified")
        self.assertTrue(any("NotApplicable triage not carried over" in x for x in data["limitations"]))


if __name__ == "__main__":
    unittest.main()
