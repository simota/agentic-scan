"""Editing the record: null removes keys, remove, renumber, paths, prose and counts."""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "skills" / "infra-scan" / "scripts"))
import findings  # noqa: E402
import iac_scan  # noqa: E402
import render  # noqa: E402

META = {"project": "p", "scope": "s", "date": "2026-10-09", "assessor": "test"}


def finding(fid, severity="Medium", location="main.tf:1", **extra):
    f = {"id": fid, "title": "t", "severity": severity, "confidence": "Suspected",
         "category": "Network exposure", "provider": "aws", "resources": ["aws_s3_bucket.b"],
         "location": location, "actor": "a", "path": "1. edge (main.tf:1)", "contrast": "none",
         "impact": "i", "fix": "f", "regression": "r", "validation": {"verdict": "Likely"}}
    f.update(extra)
    return f


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = findings.main(list(argv))
    return code, out.getvalue() + err.getvalue()


class RecordEditingTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.record = self.root / "findings.json"

    def tearDown(self):
        self.tmp.cleanup()

    def merge(self, fragment):
        path = self.root / f"frag{len(list(self.root.iterdir()))}.json"
        path.write_text(json.dumps(fragment), encoding="utf-8")
        return run("merge", str(self.record), str(path))

    def load(self):
        return json.loads(self.record.read_text(encoding="utf-8"))

    def test_null_removes_a_stale_key(self):
        f = finding("F-001", confidence="Environment-dependent", condition="x unknown", cwe="CWE-284")
        self.assertEqual(self.merge({"meta": META, "findings": [f]})[0], 0)
        code, out = self.merge({"findings": [{"id": "F-001", "confidence": "Confirmed", "condition": None}]})
        self.assertEqual(code, 0, out)
        saved = self.load()["findings"][0]
        self.assertNotIn("condition", saved)
        self.assertEqual(saved["cwe"], "CWE-284")

    def test_remove_and_renumber_keep_references_consistent(self):
        ap = {"id": "AP-01", "entry": "Internet", "target": "db", "status": "open", "edges": ["e"],
              "findings": ["F-001", "F-002", "F-003"]}
        fs = [finding("F-001", "Low", "b.tf:10", attack_paths=["AP-01"]),
              finding("F-002", "High", "a.tf:9", attack_paths=["AP-01"]),
              finding("F-003", "High", "a.tf:10", attack_paths=["AP-01"],
                      validation={"verdict": "Likely", "evidence": "same root cause as F-001; see https://x/F-001"})]
        self.assertEqual(self.merge({"meta": META, "findings": fs, "attack_paths": [ap],
                                     "decisions": ["Fix F-002 first"]})[0], 0)
        code, out = run("remove", str(self.record), "F-001")
        self.assertEqual(code, 0, out)
        self.assertEqual(self.load()["attack_paths"][0]["findings"], ["F-002", "F-003"])
        code, out = run("renumber", str(self.record))
        self.assertEqual(code, 0, out)
        data = self.load()
        self.assertEqual([f["id"] for f in data["findings"]], ["F-001", "F-002"])
        self.assertEqual(data["findings"][0]["location"], "a.tf:9")
        self.assertEqual(data["attack_paths"][0]["findings"], ["F-001", "F-002"])
        self.assertEqual(data["decisions"], ["Fix F-001 first"])
        self.assertIn("https://x/F-001", data["findings"][1]["validation"]["evidence"])
        self.assertEqual(run("remove", str(self.record), "I-001")[0], 1)

    def test_ordinary_infrastructure_prose_is_not_a_payload(self):
        texts = ["module.app is sourced from ../../modules/app",
                 "Buckets 'logs' and 'backups' share a key", "Role reads 'prod' or 'staging' secrets"]
        f = finding("F-001")
        for n, text in enumerate(texts):
            with self.subTest(n=n):
                f["path"] = text
                self.assertEqual(self.merge({"meta": META, "findings": [f]})[0], 0)
        for text in ("' or 1=1 --", "../../../etc/passwd"):
            f["path"] = text
            self.assertEqual(self.merge({"findings": [f]})[0], 1)

    def test_paths_with_spaces_and_extensionless_citations(self):
        repo = self.root / "repo"
        (repo / "env prod").mkdir(parents=True)
        (repo / "env prod" / "main.tf").write_text(
            'resource "aws_s3_bucket_acl" "b" {\n  acl = "public-read"\n}\n', encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(iac_scan.main([str(repo), "--into", str(self.record)]), 0)
        f = finding("F-001", confidence="Confirmed", path="1. Owner is unset (CODEOWNERS:3)\n2. Build (Makefile:2)",
                    validation={"verdict": "Valid", "evidence": "read"})
        code, out = self.merge({"meta": META, "findings": [f]})
        self.assertEqual(code, 0, out)
        render.validate(self.load())

    def test_nested_unknown_keys_are_refused(self):
        for change in (lambda f: f["validation"].__setitem__("evidance", "typo"),
                       lambda f: f.__setitem__("references", [{"title": "t", "url": "https://e.com/", "x": 1}])):
            f = finding("F-001")
            change(f)
            self.assertEqual(self.merge({"meta": META, "findings": [f]})[0], 2)

    def test_baseline_hit_named_by_its_root_cause_is_counted_once(self):
        data = render.empty_record()
        data["findings"] = [finding("F-001", "High", validation={"verdict": "Valid", "evidence": "root cause of I-001"}),
                            dict(finding("I-001", "High"), rule="AWS-NET-001")]
        c = render.counts(data)
        self.assertEqual((c["High"], c["covered"]), (1, 1))


if __name__ == "__main__":
    unittest.main()
