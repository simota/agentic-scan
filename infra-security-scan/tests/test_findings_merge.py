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
import render  # noqa: E402

META = {"project": "acme", "scope": "prod", "date": "2026-10-08", "assessor": "Claude Code (test)"}


def finding(fid="F-001", **extra):
    f = {
        "id": fid, "title": "Bucket readable by allUsers", "severity": "High", "confidence": "Confirmed",
        "category": "Data protection", "provider": "gcp", "resources": ["google_storage_bucket_iam_member.x"],
        "location": "envs/prod/gcp/storage.tf:27", "actor": "Anyone on the internet",
        "path": "1. allUsers binding (envs/prod/gcp/storage.tf:27)", "impact": "Expected private; actual public",
        "fix": "Remove the binding", "regression": "No allUsers members",
        "validation": {"verdict": "Valid", "evidence": "Read at the cited line"},
    }
    f.update(extra)
    return f


class MergeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.record = self.dir / "findings.json"
        self.n = 0

    def tearDown(self):
        self.tmp.cleanup()

    def fragment(self, data, raw=None):
        self.n += 1
        path = self.dir / f"frag{self.n}.json"
        path.write_text(raw if raw is not None else json.dumps(data), encoding="utf-8")
        return str(path)

    def merge(self, *fragments):
        err = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            code = findings.main(["merge", str(self.record), *fragments])
        return code, err.getvalue()

    def load(self):
        return json.loads(self.record.read_text(encoding="utf-8"))

    def test_creates_record_and_merges_in_order(self):
        code, err = self.merge(self.fragment({"meta": META}), self.fragment({"findings": [finding()]}))
        self.assertEqual(code, 0, err)
        data = self.load()
        self.assertEqual(data["schema_version"], 1)
        self.assertEqual(data["meta"]["project"], "acme")
        self.assertEqual([f["id"] for f in data["findings"]], ["F-001"])

    def test_update_by_id_key_by_key(self):
        self.merge(self.fragment({"meta": META, "findings": [finding()]}))
        code, err = self.merge(self.fragment({"findings": [{"id": "F-001", "cwe": "CWE-200"}]}))
        self.assertEqual(code, 0, err)
        f = self.load()["findings"][0]
        self.assertEqual(f["cwe"], "CWE-200")
        self.assertEqual(f["title"], "Bucket readable by allUsers")

    def test_attack_paths_lists_and_perspectives(self):
        ap = {"id": "AP-01", "entry": "Internet", "target": "exports", "status": "open",
              "edges": ["Internet → bucket (envs/prod/gcp/storage.tf:27)"], "findings": ["F-001"]}
        self.merge(self.fragment({"findings": [finding()], "attack_paths": [ap],
                                  "limitations": ["no snapshot"],
                                  "perspectives": [{"name": "Kubernetes", "status": "Not checked", "note": "no cluster"}]}))
        code, err = self.merge(self.fragment({"limitations": ["no snapshot", "no org policy"],
                                             "perspectives": [{"name": "Kubernetes", "status": "N/A", "note": "none"}]}))
        self.assertEqual(code, 0, err)
        data = self.load()
        self.assertEqual(data["limitations"], ["no snapshot", "no org policy"])
        self.assertEqual(data["perspectives"], [{"name": "Kubernetes", "status": "N/A", "note": "none"}])
        self.assertEqual(data["attack_paths"][0]["id"], "AP-01")

    def test_i_findings_owned_by_iac_scan(self):
        code, err = self.merge(self.fragment({"findings": [finding("I-001", rule="AWS-NET-001")]}))
        self.assertEqual(code, 1)
        self.assertIn("I-* findings come only from iac_scan.py", err)
        seeded = render.empty_record()
        seeded["findings"].append({k: v for k, v in finding("I-001", rule="AWS-NET-001").items()
                                   if k not in ("actor", "path", "impact", "fix", "regression")}
                                  | {"validation": {"verdict": "Unverified"}})
        self.record.write_text(json.dumps(seeded), encoding="utf-8")
        code, err = self.merge(self.fragment({"findings": [{"id": "I-001", "title": "renamed"}]}))
        self.assertEqual(code, 1)
        self.assertIn("only an I-* finding's validation", err)
        code, err = self.merge(self.fragment({"findings": [
            {"id": "I-001", "validation": {"verdict": "FalsePositive", "evidence": "port closed by NACL"}}]}))
        self.assertEqual(code, 0, err)
        self.assertEqual(self.load()["findings"][0]["validation"]["verdict"], "FalsePositive")

    def test_owned_and_unknown_keys_refused(self):
        for frag, needle in (({"meta": {"commit": "abc"}}, "meta.commit"),
                             ({"inventory": {}}, "iac_scan.py"),
                             ({"schema_version": 1}, "iac_scan.py"),
                             ({"extra": []}, "unsupported keys"),
                             ({"findings": [finding(_note="x")]}, "internal fields")):
            with self.subTest(frag=list(frag)):
                code, err = self.merge(self.fragment(frag))
                self.assertEqual(code, 1)
                self.assertIn(needle, err)
        self.assertFalse(self.record.exists())

    def test_payloads_and_credentials_refused(self):
        values = [
            "AKIA" + "Q" * 16,
            "-----BEGIN " + "RSA PRIVATE KEY-----",
            "ghp_" + "a" * 36,
            "xox" + "b-123",
            "fetch 169.254." + "169.254 from the task",
            "query metadata.google" + ".internal",
            "<scr" + "ipt>",
        ]
        for value in values:
            with self.subTest(value=value[:8]):
                code, err = self.merge(self.fragment({"findings": [finding(impact=value)]}))
                self.assertEqual(code, 1)
                self.assertIn("not a payload or credential", err)
        ap = {"id": "AP-01", "entry": "x", "target": "y", "status": "open", "edges": ["AKIA" + "Z" * 16]}
        code, _ = self.merge(self.fragment({"attack_paths": [ap]}))
        self.assertEqual(code, 1)

    def test_duplicate_json_keys_unreadable(self):
        code, err = self.merge(self.fragment(None, raw='{"meta": {}, "meta": {}}'))
        self.assertEqual(code, 2)
        self.assertIn("duplicate", err)

    def test_schema_error_leaves_record_untouched(self):
        self.merge(self.fragment({"meta": META, "findings": [finding()]}))
        before = self.record.read_text(encoding="utf-8")
        code, err = self.merge(self.fragment({"findings": [{"id": "F-001", "severity": "Critical"}]}))
        self.assertEqual(code, 2)
        self.assertIn("severity", err)
        self.assertEqual(self.record.read_text(encoding="utf-8"), before)
        self.assertEqual(sorted(p.name for p in self.dir.iterdir() if p.name.startswith(".findings.")), [])

    def test_refusal_in_later_fragment_writes_nothing(self):
        good = self.fragment({"meta": META})
        bad = self.fragment({"inventory": {}})
        code, _ = self.merge(good, bad)
        self.assertEqual(code, 1)
        self.assertFalse(self.record.exists())


if __name__ == "__main__":
    unittest.main()
