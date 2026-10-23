"""References in the record are read the same way by every tool: not inside a
resource address, not swallowed by a URL that runs into Japanese prose, and
followed by a rescan in every line the reviewer wrote. Record edits never dead-end."""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "skills" / "infra-scan" / "scripts"))
import common  # noqa: E402
import contract_check  # noqa: E402
import findings  # noqa: E402
import iac_scan  # noqa: E402
import render  # noqa: E402

META = {"project": "p", "scope": "s", "date": "2026-10-09", "assessor": "test"}
BUCKET = 'resource "aws_s3_bucket_acl" "public" {\n  bucket = "example-bucket"\n  acl = "public-read"\n}\n'
ADMIN = ('resource "aws_iam_policy" "admin" {\n  policy = jsonencode({ Statement = [{ Effect = "Allow", '
         'Action = "*", Resource = "*" }] })\n}\n')


def finding(fid, severity="Medium", location="main.tf:1", **extra):
    f = {"id": fid, "title": "t", "severity": severity, "confidence": "Suspected",
         "category": "Network exposure", "provider": "aws", "resources": ["aws_s3_bucket.b"],
         "location": location, "actor": "a", "path": "1. edge (main.tf:1)", "contrast": "none",
         "impact": "i", "fix": "f", "regression": "r", "validation": {"verdict": "Likely"}}
    f.update(extra)
    return f


def call(main, *argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main([str(a) for a in argv])
    return code, out.getvalue() + err.getvalue()


class RecordReferencesTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.record = self.root / "out" / "findings.json"
        self.record.parent.mkdir()

    def write(self, data):
        self.record.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")

    def read(self):
        return json.loads(self.record.read_text(encoding="utf-8"))

    def record_with(self, **changes):
        data = render.empty_record()
        data["meta"] = dict(META)
        data.update(changes)
        return data

    def fragment(self, data, name="fragment.json"):
        path = self.root / name
        path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        return path

    def scan(self, repo):
        code, out = call(iac_scan.main, repo, "--out", self.root / "out" / "iac.json", "--into", self.record)
        self.assertEqual(code, 0, out)
        return self.read()

    # --- reading references

    def test_url_ends_where_japanese_prose_begins(self):
        line = "手順は https://example.com/runbookを参照し、F-005を最初に修正する"
        self.assertEqual([m.group() for m in common.find_references(common.RECORD_REFERENCE, line)], ["F-005"])
        self.write(self.record_with(findings=[finding("F-005", "Info", "a.tf:1"), finding("F-006", "High", "a.tf:2")],
                                    next_steps=[line]))
        code, out = call(findings.main, "renumber", self.record)
        self.assertEqual(code, 0, out)
        self.assertEqual(self.read()["next_steps"], [line.replace("F-005", "F-002")])

    def test_an_id_shaped_resource_name_is_not_a_reference(self):
        data = self.record_with(findings=[
            finding("F-005", "Info", "a.tf:1", resources=["aws_s3_bucket.F-005"]),
            finding("F-006", "High", "a.tf:2", resources=["module.I-900.aws_security_group.web"])])
        self.assertEqual(render.dangling_references(data), [])
        self.write(data)
        code, out = call(findings.main, "renumber", self.record)
        self.assertEqual(code, 0, out)
        by_title = {f["id"]: f["resources"] for f in self.read()["findings"]}
        self.assertEqual(by_title, {"F-001": ["module.I-900.aws_security_group.web"],
                                    "F-002": ["aws_s3_bucket.F-005"]})

    def test_ids_joined_by_dots_are_still_references(self):
        line = "Fix F-001...F-003 together; see I-002..I-004 and F-003."
        self.assertEqual([m.group() for m in common.find_references(common.RECORD_REFERENCE, line)],
                         ["F-001", "F-003", "I-002", "I-004", "F-003"])
        self.write(self.record_with(findings=[finding("F-001", "Info", "a.tf:1"), finding("F-002", "Info", "a.tf:2"),
                                              finding("F-003", "High", "a.tf:3")],
                                    next_steps=["Fix F-001...F-003 together; F-003 first."]))
        code, out = call(findings.main, "renumber", self.record)
        self.assertEqual(code, 0, out)
        self.assertEqual(self.read()["next_steps"], ["Fix F-002...F-001 together; F-001 first."])

    # --- rescans

    def test_rescan_rewrites_reviewer_limitations_but_not_its_own_notes(self):
        repo = self.root / "repo"
        repo.mkdir()
        (repo / "z.tf").write_text(BUCKET, encoding="utf-8")
        data = self.scan(repo)
        self.assertEqual([f["id"] for f in data["findings"]], ["I-001"])
        note = "I-009 (was I-008): Valid triage not carried over; the hit changed. Recheck this baseline finding."
        self.write({**data, "limitations": ["I-001: the bucket owner is unconfirmed", note]})
        (repo / "a.tf").write_text(ADMIN, encoding="utf-8")  # sorts first, so the bucket becomes I-002
        data = self.scan(repo)
        bucket = next(f["id"] for f in data["findings"] if f["rule"] == "AWS-S3-001")
        self.assertEqual(bucket, "I-002")
        self.assertEqual(data["limitations"][:2], ["I-002: the bucket owner is unconfirmed", note])
        # A line the reviewer wrote that names a vanished ID is reported.
        data["limitations"].append("I-077 was accepted")
        self.assertIn(("limitations", "I-077"), render.dangling_references(data))
        self.assertNotIn(("limitations", "I-009"), render.dangling_references(data))

    # --- removing records

    def test_remove_takes_the_scanner_note_about_the_removed_finding(self):
        repo = self.root / "repo"
        repo.mkdir()
        (repo / "z.tf").write_text(BUCKET, encoding="utf-8")
        data = self.scan(repo)
        data["meta"].update(META)
        data["findings"].append(finding("F-901", validation={"verdict": "Likely", "evidence": "root cause of I-001"}))
        self.write(data)
        (repo / "z.tf").unlink()
        data = self.scan(repo)
        self.assertTrue(any(line.startswith("F-901: Baseline references removed by rescan: ")
                            for line in data["limitations"]))
        code, out = call(findings.main, "remove", self.record, "F-901")
        self.assertEqual(code, 0, out)
        data = self.read()
        self.assertEqual([f["id"] for f in data["findings"]], [])
        self.assertEqual(render.dangling_references(data), [])

    def test_remove_rewords_another_records_rescan_note(self):
        path = {"id": "AP-01", "entry": "Internet", "target": "b", "status": "unknown", "edges": ["e (main.tf:1)"],
                "findings": ["F-002"], "note": "Recheck"}
        self.write(self.record_with(findings=[finding("F-001"), finding("F-002", attack_paths=["AP-01"])],
                                    attack_paths=[path], limitations=[
                                        "AP-01: Baseline references removed by rescan: supporting evidence for F-001. "
                                        "Recheck this attack path."]))
        code, out = call(findings.main, "remove", self.record, "F-001")
        self.assertEqual(code, 0, out)
        self.assertEqual(self.read()["limitations"], [
            "AP-01: Baseline references removed by rescan: supporting evidence for a removed finding. "
            "Recheck this attack path."])

    def test_remove_does_not_depend_on_argument_order(self):
        for order in (("AP-01", "F-006"), ("F-006", "AP-01")):
            with self.subTest(order=order):
                self.write(self.record_with(
                    findings=[finding("F-006", actor="Internet on AP-01", attack_paths=["AP-01"])],
                    attack_paths=[{"id": "AP-01", "entry": "Internet", "target": "b", "status": "open",
                                   "edges": ["e (main.tf:1)"], "findings": ["F-006"]}]))
                code, out = call(findings.main, "remove", self.record, *order)
                self.assertEqual(code, 0, out)
                self.assertEqual((self.read()["findings"], self.read()["attack_paths"]), ([], []))

    def test_remove_still_refuses_a_mention_that_remains(self):
        self.write(self.record_with(findings=[finding("F-001"), finding("F-002", fix="same fix as F-001")]))
        code, out = call(findings.main, "remove", self.record, "F-001")
        self.assertEqual(code, 1, out)
        self.assertIn("F-001 is still mentioned in F-002.fix", out)
        self.assertEqual(len(self.read()["findings"]), 2)

    # --- the merge gates

    def test_merge_refuses_a_putty_private_key(self):
        self.write(self.record_with(findings=[finding("F-001")]))
        key = "PuTTY-User-Key-File-" + "3: ssh-ed25519\nEncryption: none\nPrivate-Lines: 1\nAAAA"
        frag = self.fragment({"findings": [{"id": "F-001", "validation": {"verdict": "Likely", "evidence": key}}]})
        code, out = call(findings.main, "merge", self.record, frag)
        self.assertEqual(code, 1, out)
        self.assertIn("credential-shaped content refused", out)
        self.assertNotIn("AAAA", out)

    def test_the_rule_field_is_prose_for_the_payload_gate(self):
        self.write(self.record_with(findings=[finding("F-001")]))
        frag = self.fragment({"findings": [{"id": "F-001", "rule": "curl http://169.254.169.254/latest"}]})
        code, out = call(findings.main, "merge", self.record, frag)
        self.assertEqual(code, 1, out)
        self.assertIn("F-001.rule", out)

    def test_a_null_meta_key_is_removed(self):
        self.write(self.record_with(findings=[finding("F-001")]))
        self.write({**self.read(), "meta": {**META, "method": "Static review"}})
        code, out = call(findings.main, "merge", self.record, self.fragment({"meta": {"method": None}}))
        self.assertEqual(code, 0, out)
        self.assertNotIn("method", self.read()["meta"])

    # --- messages and hand-edited records

    def test_schema_errors_hide_a_private_key_body(self):
        body = "Qm" + "x7Lp" * 12
        marker = "-----BEGIN " + "PRIVATE KEY-----"
        f = finding("F-001", confidence="Confirmed", validation={"verdict": "Valid", "evidence": "e"},
                    path=f"1. key {marker}{body}")
        with self.assertRaises(render.SchemaError) as caught:
            render.validate(self.record_with(findings=[f]))
        self.assertNotIn(body, str(caught.exception))
        self.assertNotIn(body[:12], str(caught.exception))

    def test_contract_check_reports_a_list_severity(self):
        out_dir = self.root / "out"
        self.write(self.record_with(findings=[finding("F-001", severity=["High"])]))
        code, out = call(contract_check.main, out_dir, "--no-pdf")
        self.assertEqual(code, 1, out)
        self.assertNotIn("Traceback", out)
        self.assertIn("severity", out)


if __name__ == "__main__":
    unittest.main()
