"""The record, its references and its rendered views agree with each other."""
import contextlib
import copy
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "skills" / "infra-scan" / "scripts"))
import common  # noqa: E402
import contract_check  # noqa: E402
import findings  # noqa: E402
import render  # noqa: E402

SAMPLE = REPO / "examples" / "findings.sample.json"


def quiet(main, *argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main([str(a) for a in argv])
    return code, out.getvalue() + err.getvalue()


class RecordConsistencyTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.out = Path(self.tmp.name)
        self.data = json.loads(SAMPLE.read_text(encoding="utf-8"))

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, data=None):
        data = self.data if data is None else data
        (self.out / "findings.json").write_text(json.dumps(data), encoding="utf-8")
        baseline = [f for f in data["findings"] if str(f.get("id", "")).startswith("I-")]
        (self.out / "iac.json").write_text(json.dumps({"tool": "iac_scan", "commit": data["meta"].get("commit"),
                                                       "findings": baseline}), encoding="utf-8")

    def render(self):
        code, msg = quiet(render.main, self.out / "findings.json", "--out", self.out, "--no-pdf")
        self.assertEqual(code, 0, msg)

    def test_meta_prose_follows_a_renumber(self):
        data = json.loads(SAMPLE.read_text(encoding="utf-8").replace("F-006", "F-906"))
        data["meta"]["scope"] = "Production, except the bucket in F-906"
        self.write(data)
        record = self.out / "findings.json"
        self.assertEqual(quiet(findings.main, "renumber", record)[0], 0)
        self.assertEqual(json.loads(record.read_text(encoding="utf-8"))["meta"]["scope"],
                         "Production, except the bucket in F-006")
        data["meta"]["scope"] = "Production, except the bucket in F-950"
        self.assertIn(("meta.scope", "F-950"), render.dangling_references(data))

    def test_a_finding_on_an_unknown_path_is_not_confirmed(self):
        f4 = next(f for f in self.data["findings"] if f["id"] == "F-004")
        ap5 = next(a for a in self.data["attack_paths"] if a["id"] == "AP-05")
        self.assertEqual((ap5["status"], ap5["findings"], f4["attack_paths"]), ("unknown", ["F-004"], ["AP-05"]))
        f4["confidence"] = "Confirmed"
        f4.pop("condition")
        for side in ("both", "path only", "finding only"):
            with self.subTest(side=side):
                data = copy.deepcopy(self.data)
                if side == "path only":
                    next(f for f in data["findings"] if f["id"] == "F-004").pop("attack_paths")
                if side == "finding only":
                    next(a for a in data["attack_paths"] if a["id"] == "AP-05")["findings"] = []
                with self.assertRaisesRegex(render.SchemaError, "F-004: a Medium on AP-05, whose status is unknown"):
                    render.validate(data)
                render.validate(data, partial=True)  # a merge in progress may still adjust it
        self.write()
        code, msg = quiet(contract_check.main, self.out, "--no-pdf")
        self.assertEqual(code, 1, msg)
        self.assertIn("whose status is unknown", msg)
        f4["severity"] = "Low"
        render.validate(self.data)

    def test_instance_key_shaped_like_an_id_is_an_address(self):
        for key in ("AP-07", "F-002", "I-001"):
            with self.subTest(key=key):
                text = f'aws_security_group.db["{key}"]'
                self.assertEqual(list(common.find_references(common.RECORD_REFERENCE, text)), [])
        for prose in ('see "F-002"', 'Related findings: ["F-002"]', 'items["F-002"]'):
            with self.subTest(prose=prose):
                self.assertEqual([m.group() for m in common.find_references(common.RECORD_REFERENCE, prose)],
                                 ["F-002"])
        data = copy.deepcopy(self.data)
        baseline = next(f for f in data["findings"] if f["id"].startswith("I-"))
        baseline["resources"] = ['aws_security_group.db["AP-07"]', 'aws_security_group.db["F-002"]']
        self.assertEqual(render.dangling_references(data), [])
        self.write(data)
        before = json.loads((self.out / "findings.json").read_text(encoding="utf-8"))
        code, msg = quiet(findings.main, "renumber", self.out / "findings.json")
        self.assertEqual(code, 0, msg)
        after = json.loads((self.out / "findings.json").read_text(encoding="utf-8"))
        self.assertEqual(next(f for f in after["findings"] if f["id"] == baseline["id"])["resources"],
                         next(f for f in before["findings"] if f["id"] == baseline["id"])["resources"])

    def test_report_rendered_before_the_last_merge_fails_the_contract(self):
        self.write()
        self.render()
        code, msg = quiet(contract_check.main, self.out, "--no-pdf")
        self.assertEqual(code, 0, msg)
        fragment = self.out.parent / (self.out.name + "-fragment.json")
        fragment.write_text(json.dumps({"limitations": ["PDF engine unavailable; HTML reports only."]}),
                            encoding="utf-8")
        self.addCleanup(fragment.unlink)
        code, msg = quiet(findings.main, "merge", self.out / "findings.json", fragment)
        self.assertEqual(code, 0, msg)
        code, msg = quiet(contract_check.main, self.out, "--no-pdf")
        self.assertEqual(code, 1, msg)
        self.assertIn("dashboard.html was not rendered from this findings.json", msg)
        self.assertIn("assessment.html was not rendered from this findings.json", msg)
        self.render()
        code, msg = quiet(contract_check.main, self.out, "--no-pdf")
        self.assertEqual(code, 0, msg)

    def test_report_rewritten_after_a_pdf_failure_keeps_the_stamp(self):
        self.write()
        with patch.object(render, "to_pdf", return_value=None):
            code, msg = quiet(render.main, self.out / "findings.json", "--out", self.out)
        self.assertEqual(code, 0, msg)
        self.assertFalse((self.out / "assessment.pdf").exists())
        code, msg = quiet(contract_check.main, self.out, "--no-pdf")
        self.assertEqual(code, 0, msg)

    def test_reformatting_the_record_keeps_the_stamp(self):
        self.write()
        self.render()
        path = self.out / "findings.json"
        path.write_text(json.dumps(json.loads(path.read_text(encoding="utf-8")), indent=4), encoding="utf-8")
        code, msg = quiet(contract_check.main, self.out, "--no-pdf")
        self.assertEqual(code, 0, msg)

    def test_root_dotfile_counts_as_a_cited_edge(self):
        f = self.data["findings"][0]
        self.assertEqual((f["validation"]["verdict"], f["confidence"]), ("Valid", "Confirmed"))
        for cited in (".env:3", ".npmrc:1", ".terraform-version:1"):
            with self.subTest(cited=cited):
                f["path"] = f"1. Credential committed in ({cited})\n2. Bucket readable ({f['location']})"
                render.validate(self.data)
        f["path"] = "1. Credential committed somewhere\n2. Bucket readable"
        with self.assertRaises(render.SchemaError):
            render.validate(self.data)

    def test_covered_baseline_finding_counts_as_unverified(self):
        baseline = next(f for f in self.data["findings"] if f["id"].startswith("I-"))
        root = self.data["findings"][0]
        root["validation"]["evidence"] += f" Root cause of {baseline['id']}."
        baseline["validation"] = {"verdict": "Unverified"}
        self.assertIn(baseline["id"], render.covered_by(self.data))
        self.assertEqual(render.counts(self.data)["unverified"], len(render.untriaged(self.data)))
        self.assertEqual(render.counts(self.data)["unverified"], 1)

    def test_multiline_attack_path_target_names_the_rule(self):
        self.data["attack_paths"][0]["target"] = "Customer database\n(aws_db_instance.main)"
        with self.assertRaises(render.SchemaError) as caught:
            render.validate(self.data)
        self.assertIn("AP-01: target must be one line", caught.exception.problems)


if __name__ == "__main__":
    unittest.main()
