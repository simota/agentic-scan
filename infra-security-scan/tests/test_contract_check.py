import contextlib
import copy
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "skills" / "infra-security-scan" / "scripts"))
import contract_check  # noqa: E402
import render  # noqa: E402

SAMPLE = REPO / "examples" / "findings.sample.json"


class ContractTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.out = Path(self.tmp.name)
        self.data = json.loads(SAMPLE.read_text(encoding="utf-8"))
        self.write()

    def tearDown(self):
        self.tmp.cleanup()

    def write(self):
        (self.out / "findings.json").write_text(json.dumps(self.data), encoding="utf-8")
        # The baseline the record's I-* came from, as iac_scan.py --out writes it.
        baseline = [f for f in self.data["findings"] if str(f.get("id", "")).startswith("I-")]
        (self.out / "iac.json").write_text(json.dumps({"tool": "iac_scan", "commit": self.data["meta"].get("commit"),
                                                       "findings": baseline}), encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(render.main([str(self.out / "findings.json"), "--out", str(self.out), "--no-pdf"]), 0)

    def check(self, *extra):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = contract_check.main([str(self.out), "--no-pdf", *extra])
        return code, out.getvalue(), err.getvalue()

    def test_sample_holds(self):
        code, out, err = self.check()
        self.assertEqual(code, 0, err)

    def test_untriaged_baseline_finding_is_a_violation(self):
        self.data["findings"][7]["validation"] = {"verdict": "Unverified"}
        self.write()
        code, _, err = self.check()
        self.assertEqual(code, 1)
        self.assertIn("still Unverified", err)
        self.assertIn("I-002", err)

    def test_baseline_validation_of_the_wrong_type_is_a_violation(self):
        self.data["findings"][7]["validation"] = "Valid"
        self.write_raw()
        code, _, err = self.check()
        self.assertEqual(code, 1, err)
        self.assertIn("validation.verdict", err)

    def write_raw(self):
        (self.out / "findings.json").write_text(json.dumps(self.data), encoding="utf-8")

    def test_placeholder_outputs_are_violations(self):
        for name, body in (("dashboard.html", ""), ("assessment.html", "not a report"),
                           ("iac.json", "{}"), ("assessment.pdf", "not a pdf")):
            with self.subTest(name=name):
                self.write()
                (self.out / name).write_text(body, encoding="utf-8")
                code, _, err = self.check() if name != "assessment.pdf" else self.check_pdf()
                self.assertEqual(code, 1)
                self.assertIn(f"outputs: {name} ", err)

    def check_pdf(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = contract_check.main([str(self.out)])
        return code, out.getvalue(), err.getvalue()

    def test_lines_in_one_file_order_numerically(self):
        fs = [f for f in self.data["findings"] if f["id"] in ("F-001", "F-002")]
        fs[0]["location"], fs[1]["location"] = "storage.tf:9", "storage.tf:10"
        self.write()
        code, _, err = self.check()
        self.assertEqual(code, 0, err)

    def test_pdf_required_without_flag(self):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as err:
            code = contract_check.main([str(self.out)])
        self.assertEqual(code, 1)
        self.assertIn("outputs: assessment.pdf missing", err.getvalue())

    def test_a_pdf_left_beside_a_no_pdf_render_is_a_violation(self):
        for body in (b"", b"%PDF-1.4\n%x\n"):
            with self.subTest(body=body):
                (self.out / "assessment.pdf").write_bytes(body)
                code, _, err = self.check()
                self.assertEqual(code, 1)
                self.assertIn("outputs: assessment.pdf is present although --no-pdf", err)
        (self.out / "assessment.pdf").unlink()
        self.assertEqual(self.check()[0], 0)

    def test_extra_file_needs_allow(self):
        (self.out / "README.md").write_text("x", encoding="utf-8")
        code, _, err = self.check()
        self.assertEqual(code, 1)
        self.assertIn("unexpected README.md", err)
        self.assertEqual(self.check("--allow", "README.md")[0], 0)

    def test_state_files_forbidden_even_when_allowed(self):
        (self.out / "terraform.tfstate").write_text("{}", encoding="utf-8")
        code, _, err = self.check("--allow", "terraform.tfstate")
        self.assertEqual(code, 1)
        self.assertIn("state or variable file", err)

    def test_id_order_and_gaps(self):
        fs = self.data["findings"]
        fs[0]["id"], fs[5]["id"] = "F-006", "F-001"
        for ap in self.data["attack_paths"]:
            ap["findings"] = []
        self.write()
        code, _, err = self.check()
        self.assertEqual(code, 1)
        self.assertIn("severity order", err)
        self.data["findings"][5]["id"] = "F-009"
        self.write()
        self.assertIn("without gaps", self.check()[2])

    def test_prose_naming_missing_records_is_a_violation(self):
        self.data["decisions"].append("Confirm F-099 and AP-42 with the owner")
        self.data["findings"][0]["impact"] += " See https://example.com/F-777 for background."
        self.write()
        code, _, err = self.check()
        self.assertEqual(code, 1)
        self.assertIn("names F-099", err)
        self.assertIn("names AP-42", err)
        self.assertNotIn("F-777", err)

    def test_four_digit_review_ids_follow_numeric_order(self):
        template = self.data["findings"][0]
        self.data["findings"] = []
        self.data["attack_paths"] = []
        # Prose naming the sample's records would now dangle.
        for p in self.data["perspectives"]:
            p["note"] = "applied" if p["status"] == "Applied" else "not in the inputs"
        for key in ("decisions", "next_steps"):
            self.data[key] = []
        for n in range(1000, 0, -1):
            f = copy.deepcopy(template)
            f["id"] = f"F-{n:03d}"
            f["location"] = f"resources/{n:04d}.tf:1"
            f["path"] = f"1. Public ACL ({f['location']})"
            f.pop("attack_paths", None)
            self.data["findings"].append(f)
        self.write()
        code, _, err = self.check()
        self.assertEqual(code, 0, err)
        for name in ("dashboard.html", "assessment.html"):
            page = (self.out / name).read_text(encoding="utf-8")
            self.assertLess(page.index('id="F-999"'), page.index('id="F-1000"'))

    def test_perspective_missing_and_inventory_missing(self):
        self.data["perspectives"] = self.data["perspectives"][1:]
        del self.data["inventory"]
        self.write()
        code, _, err = self.check()
        self.assertEqual(code, 1)
        self.assertIn("'Network exposure' recorded 0 times", err)
        self.assertIn("inventory: missing", err)
        # Rerunning with --into alone would leave iac.json stale; the hint names both.
        self.assertIn("--out <out>/iac.json --into <out>/findings.json", err)

    def test_schema_failure_is_a_violation(self):
        (self.out / "findings.json").write_text(json.dumps({**self.data, "meta": {}}), encoding="utf-8")
        code, _, err = self.check()
        self.assertEqual(code, 1)
        self.assertIn("meta.project: required", err)

    def test_an_assumed_severity_axis_sends_each_high_finding_to_decisions(self):
        high = [f["id"] for f in self.data["findings"]
                if f["severity"] == "High" and f["validation"]["verdict"] not in render.EXCLUDED]
        self.assertEqual(high, ["F-001", "F-002", "I-001"])
        self.data["meta"]["axis"] = "assumed"
        # I-001 is already named; a path component or a longer word does not name F-001.
        self.data["decisions"].append("See docs/F-001/notes.md and ticket XF-001")
        self.write()
        code, _, err = self.check()
        self.assertEqual(code, 1)
        for fid in ("F-001", "F-002"):
            self.assertIn(f"{fid}: its High severity rests on an assumed severity axis (meta.axis); "
                          "name it in decisions for a person to confirm", err)
        self.assertNotIn("I-001: its High severity", err)
        # An excluded finding needs no confirmation.
        self.data["findings"][1]["validation"]["verdict"] = "FalsePositive"
        self.write()
        self.assertNotIn("F-002: its High severity", self.check()[2])
        self.data["findings"][1]["validation"]["verdict"] = "Valid"
        self.data["decisions"].append("Confirm the crown jewels F-001 and F-002 rest on")
        self.write()
        code, _, err = self.check()
        self.assertEqual(code, 0, err)
        for name in ("dashboard.html", "assessment.html"):
            page = (self.out / name).read_text(encoding="utf-8")
            self.assertIn("Severity axis", page)
            self.assertIn("assumed; not confirmed by the requester", page)
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(render.main([str(self.out / "findings.json"), "--out", str(self.out),
                                          "--no-pdf", "--lang", "ja"]), 0)
        for name in ("dashboard.html", "assessment.html"):
            page = (self.out / name).read_text(encoding="utf-8")
            self.assertIn("深刻度の軸", page)
            self.assertIn("仮定（依頼者は未確認）", page)

    def test_the_severity_axis_is_recorded_as_confirmed_or_assumed(self):
        del self.data["meta"]["axis"]
        self.write()
        code, _, err = self.check()
        self.assertEqual(code, 1)
        self.assertIn("meta.axis: record whether the requester confirmed the list severity is judged "
                      "against (confirmed) or it was assumed (assumed)", err)
        self.data["meta"]["axis"] = "guessed"
        with self.assertRaisesRegex(render.SchemaError, "meta.axis"):
            render.validate(self.data, partial=True)

    def test_unreadable_is_2(self):
        (self.out / "findings.json").write_text("{", encoding="utf-8")
        self.assertEqual(self.check()[0], 2)


if __name__ == "__main__":
    unittest.main()
