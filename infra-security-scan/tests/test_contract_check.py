import contextlib
import copy
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "skills" / "infra-scan" / "scripts"))
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
        (self.out / "iac.json").write_text('{"tool": "iac_scan"}', encoding="utf-8")
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

    def test_four_digit_review_ids_follow_numeric_order(self):
        template = self.data["findings"][0]
        self.data["findings"] = []
        self.data["attack_paths"] = []
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

    def test_schema_failure_is_a_violation(self):
        (self.out / "findings.json").write_text(json.dumps({**self.data, "meta": {}}), encoding="utf-8")
        code, _, err = self.check()
        self.assertEqual(code, 1)
        self.assertIn("meta.project: required", err)

    def test_unreadable_is_2(self):
        (self.out / "findings.json").write_text("{", encoding="utf-8")
        self.assertEqual(self.check()[0], 2)


if __name__ == "__main__":
    unittest.main()
