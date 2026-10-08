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
        (self.out / "iac.json").write_text("{}", encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(render.main([str(self.out / "findings.json"), "--out", str(self.out), "--no-pdf"]), 0)

    def check(self, *extra):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = contract_check.main([str(self.out), "--no-pdf", *extra])
        return code, out.getvalue(), err.getvalue()

    def test_sample_holds_and_reports_unverified(self):
        code, out, err = self.check()
        self.assertEqual(code, 0, err)
        self.assertIn("I-002", out)

    def test_pdf_required_without_flag(self):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as err:
            code = contract_check.main([str(self.out)])
        self.assertEqual(code, 1)

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
