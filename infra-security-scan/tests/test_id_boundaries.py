"""Exercise the actual scan/merge/report pipeline across the 999-ID boundary."""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "skills" / "infra-security-scan" / "scripts"))
import contract_check  # noqa: E402
import findings  # noqa: E402
import iac_scan  # noqa: E402
import render  # noqa: E402


class IdBoundaryTest(unittest.TestCase):
    def main_ok(self, main, args):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(main(args), 0, err.getvalue())

    def test_baseline_999_then_1000_findings_can_be_merged_rendered_and_checked(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, out = root / "repo", root / "out"
            repo.mkdir()
            out.mkdir()
            record = out / "findings.json"

            def write_bucket(n):
                (repo / f"bucket{n:04d}.tf").write_text(
                    f'resource "aws_s3_bucket_acl" "public{n}" {{\n'
                    '  acl = "public-read"\n}\n', encoding="utf-8")

            for n in range(999):
                write_bucket(n)
            for count in (999, 1000):
                with self.subTest(findings=count):
                    if count == 1000:
                        write_bucket(999)
                    self.main_ok(iac_scan.main, [str(repo), "--out", str(out / "iac.json"),
                                                "--into", str(record)])
                    scanned = render.load(record)
                    self.assertEqual([f["id"] for f in scanned["findings"]],
                                     [f"I-{n:03d}" for n in range(1, count + 1)])
                    fragment = root / "fragment.json"
                    fragment.write_text(json.dumps({
                        "meta": {"project": "Large estate", "scope": "synthetic fixtures",
                                 "date": "2026-10-08", "assessor": "test", "axis": "confirmed"},
                        "perspectives": [{"name": name, "status": "Applied"}
                                         for name in render.perspective_names()],
                        "findings": [{"id": f"I-{n:03d}", "validation": {
                            "verdict": "Valid", "evidence": f"Public ACL read at bucket{n - 1:04d}.tf:2"}}
                            for n in range(1, count + 1)],
                    }), encoding="utf-8")
                    self.main_ok(findings.main, ["merge", str(record), str(fragment)])
                    merged = render.load(record)
                    self.assertEqual(len(merged["findings"]), count)
                    self.assertEqual(merged["findings"][-1]["validation"]["verdict"], "Valid")
                    self.main_ok(render.main, [str(record), "--out", str(out), "--no-pdf"])
                    self.main_ok(contract_check.main, [str(out), "--no-pdf"])
                    if count == 1000:
                        for name in ("dashboard.html", "assessment.html"):
                            page = (out / name).read_text(encoding="utf-8")
                            self.assertLess(page.index('id="I-999"'), page.index('id="I-1000"'))


if __name__ == "__main__":
    unittest.main()
