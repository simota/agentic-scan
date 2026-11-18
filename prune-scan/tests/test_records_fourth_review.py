"""Regression coverage for the fourth review round on records and the contract:
location paths, NUL in unnamed fields, status lines on strict terminals,
N/A perspectives without a reason and decisions naming a finding."""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "prune-scan" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import contract_check  # noqa: E402
import findings  # noqa: E402
from test_findings_regressions import record, units_record  # noqa: E402


class LocationPathTests(unittest.TestCase):
    def test_control_characters_and_whitespace_before_the_line_are_refused(self):
        for location in ("app.py\t:10", "app.py\r:10", "app.py :10", "app\u2028.py:10", "app\x85.py:10",
                         "\x01app.py:10", "\x1bapp.py:10", "\x7fapp.py:10"):
            with self.subTest(location=ascii(location)):
                data = record()
                data["findings"][0]["location"] = location
                with self.assertRaisesRegex(findings.RecordError, "path:line"):
                    findings.check_findings(data)

    def test_spaces_and_unicode_inside_a_path_stay_valid(self):
        for location in ("my docs/app.py:10", "資料/アプリ.py:10-12"):
            with self.subTest(location=location):
                data = record()
                data["findings"][0]["location"] = location
                findings.check_findings(data, ordered=False)

    def test_unit_paths_refuse_control_characters_and_trailing_whitespace(self):
        for path in ("app.py ", "app\t.py", "app\r", "\x01app.py", "\x7fapp.py"):
            with self.subTest(path=ascii(path)):
                units = units_record()
                units["units"][0]["paths"] = [path]
                with self.assertRaises(findings.RecordError):
                    findings.check_units(units)


class NulTextTests(unittest.TestCase):
    def test_nul_is_refused_in_fields_the_schema_does_not_name(self):
        for where in ("meta", "finding", "validation", "key"):
            with self.subTest(where=where):
                data = record()
                if where == "meta":
                    data["meta"]["reviewer"] = "a\x00b"
                elif where == "finding":
                    data["findings"][0]["notes"] = ["a\x00b"]
                elif where == "validation":
                    data["findings"][0]["validation"]["extra"] = "a\x00b"
                else:
                    data["findings"][0]["validation"]["x\x00y"] = "z"
                with self.assertRaisesRegex(findings.RecordError, "without NUL"):
                    findings.check_findings(data)

    def test_nul_is_refused_in_unnamed_units_fields(self):
        units = units_record()
        units["consumers"][0]["notes"] = "a\x00b"
        with self.assertRaisesRegex(findings.RecordError, "consumers.*without NUL"):
            findings.check_units(units)


class StrictTerminalTests(unittest.TestCase):
    def test_a_completed_merge_exits_zero_under_a_strict_utf8_stdout(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = os.path.join(os.fsencode(tmp), b"nonutf8_\xff")
            try:
                os.mkdir(directory)
            except OSError:
                self.skipTest("the file system refuses non-UTF-8 names")
            fragment = Path(tmp) / "fragment.json"
            fragment.write_text(json.dumps(record()), encoding="utf-8")
            target = os.path.join(directory, b"findings.json")
            result = subprocess.run([sys.executable, str(SCRIPTS / "findings.py"), "merge", target, str(fragment)],
                                    capture_output=True, env={**os.environ, "PYTHONIOENCODING": "utf-8"})
            self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", "replace"))
            self.assertIn(b"wrote ", result.stdout)
            self.assertTrue(os.path.exists(target))


class ContractRuleTests(unittest.TestCase):
    def run_contract(self, change):
        data = json.loads((ROOT / "examples" / "findings.sample.json").read_text(encoding="utf-8"))
        data["limitations"].append("report.pdf not produced: this test checks HTML")
        change(data)
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            sources = {
                "findings.json": json.dumps(data).encode("utf-8"),
                "units.json": (ROOT / "examples" / "units.sample.json").read_bytes(),
                "inventory.json": b'{"tool": "inventory.py"}\n',
            }
            for name, source in sources.items():
                (out / name).write_bytes(source)
            stamps = "".join(
                f'<meta name="{stamp}" content="sha256:{hashlib.sha256(sources[name]).hexdigest()}">'
                for stamp, name in ((contract_check.STAMP, "findings.json"),
                                    (contract_check.UNITS_STAMP, "units.json")))
            for name in ("dashboard.html", "report.html"):
                (out / name).write_text(f'<html lang="en"><head>{stamps}</head><body>{name}</body></html>',
                                        encoding="utf-8")
            return list(contract_check.problems(out, no_pdf=True))

    def test_the_sample_meets_the_contract(self):
        self.assertEqual(self.run_contract(lambda data: None), [])

    def test_bare_not_applicable_needs_a_reason(self):
        def bare(data):
            data["perspectives"][5] = {"name": data["perspectives"][5]["name"], "result": "N/A"}
        problems = self.run_contract(bare)
        self.assertEqual(len(problems), 1)
        self.assertIn("N/A without a reason", problems[0])

    def test_not_applicable_with_a_reason_in_result_or_note_passes(self):
        def explained(data):
            name = data["perspectives"][5]["name"]
            data["perspectives"][5] = {"name": name, "result": "N/A: the app keeps no data"}
            data["perspectives"][6] = {"name": data["perspectives"][6]["name"], "result": "n/a",
                                       "note": "No assets ship with the app."}
        self.assertEqual(self.run_contract(explained), [])

    def test_a_path_naming_the_id_does_not_name_the_finding(self):
        def path_only(data):
            undecided = [f["id"] for f in data["findings"] if f["confidence"] == "Purpose-dependent"]
            self.assertTrue(undecided)
            data["decisions"] = [line for line in data["decisions"]
                                 if not any(ident in line for ident in undecided)]
            data["decisions"].extend(f"Unrelated file docs/{ident}.md was read." for ident in undecided)
        problems = self.run_contract(path_only)
        self.assertEqual(len(problems), 1)
        self.assertTrue(problems[0].startswith("decisions:"), problems)


if __name__ == "__main__":
    unittest.main()
