"""Refuse ambiguous JSON and non-finite numbers before records can be lost."""
import json
import os
from pathlib import Path
import tempfile
import unittest

from support import complete_doc, findings, render, run_main, snapshot


def invalid_inputs():
    content = json.dumps(complete_doc())
    yield "duplicate findings", content[:-1] + ', "findings": []}', "duplicate", "findings"
    yield "duplicate severity", content.replace(
        '"severity": "High"', '"severity": "High", "severity": "Low"', 1
    ), "duplicate", "severity"
    yield "escaped duplicate", content[:-1] + ', "\\u0066indings": []}', "duplicate", "findings"
    doc = complete_doc()
    doc["meta"]["review_value"] = "NUMBER_SENTINEL"
    content = json.dumps(doc)
    for token in ("NaN", "Infinity", "-Infinity", "1e400", "-1e400"):
        yield token, content.replace('"NUMBER_SENTINEL"', token), "finite", token


class StrictJsonTests(unittest.TestCase):
    def prepare(self, root):
        out = root / "out"
        out.mkdir()
        source = out / "findings.json"
        source.write_text(json.dumps(complete_doc()), encoding="utf-8")
        (out / "report.md").write_bytes(b"Previous report\n")
        (out / "dashboard.html").write_bytes(b"Previous dashboard\n")
        fragment = root / "fragment.json"
        fragment.write_text(json.dumps({"meta": {"project": "Updated project"}}),
                            encoding="utf-8")
        if os.name == "posix":
            for path in (source, fragment, out / "report.md", out / "dashboard.html"):
                path.chmod(0o640)
        return out, source, fragment

    def invoke(self, main, args):
        return run_main(main, *args)

    def assert_diagnostic(self, message, source, reason, detail):
        self.assertIn(str(source), message)
        self.assertIn(reason, message.lower())
        self.assertIn(detail, message)
        self.assertNotIn("Traceback", message)

    def test_read_json_rejects_duplicate_members_and_non_finite_numbers(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.json"
            for case, content, reason, detail in invalid_inputs():
                with self.subTest(case=case):
                    source.write_text(content, encoding="utf-8")
                    original = source.read_bytes()
                    with self.assertRaises(findings.SchemaError) as error:
                        findings.read_json(source)
                    self.assert_diagnostic(str(error.exception), source, reason, detail)
                    self.assertEqual(source.read_bytes(), original)

    def test_merge_refuses_lossy_inputs_without_changing_existing_or_new_targets(self):
        cases = [case for case in invalid_inputs()
                 if case[0] in ("duplicate findings", "1e400")]
        for case, content, reason, detail in cases:
            for origin in ("fragment", "new target", "existing record"):
                with self.subTest(case=case, origin=origin), \
                        tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    _, source, fragment = self.prepare(root)
                    invalid = source if origin == "existing record" else fragment
                    invalid.write_text(content, encoding="utf-8")
                    if origin == "new target":
                        source.unlink()
                    original = snapshot(root)

                    code, output, errors = self.invoke(
                        findings.main, ["merge", source, fragment])

                    self.assertEqual(code, 1, errors)
                    self.assertEqual(output, "")
                    self.assertIn("refused:", errors)
                    self.assert_diagnostic(errors, invalid, reason, detail)
                    self.assertEqual(snapshot(root), original)

    def test_render_and_check_reject_ambiguous_or_non_standard_records(self):
        cases = [case for case in invalid_inputs()
                 if case[0] in ("duplicate findings", "duplicate severity", "-Infinity")]
        for case, content, reason, detail in cases:
            for operation in ("render", "check"):
                with self.subTest(case=case, operation=operation), \
                        tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    out, source, _ = self.prepare(root)
                    source.write_text(content, encoding="utf-8")
                    original = snapshot(root)

                    if operation == "render":
                        result = self.invoke(render.main, [source, "--out", out])
                        expected_code, prefix = 2, "schema:"
                    else:
                        result = self.invoke(findings.main, ["check", out])
                        expected_code, prefix = 1, "findings.json:"

                    code, output, errors = result
                    self.assertEqual(code, expected_code, errors)
                    self.assertEqual(output, "")
                    self.assertIn(prefix, errors)
                    self.assert_diagnostic(errors, source, reason, detail)
                    self.assertEqual(snapshot(root), original)

    def test_finite_numbers_separate_objects_and_fragment_updates_still_round_trip(self):
        doc = complete_doc()
        doc["meta"]["review_values"] = [
            0, 0.0, 1.5, -2.5, 1e308, -1e-300, 1.7976931348623157e308,
        ]
        doc["meta"]["review_notes"] = [{"name": "first"}, {"name": "second"}]
        doc["meta"]["literal_numbers"] = ["NaN", "Infinity", "-Infinity", "1e400"]
        updates = [doc, {"findings": [{"id": "P-001", "title": "First update"}]},
                   {"findings": [{"id": "P-001", "title": "Final update"}]}]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            out = root / "out"
            out.mkdir()
            source = out / "findings.json"
            fragments = []
            for index, update in enumerate(updates):
                fragment = root / f"fragment-{index}.json"
                fragment.write_text(json.dumps(update), encoding="utf-8")
                fragments.append(fragment)
            self.assertEqual(findings.read_json(fragments[0]), doc)

            code, _, errors = self.invoke(findings.main, ["merge", source, *fragments])
            self.assertEqual(code, 0, errors)
            expected = complete_doc()
            expected["meta"] = doc["meta"]
            expected["findings"][0]["title"] = "Final update"
            self.assertEqual(findings.read_json(source), expected)
            code, _, errors = self.invoke(render.main, [source, "--out", out])
            self.assertEqual(code, 0, errors)
            code, _, errors = self.invoke(findings.main, ["check", out])
            self.assertEqual(code, 0, errors)



class HugeIntegerTests(unittest.TestCase):
    def test_integers_beyond_the_float_range_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "x.json"
            source.write_text('{"meta": {"n": 1' + "0" * 400 + '}}', encoding="utf-8")
            with self.assertRaisesRegex(findings.SchemaError, "finite floating-point range"):
                findings.read_json(source)
            source.write_text('{"meta": {"n": 12345678901234567890}}', encoding="utf-8")
            self.assertEqual(findings.read_json(source)["meta"]["n"], 12345678901234567890)

if __name__ == "__main__":
    unittest.main()
