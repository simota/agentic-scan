"""A metadata fragment must not make an existing record unrenderable."""
from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest

from support import complete_doc, findings, render, run_main


class MetadataMergeTests(unittest.TestCase):
    FIELDS = ("project", "scope", "date", "assessor")
    INVALID = (None, False, 20261009, 1.5, [], {}, "", " \t\n")

    def run_merge(self, target, fragment):
        return run_main(findings.main, "merge", target, fragment)

    def test_present_metadata_fields_are_validated_in_partial_records(self):
        for field in self.FIELDS:
            for value in self.INVALID:
                with self.subTest(field=field, value=value):
                    with self.assertRaises(findings.SchemaError) as error:
                        findings.validate({"meta": {field: value}})
                    self.assertIn(f"meta.{field}", str(error.exception))

    def test_invalid_metadata_fragment_preserves_existing_or_absent_record(self):
        for field in self.FIELDS:
            for value in self.INVALID:
                for existing in (False, True):
                    with self.subTest(field=field, value=value, existing=existing), \
                            tempfile.TemporaryDirectory() as directory:
                        root = Path(directory)
                        target = root / "findings.json"
                        if existing:
                            target.write_text(json.dumps(complete_doc()), encoding="utf-8")
                        original = target.read_bytes() if existing else None
                        fragment = root / "fragment.json"
                        fragment.write_text(json.dumps({"meta": {field: value}}),
                                            encoding="utf-8")
                        entries = set(root.iterdir())

                        code, output, errors = self.run_merge(target, fragment)

                        self.assertEqual(code, 1)
                        self.assertEqual(output, "")
                        self.assertIn(f"meta.{field}", errors)
                        self.assertNotIn("Traceback", errors)
                        self.assertEqual(target.read_bytes() if target.exists() else None,
                                         original)
                        self.assertEqual(set(root.iterdir()), entries)

    def test_existing_invalid_metadata_is_refused_before_applying_fragments(self):
        for field in self.FIELDS:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                doc = complete_doc()
                doc["meta"][field] = 20261009
                target = root / "findings.json"
                target.write_text(json.dumps(doc), encoding="utf-8")
                original = target.read_bytes()
                fragment = root / "fragment.json"
                fragment.write_text(json.dumps({"meta": {field: "Updated value"}}),
                                    encoding="utf-8")

                code, output, errors = self.run_merge(target, fragment)

                self.assertEqual(code, 1)
                self.assertEqual(output, "")
                self.assertIn(f"meta.{field}", errors)
                self.assertEqual(target.read_bytes(), original)

    def test_valid_metadata_can_still_be_assembled_across_merges(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            out = root / "out"
            out.mkdir()
            target = out / "findings.json"
            fragment = root / "fragment.json"
            expected = complete_doc()
            initial = {key: value for key, value in expected.items() if key != "meta"}
            updates = [initial, {"meta": {"project": "Initial project"}}]
            updates.extend({"meta": {field: value}}
                           for field, value in expected["meta"].items())
            for update in updates:
                fragment.write_text(json.dumps(update), encoding="utf-8")
                code, _, errors = self.run_merge(target, fragment)
                self.assertEqual(code, 0, errors)
            self.assertEqual(json.loads(target.read_text(encoding="utf-8")), expected)
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(render.main([str(target), "--out", str(out)]), 0)
                self.assertEqual(findings.main(["check", str(out)]), 0)


if __name__ == "__main__":
    unittest.main()
