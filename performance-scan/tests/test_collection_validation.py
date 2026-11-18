"""Reject malformed collections and ambiguous record identities before writing."""
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import io
import json
from pathlib import Path
import tempfile
import unittest

from support import complete_doc, findings, render


COLLECTIONS = ("findings", "budgets", "perspectives")
INVALID_CONTAINERS = (
    ("empty object", {}),
    ("empty string", ""),
    ("null", None),
    ("boolean", False),
    ("integer", 1),
    ("nonempty object", {"unexpected": "record"}),
    ("nonempty string", "record"),
)


class CollectionValidationTests(unittest.TestCase):
    def invalid_documents(self):
        for field in COLLECTIONS:
            for kind, value in INVALID_CONTAINERS:
                doc = complete_doc()
                doc[field] = deepcopy(value)
                yield field, kind, doc

    def test_validate_rejects_non_lists_in_partial_and_complete_records(self):
        for field, kind, doc in self.invalid_documents():
            for complete in (False, True):
                with self.subTest(field=field, kind=kind, complete=complete):
                    with self.assertRaisesRegex(
                            findings.SchemaError, f"^{field}: must be a list$"):
                        findings.validate(doc, complete=complete)

    def test_empty_lists_remain_valid_schema_collections(self):
        doc = complete_doc()
        for field in COLLECTIONS:
            doc[field] = []
        for complete in (False, True):
            with self.subTest(complete=complete):
                findings.validate(doc, complete=complete)

    def test_render_rejects_non_lists_without_changing_existing_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            source = out / "findings.json"
            source.write_text(json.dumps(complete_doc()), encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                self.assertEqual(render.main([str(source), "--out", str(out)]), 0)
            originals = {out / name: (out / name).read_bytes()
                         for name in ("report.md", "dashboard.html")}

            for field, kind, doc in self.invalid_documents():
                with self.subTest(field=field, kind=kind):
                    source.write_text(json.dumps(doc), encoding="utf-8")
                    for path, content in originals.items():
                        path.write_bytes(content)
                    errors = io.StringIO()
                    with redirect_stdout(io.StringIO()), redirect_stderr(errors):
                        result = render.main([str(source), "--out", str(out)])
                    self.assertEqual(result, 2)
                    self.assertIn(f"{field}: must be a list", errors.getvalue())
                    for path, content in originals.items():
                        self.assertEqual(path.read_bytes(), content, path.name)

    def test_check_reports_the_collection_field_instead_of_accepting_or_crashing(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            source = out / "findings.json"
            source.write_text(json.dumps(complete_doc()), encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                self.assertEqual(render.main([str(source), "--out", str(out)]), 0)

            for field, kind, doc in self.invalid_documents():
                with self.subTest(field=field, kind=kind):
                    source.write_text(json.dumps(doc), encoding="utf-8")
                    problems = findings.contract_problems(out)
                    self.assertEqual(problems, [
                        f"findings.json: {field}: must be a list",
                    ])
                    errors = io.StringIO()
                    with redirect_stdout(io.StringIO()), redirect_stderr(errors):
                        result = findings.main(["check", str(out)])
                    self.assertEqual(result, 1)
                    self.assertIn(problems[0], errors.getvalue())

    def test_merge_preserves_target_when_existing_record_or_fragment_has_non_lists(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "findings.json"
            fragment = root / "fragment.json"
            for field, kind, invalid in self.invalid_documents():
                for origin, update_kind in (
                        ("existing record", "meta"),
                        ("existing record", "same collection"),
                        ("fragment", "meta")):
                    with self.subTest(field=field, kind=kind, origin=origin,
                                      update=update_kind):
                        doc = invalid if origin == "existing record" else complete_doc()
                        update = ({field: complete_doc()[field]}
                                  if update_kind == "same collection" else
                                  {"meta": {"project": "This update must not persist"}})
                        if origin == "fragment":
                            update[field] = invalid[field]
                        target.write_text(json.dumps(doc) + "\n", encoding="utf-8")
                        original = target.read_bytes()
                        fragment.write_text(json.dumps(update), encoding="utf-8")
                        errors = io.StringIO()
                        with redirect_stdout(io.StringIO()), redirect_stderr(errors):
                            result = findings.main(["merge", str(target), str(fragment)])
                        self.assertEqual(result, 1)
                        self.assertIn(f"{field}: must be a list", errors.getvalue())
                        self.assertEqual(target.read_bytes(), original)


class RecordIdentityTests(unittest.TestCase):
    def duplicate_documents(self):
        for field, key in (("budgets", "id"), ("perspectives", "name")):
            doc = complete_doc()
            duplicate = dict(doc[field][0])
            if field == "budgets":
                duplicate.update(statement="A different budget", status="holds")
            else:
                duplicate.update(status="not checked", note="This perspective was not examined")
            index = len(doc[field])
            doc[field].append(duplicate)
            yield f"{field}[{index}].{key}", doc

    def test_validate_rejects_duplicate_identities_in_partial_and_complete_records(self):
        for where, doc in self.duplicate_documents():
            for complete in (False, True):
                with self.subTest(field=where, complete=complete):
                    with self.assertRaises(findings.SchemaError) as error:
                        findings.validate(doc, complete=complete)
                    self.assertIn(where, str(error.exception))
                    self.assertIn("duplicate", str(error.exception))

    def test_render_rejects_duplicate_identities_without_changing_outputs(self):
        for where, doc in self.duplicate_documents():
            with self.subTest(field=where), tempfile.TemporaryDirectory() as directory:
                out = Path(directory)
                source = out / "findings.json"
                source.write_text(json.dumps(complete_doc()), encoding="utf-8")
                with redirect_stdout(io.StringIO()):
                    self.assertEqual(render.main([str(source), "--out", str(out)]), 0)
                originals = {out / name: (out / name).read_bytes()
                             for name in ("report.md", "dashboard.html")}
                source.write_text(json.dumps(doc), encoding="utf-8")
                errors = io.StringIO()
                with redirect_stdout(io.StringIO()), redirect_stderr(errors):
                    result = render.main([str(source), "--out", str(out)])
                self.assertEqual(result, 2)
                self.assertIn(where, errors.getvalue())
                self.assertIn("duplicate", errors.getvalue())
                for path, content in originals.items():
                    self.assertEqual(path.read_bytes(), content, path.name)

    def test_check_rejects_duplicate_identities(self):
        for where, doc in self.duplicate_documents():
            with self.subTest(field=where), tempfile.TemporaryDirectory() as directory:
                out = Path(directory)
                source = out / "findings.json"
                source.write_text(json.dumps(complete_doc()), encoding="utf-8")
                with redirect_stdout(io.StringIO()):
                    self.assertEqual(render.main([str(source), "--out", str(out)]), 0)
                source.write_text(json.dumps(doc), encoding="utf-8")
                output, errors = io.StringIO(), io.StringIO()
                with redirect_stdout(output), redirect_stderr(errors):
                    result = findings.main(["check", str(out)])
                self.assertEqual(result, 1)
                self.assertNotIn("contract ok", output.getvalue())
                self.assertIn(where, errors.getvalue())
                self.assertIn("duplicate", errors.getvalue())

    def test_merge_rejects_duplicate_existing_identities_without_writing(self):
        for where, doc in self.duplicate_documents():
            with self.subTest(field=where), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                target = root / "findings.json"
                target.write_text(json.dumps(doc) + "\n", encoding="utf-8")
                original = target.read_bytes()
                fragment = root / "fragment.json"
                fragment.write_text(json.dumps({
                    "meta": {"project": "This update must not persist"},
                }), encoding="utf-8")
                errors = io.StringIO()
                with redirect_stdout(io.StringIO()), redirect_stderr(errors):
                    result = findings.main(["merge", str(target), str(fragment)])
                self.assertEqual(result, 1)
                self.assertIn(where, errors.getvalue())
                self.assertIn("duplicate", errors.getvalue())
                self.assertEqual(target.read_bytes(), original)

    def test_merge_keeps_the_last_same_name_perspective_in_a_fragment(self):
        for existing in (False, True):
            with self.subTest(existing=existing), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                target = root / "findings.json"
                if existing:
                    target.write_text(json.dumps(complete_doc()), encoding="utf-8")
                first = {"name": "Database access", "status": "not checked",
                         "note": "Pending", "old_only": "must be replaced"}
                last = {"name": "Database access", "status": "applied", "note": "Examined"}
                fragment = root / "fragment.json"
                fragment.write_text(json.dumps({"perspectives": [first, last]}),
                                    encoding="utf-8")
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    self.assertEqual(findings.main(["merge", str(target), str(fragment)]), 0)
                doc = json.loads(target.read_text(encoding="utf-8"))
                self.assertEqual([p for p in doc["perspectives"]
                                  if p["name"] == "Database access"], [last])


if __name__ == "__main__":
    unittest.main()
