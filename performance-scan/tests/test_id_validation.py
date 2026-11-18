"""Keep finding and budget IDs canonical throughout the output workflow."""
from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest

from support import complete_doc, finding, findings, render


class IdValidationTests(unittest.TestCase):
    def invalid_documents(self):
        for field, identities in (
                ("findings", ("P-001\n", "P-００１", "P-٠٠١")),
                ("budgets", ("B-01\n", "B-０１", "B-٠١"))):
            for identity in identities:
                doc = complete_doc()
                doc[field][0]["id"] = identity
                yield field, identity, doc

    def test_commands_reject_noncanonical_ids_without_changing_outputs(self):
        for field, identity, invalid in self.invalid_documents():
            for command, expected in (("merge", 1), ("render", 2), ("check", 1)):
                with self.subTest(field=field, identity=identity, command=command), \
                        tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    out = root / "out"
                    out.mkdir()
                    source = out / "findings.json"
                    source.write_text(json.dumps(complete_doc()), encoding="utf-8")
                    with redirect_stdout(io.StringIO()):
                        self.assertEqual(render.main([str(source), "--out", str(out)]), 0)

                    if command == "merge":
                        fragment = root / "fragment.json"
                        fragment.write_text(json.dumps(invalid), encoding="utf-8")
                        main, args = findings.main, ["merge", str(source), str(fragment)]
                    else:
                        source.write_text(json.dumps(invalid), encoding="utf-8")
                        if command == "render":
                            main, args = render.main, [str(source), "--out", str(out)]
                        else:
                            main, args = findings.main, ["check", str(out)]

                    originals = {path: path.read_bytes() for path in out.iterdir()}
                    output, errors = io.StringIO(), io.StringIO()
                    with redirect_stdout(output), redirect_stderr(errors):
                        result = main(args)
                    self.assertEqual(result, expected)
                    self.assertRegex(errors.getvalue(), rf"{field}\[\d+\]\.id")
                    self.assertNotIn("contract ok", output.getvalue())
                    self.assertNotIn("Traceback", errors.getvalue())
                    self.assertEqual(set(out.iterdir()), set(originals))
                    for path, content in originals.items():
                        self.assertEqual(path.read_bytes(), content, path.name)

    def test_canonical_boundary_ids_round_trip_through_merge_render_and_check(self):
        doc = complete_doc()
        # P-999 must be tested in a gapless record for the final contract check.
        doc["findings"] = [finding(f"P-{number:03d}") for number in range(1, 1000)]
        doc["budgets"].append(dict(doc["budgets"][0], id="B-100"))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            out = root / "out"
            out.mkdir()
            source = out / "findings.json"
            fragment = root / "fragment.json"
            fragment.write_text(json.dumps(doc), encoding="utf-8")
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(findings.main(["merge", str(source), str(fragment)]), 0)
                self.assertEqual(render.main([str(source), "--out", str(out)]), 0)
                self.assertEqual(findings.main(["check", str(out)]), 0)
            self.assertEqual(json.loads(source.read_text(encoding="utf-8")), doc)
            for name in ("report.md", "dashboard.html"):
                content = (out / name).read_text(encoding="utf-8")
                for identity in ("P-001", "P-999", "B-01", "B-100"):
                    self.assertIn(identity, content, name)


if __name__ == "__main__":
    unittest.main()
