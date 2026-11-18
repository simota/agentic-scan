"""Check that scripts/ci/check_doc_refs.py finds missing citations in every documented form."""
import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("check_doc_refs", ROOT / "scripts" / "ci" / "check_doc_refs.py")
check_doc_refs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check_doc_refs)


class DocRefTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name)
        self.skill = self.repo / "skills" / "prune-scan"
        (self.skill / "scripts").mkdir(parents=True)
        (self.skill / "scripts" / "render.py").write_text("")
        (self.repo / "examples").mkdir()
        (self.repo / "examples" / "units.sample.json").write_text("{}")

    def problems(self, text):
        (self.repo / "README.md").write_text(text, encoding="utf-8")
        return list(check_doc_refs.problems(self.repo))

    def test_commands_cite_the_path_they_start_with(self):
        self.assertEqual(self.problems(
            "`scripts/gone.py --out x` and `examples/missing.json <out>`\n"), [
            "README.md cites scripts/gone.py, which does not exist",
            "README.md cites examples/missing.json, which does not exist",
        ])

    def test_existing_paths_pass_alone_or_with_arguments(self):
        self.assertEqual(self.problems(
            "`scripts/render.py` `scripts/render.py findings.json --lang ja\\|en` "
            "`examples/units.sample.json` `cp examples/missing.json`\n"), [])

    def test_line_locations_of_the_reviewed_app_stay_unchecked(self):
        self.assertEqual(self.problems("`docs/P-002.md:1` and `tests/test_items.py:12`\n"), [])

    def test_the_repository_documents_pass(self):
        self.assertEqual(list(check_doc_refs.problems()), [])


if __name__ == "__main__":
    unittest.main()
