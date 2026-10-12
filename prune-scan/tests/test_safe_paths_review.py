"""PR regressions for readable files below search-only ancestor directories."""

import os
import shutil
import tempfile
import unittest
from pathlib import Path

from test_report_regressions import ReportFixture
import contract_check
import inventory
import render
from safe_paths import open_directory


@unittest.skipUnless(render.NOFOLLOW_DIR_FD, "requires descriptor-relative directory opens")
@unittest.skipUnless(hasattr(os, "O_PATH") or hasattr(os, "O_SEARCH"),
                     "requires search-only directory descriptors")
class SearchOnlyAncestorTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.ancestor = Path(temporary.name).resolve() / "search_only"
        self.directory = self.ancestor / "readable"
        self.directory.mkdir(parents=True)
        self.addCleanup(self.ancestor.chmod, 0o700)
        self.ancestor.chmod(0o111)
        try:
            os.listdir(self.ancestor)
        except PermissionError:
            pass
        else:
            self.skipTest("this process can bypass directory read permissions")
        self.assertEqual(os.listdir(self.directory), [])

    def test_directory_can_be_pinned_through_a_search_only_ancestor(self):
        (self.directory / "source.py").write_text("pass\n", encoding="utf-8")
        descriptor = open_directory(self.directory)
        try:
            self.assertEqual(os.listdir(descriptor), ["source.py"])
            self.assertTrue(os.path.samestat(os.fstat(descriptor), self.directory.stat()))
        finally:
            os.close(descriptor)

    def test_valid_pdf_remains_complete_through_a_search_only_ancestor(self):
        path = self.directory / "report.pdf"
        content = b"%PDF-1.7\n%%EOF\n"
        path.write_bytes(content)
        self.assertEqual(path.read_bytes(), content)
        self.assertTrue(render.pdf_complete(path))

    def test_valid_pdf_can_be_read_from_a_search_only_parent(self):
        path = self.directory / "report.pdf"
        content = b"%PDF-1.7\n%%EOF\n"
        path.write_bytes(content)
        self.ancestor.chmod(0o700)
        self.addCleanup(self.directory.chmod, 0o700)
        self.directory.chmod(0o111)
        self.assertEqual(path.read_bytes(), content)
        self.assertTrue(render.pdf_complete(path))

    def test_valid_contract_remains_valid_through_a_search_only_ancestor(self):
        fixture = ReportFixture()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.render_html()
        shutil.copytree(fixture.out, self.directory, dirs_exist_ok=True)
        self.assertEqual(list(contract_check.problems(self.directory, no_pdf=True)), [])

    def test_inventory_reads_sources_through_a_search_only_ancestor(self):
        path = self.directory / "source.py"
        source = "def available_function():\n    return 1\n"
        path.write_text(source, encoding="utf-8")
        self.assertEqual(path.read_text(encoding="utf-8"), source)
        result = inventory.inventory(self.directory)
        self.assertEqual(result["files_scanned"], 1)
        self.assertEqual(result["files_skipped"], 0)
        self.assertEqual([row["name"] for row in result["unreferenced_symbols"]], ["available_function"])

    def test_snippet_reads_sources_through_a_search_only_ancestor(self):
        (self.directory / "source.py").write_text("print('available')\n", encoding="utf-8")
        snippet = render.snippet(self.directory, "source.py:1")
        self.assertIsNotNone(snippet)
        self.assertEqual(snippet["lines"], ["print('available')"])

    def test_snippet_can_be_read_from_a_search_only_repository(self):
        path = self.directory / "source.py"
        source = "print('available')\n"
        path.write_text(source, encoding="utf-8")
        self.ancestor.chmod(0o700)
        self.addCleanup(self.directory.chmod, 0o700)
        self.directory.chmod(0o111)
        self.assertEqual(path.read_text(encoding="utf-8"), source)
        snippet = render.snippet(self.directory, "source.py:1")
        self.assertIsNotNone(snippet)
        self.assertEqual(snippet["lines"], ["print('available')"])


if __name__ == "__main__":
    unittest.main()
