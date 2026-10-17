from pathlib import Path
import sys
import unittest
from unittest import mock

from helpers import REPO

sys.path.insert(0, str(REPO / "scripts" / "ci"))
import check_doc_refs  # noqa: E402


class DocRefsTest(unittest.TestCase):
    def test_repository_documents_resolve(self):
        self.assertEqual(list(check_doc_refs.problems()), [])

    def test_tracked_document_missing_from_the_work_tree_is_reported(self):
        with mock.patch.object(check_doc_refs, "DOCS", [REPO / "docs" / "deleted.md"]):
            self.assertEqual(list(check_doc_refs.problems()),
                             [f"{Path('docs/deleted.md')} is tracked by Git but missing from the work tree"])


if __name__ == "__main__":
    unittest.main()
