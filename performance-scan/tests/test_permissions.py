"""Files the scripts create start private, whatever the umask."""
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from support import complete_doc, findings, render, run_main


class PermissionTests(unittest.TestCase):
    def test_new_record_and_outputs_start_private(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fragment = root / "fragment.json"
            fragment.write_text(json.dumps(complete_doc()), encoding="utf-8")
            old = os.umask(0o022)
            try:
                code, _, err = run_main(findings.main, "merge", root / "findings.json", fragment)
                self.assertEqual(code, 0, err)
                code, _, err = run_main(render.main, root / "findings.json", "--out", root)
                self.assertEqual(code, 0, err)
            finally:
                os.umask(old)
            for name in ("findings.json", "report.md", "dashboard.html"):
                self.assertEqual(stat.S_IMODE((root / name).stat().st_mode), 0o600, name)


if __name__ == "__main__":
    unittest.main()
