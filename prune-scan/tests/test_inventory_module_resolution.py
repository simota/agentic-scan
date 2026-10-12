"""Import-resolution regressions that must not suggest removing referenced sources."""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "prune-scan" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import inventory  # noqa: E402


class JavaScriptModuleResolutionTests(unittest.TestCase):
    def test_extensionless_imports_keep_supported_source_files(self):
        for extension in sorted(inventory.JS_EXT):
            with self.subTest(extension=extension), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "main.ts").write_text('import "./helper";\n', encoding="utf-8")
                for name in ("helper", "unused"):
                    (root / f"{name}{extension}").write_text("export default 1;\n", encoding="utf-8")
                result = inventory.inventory(root)
                self.assertEqual(result["orphan_files"], [{"path": f"unused{extension}", "test_importers": []}])

    def test_extensionless_directory_imports_keep_supported_index_files(self):
        for extension in sorted(inventory.JS_EXT):
            with self.subTest(extension=extension), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "main.ts").write_text('import "./feature";\n', encoding="utf-8")
                for directory in ("feature", "unused"):
                    (root / directory).mkdir()
                    (root / directory / f"index{extension}").write_text("export default 1;\n", encoding="utf-8")
                # Expose actual inbound references; the ordinary index entry-point exemption
                # otherwise hides a broken directory import from the inventory output.
                with mock.patch.object(inventory, "ENTRY_STEMS", inventory.ENTRY_STEMS - {"index"}):
                    result = inventory.inventory(root)
                self.assertEqual(result["orphan_files"],
                                 [{"path": f"unused/index{extension}", "test_importers": []}])

    def test_test_only_extensionless_imports_are_recorded_without_hiding_orphans(self):
        for extension in (".mts", ".cts"):
            for directory in (False, True):
                with self.subTest(extension=extension, directory=directory), tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    (root / "tests").mkdir()
                    (root / "tests" / "test_load.ts").write_text('import "../helper";\n', encoding="utf-8")
                    source = f"helper/index{extension}" if directory else f"helper{extension}"
                    (root / source).parent.mkdir(exist_ok=True)
                    (root / source).write_text("export default 1;\n", encoding="utf-8")
                    with mock.patch.object(inventory, "ENTRY_STEMS", inventory.ENTRY_STEMS - {"index"}):
                        result = inventory.inventory(root)
                    self.assertEqual(result["orphan_files"],
                                     [{"path": source, "test_importers": ["tests/test_load.ts"]}])


if __name__ == "__main__":
    unittest.main()
