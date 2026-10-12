"""Regression coverage for source extensions used by JavaScript bundlers."""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "prune-scan" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import inventory  # noqa: E402


class JavaScriptResolutionTests(unittest.TestCase):
    def test_extensionless_imports_reference_mts_and_cts_sources(self):
        for extension in ("mts", "cts"):
            with self.subTest(extension=extension), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "main.ts").write_text(
                    'import "./helper";\n'
                    'import { value } from "./named";\n'
                    'export { value } from "./reexported";\n'
                    'const one = require("./required");\n'
                    'const two = import("./dynamic");\n', encoding="utf-8")
                for name in ("helper", "named", "reexported", "required", "dynamic", "unused"):
                    (root / f"{name}.{extension}").write_text("export const value = 1;\n", encoding="utf-8")
                result = inventory.inventory(root)
                self.assertEqual(result["orphan_files"],
                                 [{"path": f"unused.{extension}", "test_importers": []}])

    def test_extensionless_directory_imports_resolve_mts_and_cts_indexes(self):
        for extension in ("mts", "cts"):
            for spec in ("../helpers", "../helpers/./"):
                with self.subTest(extension=extension, spec=spec), tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    (root / "src").mkdir()
                    (root / "src" / "main.ts").write_text(f'import "{spec}";\n', encoding="utf-8")
                    for name in ("helpers", "unused"):
                        (root / name).mkdir()
                        (root / name / f"index.{extension}").write_text("export default 1;\n", encoding="utf-8")
                    # Observe import resolution independently of the entry-point exemption.
                    with mock.patch.object(inventory, "ENTRY_STEMS", inventory.ENTRY_STEMS - {"index"}):
                        result = inventory.inventory(root)
                    self.assertEqual(result["orphan_files"],
                                     [{"path": f"unused/index.{extension}", "test_importers": []}])

    def test_extensionless_test_imports_remain_candidates_with_their_importers(self):
        for extension in ("mts", "cts"):
            with self.subTest(extension=extension), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "tests").mkdir()
                (root / "tests" / "helper.test.ts").write_text('import "../helper";\n', encoding="utf-8")
                (root / f"helper.{extension}").write_text("export default 1;\n", encoding="utf-8")
                result = inventory.inventory(root)
                self.assertEqual(result["orphan_files"], [{
                    "path": f"helper.{extension}", "test_importers": ["tests/helper.test.ts"],
                }])

    def test_extensionless_imports_count_each_same_stem_candidate(self):
        for stem in ("helper", "helper.client", "helper.server"):
            for importer, prefix in (("main.ts", "./"), ("tests/helper.test.ts", "../")):
                with self.subTest(stem=stem, importer=importer), tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    (root / importer).parent.mkdir(exist_ok=True)
                    (root / importer).write_text(f'import "{prefix}{stem}";\n', encoding="utf-8")
                    for name in (f"{stem}.ts", f"{stem}.mts", f"{stem}.cts", "unused.mts"):
                        (root / name).write_text("export default 1;\n", encoding="utf-8")
                    expected = [{"path": "unused.mts", "test_importers": []}]
                    if importer.startswith("tests/"):
                        expected[:0] = [{"path": name, "test_importers": [importer]}
                                        for name in (f"{stem}.cts", f"{stem}.mts", f"{stem}.ts")]
                    result = inventory.inventory(root)
                    self.assertEqual(result["orphan_files"], expected)

    def test_extensionless_directory_imports_count_all_existing_candidates(self):
        for stem in ("helper", "helper.client"):
            with self.subTest(stem=stem), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "main.ts").write_text(f'import "./{stem}";\n', encoding="utf-8")
                for name in (f"{stem}.ts", f"{stem}.mts", f"{stem}.cts", f"{stem}/index.ts",
                             f"{stem}/index.mts", f"{stem}/index.cts", "unused/index.mts"):
                    (root / name).parent.mkdir(exist_ok=True)
                    (root / name).write_text("export default 1;\n", encoding="utf-8")
                # Different bundlers can prefer a file or one of the directory's indexes.
                with mock.patch.object(inventory, "ENTRY_STEMS", inventory.ENTRY_STEMS - {"index"}):
                    result = inventory.inventory(root)
                self.assertEqual(result["orphan_files"], [{"path": "unused/index.mts", "test_importers": []}])

    def test_explicit_source_and_emitted_extensions_keep_sibling_sources_distinct(self):
        for imported, source, unused in (
                ("helper.client", "helper.client", "helper.client.ts"),
                ("helper.js", "helper.ts", "helper.tsx"),
                ("helper.mts", "helper.mts", "helper.cts"),
                ("helper.cts", "helper.cts", "helper.mts"),
                ("helper.mjs", "helper.mts", "helper.cts"),
                ("helper.cjs", "helper.cts", "helper.mts")):
            with self.subTest(imported=imported), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "main.ts").write_text(f'import "./{imported}";\n', encoding="utf-8")
                for name in (source, unused):
                    (root / name).write_text("export default 1;\n", encoding="utf-8")
                result = inventory.inventory(root)
                self.assertEqual(result["orphan_files"], [{"path": unused, "test_importers": []}])


if __name__ == "__main__":
    unittest.main()
