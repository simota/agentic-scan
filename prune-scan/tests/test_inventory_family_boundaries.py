"""Inventory families read only the shared scan views, so each runs on sources held in memory."""

import sys
import unittest
from collections import defaultdict
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "prune-scan" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import inventory  # noqa: E402


def in_memory_scan(texts, today="2026-01-01"):
    """A Scan over sources that exist only in memory: no directory, descriptor or file is opened."""
    return inventory.Scan(SimpleNamespace(today=today, texts=texts, assets=[], locales=defaultdict(dict)))


class FamilyIsolationTests(unittest.TestCase):
    def test_families_run_on_in_memory_sources(self):
        scan = in_memory_scan({
            ".env.example": "USED_KEY=\nSTALE_KEY=\n",
            "server/app.py": "import os\nfrom server import helpers\nURL = os.environ.get('USED_KEY')\n",
            "server/helpers.py": "def unused_helper():\n    return 1\n",
            "server/orphan.py": "VALUE = 1\n",
        })
        env, reads, declared = inventory.scan_env(scan)
        self.assertEqual([row["name"] for row in env["env_declared_not_read"]], ["STALE_KEY"])
        self.assertEqual(sorted(reads), ["USED_KEY"])
        self.assertEqual(declared, [".env.example"])
        symbols, python_imports, _ = inventory.scan_symbols(scan)
        self.assertIn("unused_helper", {row["name"] for row in symbols["unreferenced_symbols"]})
        imports, _ = inventory.scan_imports(scan, python_imports)
        self.assertEqual([row["path"] for row in imports["orphan_files"]], ["server/orphan.py"])

    def test_inventory_keeps_its_key_order(self):
        """Consumers and the sample read keys in this order; splitting the scan must not reorder them."""
        result = inventory.inventory(ROOT / "examples" / "larder", today="2026-11-05")
        keys = list(result)
        self.assertEqual(keys[:6], ["tool", "version", "repository", "today", "files_scanned", "files_skipped"])
        self.assertEqual(keys[-2:], ["limits", "truncated"])
        families = keys[keys.index("unreferenced_symbols"):keys.index("sql_columns_unreferenced") + 1]
        self.assertEqual(families, [
            "unreferenced_symbols", "orphan_files", "dependencies_declared", "unimported_dependencies",
            "duplicate_purpose", "platform_replaceable", "env_read", "env_declared_not_read",
            "env_read_not_declared", "feature_flags", "i18n_unreferenced", "i18n_dynamic_prefixes",
            "assets_unreferenced", "css_unreferenced", "css_dynamic_prefixes", "routes", "unreferenced_routes",
            "scripts", "uninvoked_scripts", "unreferenced_files", "skipped_tests", "commented_code", "markers",
            "sql_tables_unreferenced", "sql_columns_unreferenced"])


if __name__ == "__main__":
    unittest.main()
