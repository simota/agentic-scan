"""The scripts' import graph: standard library only, no cycles, leaves stay leaves."""

import ast
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "ux-scan" / "scripts"
# Modules every other script may build on; they import no other script.
LEAVES = {"file_io", "secret_lines", "prose_ids"}


def imports(path):
    """Top-level module names a script imports, at module level or inside functions."""
    names = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"), str(path))):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module.split(".")[0])
    return names


class ImportGraphTests(unittest.TestCase):
    def setUp(self):
        self.local = {p.stem for p in SCRIPTS.glob("*.py")}
        self.graph = {p.stem: imports(p) for p in SCRIPTS.glob("*.py")}

    def test_scripts_import_only_the_standard_library_and_each_other(self):
        allowed = set(sys.stdlib_module_names) | self.local
        for name, deps in sorted(self.graph.items()):
            self.assertEqual(sorted(deps - allowed), [], name)

    def test_no_import_cycles(self):
        state = {}

        def visit(name, path):
            if state.get(name) == "done":
                return
            self.assertNotEqual(state.get(name), "open", " -> ".join(path + [name]))
            state[name] = "open"
            for dep in sorted(self.graph[name] & self.local):
                visit(dep, path + [name])
            state[name] = "done"

        for name in sorted(self.graph):
            visit(name, [])

    def test_leaf_modules_import_no_other_script(self):
        for name in sorted(LEAVES):
            self.assertEqual(sorted(self.graph[name] & self.local), [], name)


if __name__ == "__main__":
    unittest.main()
