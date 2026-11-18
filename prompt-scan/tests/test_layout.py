import ast
import unittest

from helpers import SCRIPTS, record, render


def imports():
    """Each script module -> the script modules it imports."""
    modules = {p.stem: p for p in SCRIPTS.glob("*.py")}
    graph = {}
    for name, path in modules.items():
        found = set()
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                found |= {a.name for a in node.names if a.name in modules}
            elif isinstance(node, ast.ImportFrom) and node.module in modules:
                found.add(node.module)
        graph[name] = found
    return graph


class LayoutTest(unittest.TestCase):
    def test_record_and_excerpt_rules_do_not_depend_on_the_tools(self):
        graph = imports()
        self.assertEqual(graph["record"], set())
        self.assertEqual(graph["excerpt"], {"record"})
        # The renderer is presentation: no tool loads it to reach the schema or the redaction rules.
        self.assertEqual({name for name, deps in graph.items() if "render" in deps}, set())

    def test_imports_are_acyclic(self):
        graph, done = imports(), set()

        def visit(name, path):
            self.assertNotIn(name, path, f"import cycle: {' -> '.join(path + (name,))}")
            if name not in done:
                for dep in graph[name]:
                    visit(dep, path + (name,))
                done.add(name)
        for name in graph:
            visit(name, ())

    def test_every_record_language_has_labels(self):
        self.assertEqual(sorted(render.LABELS), sorted(record.LANGS))
        self.assertEqual(sorted(render.DASH_LABELS), sorted(record.LANGS))


if __name__ == "__main__":
    unittest.main()
