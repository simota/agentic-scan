"""Regression coverage for the inventory's faster scans: each must find exactly
what the slower form it replaced found (statement-only AST walk, word starts
that let re skip ahead, per-line markers, shared route mentions, lazy excerpt
guards)."""

import ast
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "prune-scan" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import inventory  # noqa: E402
from test_deep_review_fixes import scan  # noqa: E402

IMPORT_SHAPES = '''
import a
from . import b
def f():
    import c
    try:
        import d
    except ImportError:
        from e import g
    else:
        import h
    finally:
        import i
class K:
    import j
    def m(self):
        lambda: __import__("not_a_statement")
        if x:
            import k
        elif y:
            import l
        while z:
            import m
        for _ in w:
            import n
        with open(p) as q:
            import o
async def r():
    async with s:
        import p2
    async for t in u:
        import q2
match v:
    case 1:
        import r2
    case _:
        from s2 import t2
import u2, v2 as w2
'''


class StatementWalkTests(unittest.TestCase):
    def test_imports_come_in_ast_walk_order_from_every_statement_body(self):
        tree = ast.parse(IMPORT_SHAPES)
        expected = [n for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))]
        found = [n for n in inventory.statement_nodes(tree) if isinstance(n, (ast.Import, ast.ImportFrom))]
        self.assertEqual(found, expected)
        self.assertEqual(len(found), 18)

    def test_the_repository_scripts_walk_the_same_way(self):
        for path in sorted(SCRIPTS.glob("*.py")) + sorted((ROOT / "tests").glob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            with self.subTest(path=path.name):
                self.assertEqual(
                    [n for n in inventory.statement_nodes(tree) if isinstance(n, (ast.Import, ast.ImportFrom))],
                    [n for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))])


class WordStartTests(unittest.TestCase):
    TEXTS = ("make x", "remake x", "_make x", "émake x", "x.make y", "$make y", "-make y", "make", "\nmake z",
             "api.get(", "my_api.get(", "1api.get(", "(api.get(", "path: '/a'", "xpath: '/a'", "t('a', {context: 1})",
             "at('a', {context: 1})", "python -m pkg.mod", "cpython -m pkg.mod", "npm run build", "pnpm run b")

    def test_word_start_matches_where_a_leading_word_boundary_does(self):
        for words, rest in ((("make",), r"(?=\s)"), (("api",), r"\.get\("), (("path", "re_path"), r"\s*:"),
                            (("t",), r"\("), (("python",), r"\s"), (("npm", "pnpm", "yarn", "bun"), r"\s")):
            slow = re.compile(r"\b(?:%s)%s" % ("|".join(words), rest))
            fast = re.compile(inventory.word_start(*words) + rest)
            for text in self.TEXTS:
                for pos in range(len(text) + 1):
                    with self.subTest(words=words, text=text, pos=pos):
                        self.assertEqual([m.span() for m in fast.finditer(text, pos)],
                                         [m.span() for m in slow.finditer(text, pos)])

    def test_word_start_refuses_words_without_a_leading_word_character(self):
        for words in (("",), ("$x",), ("make", ".x")):
            with self.subTest(words=words), self.assertRaises(ValueError):
                inventory.word_start(*words)

    def test_bare_getenv_still_needs_no_word_or_dot_before_it(self):
        reads = [next(g for g in m.groups() if g) for m in inventory.ENV_READ.finditer(
            'getenv("A")\nos.getenv("B")\nx.getenv("C")\nmygetenv("D")\n(getenv("E"))\n')]
        self.assertEqual(reads, ["A", "B", "E"])


class MarkerTests(unittest.TestCase):
    def test_only_the_first_marker_on_a_line_decides_it(self):
        result = scan({"app.py": "# until later, remove after 2020-01\n"
                                 "x = 1  # TODO deprecated\r\n"
                                 "# hack\n"
                                 "y = 2  # sunset\n"})
        self.assertEqual([(m["marker"], m["location"]) for m in result["markers"]],
                         [("until", "app.py:1"), ("sunset", "app.py:4")])
        self.assertEqual(result["markers"][0]["text"], "# until later, remove after 2020-01")

    def test_excerpts_stay_omitted_for_sensitive_sources(self):
        result = scan({"app.py": 'TOKEN = "x"\n# TODO 2020-01 rotate\n'})
        self.assertEqual(result["markers"][0]["text"], "[omitted: source may contain secrets]")


class RouteMentionTests(unittest.TestCase):
    def test_a_route_defined_twice_gets_the_same_mentions_for_each_definition(self):
        result = scan({"server/app.py": '@app.get("/users")\ndef a(): pass\n@app.post("/users")\ndef b(): pass\n',
                       "web/a.ts": 'fetch("/users");\n', "web/b.ts": 'fetch("/users/7");\n'})
        rows = [r for r in result["routes"] if r["route"] == "/users"]
        self.assertEqual(len(rows), 2)
        for row in rows:
            self.assertEqual((row["mentions"], row["mentioned_in"]), (1, ["web/a.ts"]))
        self.assertIsNot(rows[0]["mentioned_in"], rows[1]["mentioned_in"])


class DynamicClassTests(unittest.TestCase):
    def test_prefixes_come_from_template_segments_only(self):
        text = "a = `btn-${x} card-${y}`; b = 'icon-' + n; c = `plain`; d = `x` + `col-${z}`"
        self.assertEqual(list(inventory.dynamic_class_prefixes(text)), ["btn-", "card-", "col-", "icon-"])
        self.assertEqual(list(inventory.dynamic_class_prefixes("no-${templates} here")), [])


if __name__ == "__main__":
    unittest.main()
