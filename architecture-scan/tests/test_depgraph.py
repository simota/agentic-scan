"""Offline tests for scripts/depgraph.py against a throwaway Python package."""
import contextlib
import io
import json
from pathlib import Path
import re
import tempfile
import unittest

from test_architecture_scan import SKILL, import_module

depgraph = import_module(SKILL / "scripts" / "depgraph.py", "arch_depgraph")

TREE = {
    "src/acme/__init__.py": "",
    "src/acme/cli.py": "import acme.orders.service\n",
    "src/acme/web/__init__.py": "from acme.orders import place_order\n",
    "src/acme/web/views.py": "from ..orders import service\n",
    "src/acme/orders/__init__.py": "from .service import place_order\n",
    "src/acme/orders/service.py": (
        "from acme.billing import charge\n"
        "def place_order():\n"
        "    from acme.web import views\n"),
    "src/acme/billing/__init__.py": "from .core import charge\n",
    "src/acme/billing/core.py": (
        "import importlib\n"
        "from typing import TYPE_CHECKING\n"
        "import django.db\n"
        "if TYPE_CHECKING:\n"
        "    from acme.orders.service import Order\n"
        "def charge(name):\n"
        "    importlib.import_module('acme.web.views')\n"
        "    return importlib.import_module(name)\n"),
    "src/acme/broken.py": "def (:\n",
    "src/.venv/lib/x.py": "import acme.cli\n",
}

MODULES = {"layers": ["presentation", "application", "domain", "infrastructure"],
           "modules": [{"id": "web", "paths": ["src/acme/web/**"], "layer": "presentation"},
                       {"id": "orders", "paths": ["src/acme/orders/**"], "layer": "application"},
                       {"id": "billing", "paths": ["src/acme/billing/**"], "layer": "domain"},
                       {"id": "django", "external": ["django"], "layer": "infrastructure"}]}


class DepGraph(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name) / "repo"
        for rel, text in TREE.items():
            path = self.repo / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def graph(self, *args):
        out = Path(self.tmp.name) / "graph.json"
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(depgraph.main([str(self.repo), "--out", str(out), "--source-root", "src", *args]), 0)
        return json.loads(out.read_text(encoding="utf-8"))

    def with_modules(self):
        path = Path(self.tmp.name) / "modules.json"
        path.write_text(json.dumps(MODULES), encoding="utf-8")
        return self.graph("--modules", str(path))

    def edge(self, graph, a, b):
        return next(e for e in graph["edges"] if (e["from"], e["to"]) == (a, b))

    def test_default_modules_skip_the_package_every_file_shares(self):
        g = self.graph()
        self.assertEqual([m["id"] for m in g["modules"]],
                         ["acme", "billing", "broken", "cli", "orders", "web"])
        self.assertEqual(g["files"], 9)

    def test_edges_count_sites_per_kind(self):
        g = self.graph()
        self.assertEqual(self.edge(g, "web", "orders")["kinds"],
                         {"runtime": 2, "function_level": 0, "type_only": 0, "dynamic": 0})
        self.assertEqual(self.edge(g, "orders", "web")["kinds"]["function_level"], 1)
        self.assertEqual(self.edge(g, "billing", "orders")["kinds"]["type_only"], 1)
        self.assertEqual(self.edge(g, "billing", "web")["kinds"]["dynamic"], 1)
        self.assertEqual(self.edge(g, "web", "orders")["example"], "src/acme/web/__init__.py:1")
        self.assertFalse(any(e["to"] == "django" for e in g["edges"]))

    def test_a_dynamic_import_closes_a_cycle(self):
        self.assertEqual(self.graph()["cycles"], [["billing", "orders", "web"]])

    def test_one_statement_is_one_site_per_module(self):
        (self.repo / "src/acme/web/views.py").write_text(
            "from ..orders import service, place_order\n", encoding="utf-8")
        self.assertEqual(self.edge(self.graph(), "web", "orders")["kinds"]["runtime"], 2)

    def test_cycles_leave_out_type_only_edges(self):
        core = self.repo / "src/acme/billing/core.py"
        core.write_text(core.read_text(encoding="utf-8").replace(
            "    importlib.import_module('acme.web.views')\n", ""), encoding="utf-8")
        g = self.graph()
        self.assertEqual(self.edge(g, "billing", "orders")["kinds"]["type_only"], 1)
        self.assertEqual(g["cycles"], [["orders", "web"]])

    def test_into_internals_names_the_file_the_statement_names(self):
        rows = {(r["from"], r["target"]) for r in self.graph()["into_internals"]}
        self.assertEqual(rows, {("web", "src/acme/orders/service.py"),
                                ("cli", "src/acme/orders/service.py"),
                                ("orders", "src/acme/web/views.py"),
                                ("billing", "src/acme/web/views.py"),
                                ("billing", "src/acme/orders/service.py")})

    def test_unresolved_and_unparsed(self):
        g = self.graph()
        self.assertEqual([u["path_line"] for u in g["unresolved"]], ["src/acme/billing/core.py:8"])
        self.assertEqual([u["path"] for u in g["unparsed"]], ["src/acme/broken.py"])

    def test_layers_flag_upward_edges_and_external_modules(self):
        g = self.with_modules()
        self.assertEqual({(u["from"], u["to"]) for u in g["upward"]},
                         {("orders", "web"), ("billing", "web"), ("billing", "orders")})
        self.assertEqual(self.edge(g, "billing", "django")["kinds"]["runtime"], 1)
        django = next(m for m in g["modules"] if m["id"] == "django")
        self.assertTrue(django["external"])

    def test_diagram_fits_the_architecture_schema(self):
        g = self.with_modules()
        ids = [n["id"] for n in g["diagram"]["nodes"]]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(all(re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,63}", i) for i in ids))
        self.assertIn({"id": "django", "label": "django", "kind": "external"}, g["diagram"]["nodes"])
        pairs = [(e["from"], e["to"]) for e in g["diagram"]["edges"]]
        self.assertEqual(len(pairs), len(set(pairs)))
        self.assertTrue(all(a != b and a in ids and b in ids for a, b in pairs))

    def test_namespace_packages_resolve_from_the_source_root(self):
        for rel in list(self.repo.rglob("__init__.py")):
            rel.unlink()
        g = self.graph()
        self.assertEqual([m["id"] for m in g["modules"]],
                         ["billing", "broken", "cli", "orders", "web"])
        self.assertEqual(self.edge(g, "cli", "orders")["sites"], 1)
        self.assertEqual(self.edge(g, "web", "orders")["kinds"]["runtime"], 1)
        self.assertNotIn("src/acme/orders/service.py:3", [u["path_line"] for u in g["unmatched"]])

    def test_imports_naming_the_checkout_that_reach_no_file_are_unmatched(self):
        (self.repo / "src/acme/cli.py").write_text("import acme.payments\nimport json\n", encoding="utf-8")
        g = self.graph()
        self.assertEqual(g["unmatched"], [{"path_line": "src/acme/cli.py:1", "import": "acme.payments"}])

    def test_diagram_ids_are_made_valid_and_unique(self):
        d = depgraph.diagram(["9lives", "a b", "a_b"], {"9lives": "module", "a b": "module", "a_b": "module"}, [])
        self.assertEqual([n["id"] for n in d["nodes"]], ["m_9lives", "a_b", "a_b_2"])

    def test_invalid_modules_json_exits_2(self):
        bad = Path(self.tmp.name) / "bad.json"
        bad.write_text(json.dumps({"layers": ["a"], "modules": [{"id": "x", "layer": "b"}]}), encoding="utf-8")
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = depgraph.main([str(self.repo), "--out", str(Path(self.tmp.name) / "x.json"),
                                  "--modules", str(bad)])
        self.assertEqual(code, 2)
        self.assertIn("not in `layers`", err.getvalue())


if __name__ == "__main__":
    unittest.main()
