#!/usr/bin/env python3
"""Build the module-level import graph of a Python checkout for RECON §3.

    python3 -I depgraph.py REPO --out depgraph.json [--source-root PATH]...
        [--exclude GLOB]... [--modules modules.json]

Reads every `.py` file with `ast.parse`; nothing in REPO is imported or run.
Counts top-level, function-level, `if TYPE_CHECKING:` (type-only) and
`importlib.import_module("literal")` / `__import__("literal")` (dynamic)
imports; resolves relative imports and names a package's `__init__.py`
re-exports from a submodule. Imports that resolve to no file in REPO are left
out unless modules.json names them as external.

Modules: by default one per package below the packages every file shares
(`src/acme/orders/` is `orders` when everything is under `acme`), and one per
file at that level. modules.json replaces that and declares layers:

    {"layers": ["presentation", "application", "domain", "infrastructure"],
     "modules": [{"id": "orders", "paths": ["app/orders/**"], "layer": "domain"},
                 {"id": "django", "external": ["django"], "layer": "presentation"}]}

`layers` run from top to bottom: an edge to a layer above is `upward`. A file
no `paths` glob matches keeps its default module.

The JSON written to --out holds `modules`, `edges` (sites per kind and one
`path:line` example), `cycles` (strongly connected modules, type-only edges
left out because they never run), `upward`, `into_internals` (imports of a
package module's file other than its `__init__.py`: leads, not findings),
`hubs` (distinct importing modules), `unresolved` (dynamic imports of a
computed name), `unparsed` (files this Python cannot parse) and `diagram`, the
`{nodes, edges}` shape `architecture.before` takes. Exit status: 0 written,
2 invalid arguments or modules.json.
"""

import argparse
import ast
from collections import Counter, defaultdict
import json
import os
from pathlib import Path
import re
import sys

KINDS = ("runtime", "function_level", "type_only", "dynamic")
SKIP_DIRS = {"__pycache__", "node_modules", "site-packages", "venv"}
NODE_ID = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,63}")


class GraphError(Exception):
    pass


def glob_regex(pattern):
    """A path glob as a regex: `*` and `?` stay inside one segment, `**` spans any."""
    out, i = [], 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("".join(out) + r"\Z")


def matches(path, regexes):
    """A glob matches the path itself or any directory above it."""
    parts = path.split("/")
    return any(r.match("/".join(parts[:n])) for r in regexes for n in range(1, len(parts) + 1))


def python_files(repo, roots, exclude):
    found = []
    for root in roots or [""]:
        base = repo / root
        for directory, dirs, files in os.walk(base):
            dirs[:] = sorted(d for d in dirs if not d.startswith(".") and d not in SKIP_DIRS)
            for name in sorted(files):
                if name.endswith(".py"):
                    rel = (Path(directory) / name).relative_to(repo).as_posix()
                    if not matches(rel, exclude):
                        found.append(rel)
    return sorted(set(found))


def dotted_name(rel, present):
    """The import name of a file: its path from the first directory above it with no __init__.py."""
    parts = rel[:-3].split("/")
    start = len(parts) - 1
    while start > 0 and "/".join(parts[:start] + ["__init__.py"]) in present:
        start -= 1
    names = parts[start:]
    if names[-1] == "__init__":
        names = names[:-1]
    return ".".join(names)


class Imports(ast.NodeVisitor):
    """Every import in one file as (line, kind, base, names, level)."""

    def __init__(self):
        self.found, self.computed = [], []
        self.depth, self.type_only = 0, 0

    def kind(self):
        if self.type_only:
            return "type_only"
        return "function_level" if self.depth else "runtime"

    def visit_FunctionDef(self, node):
        self.depth += 1
        self.generic_visit(node)
        self.depth -= 1

    visit_AsyncFunctionDef = visit_FunctionDef
    visit_Lambda = visit_FunctionDef

    def visit_If(self, node):
        test = node.test
        guarded = (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING") or (
            isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING")
        self.visit(node.test)
        self.type_only += guarded
        for child in node.body:
            self.visit(child)
        self.type_only -= guarded
        for child in node.orelse:
            self.visit(child)

    def visit_Import(self, node):
        for alias in node.names:
            self.found.append((node.lineno, self.kind(), alias.name, [], 0))

    def visit_ImportFrom(self, node):
        names = [a.name for a in node.names]
        self.found.append((node.lineno, self.kind(), node.module or "", names, node.level))

    def visit_Call(self, node):
        func = node.func
        name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
        if name in ("import_module", "__import__") and node.args:
            arg = node.args[0]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str) and not arg.value.startswith("."):
                self.found.append((node.lineno, "dynamic", arg.value, [], 0))
            else:
                self.computed.append((node.lineno, ast.unparse(node)[:120]))
        self.generic_visit(node)


class Resolver:
    def __init__(self, files, parsed):
        present = set(files)
        self.by_name = {dotted_name(rel, present): rel for rel in files}
        self.name_of = {rel: name for name, rel in self.by_name.items()}
        self.parsed = parsed

    def package_of(self, rel):
        name = self.name_of[rel]
        return name if rel.endswith("__init__.py") else name.rpartition(".")[0]

    def deepest(self, dotted):
        parts = dotted.split(".")
        for n in range(len(parts), 0, -1):
            hit = self.by_name.get(".".join(parts[:n]))
            if hit:
                return hit
        return None

    def reexport(self, init_rel, name, seen):
        """The file a package's __init__.py takes `name` from, followed through re-exports."""
        if init_rel in seen or init_rel not in self.parsed:
            return None
        seen.add(init_rel)
        for _, _, base, names, level in self.parsed[init_rel]:
            if name in names:
                target = self.target(init_rel, base, [name], level, seen)
                if target:
                    return target[0]
        return None

    def target(self, rel, base, names, level, seen=None, follow=True):
        """The files one import statement reaches, or [] when none is in the checkout.

        With follow, a name a package's __init__.py re-exports reaches the file
        it comes from; without, the file the statement names.
        """
        if level:
            package = self.package_of(rel).split(".") if self.package_of(rel) else []
            if level - 1 > len(package):
                return []
            package = package[:len(package) - (level - 1)]
            base = ".".join(package + ([base] if base else []))
        if not names:
            hit = self.deepest(base)
            return [hit] if hit else []
        out = []
        for name in names:
            sub = self.by_name.get(f"{base}.{name}" if base else name)
            if sub:
                out.append(sub)
                continue
            module = self.by_name.get(base)
            if follow and module and module.endswith("__init__.py") and name != "*":
                out.append(self.reexport(module, name, set(seen or ())) or module)
            elif module:
                out.append(module)
            else:
                hit = self.deepest(base) if base else None
                if hit:
                    out.append(hit)
        return out


def default_modules(files, names):
    """One module per package below the packages every file shares, one per file at that level."""
    split = {rel: names[rel].split(".") if names[rel] else [Path(rel).stem] for rel in files}
    shared = []
    while True:
        level = len(shared)
        heads = {parts[level] for rel, parts in split.items() if len(parts) > level + 1
                 or (len(parts) == level + 1 and rel.endswith("__init__.py"))}
        flat = any(len(parts) <= level + 1 and not rel.endswith("__init__.py") for rel, parts in split.items())
        if flat or len(heads) != 1:
            break
        shared.append(heads.pop())
    module = {}
    for rel, parts in split.items():
        rest = parts[len(shared):]
        module[rel] = rest[0] if rest else (shared[-1] if shared else Path(rel).stem)
    return module


def load_modules(path):
    try:
        spec = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise GraphError(f"modules.json: {exc}") from None
    if not isinstance(spec, dict):
        raise GraphError("modules.json: must be an object with `layers` and `modules`")
    layers = spec.get("layers", [])
    modules = spec.get("modules", [])
    if not (isinstance(layers, list) and all(isinstance(x, str) for x in layers)):
        raise GraphError("modules.json: `layers` must be a list of names")
    if not isinstance(modules, list):
        raise GraphError("modules.json: `modules` must be a list")
    for i, m in enumerate(modules):
        where = f"modules.json: modules[{i}]"
        if not (isinstance(m, dict) and isinstance(m.get("id"), str) and m["id"]):
            raise GraphError(f"{where} needs a nonempty `id`")
        for key in ("paths", "external"):
            if not (isinstance(m.get(key, []), list) and all(isinstance(x, str) for x in m.get(key, []))):
                raise GraphError(f"{where}.{key} must be a list of strings")
        if "layer" in m and m["layer"] not in layers:
            raise GraphError(f"{where}.layer {m['layer']!r} is not in `layers`")
    return layers, modules


def strongly_connected(nodes, edges):
    """Tarjan's components with more than one module, each sorted, largest first."""
    index, low, stack, on_stack, out = {}, {}, [], set(), []
    counter = [0]

    def visit(v):
        index[v] = low[v] = counter[0]
        counter[0] += 1
        stack.append(v)
        on_stack.add(v)
        for w in sorted(edges.get(v, ())):
            if w not in index:
                visit(w)
                low[v] = min(low[v], low[w])
            elif w in on_stack:
                low[v] = min(low[v], index[w])
        if low[v] == index[v]:
            component = []
            while True:
                w = stack.pop()
                on_stack.discard(w)
                component.append(w)
                if w == v:
                    break
            if len(component) > 1:
                out.append(sorted(component))

    sys.setrecursionlimit(max(sys.getrecursionlimit(), 10 * len(nodes) + 100))
    for v in sorted(nodes):
        if v not in index:
            visit(v)
    return sorted(out, key=lambda c: (-len(c), c))


def diagram(module_ids, kinds, edges):
    ids, used = {}, set()
    for m in module_ids:
        base = re.sub(r"[^A-Za-z0-9_.-]", "_", m)
        base = (base if base[:1].isalpha() else f"m_{base}")[:64]
        node, n = base, 1
        while node in used:
            n += 1
            node = f"{base[:58]}_{n}"
        used.add(node)
        ids[m] = node
    return {"nodes": [{"id": ids[m], "label": m, "kind": kinds[m]} for m in module_ids],
            "edges": [{"from": ids[e["from"]], "to": ids[e["to"]]} for e in edges]}


def build(repo, roots=(), exclude=(), modules_path=None):
    repo = Path(repo)
    if not repo.is_dir():
        raise GraphError(f"{repo} is not a directory")
    for root in roots:
        if not (repo / root).is_dir():
            raise GraphError(f"--source-root {root} is not a directory in {repo}")
    layers, declared = load_modules(modules_path) if modules_path else ([], [])
    files = python_files(repo, roots, [glob_regex(g.rstrip("/")) for g in exclude])

    parsed, computed, unparsed = {}, [], []
    for rel in files:
        try:
            tree = ast.parse((repo / rel).read_bytes(), filename=rel)
        except (SyntaxError, ValueError) as exc:
            unparsed.append({"path": rel, "error": f"{type(exc).__name__}: {exc}"})
            continue
        visitor = Imports()
        visitor.visit(tree)
        parsed[rel] = visitor.found
        computed += [{"path_line": f"{rel}:{line}", "call": call} for line, call in visitor.computed]

    resolver = Resolver(files, parsed)
    module_of = default_modules(files, resolver.name_of)
    globbed = [(m, [glob_regex(p) for p in m.get("paths", [])]) for m in declared]
    for rel in files:
        for m, regexes in globbed:
            if regexes and any(r.match(rel) for r in regexes):
                module_of[rel] = m["id"]
                break
    external = [(prefix, m["id"]) for m in declared for prefix in m.get("external", [])]
    layer_of = {m["id"]: m["layer"] for m in declared if "layer" in m}
    external_ids = {m["id"] for m in declared if m.get("external")}

    entry = {}
    for rel in sorted(files, key=lambda f: (f.count("/"), f)):
        if rel.endswith("__init__.py"):
            entry.setdefault(module_of[rel], rel)
    sites = defaultdict(Counter)
    example = {}
    internal = {}
    for rel in sorted(parsed):
        source = module_of[rel]
        for line, kind, base, names, level in parsed[rel]:
            targets = resolver.target(rel, base, names, level)
            named = resolver.target(rel, base, names, level, follow=False)
            if not targets and not level:
                targets = named = [f"external:{mid}" for prefix, mid in external
                                   if base == prefix or base.startswith(prefix + ".")][:1]
            counted = set()
            for target, as_named in dict.fromkeys(zip(targets, named)):
                dest = target[9:] if target.startswith("external:") else module_of[target]
                if dest == source:
                    continue
                if dest not in counted:
                    counted.add(dest)
                    sites[(source, dest)][kind] += 1
                example.setdefault((source, dest), f"{rel}:{line}")
                if dest in entry and module_of.get(as_named) == dest and as_named != entry[dest]:
                    internal.setdefault((source, dest, as_named), f"{rel}:{line}")

    edges = [{"from": a, "to": b, "sites": sum(c.values()), "kinds": {k: c[k] for k in KINDS},
              "example": example[(a, b)]} for (a, b), c in sorted(sites.items())]
    module_ids = sorted(set(module_of.values()) | {e["to"] for e in edges})
    runs = defaultdict(set)
    for e in edges:
        if e["sites"] > e["kinds"]["type_only"]:
            runs[e["from"]].add(e["to"])
    order = {name: i for i, name in enumerate(layers)}
    upward = [{"from": e["from"], "to": e["to"], "from_layer": layer_of[e["from"]],
               "to_layer": layer_of[e["to"]], "example": e["example"]}
              for e in edges if e["from"] in layer_of and e["to"] in layer_of
              and order[layer_of[e["to"]]] < order[layer_of[e["from"]]]]
    fan_in = Counter(e["to"] for e in edges)
    lines = Counter()
    for rel in files:
        lines[module_of[rel]] += (repo / rel).read_bytes().count(b"\n")
    return {
        "python": ".".join(map(str, sys.version_info[:3])),
        "files": len(files),
        "modules": [{"id": m, "files": sum(module_of[f] == m for f in files), "lines": lines[m],
                     "layer": layer_of.get(m), "external": m in external_ids} for m in module_ids],
        "edges": edges,
        "cycles": strongly_connected(module_ids, runs),
        "upward": upward,
        "into_internals": [{"from": a, "to": b, "target": t, "example": ex}
                           for (a, b, t), ex in sorted(internal.items())],
        "hubs": [{"module": m, "fan_in": n} for m, n in sorted(fan_in.items(), key=lambda kv: (-kv[1], kv[0]))],
        "unresolved": computed,
        "unparsed": unparsed,
        "diagram": diagram(module_ids, {m: "external" if m in external_ids else "module" for m in module_ids},
                           edges),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("repo", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--source-root", action="append", default=[], metavar="PATH")
    parser.add_argument("--exclude", action="append", default=[], metavar="GLOB")
    parser.add_argument("--modules", type=Path, metavar="modules.json")
    args = parser.parse_args(argv)
    try:
        graph = build(args.repo, [r.strip("/") for r in args.source_root], args.exclude, args.modules)
    except GraphError as exc:
        print(f"depgraph: {exc}", file=sys.stderr)
        return 2
    args.out.write_text(json.dumps(graph, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"{graph['files']} files, {len(graph['modules'])} modules, {len(graph['edges'])} edges, "
          f"{len(graph['cycles'])} cycles, {len(graph['upward'])} upward, "
          f"{len(graph['unparsed'])} unparsed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
