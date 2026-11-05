"""Usage: metrics.py SCRIPTS_DIR. Static structure metrics of skills/infra-scan/scripts (stdlib ast)."""
import ast, sys, pathlib, collections
S = pathlib.Path(sys.argv[1]); mods = {p.stem: p for p in S.glob("*.py")}
graph = collections.defaultdict(set); names = collections.Counter(); private = []
for m, p in mods.items():
    for n in ast.walk(ast.parse(p.read_text())):
        if isinstance(n, ast.ImportFrom) and n.module in mods:
            graph[m].add(n.module); names[(m, n.module)] += len(n.names)
            private += [f"{m} <- {n.module}.{a.name}" for a in n.names if a.name.startswith("_")]
        elif isinstance(n, ast.Import):
            for a in n.names:
                if a.name in mods: graph[m].add(a.name)
def closure(m, seen=None):
    seen = seen or set()
    for d in graph[m]:
        if d not in seen: seen.add(d); closure(d, seen)
    return seen
for m in sorted(mods):
    print(f"{m:15s} lines={len(mods[m].read_text().splitlines()):5d} deps={sorted(graph[m])} transitive={sorted(closure(m))}")
print("imported names per edge:", dict(names))
print("private names imported across modules:", private)
cyc = [m for m in mods if m in closure(m)]; print("modules on a cycle:", cyc)
