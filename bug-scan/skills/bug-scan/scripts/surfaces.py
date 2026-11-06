#!/usr/bin/env python3
"""List a repository's screens, APIs, jobs, tables, external services and settings, read-only.

    surfaces.py scan <repo> --out <out>/surfaces.json
    surfaces.py merge <out>/surfaces.json <fragment.json>...

`scan` proposes candidates from file conventions and simple patterns, all marked `inferred`.
Dynamic routes and calls are missed; the reviewer confirms links and adds the rest with `merge`.
Source text is never stored, only names and locations. Standard library only.
"""
import argparse
import os
import re
import sys
from pathlib import Path

from common import LINK_BASES, RecordError, SURFACE_KINDS, load_json, redact, write_json

SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", "out", "coverage", "target", "__pycache__", ".venv", "venv",
             ".next", ".nuxt", ".cache", ".idea", ".vscode", "scan_report_kit"}
SOURCE_EXT = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".rb", ".go", ".java", ".kt", ".php", ".vue", ".svelte", ".sql", ".prisma"}
TEST_PATH = re.compile(r"(^|/)(tests?|__tests__|spec|specs|fixtures)(/|$)|(_test|\.test|\.spec)\.[^/]+$|(^|/)test_[^/]+$")
MAX_FILE = 1_000_000
MAX_PER_KIND = 300
PREFIX = dict(screen="SC", api="API", job="JOB", db="DB", ext="EXT", cfg="CFG")

API_PATTERNS = [
    re.compile(r"""@(?:\w+\.)?(?:route|get|post|put|patch|delete)\(\s*["'](?P<path>/[^"']*)["'](?P<rest>[^\n]*)""", re.I),
    re.compile(r"""\b(?:app|router|server)\.(?P<method>get|post|put|patch|delete|all)\(\s*["'`](?P<path>/[^"'`]*)["'`]""", re.I),
    re.compile(r"""\b(?:path|re_path)\(\s*r?["'](?P<path>[^"']+)["']\s*,""" ),
]
METHOD_DECORATOR = re.compile(r"@(?:\w+\.)?(get|post|put|patch|delete)\(", re.I)
JOB_PATTERNS = [
    re.compile(r"@(?:\w+\.)?(?:task|shared_task|periodic_task|scheduled_job)\b[^\n]*\n\s*(?:async\s+)?def\s+(?P<name>\w+)"),
    re.compile(r"""new\s+Worker\(\s*["'](?P<name>[^"']+)["']"""),
    re.compile(r"\bclass\s+(?P<name>\w+)\s*<\s*(?:ApplicationJob|ActiveJob::Base)"),
    re.compile(r"""\bcron\.schedule\(\s*["'][^"']+["']\s*,\s*(?P<name>\w+)"""),
]
TABLE_PATTERNS = [
    re.compile(r"\bCREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[`\"\[]?(?P<name>\w+)", re.I),
    re.compile(r"""\bcreate_table\s+[:"'](?P<name>\w+)"""),
    re.compile(r"""__tablename__\s*=\s*["'](?P<name>\w+)["']"""),
    re.compile(r"^model\s+(?P<name>\w+)\s*\{", re.M),
    re.compile(r"\bclass\s+(?P<name>\w+)\((?:[\w.]*\.)?Model\)\s*:"),
]
EXT_PATTERN = re.compile(r"""["'`]https?://(?P<host>[a-z0-9.-]+\.[a-z]{2,})(?:[:/"'`])""", re.I)
LOCAL_HOST = re.compile(r"(^|\.)(localhost|example\.(com|org|net)|w3\.org|schemas?\.\w+|json-schema\.org|github\.com|npmjs\.(com|org)|pypi\.org)$", re.I)
CFG_PATTERNS = [
    re.compile(r"""os\.environ(?:\.get\(|\[)\s*["'](?P<name>[A-Z][A-Z0-9_]+)["']"""),
    re.compile(r"""os\.getenv\(\s*["'](?P<name>[A-Z][A-Z0-9_]+)["']"""),
    re.compile(r"\bprocess\.env\.(?P<name>[A-Z][A-Z0-9_]+)"),
]
ROUTE_COMPONENT = re.compile(r"""<Route\b[^>]*\bpath=["'](?P<path>[^"']+)["']""")
SCREEN_FILE = [
    re.compile(r"(^|/)app/(?P<route>(?:[^/]+/)*)page\.(?:tsx|jsx|ts|js|vue)$"),
    re.compile(r"(^|/)pages/(?P<route>.+)\.(?:tsx|jsx|vue|svelte)$"),
    re.compile(r"(^|/)routes/(?P<route>(?:[^/]+/)*)\+page\.svelte$"),
]


def line_of(text, offset):
    return text.count("\n", 0, offset) + 1


def repo_files(repo):
    for root, dirs, names in os.walk(repo, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not d.startswith(".") and not (Path(root) / d).is_symlink())
        for name in sorted(names):
            path = Path(root) / name
            if path.suffix in SOURCE_EXT and not path.is_symlink():
                rel = path.relative_to(repo).as_posix()
                if not TEST_PATH.search(rel) and path.stat().st_size <= MAX_FILE:
                    yield rel, path


class Catalog:
    def __init__(self):
        self.items, self.seen, self.dropped = [], set(), {}

    def add(self, kind, name, note, where):
        key = (kind, name.lower())
        if key in self.seen:
            return
        if sum(1 for i in self.items if i["kind"] == kind) >= MAX_PER_KIND:
            self.dropped[kind] = self.dropped.get(kind, 0) + 1
            return
        self.seen.add(key)
        self.items.append(dict(kind=kind, name=redact(name), note=note, location=where))


def scan_file(rel, text, catalog):
    for pattern in SCREEN_FILE:
        match = pattern.search(rel)
        if match:
            route = "/" + match.group("route").rstrip("/")
            route = re.sub(r"/index$", "", route) or "/"
            catalog.add("screen", route, "file route", f"{rel}:1")
            break
    for match in ROUTE_COMPONENT.finditer(text):
        catalog.add("screen", match.group("path"), "<Route>", f"{rel}:{line_of(text, match.start())}")
    for pattern in API_PATTERNS:
        for match in pattern.finditer(text):
            path = match.group("path")
            groups = match.groupdict()
            method = (groups.get("method") or "").upper()
            if not method:
                decorator = METHOD_DECORATOR.match(match.group(0))
                method = decorator.group(1).upper() if decorator else "ANY"
            catalog.add("api", f"{method} {path if path.startswith('/') else '/' + path}", "route", f"{rel}:{line_of(text, match.start())}")
    for pattern in JOB_PATTERNS:
        for match in pattern.finditer(text):
            catalog.add("job", match.group("name"), "job", f"{rel}:{line_of(text, match.start())}")
    for pattern in TABLE_PATTERNS:
        for match in pattern.finditer(text):
            catalog.add("db", match.group("name"), "table or model", f"{rel}:{line_of(text, match.start())}")
    for match in EXT_PATTERN.finditer(text):
        if not LOCAL_HOST.search(match.group("host")):
            catalog.add("ext", match.group("host").lower(), "absolute URL", f"{rel}:{line_of(text, match.start())}")
    for pattern in CFG_PATTERNS:
        for match in pattern.finditer(text):
            catalog.add("cfg", match.group("name"), "environment variable", f"{rel}:{line_of(text, match.start())}")


def infer_links(items, texts):
    """Propose an edge when a file that defines one surface names another. A proposal, not a trace."""
    links = []
    by_file = {}
    for item in items:
        by_file.setdefault(item["location"].rsplit(":", 1)[0], []).append(item)

    def mention(text, item):
        if item["kind"] == "api":
            needle = item["name"].split(" ", 1)[-1].split("{")[0].split("<")[0].split(":")[0].rstrip("/")
            return len(needle) > 1 and needle in text
        if item["kind"] == "db":
            return re.search(rf"\b{re.escape(item['name'])}\b", text) is not None
        return item["name"] in text

    order = {"screen": ("api",), "api": ("job", "db", "ext"), "job": ("db", "ext")}
    for rel, sources in by_file.items():
        text = texts.get(rel, "")
        for source in sources:
            for target in items:
                if target["kind"] in order.get(source["kind"], ()) and target["location"].rsplit(":", 1)[0] != rel and mention(text, target):
                    links.append(dict(**{"from": source["id"], "to": target["id"]}, basis="inferred"))
                elif target["kind"] in order.get(source["kind"], ()) and target["location"].rsplit(":", 1)[0] == rel and source["kind"] != "api":
                    links.append(dict(**{"from": source["id"], "to": target["id"]}, basis="inferred"))
    unique = {(l["from"], l["to"]): l for l in links}
    return [unique[k] for k in sorted(unique)]


def scan(repo):
    repo = Path(repo).resolve()
    if not repo.is_dir():
        raise RecordError(f"{repo} is not a directory")
    catalog, texts = Catalog(), {}
    for rel, path in repo_files(repo):
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        texts[rel] = text
        scan_file(rel, text, catalog)
    counts = {}
    items = []
    for kind in SURFACE_KINDS:
        for item in sorted((i for i in catalog.items if i["kind"] == kind), key=lambda i: i["location"]):
            counts[kind] = counts.get(kind, 0) + 1
            items.append(dict(id=f"{PREFIX[kind]}-{counts[kind]:02d}", **item, basis="inferred"))
    return dict(surfaces=items, links=infer_links(items, texts), dropped=catalog.dropped)


def shape_errors(data):
    errors = []
    ids = set()
    if set(data) - {"surfaces", "links", "dropped"}:
        errors.append(f"unknown keys {sorted(set(data) - {'surfaces', 'links', 'dropped'})}")
    for item in data.get("surfaces", []):
        if not isinstance(item, dict) or set(item) - {"id", "kind", "name", "note", "location", "basis"}:
            errors.append(f"surface {item!r}: unknown keys")
            continue
        for key in ("id", "kind", "name"):
            if not isinstance(item.get(key), str) or not item[key].strip():
                errors.append(f"surface {item.get('id')}: {key} is required")
        if item.get("kind") not in SURFACE_KINDS:
            errors.append(f"surface {item.get('id')}: kind {item.get('kind')!r}")
        if item.get("basis", "inferred") not in LINK_BASES:
            errors.append(f"surface {item.get('id')}: basis {item.get('basis')!r}")
        ids.add(item.get("id"))
    for link in data.get("links", []):
        if not isinstance(link, dict) or link.get("from") not in ids or link.get("to") not in ids or link.get("basis") not in LINK_BASES:
            errors.append(f"link {link!r}: from/to must name surfaces and basis must be one of {LINK_BASES}")
    return errors


def merge(path, fragments):
    data = load_json(path) if Path(path).exists() else dict(surfaces=[], links=[])
    for fragment in fragments:
        part = load_json(fragment)
        by_id = {s["id"]: s for s in data["surfaces"]}
        for item in part.get("surfaces", []):
            if item.get("id") in by_id:
                by_id[item["id"]].update(item)
            else:
                data["surfaces"].append(item)
                by_id[item.get("id")] = item
        links = {(l["from"], l["to"]): l for l in data["links"]}
        for link in part.get("links", []):
            if isinstance(link, dict) and "from" in link and "to" in link:
                links[(link["from"], link["to"])] = link
        for pair in part.get("remove_links", []):
            links.pop(tuple(pair), None)
        data["links"] = [links[k] for k in sorted(links)]
    errors = shape_errors(data)
    if errors:
        raise RecordError("; ".join(errors))
    write_json(path, data)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    one = sub.add_parser("scan")
    one.add_argument("repo")
    one.add_argument("--out", required=True)
    two = sub.add_parser("merge")
    two.add_argument("path")
    two.add_argument("fragments", nargs="+")
    args = parser.parse_args(argv)
    try:
        if args.command == "scan":
            data = scan(args.repo)
            write_json(args.out, data)
            counts = {k: sum(1 for s in data["surfaces"] if s["kind"] == k) for k in SURFACE_KINDS}
            print(f"wrote {args.out}: {counts}, {len(data['links'])} inferred links")
        else:
            merge(args.path, args.fragments)
            print(f"merged into {args.path}")
    except RecordError as error:
        print(f"surfaces.py: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
