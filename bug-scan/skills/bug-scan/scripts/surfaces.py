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

# Each pattern is paired with a literal every match must contain, or None. A pattern that opens
# with \b gives the regex engine no prefix to scan for, so a file without the literal is skipped
# with one substring test instead of a full regex pass. Case-insensitive patterns get None.
API_PATTERNS = [
    (re.compile(r"""@(?:\w+\.)?(?:route|get|post|put|patch|delete)\(\s*["'](?P<path>/[^"']*)["'](?P<rest>[^\n]*)""", re.I), None),
    (re.compile(r"""\b(?:app|router|server)\.(?P<method>get|post|put|patch|delete|all)\(\s*["'`](?P<path>/[^"'`]*)["'`]""", re.I), None),
    (re.compile(r"""\b(?:path|re_path)\(\s*r?["'](?P<path>[^"']+)["']\s*,""" ), "path("),
]
METHOD_DECORATOR = re.compile(r"@(?:\w+\.)?(get|post|put|patch|delete)\(", re.I)
JOB_PATTERNS = [
    (re.compile(r"@(?:\w+\.)?(?:task|shared_task|periodic_task|scheduled_job)\b[^\n]*\n\s*(?:async\s+)?def\s+(?P<name>\w+)"), None),
    (re.compile(r"""new\s+Worker\(\s*["'](?P<name>[^"']+)["']"""), None),
    (re.compile(r"\bclass\s+(?P<name>\w+)\s*<\s*(?:ApplicationJob|ActiveJob::Base)"), "Job"),
    (re.compile(r"""\bcron\.schedule\(\s*["'][^"']+["']\s*,\s*(?P<name>\w+)"""), "cron.schedule("),
]
TABLE_PATTERNS = [
    (re.compile(r"\bCREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[`\"\[]?(?P<name>\w+)", re.I), None),
    (re.compile(r"""\bcreate_table\s+[:"'](?P<name>\w+)"""), "create_table"),
    (re.compile(r"""__tablename__\s*=\s*["'](?P<name>\w+)["']"""), None),
    (re.compile(r"^model\s+(?P<name>\w+)\s*\{", re.M), "model"),
    (re.compile(r"\bclass\s+(?P<name>\w+)\((?:[\w.]*\.)?Model\)\s*:"), "Model)"),
]
EXT_PATTERN = re.compile(r"""["'`]https?://(?P<host>[a-z0-9.-]+\.[a-z]{2,})(?:[:/"'`])""", re.I)
LOCAL_HOST = re.compile(r"(^|\.)(localhost|example\.(com|org|net)|w3\.org|schemas?\.\w+|json-schema\.org|github\.com|npmjs\.(com|org)|pypi\.org)$", re.I)
CFG_PATTERNS = [
    (re.compile(r"""os\.environ(?:\.get\(|\[)\s*["'](?P<name>[A-Z][A-Z0-9_]+)["']"""), None),
    (re.compile(r"""os\.getenv\(\s*["'](?P<name>[A-Z][A-Z0-9_]+)["']"""), None),
    (re.compile(r"\bprocess\.env\.(?P<name>[A-Z][A-Z0-9_]+)"), "process.env."),
]
ROUTE_COMPONENT = re.compile(r"""<Route\b[^>]*\bpath=["'](?P<path>[^"']+)["']""")
SCREEN_FILE = [
    re.compile(r"(^|/)app/(?P<route>(?:[^/]+/)*)page\.(?:tsx|jsx|ts|js|vue)$"),
    re.compile(r"(^|/)pages/(?P<route>.+)\.(?:tsx|jsx|vue|svelte)$"),
    re.compile(r"(^|/)routes/(?P<route>(?:[^/]+/)*)\+page\.svelte$"),
]


class Lines:
    """1-based line of an offset in one file, counting only the newlines since the previous answer.

    Each pattern's matches arrive in ascending order, so a file is scanned about once per
    pattern that matches rather than once per match.
    """

    def __init__(self, text):
        self.text, self.offset, self.line = text, 0, 1

    def __call__(self, offset):
        if offset < self.offset:
            self.offset, self.line = 0, 1
        self.line += self.text.count("\n", self.offset, offset)
        self.offset = offset
        return self.line


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
        self.items, self.seen, self.dropped, self.per_kind = [], set(), {}, {}

    def add(self, kind, name, note, where):
        key = (kind, name.lower())
        if key in self.seen:
            return
        if self.per_kind.get(kind, 0) >= MAX_PER_KIND:
            self.dropped[kind] = self.dropped.get(kind, 0) + 1
            return
        self.seen.add(key)
        self.per_kind[kind] = self.per_kind.get(kind, 0) + 1
        self.items.append(dict(kind=kind, name=redact(name), note=note, location=where))


def _matches(patterns, text):
    for pattern, literal in patterns:
        if literal is None or literal in text:
            yield from pattern.finditer(text)


def scan_file(rel, text, catalog):
    line = Lines(text)
    for pattern in SCREEN_FILE:
        match = pattern.search(rel)
        if match:
            route = "/" + match.group("route").rstrip("/")
            route = re.sub(r"/index$", "", route) or "/"
            catalog.add("screen", route, "file route", f"{rel}:1")
            break
    for match in ROUTE_COMPONENT.finditer(text):
        catalog.add("screen", match.group("path"), "<Route>", f"{rel}:{line(match.start())}")
    for match in _matches(API_PATTERNS, text):
        path = match.group("path")
        groups = match.groupdict()
        method = (groups.get("method") or "").upper()
        if not method:
            decorator = METHOD_DECORATOR.match(match.group(0))
            method = decorator.group(1).upper() if decorator else "ANY"
        catalog.add("api", f"{method} {path if path.startswith('/') else '/' + path}", "route", f"{rel}:{line(match.start())}")
    for match in _matches(JOB_PATTERNS, text):
        catalog.add("job", match.group("name"), "job", f"{rel}:{line(match.start())}")
    for match in _matches(TABLE_PATTERNS, text):
        catalog.add("db", match.group("name"), "table or model", f"{rel}:{line(match.start())}")
    for match in EXT_PATTERN.finditer(text):
        if not LOCAL_HOST.search(match.group("host")):
            catalog.add("ext", match.group("host").lower(), "absolute URL", f"{rel}:{line(match.start())}")
    for match in _matches(CFG_PATTERNS, text):
        catalog.add("cfg", match.group("name"), "environment variable", f"{rel}:{line(match.start())}")


def infer_links(items, texts):
    """Propose an edge when a file that defines one surface names another. A proposal, not a trace."""
    links = []
    by_file = {}
    files = [item["location"].rsplit(":", 1)[0] for item in items]
    for item, rel in zip(items, files):
        by_file.setdefault(rel, []).append(item)

    def probe(item):
        """How a file is searched for a mention of item, worked out once per item."""
        if item["kind"] == "api":
            needle = item["name"].split(" ", 1)[-1].split("{")[0].split("<")[0].split(":")[0].rstrip("/")
            return lambda text: len(needle) > 1 and needle in text
        if item["kind"] == "db":
            # The substring test is a cheap gate: a \b-anchored regex has no prefix to scan for.
            word = re.compile(rf"\b{re.escape(item['name'])}\b").search
            return lambda text, name=item["name"]: name in text and word(text) is not None
        return lambda text, name=item["name"]: name in text

    probes = {}
    order = {"screen": ("api",), "api": ("job", "db", "ext"), "job": ("db", "ext")}
    for rel, sources in by_file.items():
        text = texts.get(rel, "")
        named = {}  # target index -> whether this file mentions it; the same for every source here
        for source in sources:
            wanted = order.get(source["kind"], ())
            for index, target in enumerate(items):
                if target["kind"] not in wanted:
                    continue
                if files[index] != rel:
                    if index not in named:
                        if index not in probes:
                            probes[index] = probe(target)
                        named[index] = bool(probes[index](text))
                    if named[index]:
                        links.append(dict(**{"from": source["id"], "to": target["id"]}, basis="inferred"))
                elif source["kind"] != "api":
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
        if not isinstance(part, dict):
            raise RecordError(f"{fragment}: must be a JSON object")
        for item in part.get("surfaces", []):
            if not isinstance(item, dict) or not isinstance(item.get("id"), str):
                raise RecordError(f"{fragment}: surface {item!r} needs a string id")
        for pair in part.get("remove_links", []):
            if not isinstance(pair, list) or len(pair) != 2:
                raise RecordError(f"{fragment}: remove_links entry {pair!r} must be [from, to]")
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
