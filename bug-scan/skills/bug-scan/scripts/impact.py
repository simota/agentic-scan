#!/usr/bin/env python3
"""Show which recorded defects, sibling sites, fixed defects and recurring patterns a change touches.

    impact.py <out> --repo <repo> [--base REF] [--head REF] [--format markdown|json] [--fail-on High]
    impact.py <out> --files api/orders/validate.py web/checkout/api.ts

Use it when reviewing a change against a finished record: before a merge, or in CI. With no --head the
working tree (staged, unstaged and untracked files) is compared with --base, which defaults to the record's
meta.commit, then HEAD. Lines are compared on the base side, where the record's path:line were read.

It reads git and the record only. Not touching a record is not evidence that a change is safe, and touching
one is not evidence that it breaks anything: it says where to look. With --fail-on, exit 1 when an unresolved
record at or above that severity has its site or a live sibling site in a changed file. Standard library only.
"""
import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import (DEFECT_TYPES, LOCATION, SEVERITIES, RecordError, as_list, closed, excluded, git, load_json,  # noqa: E402
                    location_path, pattern_name)

NEAR = 3
HUNK = re.compile(r"^@@ -(?P<start>\d+)(?:,(?P<count>\d+))? \+\d+(?:,\d+)? @@")
LIVE_SIBLING = ("affected", "unknown")
WHOLE_FILE = [(1, float("inf"))]


def load(out):
    path = Path(out) / "findings.json" if Path(out).is_dir() else Path(out)
    record = load_json(path)
    if not isinstance(record, dict) or not isinstance(record.get("findings", []), list):
        raise RecordError(f"{path}: not a bug-scan record")
    return record


ESCAPES = {"a": 7, "b": 8, "t": 9, "n": 10, "v": 11, "f": 12, "r": 13, '"': 34, "\\": 92}


def _unquote(name):
    """Undo git's C-style quoting of a path ("a/\\303\\244.py"), which it uses for control characters and quotes."""
    if not (len(name) >= 2 and name[0] == name[-1] == '"'):
        return name
    body, out, index = name[1:-1], bytearray(), 0
    while index < len(body):
        char = body[index]
        if char == "\\" and re.fullmatch(r"[0-7]{3}", body[index + 1:index + 4]):
            out.append(int(body[index + 1:index + 4], 8))
            index += 4
        elif char == "\\" and index + 1 < len(body) and body[index + 1] in ESCAPES:
            out.append(ESCAPES[body[index + 1]])
            index += 2
        else:
            out.extend(char.encode("utf-8"))
            index += 1
    return out.decode("utf-8", "replace")


def parse_diff(text):
    """{base-side path: [(first, last) line ranges]} from a --unified=0 patch. New files are keyed by their new path."""
    changed, current = defaultdict(list), None
    old = None
    for line in text.splitlines():
        if line.startswith("diff --git "):
            current = old = None
        elif line.startswith("--- "):
            name = _unquote(line[4:].strip())
            old = None if name == "/dev/null" else name[2:] if name.startswith("a/") else name
        elif line.startswith("+++ "):
            name = _unquote(line[4:].strip())
            new = None if name == "/dev/null" else name[2:] if name.startswith("b/") else name
            current = old or new
            if old is None:
                changed[current] = list(WHOLE_FILE)
            else:
                changed.setdefault(current, [])
        elif current and (match := HUNK.match(line)):
            if changed[current] == WHOLE_FILE:
                continue
            start, count = int(match.group("start")), int(match.group("count") or 1)
            # A pure insertion (count 0) sits after `start`; it touches the lines on either side.
            changed[current].append((start, start + 1) if count == 0 else (start, start + count - 1))
    return dict(changed)


def changed_files(repo, base, head):
    for ref in (base, head):
        if ref is not None and (not ref or ref.startswith("-")):
            raise RecordError(f"{ref!r} is not a revision")
    if git(repo, "rev-parse", "--is-inside-work-tree", check=False).strip() != "true":
        raise RecordError(f"{repo} is not a git work tree")
    span = [f"{base}...{head}"] if head else [base]
    patch = git(repo, "diff", "--no-ext-diff", "--no-textconv", "--no-color", "--unified=0", "--find-renames", *span, "--")
    changed = parse_diff(patch)
    if not head:
        for name in git(repo, "ls-files", "--others", "--exclude-standard", "-z").split("\x00"):
            if name:
                changed[name] = list(WHOLE_FILE)
    return changed


def touch(location, changed):
    """'line' when a changed hunk is within NEAR lines of the location, 'file' when only the file changed, else None."""
    match = LOCATION.match(location)
    path = match.group("path") if match else location
    if path not in changed:
        return None
    if not match or changed[path] == WHOLE_FILE:
        return "file"
    first = int(match.group("line"))
    last = int(match.group("end") or first)
    if any(start <= last + NEAR and end >= first - NEAR for start, end in changed[path]):
        return "line"
    return "file"


def inside(path, prefix):
    prefix = prefix.strip().rstrip("/")
    return bool(prefix) and (path == prefix or path.startswith(prefix + "/"))


def at_least(severity, minimum):
    return SEVERITIES.index(severity or "Info") <= SEVERITIES.index(minimum)


def hits_of(locations, changed):
    return [dict(location=loc, match=how) for loc in locations if loc and (how := touch(loc, changed))]


def analyse(record, changed):
    sites, siblings, watch = [], [], []
    for finding in record.get("findings", []):
        if excluded(finding):
            continue
        base = dict(id=finding["id"], key=finding.get("key"), title=finding["title"], status=finding["status"],
                    severity=finding.get("severity"), pattern=finding.get("pattern"))
        hits = hits_of(as_list(finding.get("location")), changed)
        if closed(finding):
            if hits:
                watch.append(dict(base, at=hits, fixed_in=finding.get("fixed_in"), regression_test=finding.get("regression_test"),
                                  guard=finding.get("guard")))
            continue
        own = {h["location"] for h in hits}
        hop_hits = hits_of(list(dict.fromkeys(hop.get("at") for hop in finding.get("path", []) if hop.get("at") not in own)), changed)
        if hits or hop_hits:
            sites.append(dict(base, at=hits, path=hop_hits, fix=finding.get("fix"), guard=finding.get("guard"),
                              regression_test=finding.get("regression_test")))
        for site in finding.get("sibling_sites", []):
            if site["state"] in LIVE_SIBLING:
                for hit in hits_of([site["location"]], changed):
                    siblings.append(dict(base, at=hit, state=site["state"], evidence=site["evidence"]))
    grouped = defaultdict(lambda: dict(events=set(), files=set()))
    for event in record.get("fix_events", []):
        if event.get("type") not in DEFECT_TYPES:
            continue
        for path in changed:
            if (event.get("file") and location_path(event["file"]) == path) or (event.get("module") and inside(path, event["module"])):
                row = grouped[(event.get("module") or location_path(event["file"]), event.get("pattern") or "Unclassified")]
                row["events"].add(event["id"])
                row["files"].add(path)
    strength = {e["id"]: (e.get("origin") or {}).get("strength") for e in record.get("fix_events", [])}
    patterns = [dict(module=module, pattern=pattern, name=pattern_name(pattern, "en"), events=len(row["events"]),
                     traced=sum(1 for i in row["events"] if strength.get(i) == "Traced"), files=sorted(row["files"]))
                for (module, pattern), row in grouped.items()]
    patterns.sort(key=lambda r: (-r["traced"], -r["events"], r["module"], r["pattern"]))
    issues = []
    for issue in record.get("issues", []):
        at = location_path(str(issue.get("at", "")))
        if "/" in at or "." in at:
            hit = sorted(p for p in changed if inside(p, at))
            if hit:
                issues.append(dict(id=issue["id"], kind=issue.get("kind"), at=issue.get("at"), feeds=as_list(issue.get("feeds")), files=hit))
    matched = {location_path(h["location"]) for row in sites for h in row["at"] + row["path"]}
    matched |= {location_path(row["at"]["location"]) for row in siblings}
    matched |= {location_path(h["location"]) for row in watch for h in row["at"]}
    matched |= {f for row in patterns for f in row["files"]} | {f for row in issues for f in row["files"]}
    order = lambda row: (SEVERITIES.index(row.get("severity") or "Info"), row["id"])  # noqa: E731
    return dict(changed=sorted(changed), sites=sorted(sites, key=order), siblings=sorted(siblings, key=order),
                fixed_here=sorted(watch, key=order), patterns=patterns, issues=issues,
                untouched_by_record=sorted(set(changed) - matched))


def gate(result, minimum):
    """Records that fail a --fail-on threshold: unresolved, at or above it, site or live sibling in a changed file."""
    rows = result["sites"] + result["siblings"]
    return sorted({row["id"] for row in rows if at_least(row.get("severity"), minimum)})


def markdown(result, meta, base, head):
    lines = ["# bug-scan impact", ""]
    change = f"`{base}` → `{head or 'working tree'}`" if base else "listed files, compared whole"
    lines.append(f"Change: {change}, {len(result['changed'])} file(s). "
                 f"Record: {meta.get('project', '?')} at `{meta.get('commit', '?')}` ({meta.get('date', '?')}).")
    if meta.get("commit") and base and not (base.startswith(meta["commit"]) or meta["commit"].startswith(base)):
        lines += ["", "> The base is not the commit the record was read at, so recorded lines may have moved; `line` matches are approximate."]
    lines += ["", "Touching a record says where to look, not that the change breaks anything; touching none is not proof of safety.", ""]

    def section(title, rows, render):
        lines.append(f"## {title} ({len(rows)})")
        lines.extend(render(row) for row in rows) if rows else lines.append("- none")
        lines.append("")

    def where(hits, prefix=""):
        return [f"{prefix}`{h['location']}` ({h['match']})" for h in hits]

    def site_line(row):
        text = f"- **{row['id']}** [{row.get('severity') or '-'} / {row['status']}] {row['title']}: " + ", ".join(where(row["at"]) + where(row["path"], "path "))
        extra = [f"fix: {row['fix']}"] if row.get("fix") else []
        extra += [f"regression test: {row['regression_test']}"] if row.get("regression_test") else []
        return text + ("\n  - " + "\n  - ".join(extra) if extra else "")

    section("Unresolved defects at changed code", result["sites"], site_line)
    section("Sibling sites in changed files", result["siblings"],
            lambda r: f"- **{r['id']}** [{r.get('severity') or '-'}] {where([r['at']])[0]} is {r['state']}: {r['evidence']}")
    section("Fixed defects lived here: keep their guard", result["fixed_here"],
            lambda r: f"- **{r['id']}** {r['title']} (fixed in `{(r.get('fixed_in') or '?')[:12]}`): {', '.join(where(r['at']))}"
                      + (f"; regression test: {r['regression_test']}" if r.get("regression_test") else ""))
    section("Patterns that recurred in the changed modules", result["patterns"],
            lambda r: f"- {r['module']}: {r['pattern']} {r['name']}, {r['events']} defect fix(es), {r['traced']} Traced ({', '.join(r['files'])})")
    section("Known code issues in changed files", result["issues"],
            lambda r: f"- {r['id']} {r.get('kind') or ''} at {r['at']} feeds {', '.join(r['feeds']) or '-'} ({', '.join(r['files'])})")
    lines.append(f"Changed files the record says nothing about: {len(result['untouched_by_record'])}")
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("out", help="the run directory or its findings.json")
    parser.add_argument("--repo", help="the repository the change is in")
    parser.add_argument("--base", help="defaults to the record's meta.commit, then HEAD")
    parser.add_argument("--head", help="defaults to the working tree")
    parser.add_argument("--files", nargs="+", help="changed files, instead of a git diff (whole files are compared)")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    parser.add_argument("--fail-on", choices=SEVERITIES)
    args = parser.parse_args(argv)
    try:
        record = load(args.out)
        meta = record.get("meta", {})
        if args.files:
            changed, base, head = {f: list(WHOLE_FILE) for f in args.files}, None, None
        else:
            if not args.repo:
                raise RecordError("--repo is required unless --files is given")
            base = args.base or meta.get("commit") or "HEAD"
            if not args.base and meta.get("commit") and not git(args.repo, "rev-parse", "--verify", "--quiet", f"{meta['commit']}^{{commit}}", check=False).strip():
                base = "HEAD"
            head = args.head
            changed = changed_files(args.repo, base, head)
        result = analyse(record, changed)
        failing = gate(result, args.fail_on) if args.fail_on else []
        result["fail_on"] = dict(threshold=args.fail_on, records=failing) if args.fail_on else None
        print(json.dumps(result, ensure_ascii=False, indent=2) if args.format == "json" else markdown(result, meta, base, head), end="")
        if args.format == "json":
            print()
    except RecordError as error:
        print(f"impact.py: {error}", file=sys.stderr)
        return 2
    if failing:
        print(f"impact.py: {len(failing)} unresolved record(s) at or above {args.fail_on} in changed files: {', '.join(failing)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
