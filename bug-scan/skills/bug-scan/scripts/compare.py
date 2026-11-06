#!/usr/bin/env python3
"""Compare an earlier bug-scan run with a later one by content, since IDs are renumbered per run.

    compare.py <earlier-out> <later-out> [--format json]

Run the later assessment independently first. "Not found again" is reported as such, never as fixed.
Standard library only.
"""
import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from common import DEFECT_TYPES, RecordError, load_json


def is_excluded(finding):
    return finding.get("validation", {}).get("verdict") in ("FalsePositive", "NotApplicable")


def load(out):
    path = Path(out) / "findings.json" if Path(out).is_dir() else Path(out)
    return load_json(path)


def pattern_counts(record):
    return Counter(e.get("pattern") for e in record.get("fix_events", []) if e.get("type") in DEFECT_TYPES)


def module_counts(record):
    return Counter(e.get("module") for e in record.get("fix_events", []) if e.get("type") in DEFECT_TYPES)


def delta(before, after):
    return {k: dict(before=before[k], after=after[k]) for k in sorted(set(before) | set(after), key=str) if before[k] != after[k]}


def compare(earlier, later):
    old = {f["key"]: f for f in earlier.get("findings", []) if not is_excluded(f) and "key" in f}
    new = {f["key"]: f for f in later.get("findings", []) if not is_excluded(f) and "key" in f}
    changed = []
    for key in sorted(set(old) & set(new)):
        changes = {name: dict(before=old[key].get(name), after=new[key].get(name))
                   for name in ("status", "severity") if old[key].get(name) != new[key].get(name)}
        if (old[key].get("risk") or {}).get("level") != (new[key].get("risk") or {}).get("level"):
            changes["risk"] = dict(before=(old[key].get("risk") or {}).get("level"), after=(new[key].get("risk") or {}).get("level"))
        changed.append(dict(key=key, id=new[key]["id"], title=new[key]["title"], changes=changes))
    scopes_differ = earlier.get("meta", {}).get("scope") != later.get("meta", {}).get("scope")
    return dict(new=[dict(key=k, id=new[k]["id"], title=new[k]["title"]) for k in sorted(set(new) - set(old))],
                not_found_again=[dict(key=k, id=old[k]["id"], title=old[k]["title"]) for k in sorted(set(old) - set(new))],
                persisting=changed, scopes_differ=scopes_differ,
                patterns=delta(pattern_counts(earlier), pattern_counts(later)),
                modules=delta(module_counts(earlier), module_counts(later)))


def markdown(result):
    lines = ["# bug-scan comparison", ""]
    if result["scopes_differ"]:
        lines += ["> The two runs have different scopes, so a record not found again may simply be out of scope.", ""]
    lines.append(f"## New ({len(result['new'])})")
    lines += [f"- {r['id']} {r['title']}" for r in result["new"]] or ["- none"]
    lines += ["", f"## Not found again ({len(result['not_found_again'])})", "This does not prove a fix."]
    lines += [f"- {r['id']} (earlier ID) {r['title']}" for r in result["not_found_again"]] or ["- none"]
    lines += ["", f"## Persisting ({len(result['persisting'])})"]
    for row in result["persisting"]:
        notes = ", ".join(f"{k}: {v['before']} -> {v['after']}" for k, v in row["changes"].items()) or "unchanged"
        lines.append(f"- {row['id']} {row['title']}: {notes}")
    if not result["persisting"]:
        lines.append("- none")
    for name, heading in (("patterns", "Defect fixes per pattern"), ("modules", "Defect fixes per module")):
        lines += ["", f"## {heading}"]
        lines += [f"- {k}: {v['before']} -> {v['after']}" for k, v in result[name].items()] or ["- unchanged"]
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("earlier")
    parser.add_argument("later")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    args = parser.parse_args(argv)
    try:
        result = compare(load(args.earlier), load(args.later))
    except (RecordError, KeyError) as error:
        print(f"compare.py: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2) if args.format == "json" else markdown(result), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
