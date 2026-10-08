#!/usr/bin/env python3
"""Merge finding fragments into findings.json without writing ad-hoc scripts.

    python3 findings.py merge FINDINGS FRAGMENT [FRAGMENT ...]

A fragment is a JSON file written with the host's file-write tool (never a
shell heredoc or a generated script). It may hold:

- `meta` — merged key by key; `commit` is refused (it comes from iac_scan.py)
- `findings`, `attack_paths` — matched by `id`: a known record is updated key
  by key, a new one appended. `I-*` findings belong to iac_scan.py: a fragment
  may only update an existing one's `validation`
- `perspectives` — matched by `name`, replaced whole
- `checked_ok`, `decisions`, `limitations`, `next_steps` — appended without
  duplicates

`schema_version` and `inventory` are refused. FINDINGS is created when absent.
The merged record must pass render.py's schema check (meta completeness is
checked at render time) before anything is written; the write is atomic.

Prose describes the weakness, never an attack: literal exploit strings,
credential-shaped values and instance-metadata addresses are refused.

Exit codes: 0 merged, 1 a fragment was refused (reason on stderr), 2 unreadable
input or schema error.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import re
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import render  # noqa: E402

OBJECTS = ("meta",)
RECORDS = ("findings", "attack_paths")
LISTS = ("checked_ok", "decisions", "limitations", "next_steps")
ALLOWED = {*OBJECTS, *RECORDS, "perspectives", *LISTS}
OWNED = {"schema_version", "inventory"}
FINDING_PROSE = ("title", "actor", "path", "impact", "fix", "regression", "detail", "condition")
PAYLOAD = re.compile(
    r"<script\b|javascript:|onerror\s*=|'\s*(?:or|and)\s+['\d]|union\s+select|"
    r"(?:\.\./){2,}|;\s*(?:rm|curl|wget|nc|bash|sh)\s|\$\(\s*(?:curl|wget|id|cat)\b|"
    r"\{\{\s*\d+\s*\*\s*\d+\s*\}\}|/etc/passwd|"
    r"169\.254\.169\.254|metadata\.google\.internal|"
    r"(?:AKIA|ASIA)[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----|\"private_key\"\s*:|"
    r"ghp_[A-Za-z0-9]{36}|xox[baprs]-",
    re.IGNORECASE,
)


class Refused(Exception):
    pass


def prose_strings(fragment):
    """Yield (where, text) for every prose field the fragment sets."""
    for f in fragment.get("findings", []):
        fid = f.get("id", "?")
        for key in FINDING_PROSE:
            if isinstance(f.get(key), str):
                yield f"{fid}.{key}", f[key]
        val = f.get("validation")
        if isinstance(val, dict) and isinstance(val.get("evidence"), str):
            yield f"{fid}.validation.evidence", val["evidence"]
    for a in fragment.get("attack_paths", []):
        aid = a.get("id", "?")
        for i, edge in enumerate(a.get("edges", []) if isinstance(a.get("edges"), list) else []):
            if isinstance(edge, str):
                yield f"{aid}.edges[{i}]", edge
        for key in ("note", "entry", "target"):
            if isinstance(a.get(key), str):
                yield f"{aid}.{key}", a[key]
    for p in fragment.get("perspectives", []):
        if isinstance(p, dict) and isinstance(p.get("note"), str):
            yield f"perspective {p.get('name')}.note", p["note"]
    for key in LISTS:
        for i, item in enumerate(fragment.get(key, [])):
            if isinstance(item, str):
                yield f"{key}[{i}]", item


def fragment_problems(fragment, name, record):
    if not isinstance(fragment, dict):
        return [f"{name}: a fragment must be a JSON object"]
    problems = []
    owned = OWNED.intersection(fragment)
    if owned:
        problems.append(f"{name}: {sorted(owned)} are written by iac_scan.py, not fragments")
    unknown = set(fragment) - ALLOWED - OWNED
    if unknown:
        problems.append(f"{name}: unsupported keys {sorted(unknown)}")
    if "meta" in fragment:
        if not isinstance(fragment["meta"], dict):
            problems.append(f"{name}: meta must be an object")
        elif "commit" in fragment["meta"]:
            problems.append(f"{name}: meta.commit comes from iac_scan.py")
    for key in (*RECORDS, "perspectives", *LISTS):
        if key in fragment and not isinstance(fragment[key], list):
            problems.append(f"{name}: {key} must be a list")
    if problems:
        return problems
    existing = {f.get("id") for f in record.get("findings", [])}
    for key in RECORDS:
        seen = set()
        for rec in fragment.get(key, []):
            rid = rec.get("id") if isinstance(rec, dict) else None
            if not isinstance(rid, str) or not rid.strip():
                problems.append(f"{name}: {key} records need a nonblank id")
                continue
            if rid in seen:
                problems.append(f"{name}: duplicate {key} id {rid}")
            seen.add(rid)
            if key == "findings" and rid.startswith("I-"):
                if rid not in existing:
                    problems.append(f"{name}: {rid}: I-* findings come only from iac_scan.py")
                elif set(rec) - {"id", "validation"}:
                    problems.append(f"{name}: {rid}: a fragment may update only an I-* finding's validation")
    for p in fragment.get("perspectives", []):
        if not isinstance(p, dict) or not isinstance(p.get("name"), str):
            problems.append(f"{name}: perspectives entries need a name")
    pending = [fragment]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            if any(k.startswith("_") for k in value):
                problems.append(f"{name}: internal fields (leading underscore) cannot be merged")
                break
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
    if problems:
        return problems
    for where, text in prose_strings(fragment):
        if PAYLOAD.search(text):
            problems.append(f"{name}: {where}: describe the weakness, not a payload or credential; "
                            "use placeholders such as <attacker account>")
    return problems


def apply(record, fragment):
    if "meta" in fragment:
        record.setdefault("meta", {}).update(copy.deepcopy(fragment["meta"]))
    for key in RECORDS:
        current = record.setdefault(key, [])
        index = {r.get("id"): r for r in current if isinstance(r, dict)}
        for rec in fragment.get(key, []):
            if rec["id"] in index:
                index[rec["id"]].update(copy.deepcopy(rec))
            else:
                new = copy.deepcopy(rec)
                current.append(new)
                index[rec["id"]] = new
    persp = record.setdefault("perspectives", [])
    for p in fragment.get("perspectives", []):
        for i, old in enumerate(persp):
            if old.get("name") == p["name"]:
                persp[i] = copy.deepcopy(p)
                break
        else:
            persp.append(copy.deepcopy(p))
    for key in LISTS:
        current = record.setdefault(key, [])
        for item in fragment.get(key, []):
            if item not in current:
                current.append(item)


def write_atomic(path, data):
    path = Path(path)
    fd, tmp = tempfile.mkstemp(prefix=".findings.", suffix=".json", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def merge(findings_path, fragment_paths):
    path = Path(findings_path)
    record = render.load(path) if path.exists() else render.empty_record()
    merged = copy.deepcopy(record)
    for frag_path in fragment_paths:
        fragment = render.load(frag_path)
        problems = fragment_problems(fragment, frag_path, merged)
        if problems:
            raise Refused("\n".join(problems))
        apply(merged, fragment)
    render.validate(merged, partial=True)
    write_atomic(path, merged)
    return merged


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("merge", help="merge fragments into FINDINGS")
    m.add_argument("findings")
    m.add_argument("fragments", nargs="+")
    a = p.parse_args(argv)
    try:
        merged = merge(a.findings, a.fragments)
    except Refused as e:
        print(f"refused: {e}", file=sys.stderr)
        return 1
    except render.SchemaError as e:
        for problem in e.problems:
            print(f"schema: {problem}", file=sys.stderr)
        return 2
    print(f"merged {len(a.fragments)} fragment(s) into {a.findings}: "
          f"{len(merged.get('findings', []))} findings, {len(merged.get('attack_paths', []))} attack paths")
    return 0


if __name__ == "__main__":
    sys.exit(main())
