#!/usr/bin/env python3
"""Merge finding fragments into findings.json without writing ad-hoc scripts.

    python3 findings.py merge FINDINGS FRAGMENT [FRAGMENT ...]
    python3 findings.py remove FINDINGS ID [ID ...]
    python3 findings.py renumber FINDINGS
    python3 findings.py status FINDINGS

A fragment is a JSON file written with the host's file-write tool (never a
shell heredoc or a generated script). It may hold:

- `meta` — merged key by key; `commit` is refused (it comes from iac_scan.py)
- `findings`, `attack_paths` — matched by `id`: a known record is updated key
  by key (a key set to null is removed), a new one appended. `I-*` findings
  belong to iac_scan.py: a fragment may only update an existing one's
  `validation` and `confidence`
- `perspectives` — matched by `name`, replaced whole
- `checked_ok`, `decisions`, `limitations`, `next_steps` — appended without
  duplicates

`schema_version` and `inventory` are refused. FINDINGS is created when absent.

`remove` deletes `F-*` findings or `AP-*` attack paths (never `I-*`) and the
ID lists that point at them. `renumber` gives `F-*` findings the IDs F-001…
in severity order, then location, and rewrites every reference to them
(attack-path lists and standalone F-IDs in text). Run it once all review
findings are merged.
The merged record must pass render.py's schema check (meta completeness is
checked at render time) before anything is written; the write is atomic.

Credential-shaped values are refused in every string saved to the record.
Finding prose describes the weakness, never an attack: literal exploit strings
and instance-metadata addresses are refused in those fields.

`status` lists untriaged `I-*` findings and prose naming IDs no record has;
it exits 1 while either remains.

Exit codes: 0 done, 1 refused (a fragment, a removal or a renumbering; reason on
stderr), 2 unreadable input, schema error or unwritable record.
"""
import argparse
import copy
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import render  # noqa: E402
from common import STRING_LISTS as LISTS, write_json_atomic  # noqa: E402
from redaction import KEY_MARKER, SECRET_SHAPE  # noqa: E402

OBJECTS = ("meta",)
RECORDS = ("findings", "attack_paths")
ALLOWED = {*OBJECTS, *RECORDS, "perspectives", *LISTS}
OWNED = {"schema_version", "inventory"}
FINDING_PROSE = ("title", "actor", "path", "contrast", "impact", "fix", "regression", "detail", "condition")
PAYLOAD = re.compile(
    # Narrow shapes only: relative module paths (../../modules/app) and
    # quoted names joined by "and"/"or" are ordinary infrastructure prose.
    r"<script\b|javascript:|onerror\s*=|'\s*(?:or|and)\s+'?(\w+)'?\s*=\s*'?\1\b|union\s+select|"
    r"(?:\.\./){3,}|(?:\.\./){2,}(?:etc|proc|root|windows|var|home|run)\b|;\s*(?:rm|curl|wget|nc|bash|sh)\s|\$\(\s*(?:curl|wget|id|cat)\b|"
    r"\{\{\s*\d+\s*\*\s*\d+\s*\}\}|/etc/passwd|"
    r"169\.254\.169\.254|169\.254\.170\.2\b|fd00:ec2::254|\b2852039166\b|0xa9fea9fe|"
    r"metadata\.google\.internal",
    re.IGNORECASE,
)
# Share the renderer's known credential formats and retain the merge gate's
# conservative handling of private-key fields and incomplete Slack tokens.
# Token prefixes are case-sensitive: "asiaPacific..." is a name, not a key.
CREDENTIAL = re.compile(
    "|".join((SECRET_SHAPE.pattern, KEY_MARKER.pattern, r'(?i:"private_key"\s*:)', r"xox[abeoprs]-")))


class Refused(Exception):
    pass


def credential_problems(value, name):
    """Check every persisted string, including object keys and unknown fields.

    Never echo a matching value or its key: either may itself be a credential.
    """
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, dict):
            pending.extend(item.keys())
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
        elif isinstance(item, str) and CREDENTIAL.search(item):
            return [f"{name}: credential-shaped content refused; describe the weakness, "
                    "not a payload or credential; report its location and kind instead"]
    return []


def prose_strings(fragment):
    """Yield fields where literal attack payloads are prohibited."""
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
    problems = credential_problems(fragment, name)
    if problems:
        return problems
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
                elif set(rec) - {"id", "validation", "confidence", "condition"}:
                    problems.append(f"{name}: {rid}: a fragment may update only an I-* finding's "
                                    "validation, confidence and condition")
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
            target = index.get(rec["id"])
            if target is None:
                target = {}
                current.append(target)
                index[rec["id"]] = target
            for field, value in rec.items():
                if value is None:
                    target.pop(field, None)  # null removes a stale key
                else:
                    target[field] = copy.deepcopy(value)
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
    problems = credential_problems(merged, path)
    if problems:
        raise Refused("\n".join(problems))
    render.validate(merged, partial=True)
    write_json_atomic(path, merged)
    return merged


F_REFERENCE = re.compile(r"(?<![\w/.-])F-[0-9]{3,}(?![\w-])")


def record_strings(record):
    """(where, text) for every string in findings, attack paths, perspectives and lists."""
    def walk(value, where):
        if isinstance(value, str):
            yield where, value
        elif isinstance(value, list):
            for item in value:
                yield from walk(item, where)
        elif isinstance(value, dict):
            for key, item in value.items():
                yield from walk(item, f"{where}.{key}")
    for key in ("findings", "attack_paths", "perspectives"):
        for item in record.get(key, []):
            if isinstance(item, dict):
                yield from walk(item, str(item.get("id") or item.get("name") or key))
    for key in LISTS:
        yield from walk(record.get(key, []), key)


def remove(findings_path, ids):
    path = Path(findings_path)
    record = copy.deepcopy(render.load(path))
    for rid in ids:
        if not (render.F_ID.match(rid) or render.AP_ID.match(rid)):
            raise Refused(f"{rid}: only F-* findings and AP-* attack paths can be removed; "
                          "I-* findings belong to iac_scan.py")
        key = "findings" if rid.startswith("F-") else "attack_paths"
        before = len(record.get(key, []))
        record[key] = [r for r in record.get(key, []) if not (isinstance(r, dict) and r.get("id") == rid)]
        if len(record[key]) == before:
            raise Refused(f"{rid}: no such record")
        link, owner = ("findings", "attack_paths") if key == "findings" else ("attack_paths", "findings")
        for other in record.get(owner, []):
            if isinstance(other, dict) and isinstance(other.get(link), list) and rid in other[link]:
                other[link] = [x for x in other[link] if x != rid]
        # Prose mentioning the removed ID would later name whichever record
        # takes its number; make the author reword it first.
        pattern = re.compile(r"(?<![\w/.-])" + re.escape(rid) + r"(?![\w-])")
        mentions = sorted({where for where, text in record_strings(record) if pattern.search(text)})
        if mentions:
            raise Refused(f"{rid} is still mentioned in {', '.join(mentions)}; reword those fields "
                          "(merge a fragment) before removing it")
    render.validate(record, partial=True)
    write_json_atomic(path, record)
    return record


def renumber(findings_path):
    """F-001… in severity order, then location; references follow in one pass."""
    path = Path(findings_path)
    record = copy.deepcopy(render.load(path))
    render.validate(record, partial=True)
    fs = [f for f in record["findings"] if render.F_ID.match(f["id"])]
    order = sorted(fs, key=lambda f: (render.SEV_RANK[f["severity"]], render.location_key(f["location"]),
                                      render.id_key(f["id"])))
    mapping = {f["id"]: f"F-{n:03d}" for n, f in enumerate(order, 1)}
    stale = sorted({m.group() for _, text in record_strings(record) for m in F_REFERENCE.finditer(text)
                    if m.group() not in mapping})
    if stale:
        raise Refused(f"text mentions {', '.join(stale)}, which no longer exist; reword before renumbering")

    def rewrite(value):
        if isinstance(value, str):
            return F_REFERENCE.sub(lambda m: mapping.get(m.group(), m.group()), value)
        if isinstance(value, list):
            return [rewrite(x) for x in value]
        if isinstance(value, dict):
            return {k: rewrite(v) for k, v in value.items()}
        return value

    for key in ("findings", "attack_paths", "perspectives", *LISTS):
        record[key] = rewrite(record.get(key, []))
    record["attack_paths"] = sorted(record["attack_paths"], key=lambda ap: render.id_key(ap["id"]))
    record["findings"] = [f for f in record["findings"] if not render.F_ID.match(f["id"])] + \
        sorted((f for f in record["findings"] if render.F_ID.match(f["id"])), key=lambda f: render.id_key(f["id"]))
    render.validate(record, partial=True)
    write_json_atomic(path, record)
    return record, {old: new for old, new in mapping.items() if old != new}


def status(findings_path):
    """What is left before contract_check: untriaged I-* and dangling references."""
    record = render.load(findings_path)
    findings = [f for f in record.get("findings", []) if isinstance(f, dict)]
    open_items = [f for f in findings if str(f.get("id", "")).startswith("I-")
                  and isinstance(f.get("validation"), dict) and f["validation"].get("verdict") == "Unverified"]
    dangling = render.dangling_references(record)
    print(f"{len(findings)} findings, {len(record.get('attack_paths', []))} attack paths; "
          f"{len(open_items)} I-* untriaged, {len(dangling)} dangling reference(s)")
    for f in open_items:
        print(f"  untriaged {f['id']} {f.get('rule', '')} {f.get('location', '')}")
    for where, rid in dangling:
        print(f"  dangling  {rid} in {where}")
    return 1 if open_items or dangling else 0


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("merge", help="merge fragments into FINDINGS")
    m.add_argument("findings")
    m.add_argument("fragments", nargs="+")
    r = sub.add_parser("remove", help="remove F-* findings or AP-* attack paths and links to them")
    r.add_argument("findings")
    r.add_argument("ids", nargs="+")
    n = sub.add_parser("renumber", help="renumber F-* findings in severity order, then location")
    n.add_argument("findings")
    s = sub.add_parser("status", help="list untriaged I-* findings and references to missing IDs")
    s.add_argument("findings")
    a = p.parse_args(argv)
    try:
        if a.cmd == "status":
            return status(a.findings)
        if a.cmd == "remove":
            remove(a.findings, a.ids)
            print(f"removed {', '.join(a.ids)} from {a.findings}")
            return 0
        if a.cmd == "renumber":
            _, changed = renumber(a.findings)
            print(f"renumbered {len(changed)} finding(s) in {a.findings}"
                  + "".join(f"\n  {old} -> {new}" for old, new in sorted(changed.items(), key=lambda x: render.id_key(x[0]))))
            return 0
        merged = merge(a.findings, a.fragments)
    except Refused as e:
        print(f"refused: {e}", file=sys.stderr)
        return 1
    except render.SchemaError as e:
        for problem in e.problems:
            print(f"schema: {problem}", file=sys.stderr)
        return 2
    except OSError as e:
        print(f"cannot write {a.findings}: {e.strerror or e}", file=sys.stderr)
        return 2
    print(f"merged {len(a.fragments)} fragment(s) into {a.findings}: "
          f"{len(merged.get('findings', []))} findings, {len(merged.get('attack_paths', []))} attack paths")
    return 0


if __name__ == "__main__":
    sys.exit(main())
