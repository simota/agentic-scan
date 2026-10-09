#!/usr/bin/env python3
"""Merge finding fragments into findings.json and check a run's output directory.

    python3 findings.py merge FINDINGS FRAGMENT [FRAGMENT ...]
    python3 findings.py check OUT_DIR [--allow NAME ...]

A fragment is a JSON file written with the host's file-write tool (never a
shell heredoc or a generated script). It holds any of these top-level keys:
`meta` is merged key by key; `findings` and `rules` records are matched by
`id`, a known record updated key by key and a new one appended; `perspectives`
are matched by `name` and replaced whole; the string lists (`checked_ok`,
`decisions`, `limitations`, `next_steps`) are appended without duplicates.
FINDINGS is created when absent. The merged record must pass the schema check
(`reference/findings-schema.md`) before anything is written.

`check` is the run contract: the output directory holds exactly
`findings.json`, `dashboard.html` and `report.md` (plus `--allow` names), the
record is complete, IDs are gapless in severity order and every perspective in
`reference/perspectives.md` is recorded.

Exit codes: 0 ok, 1 a fragment was refused, the input was unreadable or the
contract failed (reasons on stderr).
"""
import argparse
import json
from pathlib import Path
import re
import sys

SEVERITIES = ("High", "Medium", "Low", "Info")
CONFIDENCES = ("Confirmed", "Environment-dependent", "Suspected")
VERDICTS = ("Valid", "Likely", "Unverified", "Unlikely", "FalsePositive", "NotApplicable")
DEFINITIVE = ("Valid", "FalsePositive", "NotApplicable")
EXCLUDED = ("FalsePositive", "NotApplicable")
METHODS = ("static", "analysed")
STATUSES = ("Open", "Fixed", "Accepted")
RULE_STATUSES = ("holds", "violated", "partly read", "not checked")
PERSPECTIVE_STATUSES = ("applied", "N/A", "not checked")
PERSPECTIVES = (
    "Boundaries and layering", "Cohesion and responsibility", "Coupling",
    "Domain model and data ownership", "Consistency and transactions",
    "Failure handling", "API and event contracts", "Configuration and environment",
    "Testability", "Operability", "Duplication and consistency of patterns",
    "Dependencies and evolution",
)
LISTS = ("checked_ok", "decisions", "limitations", "next_steps")
TOP_KEYS = {"meta", "findings", "rules", "perspectives", *LISTS}
META_REQUIRED = ("project", "scope", "date", "assessor", "lang")
TEXT_FIELDS = ("title", "scenario", "blast_radius", "trace", "impact", "fix", "guard")
FINDING_REQUIRED = ("id", "severity", "confidence", "category", "location", "validation",
                    *TEXT_FIELDS)
OUTPUTS = {"findings.json", "dashboard.html", "report.md"}
FINDING_ID = re.compile(r"^A-\d{3}$")
RULE_ID = re.compile(r"^R-\d{2,}$")
LOCATION = re.compile(r"[^\r\n]+:\d+(?:-\d+)?")


class SchemaError(ValueError):
    pass


def read_json(path):
    def unique_object(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise SchemaError(f"{path}: duplicate object key {key!r}")
            obj[key] = value
        return obj

    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=unique_object)
        # Escaped lone surrogates parse as JSON but cannot be written as UTF-8.
        json.dumps(doc, ensure_ascii=False).encode("utf-8")
        return doc
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SchemaError(f"{path}: {exc}") from exc


def _text(value, where):
    if not isinstance(value, str) or not value.strip():
        raise SchemaError(f"{where}: must be a nonblank string")


def _list(value, where):
    if not isinstance(value, list):
        raise SchemaError(f"{where}: must be a list")
    return value


def _choice(value, allowed, where):
    if value not in allowed:
        raise SchemaError(f"{where}: {value!r} is not one of {', '.join(allowed)}")


def validate_finding(f, where):
    if not isinstance(f, dict):
        raise SchemaError(f"{where}: must be an object")
    for key in FINDING_REQUIRED:
        if key not in f:
            raise SchemaError(f"{where}: missing {key}")
    if not FINDING_ID.fullmatch(str(f["id"])):
        raise SchemaError(f"{where}.id: {f['id']!r} must look like A-001")
    for key in TEXT_FIELDS:
        _text(f[key], f"{where}.{key}")
    for key in ("contrast", "rule"):
        if key in f and not isinstance(f[key], str):
            raise SchemaError(f"{where}.{key}: must be a string")
    _choice(f["severity"], SEVERITIES, f"{where}.severity")
    _choice(f["confidence"], CONFIDENCES, f"{where}.confidence")
    _choice(f["category"], PERSPECTIVES, f"{where}.category")
    _choice(f.get("status", "Open"), STATUSES, f"{where}.status")
    locations = f["location"] if isinstance(f["location"], list) else [f["location"]]
    if not locations:
        raise SchemaError(f"{where}.location: at least one path:line")
    for loc in locations:
        if not isinstance(loc, str) or not LOCATION.fullmatch(loc):
            raise SchemaError(f"{where}.location: {loc!r} must be path:line")
    v = f["validation"]
    if not isinstance(v, dict):
        raise SchemaError(f"{where}.validation: must be an object")
    _choice(v.get("verdict"), VERDICTS, f"{where}.validation.verdict")
    _choice(v.get("method"), METHODS, f"{where}.validation.method")
    if "evidence" in v and not isinstance(v["evidence"], str):
        raise SchemaError(f"{where}.validation.evidence: must be a string")
    if v["verdict"] in DEFINITIVE:
        _text(v.get("evidence"), f"{where}.validation.evidence ({v['verdict']} needs evidence)")
    if v["method"] == "analysed" and "analysis" not in f:
        raise SchemaError(f"{where}.analysis: required when validation.method is analysed")
    if "analysis" in f:
        a = f["analysis"]
        if not isinstance(a, dict):
            raise SchemaError(f"{where}.analysis: must be an object")
        for key in ("tool", "command", "result"):
            _text(a.get(key), f"{where}.analysis.{key}")
    for i, ref in enumerate(_list(f.get("references", []), f"{where}.references")):
        if not isinstance(ref, dict):
            raise SchemaError(f"{where}.references[{i}]: must be an object")
        _text(ref.get("url"), f"{where}.references[{i}].url")
        if "title" in ref and not isinstance(ref["title"], str):
            raise SchemaError(f"{where}.references[{i}].title: must be a string")


def _validate_perspectives(records, where):
    names = set()
    for i, p in enumerate(_list(records, where)):
        field = f"{where}[{i}]"
        if not isinstance(p, dict):
            raise SchemaError(f"{field}: must be an object")
        _choice(p.get("name"), PERSPECTIVES, f"{field}.name")
        if p["name"] in names:
            raise SchemaError(f"{field}.name: duplicate {p['name']}")
        names.add(p["name"])
        _choice(p.get("status"), PERSPECTIVE_STATUSES, f"{field}.status")
        _text(p.get("note"), f"{field}.note")
    return names


def validate(doc, complete=False):
    """Raise SchemaError when doc does not match reference/findings-schema.md."""
    if not isinstance(doc, dict):
        raise SchemaError("top level: must be an object")
    unknown = set(doc) - TOP_KEYS
    if unknown:
        raise SchemaError(f"top level: unknown keys {sorted(unknown)}")
    meta = doc.get("meta", {})
    if not isinstance(meta, dict):
        raise SchemaError("meta: must be an object")
    if complete:
        for key in META_REQUIRED:
            _text(meta.get(key), f"meta.{key}")
    if "lang" in meta:
        _choice(meta["lang"], ("ja", "en"), "meta.lang")
    for key in ("method", "commit"):
        if key in meta and not isinstance(meta[key], str):
            raise SchemaError(f"meta.{key}: must be a string")
    seen = set()
    for i, f in enumerate(_list(doc.get("findings", []), "findings")):
        validate_finding(f, f"findings[{i}]")
        if f["id"] in seen:
            raise SchemaError(f"findings[{i}].id: duplicate {f['id']}")
        seen.add(f["id"])
    rule_ids = set()
    for i, r in enumerate(_list(doc.get("rules", []), "rules")):
        where = f"rules[{i}]"
        if not isinstance(r, dict) or not RULE_ID.fullmatch(str(r.get("id"))):
            raise SchemaError(f"{where}.id: must look like R-01")
        if r["id"] in rule_ids:
            raise SchemaError(f"{where}.id: duplicate {r['id']}")
        rule_ids.add(r["id"])
        for key in ("statement", "source"):
            _text(r.get(key), f"{where}.{key}")
        _choice(r.get("status"), RULE_STATUSES, f"{where}.status")
        if "reason" in r and not isinstance(r["reason"], str):
            raise SchemaError(f"{where}.reason ({r['id']}): must be a string")
    _validate_perspectives(doc.get("perspectives", []), "perspectives")
    for key in LISTS:
        values = _list(doc.get(key, []), key)
        for i, value in enumerate(values):
            _text(value, f"{key}[{i}]")


def _merge_records(current, incoming, where):
    for records in (current, incoming):
        ids = [r.get("id") if isinstance(r, dict) else None for r in _list(records, where)]
        if any(not isinstance(fid, str) for fid in ids) or len(set(ids)) != len(ids):
            raise SchemaError(f"{where}: every record needs a unique string id")
    index = {r["id"]: r for r in current}
    for record in incoming:
        if record["id"] in index:
            index[record["id"]].update(record)
        else:
            current.append(dict(record))
            index[record["id"]] = current[-1]


def merge(doc, fragment, where):
    if not isinstance(fragment, dict):
        raise SchemaError(f"{where}: must be an object")
    unknown = set(fragment) - TOP_KEYS
    if unknown:
        raise SchemaError(f"{where}: unknown keys {sorted(unknown)}")
    if "meta" in fragment:
        if not isinstance(fragment["meta"], dict):
            raise SchemaError(f"{where}.meta: must be an object")
        doc.setdefault("meta", {}).update(fragment["meta"])
    for key in ("findings", "rules", "perspectives"):
        if key not in fragment:
            continue
        if not isinstance(fragment[key], list):
            raise SchemaError(f"{where}.{key}: must be a list")
        if key == "perspectives":
            names = _validate_perspectives(fragment[key], f"{where}.{key}")
            doc[key] = [q for q in doc.get(key, []) if q.get("name") not in names]
            doc[key].extend(fragment[key])
        else:
            _merge_records(doc.setdefault(key, []), fragment[key], f"{where}.{key}")
    for key in LISTS:
        if key in fragment:
            if not isinstance(fragment[key], list):
                raise SchemaError(f"{where}.{key}: must be a list")
            target = doc.setdefault(key, [])
            target.extend(v for v in fragment[key] if v not in target)
    return doc


def cmd_merge(args):
    target = Path(args.findings)
    try:
        doc = read_json(target) if target.exists() else {}
        validate(doc)
        for path in args.fragments:
            merge(doc, read_json(path), path)
            # Each fragment must leave a valid record, even in a batch.
            validate(doc)
        # Encode before opening the target so invalid Unicode cannot truncate it.
        data = (json.dumps(doc, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    except (SchemaError, UnicodeError) as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 1
    target.write_bytes(data)
    print(f"merged {len(args.fragments)} fragment(s) into {target}: "
          f"{len(doc.get('findings', []))} finding(s)")
    return 0


def contract_problems(out, allow=()):
    """Return the run-contract violations for an output directory."""
    out = Path(out)
    problems = []
    present = {p.name for p in out.iterdir()} if out.is_dir() else set()
    for name in sorted(OUTPUTS - present):
        problems.append(f"missing output: {name}")
    for name in sorted(present - OUTPUTS - set(allow)):
        problems.append(f"unexpected output: {name} (pass --allow {name} if requested)")
    not_files = {name for name in OUTPUTS & present if not (out / name).is_file()}
    for name in sorted(not_files):
        problems.append(f"output is not a file: {name}")
    if "findings.json" not in present or "findings.json" in not_files:
        return problems
    try:
        doc = read_json(out / "findings.json")
        validate(doc, complete=True)
    except SchemaError as exc:
        return problems + [f"findings.json: {exc}"]
    findings = doc.get("findings", [])
    expected = [f"A-{i:03d}" for i in range(1, len(findings) + 1)]
    if [f["id"] for f in findings] != expected:
        problems.append(f"IDs must be gapless in order: expected {', '.join(expected) or 'none'}")
    ranks = [SEVERITIES.index(f["severity"]) for f in findings if
             f["validation"]["verdict"] not in EXCLUDED]
    if ranks != sorted(ranks):
        problems.append("findings must be numbered in severity order (High first)")
    recorded = {p["name"] for p in doc.get("perspectives", [])}
    for name in PERSPECTIVES:
        if name not in recorded:
            problems.append(f"perspective not recorded: {name}")
    for r in doc.get("rules", []):
        if r["status"] == "not checked":
            reason = r.get("reason")
            if not isinstance(reason, str) or not reason.strip():
                problems.append(f"{r['id']}: a not-checked rule needs a nonblank string reason")
    if not doc.get("limitations"):
        problems.append("limitations: state what static reading cannot show")
    if not doc.get("checked_ok"):
        problems.append("checked_ok: list what was examined and held")
    return problems


def cmd_check(args):
    problems = contract_problems(args.out, args.allow)
    for problem in problems:
        print(problem, file=sys.stderr)
    if problems:
        return 1
    print(f"contract ok: {args.out}")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("merge", help="merge fragments into findings.json")
    m.add_argument("findings")
    m.add_argument("fragments", nargs="+")
    c = sub.add_parser("check", help="check the run contract of an output directory")
    c.add_argument("out")
    c.add_argument("--allow", action="append", default=[])
    args = parser.parse_args(argv)
    return cmd_merge(args) if args.cmd == "merge" else cmd_check(args)


if __name__ == "__main__":
    sys.exit(main())
