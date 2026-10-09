#!/usr/bin/env python3
"""Merge finding fragments into findings.json and check a run's output directory.

    python3 findings.py merge FINDINGS FRAGMENT [FRAGMENT ...]
    python3 findings.py check OUT_DIR [--allow NAME ...]

A fragment is a JSON file written with the host's file-write tool (never a
shell heredoc or a generated script). It holds any of these top-level keys:
`meta` is merged key by key; `findings` and `budgets` records are matched by
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
METHODS = ("static", "measured")
STATUSES = ("Open", "Fixed", "Accepted")
BUDGET_STATUSES = ("holds", "violated", "partly read", "not checked")
PERSPECTIVE_STATUSES = ("applied", "N/A", "not checked")
PERSPECTIVES = (
    "Database access", "Algorithms and data structures", "Memory", "I/O and network",
    "Caching", "Concurrency and resources", "Payload and API shape", "Front end",
    "Background work", "Startup and configuration", "Dependencies and platform",
    "Observability",
)
LISTS = ("checked_ok", "decisions", "limitations", "next_steps")
TOP_KEYS = {"meta", "findings", "budgets", "perspectives", *LISTS}
META_REQUIRED = ("project", "scope", "date", "assessor", "lang")
FINDING_REQUIRED = ("id", "title", "severity", "confidence", "category", "location",
                    "workload", "scale_driver", "cost_model", "request", "impact",
                    "fix", "regression_test", "validation")
OUTPUTS = {"findings.json", "dashboard.html", "report.md"}
FINDING_ID = re.compile(r"^P-\d{3}$")
BUDGET_ID = re.compile(r"^B-\d{2,}$")
LOCATION = re.compile(r"(?P<path>[^\r\n]+):(?P<start>[0-9]+)(?:-(?P<end>[0-9]+))?")


class SchemaError(ValueError):
    pass


def read_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SchemaError(f"{path}: {exc}") from exc


def _text(value, where):
    if not isinstance(value, str) or not value.strip():
        raise SchemaError(f"{where}: must be a nonblank string")


def _choice(value, allowed, where):
    if value not in allowed:
        raise SchemaError(f"{where}: {value!r} is not one of {', '.join(allowed)}")


def validate_finding(f, where):
    if not isinstance(f, dict):
        raise SchemaError(f"{where}: must be an object")
    for key in FINDING_REQUIRED:
        if key not in f:
            raise SchemaError(f"{where}: missing {key}")
    if not FINDING_ID.match(str(f["id"])):
        raise SchemaError(f"{where}.id: {f['id']!r} must look like P-001")
    for key in ("title", "workload", "scale_driver", "cost_model", "request",
                "impact", "fix", "regression_test"):
        _text(f[key], f"{where}.{key}")
    _choice(f["severity"], SEVERITIES, f"{where}.severity")
    _choice(f["confidence"], CONFIDENCES, f"{where}.confidence")
    _choice(f["category"], PERSPECTIVES, f"{where}.category")
    _choice(f.get("status", "Open"), STATUSES, f"{where}.status")
    locations = f["location"] if isinstance(f["location"], list) else [f["location"]]
    if not locations:
        raise SchemaError(f"{where}.location: at least one path:line")
    for loc in locations:
        match = LOCATION.fullmatch(loc) if isinstance(loc, str) else None
        if match is None or not match["path"].strip():
            raise SchemaError(f"{where}.location: {loc!r} must be path:line")
        start = int(match["start"])
        end = int(match["end"] or match["start"])
        if start < 1 or end < start:
            raise SchemaError(f"{where}.location: {loc!r} needs positive line numbers "
                              "and a range end not before its start")
    v = f["validation"]
    if not isinstance(v, dict):
        raise SchemaError(f"{where}.validation: must be an object")
    _choice(v.get("verdict"), VERDICTS, f"{where}.validation.verdict")
    _choice(v.get("method"), METHODS, f"{where}.validation.method")
    if v["verdict"] in DEFINITIVE:
        _text(v.get("evidence"), f"{where}.validation.evidence ({v['verdict']} needs evidence)")
    if v["method"] == "measured" and "measurement" not in f:
        raise SchemaError(f"{where}.measurement: required when validation.method is measured")
    if "measurement" in f:
        m = f["measurement"]
        if not isinstance(m, dict):
            raise SchemaError(f"{where}.measurement: must be an object")
        for key in ("environment", "command", "result"):
            _text(m.get(key), f"{where}.measurement.{key}")
    for i, ref in enumerate(f.get("references", [])):
        if not isinstance(ref, dict):
            raise SchemaError(f"{where}.references[{i}]: must be an object")
        _text(ref.get("url"), f"{where}.references[{i}].url")


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
    seen = set()
    for i, f in enumerate(doc.get("findings", [])):
        validate_finding(f, f"findings[{i}]")
        if f["id"] in seen:
            raise SchemaError(f"findings[{i}].id: duplicate {f['id']}")
        seen.add(f["id"])
    for i, b in enumerate(doc.get("budgets", [])):
        where = f"budgets[{i}]"
        if not isinstance(b, dict) or not BUDGET_ID.match(str(b.get("id"))):
            raise SchemaError(f"{where}.id: must look like B-01")
        for key in ("statement", "source"):
            _text(b.get(key), f"{where}.{key}")
        _choice(b.get("status"), BUDGET_STATUSES, f"{where}.status")
    for i, p in enumerate(doc.get("perspectives", [])):
        where = f"perspectives[{i}]"
        if not isinstance(p, dict):
            raise SchemaError(f"{where}: must be an object")
        _choice(p.get("name"), PERSPECTIVES, f"{where}.name")
        _choice(p.get("status"), PERSPECTIVE_STATUSES, f"{where}.status")
        _text(p.get("note"), f"{where}.note")
    for key in LISTS:
        values = doc.get(key, [])
        if not isinstance(values, list):
            raise SchemaError(f"{key}: must be a list")
        for i, value in enumerate(values):
            _text(value, f"{key}[{i}]")


def _merge_records(current, incoming, key, where):
    ids = [r.get(key) if isinstance(r, dict) else None for r in incoming]
    if None in ids or len(set(ids)) != len(ids):
        raise SchemaError(f"{where}: every record needs a unique {key}")
    index = {r[key]: r for r in current}
    for record in incoming:
        if record[key] in index:
            index[record[key]].update(record)
        else:
            current.append(dict(record))
            index[record[key]] = current[-1]


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
    for key, match in (("findings", "id"), ("budgets", "id"), ("perspectives", "name")):
        if key in fragment:
            if not isinstance(fragment[key], list):
                raise SchemaError(f"{where}.{key}: must be a list")
            if key == "perspectives":
                for p in fragment[key]:
                    doc.setdefault(key, [])
                    doc[key] = [q for q in doc[key] if q.get("name") != p.get("name")]
                    doc[key].append(p)
            else:
                _merge_records(doc.setdefault(key, []), fragment[key], match, f"{where}.{key}")
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
        for path in args.fragments:
            merge(doc, read_json(path), path)
        validate(doc)
    except SchemaError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 1
    target.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
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
    if "findings.json" not in present:
        return problems
    try:
        doc = read_json(out / "findings.json")
        validate(doc, complete=True)
    except SchemaError as exc:
        return problems + [f"findings.json: {exc}"]
    findings = doc.get("findings", [])
    expected = [f"P-{i:03d}" for i in range(1, len(findings) + 1)]
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
    for b in doc.get("budgets", []):
        if b["status"] == "not checked" and "reason" not in b:
            problems.append(f"{b['id']}: a not-checked budget needs a reason")
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
