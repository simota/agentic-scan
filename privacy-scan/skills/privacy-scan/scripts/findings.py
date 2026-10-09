#!/usr/bin/env python3
"""Merge finding fragments into findings.json and check a run's output directory.

    python3 findings.py merge FINDINGS FRAGMENT [FRAGMENT ...]
    python3 findings.py check OUT_DIR [--allow NAME ...]

A fragment is a JSON file written with the host's file-write tool (never a
shell heredoc or a generated script). It holds any of these top-level keys:
`meta` is merged key by key; `findings` and `commitments` records are matched by
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

Findings describe where personal data goes, never the data itself: public
prose or evidence containing an e-mail address (other than the reserved
example domains) or a run of 12 or more digits is refused.
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
COMMITMENT_STATUSES = ("holds", "violated", "partly read", "not checked")
PERSPECTIVE_STATUSES = ("applied", "N/A", "not checked")
PERSPECTIVES = (
    "Data inventory and minimisation", "Purpose and consent", "Retention and deletion",
    "Data subject rights", "Third-party sharing", "Logs, telemetry and errors",
    "Exposure to other actors", "Storage protection", "Client-side tracking",
    "Identifiers and pseudonymisation", "Non-production and derived copies",
    "Location and transfers",
)
LISTS = ("checked_ok", "decisions", "limitations", "next_steps")
TOP_KEYS = {"meta", "findings", "commitments", "perspectives", *LISTS}
META_REQUIRED = ("project", "scope", "date", "assessor", "lang")
TEXT_FIELDS = ("title", "data", "subjects", "flow", "impact", "fix", "guard")
FINDING_REQUIRED = ("id", "severity", "confidence", "category", "location", "validation",
                    *TEXT_FIELDS)
OUTPUTS = {"findings.json", "dashboard.html", "report.md"}
FINDING_ID = re.compile(r"^PV-\d{3}$")
COMMITMENT_ID = re.compile(r"^C-\d{2,}$")
COMMIT_HASH = re.compile(r"[0-9a-fA-F]{4,64}\Z")
LOCATION = re.compile(r"^[^\s:]+(?::\d+(?:-\d+)?)$")
# Values that look like real personal data. Field names and placeholders such
# as `<email>` or `user@example.com` are fine; the value itself never is.
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)")
EXAMPLE_DOMAINS = re.compile(r"(?:^|\.)example\.(?:com|org|net)$|\.(?:example|test|invalid)$",
                             re.IGNORECASE)
LONG_NUMBER = re.compile(r"\d(?:[ -]?\d){11,}")


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


def _optional_strings(record, keys, where):
    for key in keys:
        if key in record and not isinstance(record[key], str):
            raise SchemaError(f"{where}.{key}: must be a string")


def _list(value, where):
    if not isinstance(value, list):
        raise SchemaError(f"{where}: must be a list")


def _choice(value, allowed, where):
    if value not in allowed:
        raise SchemaError(f"{where}: must be one of {', '.join(allowed)}")


def _no_personal_values(value, where):
    if value is None:
        return
    # Keep this guard safe for callers that have not checked the shape yet.
    value = str(value)
    for match in EMAIL.finditer(value):
        if not EXAMPLE_DOMAINS.search(match.group(1)):
            raise SchemaError(f"{where}: contains an e-mail address; name the field, not the value")
    if LONG_NUMBER.search(value):
        raise SchemaError(f"{where}: contains a long number shaped like personal data; use a placeholder")


def _check_prose(record, keys, where):
    """Check the schema's public text without scanning technical identifiers."""
    for key in keys:
        _no_personal_values(record.get(key), f"{where}.{key}")


def validate_finding(f, where):
    if not isinstance(f, dict):
        raise SchemaError(f"{where}: must be an object")
    for key in FINDING_REQUIRED:
        if key not in f:
            raise SchemaError(f"{where}: missing {key}")
    if not isinstance(f["id"], str) or not FINDING_ID.fullmatch(f["id"]):
        raise SchemaError(f"{where}.id: must look like PV-001")
    for key in TEXT_FIELDS:
        _text(f[key], f"{where}.{key}")
    _optional_strings(f, ("contrast", "commitment", "step"), where)
    _check_prose(f, (*TEXT_FIELDS, "contrast", "step"), where)
    commitment = f.get("commitment")
    if not isinstance(commitment, str) or not COMMITMENT_ID.fullmatch(commitment):
        _no_personal_values(commitment, f"{where}.commitment")
    _choice(f["severity"], SEVERITIES, f"{where}.severity")
    _choice(f["confidence"], CONFIDENCES, f"{where}.confidence")
    _choice(f["category"], PERSPECTIVES, f"{where}.category")
    _choice(f.get("status", "Open"), STATUSES, f"{where}.status")
    locations = f["location"] if isinstance(f["location"], list) else [f["location"]]
    if not locations:
        raise SchemaError(f"{where}.location: at least one path:line")
    for i, loc in enumerate(locations):
        if not isinstance(loc, str) or not LOCATION.fullmatch(loc):
            raise SchemaError(f"{where}.location[{i}]: must be path:line")
        # The parsed line range is technical metadata; the path can hold PII.
        _no_personal_values(loc.rsplit(":", 1)[0], f"{where}.location[{i}]")
    v = f["validation"]
    if not isinstance(v, dict):
        raise SchemaError(f"{where}.validation: must be an object")
    _choice(v.get("verdict"), VERDICTS, f"{where}.validation.verdict")
    _choice(v.get("method"), METHODS, f"{where}.validation.method")
    _optional_strings(v, ("evidence",), f"{where}.validation")
    _check_prose(v, ("evidence",), f"{where}.validation")
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
        _check_prose(a, ("tool", "command", "result"), f"{where}.analysis")
    references = f.get("references", [])
    _list(references, f"{where}.references")
    for i, ref in enumerate(references):
        if not isinstance(ref, dict):
            raise SchemaError(f"{where}.references[{i}]: must be an object")
        _text(ref.get("url"), f"{where}.references[{i}].url")
        _optional_strings(ref, ("title",), f"{where}.references[{i}]")
        _check_prose(ref, ("title", "url"), f"{where}.references[{i}]")


def validate(doc, complete=False):
    """Raise SchemaError when doc does not match reference/findings-schema.md."""
    if not isinstance(doc, dict):
        raise SchemaError("top level: must be an object")
    unknown = set(doc) - TOP_KEYS
    if unknown:
        raise SchemaError("top level: contains unknown keys")
    meta = doc.get("meta", {})
    if not isinstance(meta, dict):
        raise SchemaError("meta: must be an object")
    _optional_strings(meta, (*META_REQUIRED, "commit", "method"), "meta")
    if complete:
        for key in META_REQUIRED:
            _text(meta.get(key), f"meta.{key}")
    if "lang" in meta:
        _choice(meta["lang"], ("ja", "en"), "meta.lang")
    _check_prose(meta, ("project", "scope", "date", "assessor", "method"), "meta")
    commit = meta.get("commit")
    # Numeric hexadecimal revisions are valid too; arbitrary commit prose is not exempt.
    if not isinstance(commit, str) or not COMMIT_HASH.fullmatch(commit):
        _no_personal_values(commit, "meta.commit")
    for key in ("findings", "commitments", "perspectives"):
        _list(doc.get(key, []), key)
    seen = set()
    for i, f in enumerate(doc.get("findings", [])):
        validate_finding(f, f"findings[{i}]")
        if f["id"] in seen:
            raise SchemaError(f"findings[{i}].id: duplicate id")
        seen.add(f["id"])
    for i, r in enumerate(doc.get("commitments", [])):
        where = f"commitments[{i}]"
        if (not isinstance(r, dict) or not isinstance(r.get("id"), str)
                or not COMMITMENT_ID.fullmatch(r["id"])):
            raise SchemaError(f"{where}.id: must look like C-01")
        for key in ("statement", "source"):
            _text(r.get(key), f"{where}.{key}")
        _optional_strings(r, ("reason", "family"), where)
        if "inferred" in r and not isinstance(r["inferred"], bool):
            raise SchemaError(f"{where}.inferred: must be a boolean")
        _choice(r.get("status"), COMMITMENT_STATUSES, f"{where}.status")
        _check_prose(r, ("statement", "source", "reason"), where)
    for i, p in enumerate(doc.get("perspectives", [])):
        where = f"perspectives[{i}]"
        if not isinstance(p, dict):
            raise SchemaError(f"{where}: must be an object")
        _choice(p.get("name"), PERSPECTIVES, f"{where}.name")
        _choice(p.get("status"), PERSPECTIVE_STATUSES, f"{where}.status")
        _text(p.get("note"), f"{where}.note")
        _check_prose(p, ("note",), where)
    for key in LISTS:
        values = doc.get(key, [])
        _list(values, key)
        for i, value in enumerate(values):
            _text(value, f"{key}[{i}]")
            _no_personal_values(value, f"{key}[{i}]")


def _merge_records(current, incoming, where):
    _list(current, where)
    ids = [r.get("id") if isinstance(r, dict) else None for r in incoming]
    if any(not isinstance(value, str) for value in ids) or len(set(ids)) != len(ids):
        raise SchemaError(f"{where}: every record needs a unique string id")
    if any(not isinstance(r, dict) or not isinstance(r.get("id"), str) for r in current):
        raise SchemaError(f"{where}: existing records need string ids")
    index = {r["id"]: r for r in current}
    for record in incoming:
        if record["id"] in index:
            index[record["id"]].update(record)
        else:
            current.append(dict(record))
            index[record["id"]] = current[-1]


def merge(doc, fragment, where):
    if not isinstance(doc, dict):
        raise SchemaError("top level: must be an object")
    if not isinstance(fragment, dict):
        raise SchemaError(f"{where}: must be an object")
    unknown = set(fragment) - TOP_KEYS
    if unknown:
        raise SchemaError(f"{where}: contains unknown keys")
    if "meta" in fragment:
        if not isinstance(fragment["meta"], dict):
            raise SchemaError(f"{where}.meta: must be an object")
        target = doc.setdefault("meta", {})
        if not isinstance(target, dict):
            raise SchemaError("meta: must be an object")
        target.update(fragment["meta"])
    for key in ("findings", "commitments", "perspectives"):
        if key not in fragment:
            continue
        _list(fragment[key], f"{where}.{key}")
        if key == "perspectives":
            current = doc.get(key, [])
            _list(current, key)
            for records, prefix in ((current, key), (fragment[key], f"{where}.{key}")):
                for i, p in enumerate(records):
                    if not isinstance(p, dict):
                        raise SchemaError(f"{prefix}[{i}]: must be an object")
                    _choice(p.get("name"), PERSPECTIVES, f"{prefix}[{i}].name")
            names = {p["name"] for p in fragment[key]}
            doc[key] = [q for q in current if q["name"] not in names]
            doc[key].extend(fragment[key])
        else:
            _merge_records(doc.setdefault(key, []), fragment[key], f"{where}.{key}")
    for key in LISTS:
        if key in fragment:
            _list(fragment[key], f"{where}.{key}")
            target = doc.setdefault(key, [])
            _list(target, key)
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
    expected = [f"PV-{i:03d}" for i in range(1, len(findings) + 1)]
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
    for r in doc.get("commitments", []):
        if r["status"] == "not checked" and "reason" not in r:
            problems.append(f"{r['id']}: a not-checked commitment needs a reason")
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
