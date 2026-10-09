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
FINDINGS is created when absent. The record must pass the schema check
(`reference/findings-schema.md`) after every fragment before anything is
written. A merge never removes a key.
Run merges to the same FINDINGS sequentially; atomic replacement does not
detect concurrent updates.

`check` is the run contract: the output directory holds exactly
`findings.json`, `dashboard.html` and `report.md` (plus `--allow` names), the
required outputs are readable nonempty regular files, the record is complete,
IDs are gapless in severity order and every perspective in
`reference/perspectives.md` is recorded.

Exit codes: 0 ok, 1 a fragment was refused, the input was unreadable or the
contract failed (reasons on stderr), 2 a command-line usage error.
"""
import argparse
import errno
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import tempfile

SEVERITIES = ("High", "Medium", "Low", "Info")
CONFIDENCES = ("Confirmed", "Environment-dependent", "Suspected")
VERDICTS = ("Valid", "Likely", "Unverified", "Unlikely", "FalsePositive", "NotApplicable")
DEFINITIVE = ("Valid", "FalsePositive", "NotApplicable")
EXCLUDED = ("FalsePositive", "NotApplicable")
METHODS = ("static", "measured")
STATUSES = ("Open", "Fixed", "Accepted")
BUDGET_FAMILIES = ("QRY", "SIZE", "CPLX", "LAT", "RES", "FE")
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
FINDING_ID = re.compile(r"P-[0-9]{3}")
BUDGET_ID = re.compile(r"B-[0-9]{2,}")
# Evidence for a definitive verdict cites at least one path:line (or path#L42).
CITATION = re.compile(r"([^\s:：#()\[\]'\"`,;<>]+)(?:[:：]|#L)[1-9][0-9]*")
LOCATION = re.compile(r"(?P<path>[^\r\n]+):(?P<start>[0-9]+)(?:-(?P<end>[0-9]+))?")


class SchemaError(ValueError):
    pass


def cites_location(text):
    """True when text names a file position, not a URL port, a time or a ratio."""
    for match in CITATION.finditer(text):
        path = match.group(1)
        if "//" in path or path.isdigit():
            continue
        # A file has an extension, a directory part, or a conventional name (Makefile).
        if (re.search(r"\.[A-Za-z0-9]+$", path) or "/" in path or "\\" in path
                or re.fullmatch(r"[A-Z][A-Za-z]*file", path)):
            return True
    return False


def resolve_path(path):
    """Resolve symbolic links, reporting a loop as an I/O error on every Python version.

    Python 3.12 and earlier raise RuntimeError; 3.13+ return the looping link
    itself, which would otherwise look like an absent file and be replaced.
    """
    try:
        resolved = Path(path).resolve()
    except RuntimeError as exc:
        raise OSError(f"cannot resolve {path}: {exc}") from exc
    if resolved.is_symlink():
        raise OSError(errno.ELOOP, f"cannot resolve {path}: symbolic link loop")
    return resolved


def file_mode(path):
    """Return st_mode, or None when the path does not exist; other errors propagate."""
    try:
        return path.stat().st_mode
    except FileNotFoundError:
        return None


def _unique_object(pairs):
    """Reject ambiguous members before the decoder can discard earlier values."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object member: {key!r}")
        result[key] = value
    return result


def _reject_constant(token):
    raise ValueError(f"non-finite JSON numeric constant: {token}")


def _finite_float(token):
    value = float(token)
    if not math.isfinite(value):
        raise ValueError(f"JSON number exceeds the finite floating-point range: {token}")
    return value


def read_json(path):
    """Read unambiguous UTF-8 JSON from a regular file, following symbolic links."""
    try:
        source = Path(path)
        if not stat.S_ISREG(source.stat().st_mode):
            raise ValueError("input must be a regular file")
        return json.loads(source.read_text(encoding="utf-8"),
                          object_pairs_hook=_unique_object,
                          parse_constant=_reject_constant, parse_float=_finite_float)
    except (OSError, ValueError, RecursionError) as exc:
        raise SchemaError(f"{path}: {exc}") from exc


def _text(value, where):
    if not isinstance(value, str) or not value.strip():
        raise SchemaError(f"{where}: must be a nonblank string")


def _optional_strings(record, keys, where):
    for key in keys:
        if key in record and not isinstance(record[key], str):
            raise SchemaError(f"{where}.{key}: must be a string")


def _show(value, limit=80):
    """Quote a value for an error message without dumping a huge or nested input."""
    text = repr(value)
    return text if len(text) <= limit else text[:limit - 3] + "..."


def _choice(value, allowed, where):
    if value not in allowed:
        raise SchemaError(f"{where}: {_show(value)} is not one of {', '.join(allowed)}")


def validate_finding(f, where):
    if not isinstance(f, dict):
        raise SchemaError(f"{where}: must be an object")
    for key in FINDING_REQUIRED:
        if key not in f:
            raise SchemaError(f"{where}: missing {key}")
    if not isinstance(f["id"], str) or not FINDING_ID.fullmatch(f["id"]):
        raise SchemaError(f"{where}.id: {_show(f['id'])} must look like P-001")
    for key in ("title", "workload", "scale_driver", "cost_model", "request",
                "impact", "fix", "regression_test"):
        _text(f[key], f"{where}.{key}")
    _optional_strings(f, ("contrast", "budget", "step"), where)
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
            raise SchemaError(f"{where}.location: {_show(loc)} must be path:line")
        # Compare decimal strings without Python's integer-conversion digit limit.
        start = match["start"].lstrip("0") or "0"
        end = (match["end"] or match["start"]).lstrip("0") or "0"
        if start == "0" or (len(end), end) < (len(start), start):
            raise SchemaError(f"{where}.location: {_show(loc)} needs positive line numbers "
                              "and a range end not before its start")
    v = f["validation"]
    if not isinstance(v, dict):
        raise SchemaError(f"{where}.validation: must be an object")
    _choice(v.get("verdict"), VERDICTS, f"{where}.validation.verdict")
    _choice(v.get("method"), METHODS, f"{where}.validation.method")
    if v["verdict"] in DEFINITIVE:
        _text(v.get("evidence"), f"{where}.validation.evidence ({v['verdict']} needs evidence)")
    else:
        _optional_strings(v, ("evidence",), f"{where}.validation")
    if v["method"] == "measured" and "measurement" not in f:
        raise SchemaError(f"{where}.measurement: required when validation.method is measured")
    if "measurement" in f:
        m = f["measurement"]
        if not isinstance(m, dict):
            raise SchemaError(f"{where}.measurement: must be an object")
        for key in ("environment", "command", "result"):
            _text(m.get(key), f"{where}.measurement.{key}")
    references = f.get("references", [])
    if not isinstance(references, list):
        raise SchemaError(f"{where}.references: must be a list")
    for i, ref in enumerate(references):
        if not isinstance(ref, dict):
            raise SchemaError(f"{where}.references[{i}]: must be an object")
        _text(ref.get("url"), f"{where}.references[{i}].url")
        _optional_strings(ref, ("title",), f"{where}.references[{i}]")


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
    for key in META_REQUIRED:
        if complete or key in meta:
            _text(meta.get(key), f"meta.{key}")
    if "lang" in meta:
        _choice(meta["lang"], ("ja", "en"), "meta.lang")
    _optional_strings(meta, ("commit", "method"), "meta")
    for key in ("findings", "budgets", "perspectives"):
        if not isinstance(doc.get(key, []), list):
            raise SchemaError(f"{key}: must be a list")
    seen = set()
    for i, f in enumerate(doc.get("findings", [])):
        try:
            validate_finding(f, f"findings[{i}]")
        except SchemaError as exc:
            # After a merge the index is the combined record's, not the fragment's.
            if (isinstance(f, dict) and isinstance(f.get("id"), str)
                    and not str(exc).startswith(f"findings[{i}].id:")):
                raise SchemaError(f"{exc} (finding {_show(f['id'])})") from exc
            raise
        if f["id"] in seen:
            raise SchemaError(f"findings[{i}].id: duplicate {f['id']}")
        seen.add(f["id"])
    seen = set()
    for i, b in enumerate(doc.get("budgets", [])):
        where = f"budgets[{i}]"
        if (not isinstance(b, dict) or not isinstance(b.get("id"), str)
                or not BUDGET_ID.fullmatch(b["id"])):
            raise SchemaError(f"{where}.id: must look like B-01")
        if b["id"] in seen:
            raise SchemaError(f"{where}.id: duplicate {b['id']}")
        seen.add(b["id"])
        for key in ("statement", "source"):
            _text(b.get(key), f"{where}.{key}")
        if "inferred" in b and not isinstance(b["inferred"], bool):
            raise SchemaError(f"{where}.inferred: must be a boolean")
        _optional_strings(b, ("reason",), where)
        if "family" in b:
            _choice(b["family"], BUDGET_FAMILIES, f"{where}.family")
        _choice(b.get("status"), BUDGET_STATUSES, f"{where}.status")
    seen = set()
    for i, p in enumerate(doc.get("perspectives", [])):
        where = f"perspectives[{i}]"
        if not isinstance(p, dict):
            raise SchemaError(f"{where}: must be an object")
        _choice(p.get("name"), PERSPECTIVES, f"{where}.name")
        if p["name"] in seen:
            raise SchemaError(f"{where}.name: duplicate {p['name']}")
        seen.add(p["name"])
        _choice(p.get("status"), PERSPECTIVE_STATUSES, f"{where}.status")
        _text(p.get("note"), f"{where}.note")
    for key in LISTS:
        values = doc.get(key, [])
        if not isinstance(values, list):
            raise SchemaError(f"{key}: must be a list")
        for i, value in enumerate(values):
            _text(value, f"{key}[{i}]")


def _record_identity(record, key, where):
    if not isinstance(record, dict):
        raise SchemaError(f"{where}: must be an object")
    value = record.get(key)
    _text(value, f"{where}.{key}")
    return value


def _merge_records(current, incoming, key, where):
    ids = [_record_identity(record, key, f"{where}[{i}]")
           for i, record in enumerate(incoming)]
    if len(set(ids)) != len(ids):
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
                for i, p in enumerate(fragment[key]):
                    name = _record_identity(p, match, f"{where}.{key}[{i}]")
                    doc.setdefault(key, [])
                    doc[key] = [q for q in doc[key] if q.get("name") != name]
                    doc[key].append(p)
            else:
                _merge_records(doc.setdefault(key, []), fragment[key], match, f"{where}.{key}")
    for key in LISTS:
        if key in fragment:
            if not isinstance(fragment[key], list):
                raise SchemaError(f"{where}.{key}: must be a list")
            target = doc.setdefault(key, [])
            seen = set(target)  # A list scan per item made large merges quadratic.
            for i, value in enumerate(fragment[key]):
                _text(value, f"{where}.{key}[{i}]")
                if value not in seen:
                    seen.add(value)
                    target.append(value)
    return doc


def write_atomic(target, content):
    """Replace a resolved target only after all bytes have been written and closed."""
    mode = file_mode(target)
    mode = None if mode is None else stat.S_IMODE(mode)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="wb", dir=target.parent,
                                         prefix=f".{target.name}.", suffix=".tmp",
                                         delete=False) as output:
            temporary = Path(output.name)
            output.write(content)
        if mode is not None:
            temporary.chmod(mode)
        os.replace(temporary, target)
        temporary = None
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError as exc:
                print(f"cleanup: {temporary}: {exc}", file=sys.stderr)


def cmd_merge(args):
    target = Path(args.findings)
    try:
        # Keep the existing behavior of reading and updating a symlink's destination.
        destination = resolve_path(target)
        doc = read_json(destination) if file_mode(destination) is not None else {}
        try:
            validate(doc)
        except SchemaError as exc:
            raise SchemaError(f"{target}: {exc}") from exc
        for path in args.fragments:
            merge(doc, read_json(path), path)
            # Validate per fragment: a finding must be complete where it first appears.
            try:
                validate(doc)
            except SchemaError as exc:
                raise SchemaError(f"{path}: {exc}") from exc
        content = (json.dumps(doc, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        write_atomic(destination, content)
    except (SchemaError, OSError, UnicodeError, RecursionError) as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 1
    print(f"merged {len(args.fragments)} fragment(s) into {target}: "
          f"{len(doc.get('findings', []))} finding(s)")
    return 0


def contract_problems(out, allow=()):
    """Return the run-contract violations for an output directory."""
    out = Path(out)
    problems = []
    try:
        if not out.is_dir():
            return [f"not a directory: {out}"]
        present = {p.name for p in out.iterdir()}
    except OSError as exc:
        return [f"cannot inspect output directory: {out}: {exc}"]
    for name in sorted(OUTPUTS - present):
        problems.append(f"missing output: {name}")
    for name in sorted(present - OUTPUTS - set(allow)):
        problems.append(f"unexpected output: {name} (pass --allow {name} if requested)")
    readable = set()
    for name in sorted(OUTPUTS & present):
        path = out / name
        try:
            # Follow valid symlinks, but never open a FIFO or device as a report.
            if not stat.S_ISREG(path.stat().st_mode):
                problems.append(f"invalid output: {name} (must be a regular file)")
                continue
            with path.open("rb") as source:
                if not source.read(1):
                    problems.append(f"empty output: {name}")
                    continue
        except OSError as exc:
            problems.append(f"unreadable output: {name}: {exc}")
            continue
        readable.add(name)
    if "findings.json" not in readable:
        return problems
    try:
        doc = read_json(out / "findings.json")
        validate(doc, complete=True)
        # A "\ud800" escape decodes to a lone surrogate that render cannot encode.
        json.dumps(doc, ensure_ascii=False).encode("utf-8")
    except (SchemaError, UnicodeError) as exc:
        return problems + [f"findings.json: {exc}"]
    findings = doc.get("findings", [])
    expected = [f"P-{i:03d}" for i in range(1, len(findings) + 1)]
    if [f["id"] for f in findings] != expected:
        problems.append(f"IDs must be gapless in order: expected {', '.join(expected) or 'none'}")
    included = [f for f in findings if f["validation"]["verdict"] not in EXCLUDED]
    for before, after in zip(included, included[1:]):
        if SEVERITIES.index(after["severity"]) < SEVERITIES.index(before["severity"]):
            problems.append("findings must be numbered in severity order (High first): "
                            f"{after['id']} ({after['severity']}) follows "
                            f"{before['id']} ({before['severity']})")
            break
    seen_excluded = None
    for f in findings:
        if f["validation"]["verdict"] in EXCLUDED:
            seen_excluded = seen_excluded or f["id"]
        elif seen_excluded:
            problems.append(f"{f['id']}: excluded findings ({seen_excluded}) must be numbered "
                            "after all others")
            break
    for f in findings:
        v = f["validation"]
        if v["verdict"] in DEFINITIVE and not cites_location(v["evidence"]):
            problems.append(f"{f['id']}.validation.evidence: {v['verdict']} evidence must "
                            "cite a path:line")
        if f["confidence"] == "Suspected" and v["verdict"] == "Valid":
            problems.append(f"{f['id']}: a Suspected finding cannot be Valid; confirm the "
                            "code link (Confirmed or Environment-dependent) or record Likely")
    recorded = {p["name"] for p in doc.get("perspectives", [])}
    for name in PERSPECTIVES:
        if name not in recorded:
            problems.append(f"perspective not recorded: {name}")
    budget_ids = set()
    for b in doc.get("budgets", []):
        budget_ids.add(b["id"])
        if b["status"] == "not checked" and not b.get("reason", "").strip():
            problems.append(f"{b['id']}: a not-checked budget needs a reason")
    holding = {b["id"] for b in doc.get("budgets", []) if b["status"] == "holds"}
    for f in findings:
        budget = f.get("budget", "")
        if budget.strip() and budget not in budget_ids:
            problems.append(f"{f['id']}.budget: {_show(budget)} is not in budgets")
        elif (budget in holding and f.get("status", "Open") != "Fixed"
              and f["validation"]["verdict"] == "Valid"):
            problems.append(f"{budget}: status holds, but {f['id']} is a Valid, unfixed "
                            "violation of it")
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
