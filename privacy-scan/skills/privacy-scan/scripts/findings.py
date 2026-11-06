#!/usr/bin/env python3
"""Merge finding fragments into findings.json and check a run's output directory.

    python3 findings.py merge FINDINGS FRAGMENT [FRAGMENT ...]
    python3 findings.py renumber FINDINGS
    python3 findings.py counts FINDINGS
    python3 findings.py diff OLD NEW [--json] [--lang ja|en]
    python3 findings.py check OUT_DIR [--allow NAME]...   (one --allow per name)

A fragment is a JSON file written with the host's file-write tool (never a
shell heredoc or a generated script). It holds any of these top-level keys:
`meta` is merged key by key; `findings` and `commitments` records are matched by
`id`, a known record updated key by key and a new one appended; `perspectives`
are matched by `name` and replaced whole; the string lists (`checked_ok`,
`decisions`, `limitations`, `next_steps`) are appended without duplicates.
Nested `validation` and `analysis` objects of a known finding also merge key by
key. FINDINGS is created when absent (its directory must exist). The record merged
from all the fragments must pass the schema check (`reference/findings-schema.md`)
before anything is written.

`renumber` numbers findings PV-001… in severity order, then path (excluded
findings last), and rewrites `PV-NNN` references in IDs and prose (never in
locations, commitment sources, URLs, also those written in prose, commands or
revisions). Run it after the last merge; IDs
change, so read them back before writing another fragment.

`diff` compares an earlier assessment's record with the current one and prints
new, reopened, resolved and persisting findings, active counts by severity and
commitment status changes, as Markdown (or JSON with `--json`). IDs change
between runs, so findings are matched by perspective, location and title
(`scripts/compare.py`); each pair names how it was matched.

`check` is the run contract; its complete rule list is in
`reference/findings-schema.md`.

Exit codes: 0 ok, 1 a fragment was refused, the input was unreadable or the
contract failed (reasons on stderr), 2 the command line is invalid.

Findings describe where personal data goes, never the data itself: public
prose or evidence containing an e-mail address (other than the reserved
example domains) or a run of 12 or more digits is refused.

The personal-value guard and its full rules are in `scripts/personal_values.py`.
"""
import argparse
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys
import threading

# Keep source-only CLI runs from writing imported helpers into the skill tree.
sys.dont_write_bytecode = True


def _import_sibling(name):
    """Import a helper beside this script, even in isolated (-I) or -P runs."""
    here = str(Path(__file__).resolve().parent)
    if here not in sys.path:
        sys.path.insert(0, here)
    return __import__(name)


write_utf8_files = _import_sibling("output_io").write_utf8_files
personal_values = _import_sibling("personal_values")

SEVERITIES = ("High", "Medium", "Low", "Info")
CONFIDENCES = ("Confirmed", "Environment-dependent", "Suspected")
VERDICTS = ("Valid", "Likely", "Unverified", "Unlikely", "FalsePositive", "NotApplicable")
DEFINITIVE = ("Valid", "FalsePositive", "NotApplicable")
EXCLUDED = ("FalsePositive", "NotApplicable")
METHODS = ("static", "analysed")
STATUSES = ("Open", "Fixed", "Accepted")
COMMITMENT_STATUSES = ("holds", "violated", "partly read", "not checked")
PERSPECTIVE_STATUSES = ("applied", "partly applied", "N/A", "not checked")
# A finding may sit under a perspective that was applied in full or in part.
APPLIED = ("applied", "partly applied")
PERSPECTIVES = (
    "Data inventory and minimisation", "Purpose and consent", "Retention and deletion",
    "Data subject rights", "Third-party sharing", "Logs, telemetry and errors",
    "Exposure to other actors", "Storage protection", "Client-side tracking",
    "Identifiers and pseudonymisation", "Non-production and derived copies",
    "Location and transfers",
)
# Hunt-step prefixes per perspective (reference/perspectives.md headings).
STEP_PREFIXES = dict(zip(PERSPECTIVES, ("MN", "PC", "RD", "DR", "TP", "LT", "EX", "SP", "CT",
                                         "ID", "NP", "LO")))
# Hunt steps per perspective, numbered from 1 (the rows of each hunt table).
STEP_COUNTS = dict(zip(PERSPECTIVES, (4, 4, 3, 4, 6, 4, 6, 2, 3, 2, 3, 2)))
STEP_ID = re.compile(r"([A-Z]{2})([1-9]\d{0,2})")
LISTS = ("checked_ok", "decisions", "limitations", "next_steps")
TOP_KEYS = {"meta", "findings", "commitments", "perspectives", *LISTS}
META_REQUIRED = ("project", "scope", "date", "assessor", "lang")
META_KEYS = {*META_REQUIRED, "commit", "method"}
TEXT_FIELDS = ("title", "data", "subjects", "flow", "impact", "fix", "guard")
# A finding excluded as FalsePositive or NotApplicable needs no remedy.
ACTION_FIELDS = ("fix", "guard")
FINDING_REQUIRED = ("id", "severity", "confidence", "category", "location", "validation",
                    *TEXT_FIELDS)
FINDING_KEYS = {*FINDING_REQUIRED, "step", "contrast", "commitment", "analysis", "conditions",
                "status", "references"}
VALIDATION_KEYS = {"verdict", "method", "evidence"}
ANALYSIS_KEYS = {"tool", "command", "result"}
REFERENCE_KEYS = {"title", "url"}
COMMITMENT_KEYS = {"id", "statement", "source", "status", "family", "inferred", "reason"}
PERSPECTIVE_KEYS = {"name", "status", "note"}
OUTPUTS = {"findings.json", "dashboard.html", "report.md"}
# IDs and line numbers are ASCII digits; Unicode `\d` would also accept
# Arabic-Indic or full-width digits that no source line or ledger uses.
FINDING_ID = re.compile(r"^PV-[0-9]{3}$")
# Bounded so a long digit run cannot pass as an exempt technical identifier.
COMMITMENT_ID = re.compile(r"^C-[0-9]{2,6}$")
# ASCII boundaries: Japanese prose writes IDs flush against kana and kanji
# ("C-01の"), which `\w` would count as part of a longer word. Any digits
# count here, so a citation in other digits is reported as missing from the ledger.
COMMITMENT_REF = re.compile(r"(?<![A-Za-z0-9_-])C-\d{2,6}(?![A-Za-z0-9_-])")
COMMIT_HASH = re.compile(r"[0-9a-fA-F]{4,64}\Z")
# Spaces are valid in source paths; control characters and line breaks are not.
LOCATION = re.compile(r"^[^:\x00-\x1f\x7f-\x9f\u2028\u2029]+:[0-9]{1,9}(?:-[0-9]{1,9})?$")


class SchemaError(ValueError):
    pass


# Records and fragments are small; anything larger is not one of them.
MAX_INPUT_BYTES = 16 * 1024 * 1024


def read_limited(path, limit=MAX_INPUT_BYTES):
    """Read a regular file of at most `limit` bytes; never block on FIFOs or devices."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise SchemaError(f"{path}: must be a regular file")
        if info.st_size > limit:
            raise SchemaError(f"{path}: larger than {limit // (1024 * 1024)} MiB")
        # Size the read by the file, not the limit: reading `limit + 1` at once
        # reserves a 16 MiB buffer for every record. A file that grew since
        # fstat is read on, up to the same `limit + 1` bytes in total.
        data = stream.read(info.st_size + 1)
        if len(data) > info.st_size:
            data += stream.read(limit + 1 - len(data))
    if len(data) > limit:
        raise SchemaError(f"{path}: larger than {limit // (1024 * 1024)} MiB")
    return data


def read_json(path):
    try:
        return json.loads(read_limited(path).decode("utf-8"))
    except SchemaError:
        raise
    except UnicodeDecodeError as exc:
        raise SchemaError(f"{path}: must contain UTF-8 JSON") from exc
    except OSError as exc:
        raise SchemaError(f"{path}: {exc.strerror or type(exc).__name__}") from exc
    except json.JSONDecodeError as exc:
        raise SchemaError(f"{path}: {exc}") from exc
    except (ValueError, RecursionError) as exc:
        # Over-long integers and deep nesting are refused, not tracebacks.
        raise SchemaError(f"{path}: not usable JSON ({type(exc).__name__})") from None


def _utf8(value, where):
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise SchemaError(f"{where}: must contain valid Unicode characters") from None


def _text(value, where):
    if not isinstance(value, str) or not value.strip():
        raise SchemaError(f"{where}: must be a nonblank string")
    _utf8(value, where)


def _object(value, allowed, where):
    if not isinstance(value, dict):
        raise SchemaError(f"{where}: must be an object")
    if set(value) - allowed:
        # Unknown keys can themselves contain personal values.
        raise SchemaError(f"{where}: unknown fields are not allowed")


def _list(value, where):
    if not isinstance(value, list):
        raise SchemaError(f"{where}: must be a list")


def _optional_strings(record, keys, where):
    for key in keys:
        if key in record:
            if not isinstance(record[key], str):
                raise SchemaError(f"{where}.{key}: must be a string when present")
            _utf8(record[key], f"{where}.{key}")


def _id(value, pattern, example, where):
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise SchemaError(f"{where}: must look like {example}")


def _choice(value, allowed, where):
    if not isinstance(value, str) or value not in allowed:
        raise SchemaError(f"{where}: must be one of {', '.join(allowed)}")


def _no_personal_values(value, where):
    """Refuse text the personal-value guard flags, naming the field."""
    reason = personal_values.find(value)
    if reason:
        raise SchemaError(f"{where}: {reason}")


def _check_prose(record, keys, where):
    """Check the schema's public text without scanning technical identifiers."""
    for key in keys:
        _no_personal_values(record.get(key), f"{where}.{key}")


def _check_reference_url(value, where):
    """Inspect raw and decoded URL values without changing the saved spelling."""
    reason = personal_values.find_in_url(value)
    if reason:
        raise SchemaError(f"{where}: {reason}")


def validate_finding(f, where):
    _object(f, FINDING_KEYS, where)
    v = f.get("validation")
    excluded = isinstance(v, dict) and v.get("verdict") in EXCLUDED
    optional = ACTION_FIELDS if excluded else ()
    for key in FINDING_REQUIRED:
        if key not in f and key not in optional:
            raise SchemaError(f"{where}: missing {key}")
    _id(f["id"], FINDING_ID, "PV-001", f"{where}.id")
    for key in TEXT_FIELDS:
        if key in f or key not in optional:
            _text(f[key], f"{where}.{key}")
    _optional_strings(f, ("contrast", "step", "commitment", "conditions"), where)
    _check_prose(f, (*TEXT_FIELDS, "contrast", "step", "conditions"), where)
    commitment = f.get("commitment")
    if not isinstance(commitment, str) or not COMMITMENT_ID.fullmatch(commitment):
        _no_personal_values(commitment, f"{where}.commitment")
    _choice(f["severity"], SEVERITIES, f"{where}.severity")
    _choice(f["confidence"], CONFIDENCES, f"{where}.confidence")
    _choice(f["category"], PERSPECTIVES, f"{where}.category")
    _choice(f.get("status", "Open"), STATUSES, f"{where}.status")
    written = f["location"] if isinstance(f["location"], list) else [f["location"]]
    if not written:
        raise SchemaError(f"{where}.location: at least one path:line")
    for i, loc in enumerate(written):
        if not isinstance(loc, str) or not LOCATION.fullmatch(loc):
            raise SchemaError(f"{where}.location[{i}]: must be path:line")
        # The parsed line range is technical metadata; the path can hold PII.
        path = loc.rsplit(":", 1)[0]
        _text(path, f"{where}.location[{i}]")
        _no_personal_values(personal_values.PATH_TIMESTAMP.sub("#", path), f"{where}.location[{i}]")
    v = f["validation"]
    _object(v, VALIDATION_KEYS, f"{where}.validation")
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
        _object(a, ANALYSIS_KEYS, f"{where}.analysis")
        for key in ("tool", "command", "result"):
            _text(a.get(key), f"{where}.analysis.{key}")
        _check_prose(a, ("tool", "command", "result"), f"{where}.analysis")
    references = f.get("references", [])
    _list(references, f"{where}.references")
    for i, ref in enumerate(references):
        _object(ref, REFERENCE_KEYS, f"{where}.references[{i}]")
        _text(ref.get("url"), f"{where}.references[{i}].url")
        _optional_strings(ref, ("title",), f"{where}.references[{i}]")
        _check_prose(ref, ("title",), f"{where}.references[{i}]")
        _check_reference_url(ref["url"], f"{where}.references[{i}].url")


def validate(doc, complete=False):
    """Raise SchemaError when doc does not match reference/findings-schema.md."""
    _object(doc, TOP_KEYS, "top level")
    meta = doc.get("meta", {})
    _object(meta, META_KEYS, "meta")
    _optional_strings(meta, META_KEYS, "meta")
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
            raise SchemaError(f"findings[{i}].id: must be unique")
        seen.add(f["id"])
    seen = set()
    for i, r in enumerate(doc.get("commitments", [])):
        where = f"commitments[{i}]"
        _object(r, COMMITMENT_KEYS, where)
        _id(r.get("id"), COMMITMENT_ID, "C-01", f"{where}.id")
        if r["id"] in seen:
            raise SchemaError(f"{where}.id: must be unique")
        seen.add(r["id"])
        for key in ("statement", "source"):
            _text(r.get(key), f"{where}.{key}")
        _choice(r.get("status"), COMMITMENT_STATUSES, f"{where}.status")
        _optional_strings(r, ("family", "reason"), where)
        if "inferred" in r and not isinstance(r["inferred"], bool):
            raise SchemaError(f"{where}.inferred: must be a boolean when present")
        _check_prose(r, ("statement", "source", "reason", "family"), where)
    seen = set()
    for i, p in enumerate(doc.get("perspectives", [])):
        where = f"perspectives[{i}]"
        _object(p, PERSPECTIVE_KEYS, where)
        _choice(p.get("name"), PERSPECTIVES, f"{where}.name")
        if p["name"] in seen:
            raise SchemaError(f"{where}.name: must be unique")
        seen.add(p["name"])
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
    for records in (current, incoming):
        _list(records, where)
        ids = [r.get("id") if isinstance(r, dict) else None for r in records]
        if any(not isinstance(rid, str) for rid in ids) or len(set(ids)) != len(ids):
            raise SchemaError(f"{where}: every record needs a unique string id")
    index = {r["id"]: r for r in current}
    for record in incoming:
        if record["id"] in index:
            known = index[record["id"]]
            for key, value in record.items():
                # Nested objects (validation, analysis) merge key by key too,
                # so a later fragment can change just a verdict.
                if isinstance(value, dict) and isinstance(known.get(key), dict):
                    known[key] = {**known[key], **value}
                else:
                    known[key] = value
        else:
            current.append(dict(record))
            index[record["id"]] = current[-1]


def merge(doc, fragment, where):
    _object(doc, TOP_KEYS, "existing record")
    _object(fragment, TOP_KEYS, where)
    if "meta" in fragment:
        _object(doc.get("meta", {}), META_KEYS, "meta")
        _object(fragment["meta"], META_KEYS, f"{where}.meta")
        doc.setdefault("meta", {}).update(fragment["meta"])
    for key in ("findings", "commitments", "perspectives"):
        if key not in fragment:
            continue
        _list(fragment[key], f"{where}.{key}")
        if key == "perspectives":
            _list(doc.get(key, []), key)
            for label, records in ((key, doc.get(key, [])), (f"{where}.{key}", fragment[key])):
                names = set()
                for i, p in enumerate(records):
                    at = f"{label}[{i}]"
                    _object(p, PERSPECTIVE_KEYS, at)
                    _choice(p.get("name"), PERSPECTIVES, f"{at}.name")
                    if p["name"] in names:
                        raise SchemaError(f"{at}.name: must be unique")
                    names.add(p["name"])
            doc[key] = [q for q in doc.get(key, []) if q.get("name") not in names]
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


NOT_REFERENCES = {"location", "url", "command", "commit", "source"}
# ASCII boundaries, as COMMITMENT_REF. A hyphen may join references
# (`PV-001-PV-003`) or a word (`PV-002-related`), but another prefix
# (`ACME-PV-001`) is a different identifier.
PV_REFERENCE = re.compile(r"(?<![A-Za-z0-9_])(?:(?<=PV-\d{3}-)|(?<!-))PV-\d{3}(?![A-Za-z0-9_])")
# URLs of any scheme written in prose are technical values too: `…/browse/PV-002`
# and `ftp://…/PV-002.pdf` keep their targets.
# Non-ASCII text belongs to the URL when a `/` or `.` follows it (`https://例.example/`,
# `/課題/`); otherwise it is prose run straight on after the URL (`…/aを参照、PV-002`).
# A scheme is tried only where a run of scheme characters starts, so a long
# word is read once rather than once per letter; leading digits, `+`, `.` or
# `-` (`1svn+ssh://`) join the match but hold no reference.
PROSE_URL = re.compile(r"(?:(?<![A-Za-z0-9+.-])[0-9+.-]*[A-Za-z][A-Za-z0-9+.-]*://|(?i:www\.))"
                       r"(?:[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]|[^\x00-\x7f\s]+(?=[/.]))+")
PV_OR_URL = re.compile(f"(?P<url>{PROSE_URL.pattern})|{PV_REFERENCE.pattern}")


def renumber(doc):
    """Number findings PV-001… in severity order and rewrite every PV- reference.

    Reported findings are ordered by severity, then by their first location's
    path; excluded findings follow them. Returns the old-to-new ID mapping.
    """
    ordered = sorted(doc.get("findings", []), key=order_key)
    mapping = {f["id"]: f"PV-{i:03d}" for i, f in enumerate(ordered, 1)}

    def rewrite(value, key=None):
        # Technical values (source paths, URLs, commands, revisions) may contain
        # text shaped like an ID; only IDs and prose are cross-references.
        if key in NOT_REFERENCES:
            return value
        if isinstance(value, str):
            return PV_OR_URL.sub(lambda m: m.group() if m.group("url")
                                 else mapping.get(m.group(), m.group()), value)
        if isinstance(value, list):
            return [rewrite(item) for item in value]
        if isinstance(value, dict):
            return {k: rewrite(item, k) for k, item in value.items()}
        return value

    doc.update(rewrite({**doc, "findings": ordered}))
    return {old: new for old, new in mapping.items() if old != new}


def cmd_renumber(args):
    target = Path(args.findings)
    try:
        doc = read_json(target)
        validate(doc)
        changed = renumber(doc)
        validate(doc)
    except SchemaError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 1
    try:
        write_utf8_files({target: json.dumps(doc, ensure_ascii=False, indent=2) + "\n"})
    except (OSError, UnicodeError) as exc:
        print(f"write failed: could not save renumbered record ({type(exc).__name__})", file=sys.stderr)
        return 1
    moves = ", ".join(f"{old} -> {new}" for old, new in changed.items()) or "no changes"
    print(f"renumbered {target}: {moves}")
    return 0


def counts(doc):
    """The counts the report templates use, derived from the record alone.

    Severity counts cover reported findings only (excluded ones are counted in
    `n_excluded`), matching the dashboard and report.md.
    """
    findings = doc.get("findings", [])
    reported = [f for f in findings if not excluded(f)]
    result = {}
    for severity in SEVERITIES:
        rows = [f for f in reported if f["severity"] == severity]
        result[f"n_{severity.lower()}"] = len(rows)
        result[f"n_{severity.lower()}_valid"] = sum(f["validation"]["verdict"] == "Valid" for f in rows)
    result["n_excluded"] = len(findings) - len(reported)
    for verdict in ("Likely", "Unverified", "Unlikely"):
        result[f"n_{verdict.lower()}"] = sum(f["validation"]["verdict"] == verdict for f in reported)
    return result


def cmd_counts(args):
    try:
        doc = read_json(args.findings)
        validate(doc)
    except SchemaError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(counts(doc), indent=2))
    return 0


def cmd_diff(args):
    try:
        old, new = read_json(args.old), read_json(args.new)
        validate(old, complete=True)
    except SchemaError as exc:
        print(f"refused: earlier record: {exc}", file=sys.stderr)
        return 1
    try:
        validate(new, complete=True)
    except SchemaError as exc:
        print(f"refused: current record: {exc}", file=sys.stderr)
        return 1
    compare = _import_sibling("compare")
    result = compare.compare(old, new)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        render = _import_sibling("render")  # render imports this module, so load it lazily
        print(compare.render_markdown(result, args.lang or new["meta"]["lang"], render.markdown_text,
                                     render.markdown_code),
              end="")
    return 0


def _record_exists(path):
    """Whether the record exists; a path that cannot be checked is refused."""
    try:
        return path.exists()
    except OSError as exc:  # too long, no search permission: not merely missing
        raise SchemaError(f"{path}: {exc.strerror or type(exc).__name__}") from None


def cmd_merge(args):
    target = Path(args.findings)
    try:
        doc = read_json(target) if _record_exists(target) else {}
        for path in args.fragments:
            merge(doc, read_json(path), path)
        validate(doc)
    except SchemaError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 1
    try:
        write_utf8_files({target: json.dumps(doc, ensure_ascii=False, indent=2) + "\n"})
    except (OSError, UnicodeError) as exc:
        print(f"write failed: could not save merged record ({type(exc).__name__})", file=sys.stderr)
        return 1
    print(f"merged {len(args.fragments)} fragment(s) into {target}: "
          f"{len(doc.get('findings', []))} finding(s)")
    return 0


def contract_problems(out, allow=()):
    """Return the run-contract violations for an output directory."""
    out = Path(out)
    problems = []
    try:
        present = {p.name for p in out.iterdir()} if out.is_dir() else set()
    except OSError:
        return ["output directory is not readable"]
    for name in sorted(OUTPUTS - present):
        problems.append(f"missing output: {name}")
    staging = _staging_files(out, present)
    for path in sorted(staging):
        shown = path.name if path.parent == out.resolve() else str(path)
        problems.append(f"stale staging file from an interrupted write: {shown} (delete it)")
    for name in sorted(present - OUTPUTS - set(allow)):
        try:
            resolved = (out / name).resolve()
        except (OSError, RuntimeError):  # symlink loops raise RuntimeError before 3.13
            resolved = None
        if resolved not in staging:
            problems.append(f"unexpected output: {name} (pass --allow {name} if requested)")
    unusable = set()
    for name in sorted(OUTPUTS & present):
        path = out / name
        try:
            if not path.is_file():
                problems.append(f"output is not a file: {name}")
                unusable.add(name)
                continue
            with path.open("rb") as stream:
                if not stream.read(1):
                    problems.append(f"empty output: {name}")
                    unusable.add(name)
        except OSError:
            problems.append(f"unreadable output: {name}")
            unusable.add(name)
    if "findings.json" not in present or "findings.json" in unusable:
        return problems
    try:
        doc = read_json(out / "findings.json")
        validate(doc, complete=True)
    except SchemaError as exc:
        return problems + [f"findings.json: {exc}"]
    return problems + record_problems(doc) + _stale_outputs(out, doc, unusable | (OUTPUTS - present))


def _staging_files(out, present):
    """Find leftover staging files beside each output's resolved destination.

    output_io stages `.NAME.<random>.tmp` next to the file it replaces, and a
    symlinked output is replaced at its target, possibly elsewhere or renamed.
    """
    found = set()
    for name in OUTPUTS:
        destinations = {out / name}
        if name in present:
            try:
                destinations.add((out / name).resolve())
            except (OSError, RuntimeError):
                pass
        for destination in destinations:
            prefix = f".{destination.name}."
            try:
                # Plain name matching: a target name may contain glob characters.
                candidates = [path for path in destination.parent.iterdir()
                              if path.name.startswith(prefix) and path.name.endswith(".tmp")
                              and len(path.name) > len(prefix) + len(".tmp")]
            except OSError:
                continue
            # output_io stages regular files, never links: a link named like one
            # is reported as an unexpected output, never its target for deletion.
            found.update(path.resolve() for path in candidates
                         if not path.is_symlink() and path.is_file())
    return found


def locations(f):
    """A finding's `location` as a list (a single `path:line` string is allowed)."""
    return f["location"] if isinstance(f["location"], list) else [f["location"]]


def excluded(f):
    return f["validation"]["verdict"] in EXCLUDED


def _first_path(f):
    return locations(f)[0].rsplit(":", 1)[0]


def order_key(f):
    """The run contract's order: reported findings by severity, then path;
    excluded findings last, by path. `renumber` and `check` share it."""
    return (excluded(f), 0 if excluded(f) else SEVERITIES.index(f["severity"]), _first_path(f))


def record_problems(doc):
    """Contract violations visible in a schema-valid record alone (no outputs needed)."""
    problems = []
    findings = doc.get("findings", [])
    expected = [f"PV-{i:03d}" for i in range(1, len(findings) + 1)]
    if [f["id"] for f in findings] != expected:
        problems.append(f"IDs must be gapless in order: expected {', '.join(expected) or 'none'}; "
                        "run scripts/findings.py renumber, then re-run scripts/render.py")
    keys = [order_key(f) for f in findings]
    if keys != sorted(keys):
        order = ", ".join(f"{f['id']} {'excluded' if excluded(f) else f['severity']}"
                          for f in findings)
        problems.append("findings must be numbered in severity order (High first), then by path, "
                        f"excluded findings last: {order}; run scripts/findings.py renumber, "
                        "then re-run scripts/render.py")
    for i, f in enumerate(findings):
        if (f["confidence"] == "Environment-dependent" and not excluded(f)
                and not f.get("conditions", "").strip()):
            problems.append(f"findings[{i}].conditions: name the runtime setting an "
                            "Environment-dependent finding assumes")
        if (f["severity"] in ("High", "Medium") and not excluded(f)
                and not f["validation"].get("evidence", "").strip()):
            problems.append(f"{f['id']}.validation.evidence: a {f['severity']} finding needs "
                            "evidence; for an untraced one, name the hop that was not read")
    recorded = {p["name"]: p["status"] for p in doc.get("perspectives", [])}
    for name in PERSPECTIVES:
        if name not in recorded:
            problems.append(f"perspective not recorded: {name}")
    first_seen = {}
    for f in findings:
        if not excluded(f):
            location = locations(f)
            if location[0] in first_seen:
                problems.append(f"{first_seen[location[0]]} and {f['id']} share their first location; "
                                "one finding per fix location: merge them or anchor each at its own "
                                "fix site")
            first_seen.setdefault(location[0], f["id"])
        # Every finding, excluded or not, names a real step of its perspective.
        written = f.get("step", "").strip()
        step = STEP_ID.fullmatch(written)
        if written and not step:
            problems.append(f"{f['id']}.step: must be one hunt step ID such as "
                            f"{STEP_PREFIXES[f['category']]}1, or omitted")
        elif step and step.group(1) != STEP_PREFIXES[f["category"]]:
            problems.append(f"{f['id']}.step: {step.group(0)} is not a step of {f['category']} "
                            f"({STEP_PREFIXES[f['category']]}…); fix the step or the category")
        elif step and int(step.group(2)) > STEP_COUNTS[f["category"]]:
            prefix, last = STEP_PREFIXES[f["category"]], STEP_COUNTS[f["category"]]
            problems.append(f"{f['id']}.step: {step.group(0)} is not a hunt step of {f['category']} "
                            f"({prefix}1–{prefix}{last} in reference/perspectives.md)")
    ledger = {r["id"] for r in doc.get("commitments", [])}
    for i, f in enumerate(findings):
        # Ledger IDs are technical identifiers; other prose was checked by validate.
        for cited in COMMITMENT_REF.findall(f.get("commitment", "")):
            if cited not in ledger:
                problems.append(f"findings[{i}].commitment: {cited} is not in the commitments ledger")
        status = recorded.get(f["category"])
        if not excluded(f) and status not in (None, *APPLIED):
            problems.append(f"findings[{i}].category: its perspective is recorded as {status}, "
                            "not applied")
    citing = commitment_citations(doc)
    # Valid, unfixed findings in record order, gathered once rather than once per commitment.
    unfixed_valid = [f["id"] for f in findings
                     if f["validation"]["verdict"] == "Valid" and f.get("status", "Open") != "Fixed"]
    for i, r in enumerate(doc.get("commitments", [])):
        if r["status"] == "not checked" and not r.get("reason", "").strip():
            problems.append(f"commitments[{i}]: a not-checked commitment needs a nonblank reason")
        cited_by = citing.get(r["id"], [])
        if r["status"] == "violated" and not cited_by:
            problems.append(f"commitments[{i}]: {r['id']} is recorded as violated, but no reported "
                            "finding cites it in `commitment`; cite it from the finding that "
                            "breaks it, or correct the status")
        # Only a commitment recorded as holding, and cited, can be contradicted.
        cited = set(cited_by) if r["status"] == "holds" else ()
        broken = [fid for fid in unfixed_valid if fid in cited]
        if broken:
            problems.append(f"commitments[{i}]: {r['id']} is recorded as holds, but {', '.join(broken)} "
                            "(Valid, not Fixed) cites it as broken; set the status to violated, "
                            "or correct the finding")
    if not doc.get("limitations"):
        problems.append("limitations: state what static reading cannot show")
    if not doc.get("checked_ok"):
        problems.append("checked_ok: list what was examined and held")
    return problems


def commitment_citations(doc):
    """Ledger ID -> IDs of the reported findings whose `commitment` cites it, in record order.

    Excluded findings break no commitment, so they are not counted.
    """
    citing = {}
    for f in doc.get("findings", []):
        if excluded(f):
            continue
        for cited in dict.fromkeys(COMMITMENT_REF.findall(f.get("commitment", ""))):
            citing.setdefault(cited, []).append(f["id"])
    return citing


def _stale_outputs(out, doc, skip):
    """Report rendered outputs that no longer match the record they came from."""
    names = ("report.md", "dashboard.html")
    if any(name in skip for name in names):
        return []
    render = _import_sibling("render")  # render imports this module, so load it lazily

    try:
        current = {name: read_limited(out / name) for name in names}
    except SchemaError:
        return ["stale outputs: report.md or dashboard.html is too large to be a rendering "
                "of findings.json; re-run scripts/render.py"]
    except OSError:
        return [f"unreadable output: {name}" for name in names]
    # Either language is a valid rendering (render.py --lang may override meta.lang).
    # The recorded language is the likely one, so it is tried first, and the
    # dashboard is rendered only when report.md already matches; the verdict
    # does not depend on the order.
    recorded = doc.get("meta", {}).get("lang")
    for lang in sorted(render.LABELS, key=lambda lang: lang != recorded):
        if (current["report.md"] == render.render_markdown(doc, lang).encode("utf-8")
                and current["dashboard.html"] == render.render_html(doc, lang).encode("utf-8")):
            return []
    return ["stale outputs: report.md and dashboard.html must both be rendered from the current "
            "findings.json in one language; re-run scripts/render.py"]


def cmd_check(args):
    problems = contract_problems(args.out, args.allow)
    for problem in problems:
        print(problem, file=sys.stderr)
    if problems:
        return 1
    print(f"contract ok: {args.out}")
    return 0


def prepare_cli():
    """Let SIGTERM (tool timeouts) run cleanup, and never fail while reporting success."""
    if threading.current_thread() is threading.main_thread():
        signal.signal(signal.SIGTERM, lambda signum, frame: sys.exit(128 + signum))
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="backslashreplace")


def main(argv=None):
    prepare_cli()
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("merge", help="merge fragments into findings.json")
    m.add_argument("findings")
    m.add_argument("fragments", nargs="+")
    n = sub.add_parser("counts", help="print the counts the report templates use ({{n_high}}…)")
    n.add_argument("findings")
    d = sub.add_parser("diff", help="compare an earlier record with the current one")
    d.add_argument("old")
    d.add_argument("new")
    d.add_argument("--json", action="store_true", help="print the comparison as JSON")
    d.add_argument("--lang", choices=("ja", "en"), help="labels; defaults to the current meta.lang")
    r = sub.add_parser("renumber", help="number findings in severity order and rewrite PV- references")
    r.add_argument("findings")
    c = sub.add_parser("check", help="check the run contract of an output directory")
    c.add_argument("out")
    c.add_argument("--allow", action="append", default=[])
    args = parser.parse_args(argv)
    return {"merge": cmd_merge, "renumber": cmd_renumber, "counts": cmd_counts,
            "check": cmd_check, "diff": cmd_diff}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
