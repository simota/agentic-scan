#!/usr/bin/env python3
"""Merge finding fragments into findings.json and check a run's output directory.

    python3 findings.py merge FINDINGS FRAGMENT [FRAGMENT ...]
    python3 findings.py renumber FINDINGS
    python3 findings.py check OUT_DIR [--allow NAME ...]

A fragment is a JSON file written with the host's file-write tool (never a
shell heredoc or a generated script). It holds any of these top-level keys:
`meta` is merged key by key; `findings` and `rules` records are matched by
`id`, a known record updated key by key and a new one appended; `perspectives`
are matched by `name` and replaced whole; the string lists (`checked_ok`,
`decisions`, `limitations`, `next_steps`) are appended without duplicates.
A `null` value removes an optional key from `meta`, a finding or a rule, and
`remove` deletes list items (`{"next_steps": ["exact text"]}`) or ledger
entries by id (`{"rules": ["R-05"]}`) before the fragment's own items are
appended. A finding is never removed: a wrong one is marked `FalsePositive` or
`NotApplicable` with evidence, as SKILL.md requires.
A complete finding whose ID already holds a finding with another title or
location is refused as an ID collision; a correction sends only the fields
that change.
FINDINGS is created when absent. The merged record must pass the schema check
(`reference/findings-schema.md`) before anything is written.

`renumber` orders the findings by severity, then path and line of their first
location, and renames them `A-001`… without gaps. Every whole-word mention of
an old ID in the record's prose is rewritten in the same pass, so `next_steps`
and traces keep pointing at the same finding; `meta`, locations, URLs,
commands and rule sources keep theirs.

`check` is the run contract: the output directory holds exactly
`findings.json`, `dashboard.html` and `report.md` (plus `--allow` names), the
record is complete, IDs are gapless in severity order, every perspective in
`reference/perspectives.md` is recorded, every cited rule exists, no finding
outside the excluded verdicts sits under a perspective not applied, High and
Medium findings are traced (not Unverified) and carry evidence, definitive
evidence cites a `path:line`, and
both rendered files match what `render.py` produces from the current record
in `meta.lang`.

Exit codes: 0 ok, 1 a fragment was refused, input/output failed or the contract
failed (reasons on stderr), 2 the command line is wrong.
"""
import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys

try:
    import fcntl
except ImportError:  # Windows: merges must run one at a time.
    fcntl = None

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
# Hunt step prefixes, in PERSPECTIVES order (reference/perspectives.md).
STEP_PREFIXES = ("BL", "CR", "CP", "DM", "TX", "FH", "AC", "CF", "TS", "OP", "DU", "DE")
STEP_COUNTS = (4, 3, 4, 5, 5, 3, 3, 3, 3, 3, 2, 3)
RULE_FAMILIES = ("LAYER", "BOUND", "OWN", "TX", "FAIL", "CONTRACT", "SEAM")
LISTS = ("checked_ok", "decisions", "limitations", "next_steps")
TOP_KEYS = {"meta", "findings", "rules", "perspectives", *LISTS}
META_REQUIRED = ("project", "scope", "date", "assessor", "lang")
RULE_REQUIRED = ("id", "statement", "source", "status")
# Every key the schema knows in a record that is rendered. A typo such as
# `contrats` is refused instead of being kept and never shown. `meta` stays
# open for run context the outputs do not show.
RULE_KEYS = {*RULE_REQUIRED, "reason", "family", "inferred"}
PERSPECTIVE_KEYS = {"name", "status", "note"}
VALIDATION_KEYS = {"verdict", "method", "evidence"}
ANALYSIS_KEYS = {"tool", "command", "result"}
REFERENCE_KEYS = {"url", "title"}
TEXT_FIELDS = ("title", "scenario", "blast_radius", "trace", "impact", "fix", "guard")
FINDING_REQUIRED = ("id", "severity", "confidence", "category", "location", "validation",
                    *TEXT_FIELDS)
FINDING_KEYS = {*FINDING_REQUIRED, "contrast", "rule", "step", "status", "analysis", "references"}
OUTPUTS = {"findings.json", "dashboard.html", "report.md"}
# ASCII digits only: `\d` would also accept other scripts' digits.
FINDING_ID = re.compile(r"A-[0-9]{3}")
RULE_ID = re.compile(r"R-[0-9]{2,}")
STEP_ID = re.compile(r"([A-Z]{2})([1-9][0-9]*)")
# A `path:line` candidate: it starts after a blank, opening punctuation or a
# label's colon (`根拠:job.py:58`), but not as the `//host` of a URL, so a port
# is not a line; it has a letter (`10:30` is not one) and a line from 1. A
# Windows drive (`C:\repo\a.py:3`) is allowed. `cites_line` decides whether the
# token is a path.
EVIDENCE_LINE = re.compile(
    r"(?<![^\s(\[{'\"`,;:])(?!//)"
    r"(?P<path>(?:[A-Za-z]:)?[^\s:]*[A-Za-z][^\s:]*):[1-9][0-9]*")
# Extensionless files that hold code or rules (`Makefile` and `*file` match by suffix).
EXTENSIONLESS = {"BUILD", "BUILD.bazel", "WORKSPACE", "CODEOWNERS", "OWNERS", "LICENSE",
                 "VERSION", "MODULE.bazel"}
LOCATION = re.compile(r"[^\r\n]+:([0-9]+)(?:-([0-9]+))?")


class SchemaError(ValueError):
    pass


def as_locations(value):
    """A finding's `location`, a string or a list, as a list."""
    return value if isinstance(value, list) else [value]


def split_location(loc):
    """`path:line` or `path:start-end` as (path, start, end); None if not one."""
    match = LOCATION.fullmatch(loc) if isinstance(loc, str) else None
    if not match:
        return None
    start = int(match[1])
    return loc[:match.start(1) - 1], start, int(match[2] or start)


def read_json(path):
    def unique_object(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise SchemaError(f"{path}: duplicate object key {key!r}")
            obj[key] = value
        return obj

    try:
        # utf-8-sig: a byte order mark from a Windows editor is not content.
        doc = json.loads(Path(path).read_text(encoding="utf-8-sig"), object_pairs_hook=unique_object)
        # Reject lone surrogates and non-finite numbers, including float overflow.
        json.dumps(doc, ensure_ascii=False, allow_nan=False).encode("utf-8")
        return doc
    except SchemaError:
        raise
    except (OSError, ValueError) as exc:
        raise SchemaError(f"{path}: {exc}") from exc


def _text(value, where):
    if not isinstance(value, str) or not value.strip():
        raise SchemaError(f"{where}: must be a nonblank string")


def _list(value, where):
    if not isinstance(value, list):
        raise SchemaError(f"{where}: must be a list")
    return value


def _known(record, allowed, where):
    unknown = set(record) - allowed
    if unknown:
        raise SchemaError(f"{where}: unknown keys {sorted(unknown)} (known: "
                          f"{', '.join(sorted(allowed))})")


def _choice(value, allowed, where):
    if value not in allowed:
        raise SchemaError(f"{where}: {value!r} is not one of {', '.join(allowed)}")


def validate_finding(f, where):
    if not isinstance(f, dict):
        raise SchemaError(f"{where}: must be an object")
    for key in FINDING_REQUIRED:
        if key not in f:
            raise SchemaError(f"{where}: missing {key}")
    _known(f, FINDING_KEYS, where)
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
    locations = as_locations(f["location"])
    if not locations:
        raise SchemaError(f"{where}.location: at least one path:line")
    for loc in locations:
        parts = split_location(loc)
        if not parts:
            raise SchemaError(f"{where}.location: {loc!r} must be path:line")
        _, start, end = parts
        if not 1 <= start <= end:
            raise SchemaError(f"{where}.location: {loc!r} needs lines from 1, start <= end")
    if "step" in f:
        step = STEP_ID.fullmatch(f["step"]) if isinstance(f["step"], str) else None
        if not step or step[1] not in STEP_PREFIXES:
            raise SchemaError(f"{where}.step: {f['step']!r} must be a hunt step ID like DM1")
        index = PERSPECTIVES.index(f["category"])
        expected, count = STEP_PREFIXES[index], STEP_COUNTS[index]
        if step[1] != expected or int(step[2]) > count:
            raise SchemaError(f"{where}.step: {f['step']} is not a {f['category']} step "
                              f"({expected}1-{expected}{count})")
    v = f["validation"]
    if not isinstance(v, dict):
        raise SchemaError(f"{where}.validation: must be an object")
    _known(v, VALIDATION_KEYS, f"{where}.validation")
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
        _known(a, ANALYSIS_KEYS, f"{where}.analysis")
        for key in ("tool", "command", "result"):
            _text(a.get(key), f"{where}.analysis.{key}")
    for i, ref in enumerate(_list(f.get("references", []), f"{where}.references")):
        if not isinstance(ref, dict):
            raise SchemaError(f"{where}.references[{i}]: must be an object")
        _known(ref, REFERENCE_KEYS, f"{where}.references[{i}]")
        _text(ref.get("url"), f"{where}.references[{i}].url")
        if "title" in ref and not isinstance(ref["title"], str):
            raise SchemaError(f"{where}.references[{i}].title: must be a string")


def _location_paths(locations):
    """Each location's path and its file name, e.g. `bin/server` and `server`."""
    paths = set()
    for parts in filter(None, map(split_location, as_locations(locations))):
        paths |= {parts[0], re.split(r"[/\\]", parts[0])[-1]}
    return paths


def cites_line(evidence, locations=()):
    """True when evidence names a file and a line, e.g. `job.py:58` or `BUILD:12`.

    A token is a path when it has a `.`, `/` or `\\`, names a build file
    (`Makefile`, `CODEOWNERS`), or is a path or file name from the finding's own
    locations (`server:9` beside `bin/server:9`). `ABC:123` or `ratio:3` is not.
    """
    known = _location_paths(locations)
    for match in EVIDENCE_LINE.finditer(evidence):
        path = match["path"]
        if (re.search(r"[./\\]", path) or path.lower().endswith("file")
                or path in EXTENSIONLESS or path in known):
            return True
    return False


def _validate_perspectives(records, where):
    names = set()
    for i, p in enumerate(_list(records, where)):
        field = f"{where}[{i}]"
        if not isinstance(p, dict):
            raise SchemaError(f"{field}: must be an object")
        _known(p, PERSPECTIVE_KEYS, field)
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
    for key in META_REQUIRED:
        if complete or key in meta:
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
        _known(r, RULE_KEYS, where)
        for key in ("statement", "source"):
            _text(r.get(key), f"{where}.{key}")
        _choice(r.get("status"), RULE_STATUSES, f"{where}.status")
        if "reason" in r and not isinstance(r["reason"], str):
            raise SchemaError(f"{where}.reason ({r['id']}): must be a string")
        if "family" in r:
            _choice(r["family"], RULE_FAMILIES, f"{where}.family")
        if "inferred" in r and not isinstance(r["inferred"], bool):
            raise SchemaError(f"{where}.inferred ({r['id']}): must be true or false")
    _validate_perspectives(doc.get("perspectives", []), "perspectives")
    for key in LISTS:
        values = _list(doc.get(key, []), key)
        for i, value in enumerate(values):
            _text(value, f"{key}[{i}]")


def _apply(target, updates, required, where):
    """Update target key by key; a null value removes an optional key."""
    for key, value in updates.items():
        if value is not None:
            target[key] = value
        elif key in required:
            raise SchemaError(f"{where}.{key}: required; null removes only optional keys")
        else:
            target.pop(key, None)
    return target


def _same_location(a, b):
    return as_locations(a) == as_locations(b)


def _collides(existing, record):
    """A complete record unlike the finding that holds its ID: another unit's finding.

    Two findings can share a location, so either a new title or a new location
    marks a different finding; a correction sends only the fields that change.
    """
    return (all(key in record for key in FINDING_REQUIRED)
            and (" ".join(str(record["title"]).split())
                 != " ".join(str(existing.get("title", "")).split())
                 or not _same_location(record["location"], existing.get("location"))))


def _merge_records(current, incoming, where, required):
    for records in (current, incoming):
        ids = [r.get("id") if isinstance(r, dict) else None for r in _list(records, where)]
        if any(not isinstance(fid, str) for fid in ids) or len(set(ids)) != len(ids):
            raise SchemaError(f"{where}: every record needs a unique string id")
    index = {r["id"]: r for r in current}
    for record in incoming:
        rid = record["id"]
        if rid in index:
            if required is FINDING_REQUIRED and _collides(index[rid], record):
                raise SchemaError(
                    f"{where}: {rid} already holds {index[rid].get('title')!r}; give the new "
                    f"finding another ID, or send only the fields that change")
            _apply(index[rid], record, required, f"{where}.{rid}")
        else:
            current.append(_apply({}, record, required, f"{where}.{rid}"))
            index[rid] = current[-1]


def _remove_items(doc, removals, where):
    if not isinstance(removals, dict):
        raise SchemaError(f"{where}: must be an object of list names")
    unknown = set(removals) - set(LISTS) - {"rules"}
    if unknown:
        raise SchemaError(f"{where}: only rules and {', '.join(LISTS)} can be removed from, "
                          f"not {sorted(unknown)} (a finding is never removed: mark it "
                          "FalsePositive or NotApplicable with evidence; a perspective "
                          "is replaced, not removed)")
    for key, values in removals.items():
        if key == "rules":
            # A spurious ledger entry, by id; check then catches a finding citing it.
            for rid in _list(values, f"{where}.rules"):
                ids = [r.get("id") for r in doc.get("rules", [])]
                if rid not in ids:
                    raise SchemaError(f"{where}.rules: {rid!r} is not recorded")
                del doc["rules"][ids.index(rid)]
            continue
        for value in _list(values, f"{where}.{key}"):
            if value not in doc.get(key, []):
                raise SchemaError(f"{where}.{key}: {value!r} is not recorded")
            doc[key].remove(value)


def merge(doc, fragment, where):
    if not isinstance(fragment, dict):
        raise SchemaError(f"{where}: must be an object")
    unknown = set(fragment) - TOP_KEYS - {"remove"}
    if unknown:
        raise SchemaError(f"{where}: unknown keys {sorted(unknown)}")
    if "meta" in fragment:
        if not isinstance(fragment["meta"], dict):
            raise SchemaError(f"{where}.meta: must be an object")
        _apply(doc.setdefault("meta", {}), fragment["meta"], META_REQUIRED, f"{where}.meta")
    if "remove" in fragment:
        # First, so one fragment can remove an entry and send its replacement.
        _remove_items(doc, fragment["remove"], f"{where}.remove")
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
            required = FINDING_REQUIRED if key == "findings" else RULE_REQUIRED
            _merge_records(doc.setdefault(key, []), fragment[key], f"{where}.{key}", required)
    for key in LISTS:
        if key in fragment:
            if not isinstance(fragment[key], list):
                raise SchemaError(f"{where}.{key}: must be a list")
            target = doc.setdefault(key, [])
            target.extend(v for v in fragment[key] if v not in target)
    return doc


def _atomic_write(target, data):
    _atomic_write_all({target: data})


def _stage(target, data):
    """Write data beside target; return (temporary, resolved target)."""
    # Follow symlinks as write_bytes did, preserving the link itself.
    target = target.resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        # Check write access without truncating the existing record.
        with target.open("r+b") as current:
            mode = stat.S_IMODE(os.fstat(current.fileno()).st_mode)
    except FileNotFoundError:
        mode = None
    while True:
        temporary = target.parent / f".findings-{secrets.token_hex(16)}.tmp"
        try:
            # Exclusive creation retains the normal 0666 & umask for new files.
            stream = temporary.open("xb")
        except FileExistsError:
            continue
        break
    try:
        with stream:
            if mode is not None:
                temporary.chmod(mode)
            stream.write(data)
            stream.flush()
            # The replacement must never expose a record that is not yet on disk.
            os.fsync(stream.fileno())
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return temporary, target


def _atomic_write_all(files):
    """Replace every target only after all of them are staged, keeping links and modes."""
    staged = []
    try:
        for target, data in files.items():
            staged.append(_stage(target, data))
        for temporary, target in staged:
            os.replace(temporary, target)
    finally:
        for temporary, _ in staged:
            temporary.unlink(missing_ok=True)


# An ID mention, but not part of a longer token such as `JIRA-A-001` or `A-0012`,
# nor a path segment (`docs/A-001.md`). ASCII word characters only, so an ID
# next to Japanese text (`A-001を`) is still a mention.
ID_MENTION = re.compile(r"(?<![\w/\\-])A-[0-9]{3}(?![\w/\\-]|\.[A-Za-z0-9])", re.ASCII)


def _first_location(f):
    path, start, _ = split_location(as_locations(f["location"])[0])
    return path, start


# Literal values that only look like prose: a path, a URL, a command that ran,
# a rule's source. An `A-001` in them is a file, ticket or argument, not a finding.
LITERAL_KEYS = {"location", "url", "command", "source"}


def _rewrite_ids(value, mapping, key=None):
    if key in LITERAL_KEYS:
        return value
    if isinstance(value, str):
        return ID_MENTION.sub(lambda m: mapping.get(m[0], m[0]), value)
    if isinstance(value, list):
        return [_rewrite_ids(v, mapping, key) for v in value]
    if isinstance(value, dict):
        return {k: _rewrite_ids(v, mapping, k) for k, v in value.items()}
    return value


def renumber(doc):
    """Return (doc, mapping): findings in severity then path order, IDs gapless."""
    findings = doc.get("findings", [])
    order = sorted(range(len(findings)), key=lambda i: (
        SEVERITIES.index(findings[i]["severity"]), _first_location(findings[i]), i))
    mapping = {findings[i]["id"]: f"A-{n:03d}" for n, i in enumerate(order, 1)}
    # One pass over the old text, so A-001 -> A-002 and A-002 -> A-001 do not chain.
    # meta describes the run (its scope may name an earlier run's IDs).
    renamed = {k: v if k == "meta" else _rewrite_ids(v, mapping) for k, v in doc.items()}
    if findings:
        renamed["findings"] = [renamed["findings"][i] for i in order]
        for f, i in zip(renamed["findings"], order):
            f["id"] = mapping[findings[i]["id"]]
    return renamed, {old: new for old, new in mapping.items() if old != new}


def _serialize(doc):
    return (json.dumps(doc, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode("utf-8")


@contextmanager
def _exclusive(target):
    """Hold an exclusive lock on target's directory from read to replace.

    Two merges started together would otherwise both read the same record and
    the later replace would drop the other's findings. The lock is on the
    directory, so no lock file joins the outputs. Without fcntl (Windows), run
    merges one at a time.
    """
    directory = target.resolve().parent
    # The directory is never removed again: a merge may already hold it open,
    # waiting for the lock, and would then lock a deleted directory.
    directory.mkdir(parents=True, exist_ok=True)
    yield from _locked(directory)


def _locked(directory):
    if fcntl is None:
        yield
        return
    try:
        fd = os.open(directory, os.O_RDONLY)
    except PermissionError:
        # A directory that can be written but not read cannot be locked.
        print(f"warning: cannot lock {directory}; run merges one at a time", file=sys.stderr)
        yield
        return
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def cmd_renumber(args):
    target = Path(args.findings)
    try:
        with _exclusive(target):
            changed = _renumber_file(target)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 1
    _report_renumber(target, changed)
    return 0


def _renumber_file(target):
    doc = read_json(target)
    validate(doc)
    if len(doc.get("findings", [])) > 999:
        raise SchemaError(f"{target}: more than 999 findings cannot be numbered A-NNN")
    doc, changed = renumber(doc)
    validate(doc)
    if changed:
        _atomic_write(target, _serialize(doc))
    return changed


def _report_renumber(target, changed):
    for old, new in sorted(changed.items()):
        print(f"{old} -> {new}")
    if changed:
        print(f"renumbered {len(changed)} finding(s) in {target}")
        # A fragment written before this run still names the old IDs, and merge
        # would apply it to whichever finding holds that ID now.
        print("use only the new IDs from here on; rewrite any unmerged fragment first",
              file=sys.stderr)
    else:
        print(f"already in order: {target}")


def _merge_all(doc, fragments):
    validate(doc)
    for path in fragments:
        merge(doc, read_json(path), path)
        # Each fragment must leave a valid record, even in a batch.
        validate(doc)
    return doc


def cmd_merge(args):
    target = Path(args.findings)
    try:
        if not target.resolve().parent.exists():
            # Refuse a bad first batch before creating the output directory.
            _merge_all({}, args.fragments)
        with _exclusive(target):
            doc = _merge_all(read_json(target) if target.exists() else {}, args.fragments)
            # Serialize before staging any output.
            _atomic_write(target, _serialize(doc))
    except (OSError, ValueError, RuntimeError) as exc:
        # RuntimeError: Path.resolve() on a symlink loop before Python 3.13.
        print(f"refused: {exc}", file=sys.stderr)
        return 1
    print(f"merged {len(args.fragments)} fragment(s) into {target}: "
          f"{len(doc.get('findings', []))} finding(s)")
    return 0


def contract_problems(out, allow=()):
    """Return the run-contract violations for an output directory."""
    out = Path(out)
    if not out.is_dir():
        return [f"output directory does not exist or is not a directory: {out}"]
    try:
        present = {p.name for p in out.iterdir()}
    except OSError as exc:
        return [f"output directory cannot be listed: {exc}"]
    problems = []
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
    recorded = {p["name"]: p["status"] for p in doc.get("perspectives", [])}
    for name in PERSPECTIVES:
        if name not in recorded:
            problems.append(f"perspective not recorded: {name}")
    rule_status = {r["id"]: r["status"] for r in doc.get("rules", [])}
    for f in findings:
        verdict, evidence = f["validation"]["verdict"], f["validation"].get("evidence", "")
        if f.get("rule", "").strip():
            status = rule_status.get(f["rule"])
            if status is None:
                problems.append(f"{f['id']}: rule {f['rule']!r} is not a rules[] id")
            elif verdict in ("Valid", "Likely") and status not in ("violated", "partly read"):
                problems.append(f"{f['id']}: {verdict} finding cites {f['rule']}, recorded as "
                                f"{status}, not violated or partly read")
        if verdict in DEFINITIVE and not cites_line(evidence, f["location"]):
            problems.append(f"{f['id']}: {verdict} evidence must cite path:line")
        if verdict in EXCLUDED:
            continue
        if recorded.get(f["category"], "applied") != "applied":
            problems.append(f"{f['id']}: category {f['category']} is recorded as "
                            f"{recorded[f['category']]}, not applied")
        if f["severity"] in ("High", "Medium"):
            # SKILL.md: never report a High or Medium finding that was not traced.
            if verdict == "Unverified":
                # Severity is graded apart from confidence, so it is never the remedy.
                problems.append(f"{f['id']}: an Unverified {f['severity']} finding was not "
                                "traced; trace it end to end and record the verdict "
                                "(Valid, Likely or Unlikely) with its evidence")
            elif not evidence.strip():
                problems.append(f"{f['id']}: a {f['severity']} finding needs validation.evidence "
                                "naming what the trace found")
    for r in doc.get("rules", []):
        if r["status"] == "not checked":
            reason = r.get("reason")
            if not isinstance(reason, str) or not reason.strip():
                problems.append(f"{r['id']}: a not-checked rule needs a nonblank string reason")
    if not doc.get("limitations"):
        problems.append("limitations: state what static reading cannot show")
    if not doc.get("checked_ok"):
        problems.append("checked_ok: list what was examined and held")
    return problems + _stale_outputs(out, doc, not_files | (OUTPUTS - present))


def _stale_outputs(out, doc, unusable):
    """Name each output that render.py would not produce from doc in meta.lang."""
    names = ("report.md", "dashboard.html")
    if any(name in unusable for name in names):
        return []
    try:
        current = {name: (out / name).read_bytes() for name in names}
    except OSError as exc:
        return [f"rendered output cannot be read: {exc}"]
    lang = doc["meta"]["lang"]
    expected = _renderer().rendered_outputs(doc, lang)
    return [f"{name} does not match findings.json: the record changed after the last render, "
            f"or it was rendered in another language than meta.lang {lang} "
            "(re-run scripts/render.py without --lang)"
            for name in names if current[name] != expected[name]]


def _renderer():
    here = str(Path(__file__).resolve().parent)
    if here not in sys.path:
        sys.path.insert(0, here)
    # Leave no __pycache__ beside the skill (it may be a linked checkout).
    sys.dont_write_bytecode = True
    import render
    return render


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
    r = sub.add_parser("renumber", help="order findings by severity and path, IDs gapless")
    r.add_argument("findings")
    c = sub.add_parser("check", help="check the run contract of an output directory")
    c.add_argument("out")
    c.add_argument("--allow", action="append", default=[])
    args = parser.parse_args(argv)
    return {"merge": cmd_merge, "renumber": cmd_renumber, "check": cmd_check}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
