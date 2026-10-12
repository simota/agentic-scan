#!/usr/bin/env python3
"""Validate and merge prune-scan records (reference/findings-schema.md, reference/units.md).

    python3 findings.py check    <out>/findings.json
    python3 findings.py merge    <out>/findings.json FRAGMENT...
    python3 findings.py units    <out>/units.json    FRAGMENT...
    python3 findings.py renumber <out>/findings.json

merge updates findings by id, appends new lines to checked_ok, limitations,
decisions and next_steps (a fragment's "remove" deletes exact lines), and
replaces perspectives by name. units adds or replaces purpose items, entry
points and units by id and consumers by name, and replaces app. Both check the
result before replacing anything, then write it atomically; a refused fragment
changes nothing. merge accepts findings in any order; renumber then numbers
them P-001.. by severity, then path and line (FalsePositive / NotApplicable
last), and rewrites P-* finding references while preserving source identities.
check, render.py and contract_check.py require that order. Standard library only.
Exit status: 0 ok, 2 invalid input (reasons on stderr).
"""

import json
import math
import os
import re
import stat
import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan_report_kit.output import write_output  # noqa: E402
from scan_report_kit.report import FormatError, LINE_BREAKS, http_url  # noqa: E402

SEVERITIES = ("High", "Medium", "Low", "Info")
CONFIDENCES = ("Confirmed", "Externally-dependent", "Purpose-dependent", "Suspected")
STATUSES = ("Open", "Fixed", "Accepted")
VERDICTS = ("Valid", "Likely", "Unverified", "Unlikely", "FalsePositive", "NotApplicable")
EXCLUDED = ("FalsePositive", "NotApplicable")
ACTIONS = ("remove", "reduce", "consolidate")
SOURCES = ("documented", "stated", "inferred")
PURPOSE_KINDS = ("statement", "user", "job", "non_goal", "scale")
ENTRY_KINDS = ("endpoint", "screen", "cli", "job", "webhook", "hook", "package", "other")
EXPOSURES = ("public", "authenticated", "admin", "internal", "partner")
CONSUMER_KINDS = ("web", "mobile", "service", "partner", "ops", "library-user", "other")
UNIT_KINDS = ("area", "shared")
LIST_KEYS = ("checked_ok", "limitations", "decisions", "next_steps")
HUNT_STEPS = {"DC": 4, "UF": 4, "FF": 3, "DP": 4, "CF": 3, "DA": 4, "AS": 4,
              "TT": 4, "DU": 3, "AP": 3, "PI": 3, "PX": 4, "OB": 5}
FAMILIES = tuple(HUNT_STEPS)
PURPOSE_FAMILIES = ("PX", "OB")
FINDING_ID = re.compile(r"^P-[0-9]{3}\Z")
UNIT_ID = re.compile(r"^UN-[0-9]{2,3}\Z")
ENTRY_ID = re.compile(r"^EP-[0-9]{2,3}\Z")
PURPOSE_ID = re.compile(r"^PB-[0-9]{2,3}\Z")
PERSPECTIVE = re.compile(r"^(?:%s)\Z" % "|".join(f"{family}[1-{steps}]" for family, steps in HUNT_STEPS.items()))
LOCATION = re.compile(r"^(?!/)(?!.*(?:^|/)\.\.(?:/|:))[^\s:][^:\n]*:[1-9][0-9]*(?:-[1-9][0-9]*)?\Z")
REPO_PATH = re.compile(r"^(?!/)(?!.*(?:^|/)\.\.(?:/|\Z))[^\s:][^:\n]*\Z")
TEXT_FIELDS = ("title", "category", "element", "observed", "basis", "impact", "risk")
SUBTRACTION_FIELDS = ("what", "remains", "loses")
INVALID_TEXT = re.compile(r"[\x00\ud800-\udfff]")


class RecordError(Exception):
    pass


def _str(obj, key, where, required=False):
    value = obj.get(key, "")
    if not isinstance(value, str):
        raise RecordError(f"{where}.{key}: expected a string")
    if INVALID_TEXT.search(value):
        raise RecordError(f"{where}.{key}: expected Unicode text without NUL or surrogate code points")
    if required and not value.strip():
        raise RecordError(f"{where}.{key}: required")
    return value


def _strings(value, where, non_empty=True):
    if not isinstance(value, list) or not all(isinstance(x, str) and (x.strip() or not non_empty) for x in value):
        raise RecordError(f"{where}: expected a list of {'non-empty ' if non_empty else ''}strings")
    if any(INVALID_TEXT.search(x) for x in value):
        raise RecordError(f"{where}: expected Unicode text without NUL or surrogate code points")
    return value


def _keyed(value, where, ident):
    """Validate rows before indexing them, so malformed or duplicate rows cannot disappear."""
    if not isinstance(value, list):
        raise RecordError(f"{where}: expected a list")
    result = {}
    for i, item in enumerate(value):
        if not isinstance(item, dict):
            raise RecordError(f"{where}[{i}]: expected an object")
        key = _str(item, ident, f"{where}[{i}]", required=True)
        if key in result:
            raise RecordError(f"{where}[{i}].{ident}: duplicate {key!r}")
        result[key] = item
    return result


def _location(value, where):
    if not isinstance(value, str) or INVALID_TEXT.search(value) or not LOCATION.match(value):
        raise RecordError(f"{where}: {value!r} is not a repository-relative path:line")
    first, _, last = value.rpartition(":")[2].partition("-")
    try:
        first_line, last_line = int(first), int(last or first)
    except ValueError:
        raise RecordError(f"{where}: line number is too large") from None
    if last_line < first_line:
        raise RecordError(f"{where}: last line precedes first line in {value!r}")
    return value


def _http(url, where):
    try:
        http_url(url, where)
    except FormatError as e:
        raise RecordError(str(e)) from None


def _items(units, key, where, id_rx, id_hint, required=True):
    items = units.get(key)
    if not isinstance(items, list) or (required and not items):
        raise RecordError(f"{where}.{key}: expected a non-empty list")
    seen = set()
    for i, item in enumerate(items):
        if not isinstance(item, dict):
            raise RecordError(f"{where}.{key}[{i}]: expected an object")
        iid = _str(item, "id", f"{where}.{key}[{i}]", required=True)
        if not id_rx.match(iid):
            raise RecordError(f"{where}.{key}[{i}].id: expected {id_hint}")
        if iid in seen:
            raise RecordError(f"{where}.{key}[{i}].id: duplicate {iid}")
        seen.add(iid)
    return items


def check_units(units):
    """Raise RecordError unless units matches reference/units.md; return it."""
    if not isinstance(units, dict):
        raise RecordError("units: expected an object")
    _str(units, "app", "units", required=True)
    for item in _items(units, "purpose", "units", PURPOSE_ID, "PB- and two or three digits (PB-01)"):
        where = f"purpose {item['id']}"
        if item.get("kind") not in PURPOSE_KINDS:
            raise RecordError(f"{where}.kind: expected one of {', '.join(PURPOSE_KINDS)}")
        if item.get("source") not in SOURCES:
            raise RecordError(f"{where}.source: expected one of {', '.join(SOURCES)}")
        _str(item, "text", where, required=True)
        _str(item, "evidence", where, required=True)
    if not any(item["kind"] == "job" for item in units["purpose"]):
        raise RecordError("units.purpose: no core job (kind job); excess and purpose fit are judged against the jobs")
    for ep in _items(units, "entry_points", "units", ENTRY_ID, "EP- and two or three digits (EP-01)"):
        where = f"entry point {ep['id']}"
        if ep.get("kind") not in ENTRY_KINDS:
            raise RecordError(f"{where}.kind: expected one of {', '.join(ENTRY_KINDS)}")
        if ep.get("exposure") not in EXPOSURES:
            raise RecordError(f"{where}.exposure: expected one of {', '.join(EXPOSURES)}")
        _str(ep, "name", where, required=True)
        _location(ep.get("location"), f"{where}.location")
    consumers = units.get("consumers")
    if not isinstance(consumers, list) or not consumers:
        raise RecordError("units.consumers: expected a non-empty list (who calls this app, in and outside the repository)")
    names = set()
    for i, c in enumerate(consumers):
        if not isinstance(c, dict):
            raise RecordError(f"units.consumers[{i}]: expected an object")
        name = _str(c, "name", f"units.consumers[{i}]", required=True)
        if name in names:
            raise RecordError(f"units.consumers[{i}].name: duplicate {name!r}")
        names.add(name)
        where = f"consumer {name!r}"
        if c.get("kind") not in CONSUMER_KINDS:
            raise RecordError(f"{where}.kind: expected one of {', '.join(CONSUMER_KINDS)}")
        if not isinstance(c.get("in_repo"), bool):
            raise RecordError(f"{where}.in_repo: expected true or false")
        _str(c, "evidence", where, required=True)
    entry_ids = {ep["id"] for ep in units["entry_points"]}
    covered = set()
    for unit in _items(units, "units", "units", UNIT_ID, "UN- and two or three digits (UN-01)"):
        where = f"unit {unit['id']}"
        _str(unit, "name", where, required=True)
        if unit.get("kind") not in UNIT_KINDS:
            raise RecordError(f"{where}.kind: expected one of {', '.join(UNIT_KINDS)}")
        for p in _strings(unit.get("paths"), f"{where}.paths"):
            if not REPO_PATH.match(p):
                raise RecordError(f"{where}.paths: {p!r} is not a repository-relative path")
        refs = _strings(unit.get("entry_points", []), f"{where}.entry_points")
        for ref in refs:
            if ref not in entry_ids:
                raise RecordError(f"{where}.entry_points: {ref} is not an entry point")
        covered.update(refs)
    uncovered = sorted(entry_ids - covered)
    if uncovered:
        raise RecordError(f"units.entry_points: {', '.join(uncovered)} belong to no unit; add each to the unit that reviews it")
    return units


def check_findings(data, units=None, ordered=True):
    """Raise RecordError unless data matches reference/findings-schema.md.

    units is the checked units.json; None skips the cross-reference checks.
    ordered=False skips numbering and ordering, which renumber restores after merging.
    """
    if not isinstance(data, dict):
        raise RecordError("findings: expected an object")
    if type(data.get("schema_version")) is not int or data["schema_version"] != 1:
        raise RecordError("schema_version: expected 1")
    meta = data.get("meta")
    if not isinstance(meta, dict):
        raise RecordError("meta: expected an object")
    for key in ("project", "date", "assessor"):
        _str(meta, key, "meta", required=True)
    if not re.match(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}\Z", meta["date"]):
        raise RecordError("meta.date: expected YYYY-MM-DD")
    try:
        date.fromisoformat(meta["date"])
    except ValueError:
        raise RecordError("meta.date: expected a valid calendar date (YYYY-MM-DD)") from None
    for key in ("scope", "method", "commit"):
        _str(meta, key, "meta")
    _str(data, "summary", "findings")
    for key in LIST_KEYS:
        if key in data:
            _strings(data[key], key, non_empty=False)
    perspectives = data.get("perspectives", [])
    _keyed(perspectives, "perspectives", "name")
    for i, p in enumerate(perspectives):
        _str(p, "result", f"perspectives[{i}]")
        _str(p, "note", f"perspectives[{i}]")
    findings = data.get("findings")
    if not isinstance(findings, list):
        raise RecordError("findings: expected a list")
    if len(findings) > 999:
        raise RecordError("findings: at most 999 findings fit the P-001 through P-999 id format")
    unit_ids = entry_ids = purpose = None
    if units is not None:
        unit_ids = {u["id"] for u in units["units"]}
        entry_ids = {ep["id"] for ep in units["entry_points"]}
        purpose = {p["id"]: p for p in units["purpose"]}
    seen = set()
    for i, f in enumerate(findings):
        where = f"findings[{i}]"
        if not isinstance(f, dict):
            raise RecordError(f"{where}: expected an object")
        fid = _str(f, "id", where, required=True)
        if not FINDING_ID.match(fid):
            raise RecordError(f"{where}.id: expected P- and three digits, got {fid!r}")
        if fid in seen:
            raise RecordError(f"{where}.id: duplicate {fid}")
        seen.add(fid)
        where = f"finding {fid}"
        for key, allowed in (("severity", SEVERITIES), ("confidence", CONFIDENCES), ("status", STATUSES)):
            if f.get(key) not in allowed:
                raise RecordError(f"{where}.{key}: expected one of {', '.join(allowed)}")
        for key in TEXT_FIELDS:
            _str(f, key, where, required=key in ("title", "element", "basis", "risk"))
        if LINE_BREAKS.search(f["title"]):
            raise RecordError(f"{where}.title: expected one line")
        perspective = _str(f, "perspective", where, required=True)
        if not PERSPECTIVE.match(perspective):
            raise RecordError(f"{where}.perspective: expected a hunt step id such as DC1 or OB2")
        ref = _str(f, "unit_ref", where, required=True)
        if not UNIT_ID.match(ref):
            raise RecordError(f"{where}.unit_ref: expected a unit id such as UN-01")
        if unit_ids is not None and ref not in unit_ids:
            raise RecordError(f"{where}.unit_ref: {ref} is not a unit in units.json")
        if "entry_ref" in f:
            eref = _str(f, "entry_ref", where, required=True)
            if not ENTRY_ID.match(eref):
                raise RecordError(f"{where}.entry_ref: expected an entry point id such as EP-01")
            if entry_ids is not None and eref not in entry_ids:
                raise RecordError(f"{where}.entry_ref: {eref} is not an entry point in units.json")
        pref = _str(f, "purpose_ref", where, required=perspective[:2] in PURPOSE_FAMILIES
                    or f["confidence"] == "Purpose-dependent")
        if pref:
            if not PURPOSE_ID.match(pref):
                raise RecordError(f"{where}.purpose_ref: expected a purpose item id such as PB-01")
            if purpose is not None:
                if pref not in purpose:
                    raise RecordError(f"{where}.purpose_ref: {pref} is not a purpose item in units.json")
                if purpose[pref]["source"] == "inferred" and f["confidence"] != "Purpose-dependent":
                    raise RecordError(f"{where}.confidence: {pref} is an inferred purpose item; "
                                      "a finding resting on it must be Purpose-dependent (a human decides)")
        sub = f.get("subtraction")
        if not isinstance(sub, dict):
            raise RecordError(f"{where}.subtraction: required ({{action, what, remains, loses}})")
        if sub.get("action") not in ACTIONS:
            raise RecordError(f"{where}.subtraction.action: expected one of {', '.join(ACTIONS)}")
        for key in SUBTRACTION_FIELDS:
            _str(sub, key, f"{where}.subtraction", required=True)
        location = _location(_str(f, "location", where, required=True), f"{where}.location")
        for loc in _strings(f.get("occurrences", [location]), f"{where}.occurrences"):
            _location(loc, f"{where}.occurrences")
        validation = f.get("validation")
        if not isinstance(validation, dict):
            raise RecordError(f"{where}.validation: required")
        verdict = validation.get("verdict")
        if verdict not in VERDICTS:
            raise RecordError(f"{where}.validation.verdict: expected one of {', '.join(VERDICTS)}")
        _str(validation, "evidence", f"{where}.validation", required=verdict != "Unverified")
        _str(validation, "dynamic_checked", f"{where}.validation", required=verdict in ("Valid", "Likely"))
        if verdict == "Valid" and f["confidence"] != "Confirmed":
            raise RecordError(f"{where}.validation.verdict: Valid needs Confirmed confidence; a {f['confidence']} "
                              "finding is at most Likely")
        refs = f.get("references", [])
        if not isinstance(refs, list):
            raise RecordError(f"{where}.references: expected a list")
        for j, ref_ in enumerate(refs):
            if not isinstance(ref_, dict):
                raise RecordError(f"{where}.references[{j}]: expected an object")
            _http(ref_.get("url"), f"{where}.references[{j}].url")
            for key in ("type", "title"):
                _str(ref_, key, f"{where}.references[{j}]")
    if ordered:
        mapping = renumber_map(findings)
        ids = [f["id"] for f in findings]
        if ids != list(mapping) or any(old != new for old, new in mapping.items()):
            raise RecordError("findings: use consecutive ids in severity order (High first), then path and line, "
                              "with excluded findings last; run findings.py renumber <out>/findings.json")
    return data


# ASCII identifier boundaries also recognize references next to Japanese prose.
FINDING_REF = re.compile(r"(?<![A-Za-z0-9_])P-[0-9]{3}(?![A-Za-z0-9_])")


def renumber_map(findings):
    """Old id -> new id: severity, then path and line; excluded findings last, in their old order."""
    def key(f):
        path, _, lines = f["location"].rpartition(":")
        return SEVERITIES.index(f["severity"]), path, int(lines.split("-")[0]), f["id"]
    active = sorted((f for f in findings if f["validation"]["verdict"] not in EXCLUDED), key=key)
    excluded = sorted((f for f in findings if f["validation"]["verdict"] in EXCLUDED), key=lambda f: f["id"])
    return {f["id"]: f"P-{n:03d}" for n, f in enumerate(active + excluded, 1)}


def renumber(data, mapping):
    """Rewrite finding ids and prose references, retaining the identities of the reviewed sources."""
    # These schema fields describe the review's provenance, actual source data,
    # external citations or category names. An embedded P-* is not a finding id.
    # Match their schema locations, so names in unknown extensions still rewrite.
    literal_fields = {
        "record": ("meta",),
        "finding": ("element", "observed", "location", "occurrences", "references", "category"),
        "perspective": ("name",),
    }
    sections = {"findings": "finding", "perspectives": "perspective"}

    def rewrite(value, section=None, literal=False):
        if isinstance(value, str):
            return value if literal else FINDING_REF.sub(lambda m: mapping.get(m.group(0), m.group(0)), value)
        if isinstance(value, dict):
            return {k: rewrite(v, sections.get(k) if section == "record" else None,
                               literal or k in literal_fields.get(section, ()))
                    for k, v in value.items()}
        if isinstance(value, list):
            return [rewrite(v, section, literal) for v in value]
        return value
    try:
        data = rewrite(data, "record")
    except RecursionError:
        raise RecordError("findings: JSON nesting is too deep to renumber") from None
    data["findings"].sort(key=lambda f: f["id"])
    return data


def parse_json(source, where="JSON"):
    """Decode a UTF-8 record without silently dropping duplicate keys or accepting non-finite numbers."""
    def unique_object(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise ValueError(f"duplicate JSON key {key!r}")
            obj[key] = value
        return obj

    def invalid_constant(value):
        raise ValueError(f"invalid JSON constant {value}")

    if not isinstance(source, (str, bytes)):
        raise RecordError(f"{where}: expected JSON text or UTF-8 bytes")
    try:
        if isinstance(source, bytes):
            source = source.decode("utf-8")
        data = json.loads(source, object_pairs_hook=unique_object, parse_constant=invalid_constant)
        pending = [data]
        while pending:
            value = pending.pop()
            if isinstance(value, str):
                value.encode("utf-8")  # Reject escaped lone surrogates, which cannot be written as UTF-8.
            elif isinstance(value, dict):
                pending.extend(value)
                pending.extend(value.values())
            elif isinstance(value, list):
                pending.extend(value)
            elif isinstance(value, float) and not math.isfinite(value):
                raise ValueError("JSON number is outside the finite range")
        return data
    except (ValueError, RecursionError) as e:
        raise RecordError(f"{where}: {e}") from None


def read_json_source(path):
    """Read bytes from a regular file; a symlink may resolve to one, but FIFOs and devices are refused."""
    try:
        # Open non-blocking before fstat so a FIFO, including one swapped in after a path check, cannot hang.
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(fd, "rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise RecordError(f"{path}: expected a regular JSON file")
            return handle.read()
    except OSError as e:
        raise RecordError(f"{path}: {e}") from None


def load_json(path):
    return parse_json(read_json_source(path), where=str(path))


def record_exists(path):
    """Only an absent path is optional; broken links and inaccessible records must fail when read."""
    try:
        Path(path).lstat()
    except FileNotFoundError:
        return False
    return True


def units_beside(findings_path):
    """The checked units.json next to findings_path, or None when there is none."""
    path = Path(findings_path).with_name("units.json")
    return check_units(load_json(path)) if record_exists(path) else None


def merge_units(base, fragment):
    """base with app replaced, purpose / entry_points / units merged by id and consumers by name."""
    if not isinstance(base, dict):
        raise RecordError("units: expected an object")
    if not isinstance(fragment, dict):
        raise RecordError("units fragment: expected an object")
    out = dict(base)
    for key, value in fragment.items():
        if key in ("purpose", "entry_points", "units", "consumers"):
            ident = "name" if key == "consumers" else "id"
            by_key = _keyed(base.get(key, []), f"units.{key}", ident)
            by_key.update(_keyed(value, f"units fragment.{key}", ident))
            out[key] = list(by_key.values())
        else:
            out[key] = value
    return out


def merge(base, fragment):
    if not isinstance(base, dict):
        raise RecordError("findings: expected an object")
    if not isinstance(fragment, dict):
        raise RecordError("fragment: expected an object")
    out = dict(base)
    for key, value in fragment.items():
        if key in LIST_KEYS:
            old = _strings(base.get(key, []), key, non_empty=False)
            new = _strings(value, f"fragment.{key}", non_empty=False)
            out[key] = list(dict.fromkeys([*old, *new]))
        elif key == "perspectives":
            by_name = _keyed(base.get("perspectives", []), "perspectives", "name")
            by_name.update(_keyed(value, "fragment.perspectives", "name"))
            out[key] = list(by_name.values())
        elif key not in ("findings", "remove"):
            out[key] = value
    remove = fragment.get("remove", {})
    if not isinstance(remove, dict) or not all(k in LIST_KEYS and isinstance(v, list) for k, v in remove.items()):
        raise RecordError(f"remove: expected {{section: [exact lines]}} for {', '.join(LIST_KEYS)}")
    for key, lines in remove.items():
        _strings(lines, f"remove.{key}", non_empty=False)
        if not lines:
            continue
        missing = [x for x in lines if x not in out.get(key, [])]
        if missing:
            raise RecordError(f"remove.{key}: no such line {missing[0]!r}")
        out[key] = [x for x in out[key] if x not in lines]
    by_id = _keyed(base.get("findings", []), "findings", "id")
    for fid, f in _keyed(fragment.get("findings", []), "fragment.findings", "id").items():
        by_id[fid] = {**by_id.get(fid, {}), **f}
    out["findings"] = sorted(by_id.values(), key=lambda f: f["id"])
    return out


def dump(data):
    try:
        return json.dumps(data, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    except (ValueError, RecursionError) as e:
        raise RecordError(f"findings: cannot serialize JSON: {e}") from None


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if (len(argv) < 2 or argv[0] not in ("check", "merge", "units", "renumber")
            or (argv[0] in ("merge", "units") and len(argv) < 3)
            or (argv[0] in ("check", "renumber") and len(argv) != 2)):
        print("usage:\n" + "\n".join(__doc__.splitlines()[2:6]), file=sys.stderr)
        return 2
    cmd, target, fragments = argv[0], Path(argv[1]), argv[2:]
    try:
        if cmd == "check":
            check_findings(load_json(target), units_beside(target))
            print(f"ok {target}")
            return 0
        if cmd == "units":
            result = check_units(load_json(target)) if record_exists(target) else {}
            for fragment in fragments:
                result = merge_units(result, load_json(fragment))
            check_units(result)
            beside = target.with_name("findings.json")
            if record_exists(beside):  # Every unit, entry and purpose reference in the record must stay valid.
                check_findings(load_json(beside), result, ordered=False)
            write_output(target, dump(result))
            print(f"wrote {target} ({len(result['purpose'])} purpose items, {len(result['entry_points'])} entry points, "
                  f"{len(result['units'])} units)")
            return 0
        if cmd == "renumber":
            data = check_findings(load_json(target), units_beside(target), ordered=False)
            mapping = renumber_map(data["findings"])
            moved = ", ".join(f"{old}->{new}" for old, new in sorted(mapping.items()) if old != new)
            if not moved and [f["id"] for f in data["findings"]] == list(mapping):
                print(f"{target}: findings already in order")
                return 0
            reordered = renumber(data, mapping)
            data = check_findings(reordered, units_beside(target))
            write_output(target, dump(data))
            print(f"renumbered {target}: {moved or 'reordered findings'}")
            return 0
        data = (check_findings(load_json(target), units_beside(target), ordered=False)
                if record_exists(target) else {"schema_version": 1, "findings": []})
        for fragment in fragments:
            data = merge(data, load_json(fragment))
        check_findings(data, units_beside(target), ordered=False)
        write_output(target, dump(data))
        print(f"wrote {target} ({len(data['findings'])} findings)")
        return 0
    except (RecordError, OSError) as e:
        print(f"findings.py: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
