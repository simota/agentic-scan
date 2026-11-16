#!/usr/bin/env python3
"""Merge finding fragments into findings.json and check a run's output directory.

    python3 findings.py merge FINDINGS FRAGMENT [FRAGMENT ...]
    python3 findings.py renumber FINDINGS
    python3 findings.py counts FINDINGS
    python3 findings.py check OUT_DIR [--repo CHECKOUT] [--allow NAME]...

A fragment is a JSON file written with the host's file-write tool (never a
shell heredoc or a generated script). It holds any of these top-level keys:
`meta` is merged key by key; `findings` and `conventions` records are matched
by `id`, a known record updated key by key and a new one appended;
`perspectives` are matched by `name` and `plan` batches by `batch`, both
replaced whole; the string lists (`checked_ok`, `decisions`, `limitations`,
`next_steps`) are appended without duplicates.
A `null` value removes an optional key from `meta`, a finding or a convention,
and `remove` deletes list items (`{"next_steps": ["exact text"]}`), ledger
entries by id (`{"conventions": ["C-05"]}`) or plan batches by number
(`{"plan": [3]}`) before the fragment's own items are added; list items take
the place of the first item removed from their list. A finding is never
removed: a wrong one is marked `FalsePositive` or `NotApplicable` with
evidence, as SKILL.md requires.
A complete finding whose ID already holds a finding with another title or
location is refused as an ID collision; a correction sends only the fields
that change. A new ID whose title and location match a recorded finding is
refused too, unless one is kept as `NotApplicable` "Duplicate of" the other,
or both as duplicates of the same finding: it is usually a fragment written
before `renumber`.
FINDINGS is created when absent. The merged record must pass the field shapes
of `reference/findings-schema.md` before anything is written; the rules that
span fields or records (enforcement agreeing with itself, a change reason on
Shared and Correction findings, `verify:` in steps,
exposure, a counterexample, invariants and a plan batch for Medium and above) are `check`'s, so a record may be
incomplete while it is being built.

`renumber` orders the findings by severity, then path and line of their first
location, excluded verdicts last, and renames them `F-001`… without gaps.
Every whole-word mention of an old ID in the record's prose, `depends_on` and
`plan` is rewritten in the same pass; `meta`, locations, enforcement sites, URLs,
commands and convention sources keep theirs.

`counts` prints the `n_*` summary counts for the chat summary or a draft,
one `name=value` per line, counted as report.md counts them (excluded
verdicts apart).

`check` is the run contract: the output directory holds exactly
`findings.json`, `dashboard.html` and `report.md` (plus `--allow` names), the
record is complete, IDs are gapless in severity, then path order with excluded
verdicts last (the order `renumber` gives), every perspective in
`reference/perspectives.md` is recorded, every cited convention exists and every
drifted one is cited by a Valid or Likely finding and every inferred one is
named in decisions, no finding outside the excluded verdicts sits under a
perspective not applied, High and Medium findings are traced (not Unverified)
and carry evidence, exposure, a counterexample, the invariants that must hold, an
enforcement record and steps, every enforcement record agrees with itself, every Shared and Correction
finding names its change_reason, every
recorded step says how it is verified, `depends_on` resolves without cycles,
every open Medium-or-higher finding sits in exactly one plan batch after its
dependencies, definitive evidence cites a `path:line` (a duplicate may name
the finding it repeats), and both rendered files match what `render.py`
produces from the current record in `meta.lang`. With `--repo`, each
location's and enforcement site's file must exist in that checkout and its line
must be within the file.

Exit codes: 0 ok, 1 a fragment was refused, input/output failed or the contract
failed (reasons on stderr), 2 the command line is wrong.
"""
import argparse
import contextlib
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import unicodedata

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
CHANGES = ("Local", "Shared", "Correction")
EFFORTS = ("S", "M", "L")
NETS = ("enforced", "partial", "none")
CONVENTION_STATUSES = ("holds", "drifted", "partly read", "not checked")
PERSPECTIVE_STATUSES = ("applied", "N/A", "not checked")
PERSPECTIVES = (
    "Boundaries and ranges", "Conditions and branches", "Null, empty and missing",
    "Numbers and money", "Dates, times and time zones", "State and lifecycle",
    "Collections and aggregation", "Text, encoding and locale", "In-process concurrency and ordering",
    "Rule duplication and drift", "Error paths and defaults", "Equality and types",
)
# Hunt step prefixes, in PERSPECTIVES order (reference/perspectives.md).
STEP_PREFIXES = ("BD", "CB", "NE", "NM", "DT", "SL", "CA", "TE", "CO", "RD", "ER", "EQ")
STEP_COUNTS = (3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3)
# The remedy names of reference/remedies.md, in its order.
REMEDIES = (
    "Fix Range Boundary", "Handle Empty and Extreme Inputs", "Correct the Condition",
    "Make Case Analysis Exhaustive", "Reorder Guards", "Distinguish Missing from Zero",
    "Make Absence Explicit", "Use Exact Arithmetic", "Centralise Rounding", "Make Units Explicit",
    "Use Zone-Aware Time", "Use Calendar Arithmetic", "Compare at the Right Granularity",
    "Enforce Transitions in One Place", "Derive State from One Source", "Fix Aggregation Key",
    "Make Ordering Explicit", "Copy Before Mutating", "Normalise Before Comparing",
    "Parse and Format with Explicit Locale", "Measure Text in Characters", "Make Check-and-Act Atomic",
    "Discard Stale Results", "Single Source for the Rule", "Align Code with the Stated Rule",
    "Propagate Errors Instead of Defaults", "Track Completeness", "Compare by Value with Matching Types",
)
CONCERNS = ("BOUNDARIES", "NUMBERS", "TIME", "STATE", "NULLS", "TEXT", "CONCURRENCY", "ERRORS",
            "OTHER")
# Evidence that is the duplicate statement and nothing else: `Duplicate of
# F-004`, `Duplicates F-004.`, `重複: F-004。`. Any other text, which could
# qualify or contradict it, needs a `path:line` like any other evidence; the
# reasons live in the finding it repeats.
DUPLICATE_OF = re.compile(r"(?i)\s*(?:duplicates?(?: of)?|重複[:：])\s*(F-[0-9]{3})\s*[.。]?\s*",
                          re.ASCII)
# `findings[].convention` names one ledger entry or several (`C-01, C-02`).
ID_LIST = re.compile(r"[\s,、，;；]+")
LISTS = ("checked_ok", "decisions", "limitations", "next_steps")
TOP_KEYS = {"meta", "findings", "conventions", "plan", "perspectives", *LISTS}
META_REQUIRED = ("project", "scope", "date", "assessor", "lang")
CONVENTION_REQUIRED = ("id", "idiom", "source", "status")
ALLOWED_CONVENTION_STATUS = {"Valid": ("drifted",), "Likely": ("drifted", "partly read")}
# Every key the schema knows in a record that is rendered. A typo such as
# `remdy` is refused instead of being kept and never shown. `meta` stays
# open for run context the outputs do not show.
CONVENTION_KEYS = {*CONVENTION_REQUIRED, "reason", "concern", "inferred"}
PERSPECTIVE_KEYS = {"name", "status", "note"}
VALIDATION_KEYS = {"verdict", "method", "evidence"}
ANALYSIS_KEYS = {"tool", "command", "result"}
REFERENCE_KEYS = {"url", "title"}
ENFORCEMENT_KEYS = {"net", "sites", "gaps"}
COUNTEREXAMPLE_KEYS = ("input", "expected", "actual", "oracle")
BATCH_KEYS = {"batch", "title", "findings", "prerequisite", "pr_title"}
TEXT_FIELDS = ("title", "hazard", "scenario", "blast_radius", "trace", "impact", "fix")
FINDING_REQUIRED = ("id", "severity", "change", "effort", "confidence", "category", "remedy",
                    "location", "validation", *TEXT_FIELDS)
FINDING_KEYS = {*FINDING_REQUIRED, "exposure", "counterexample", "enforcement", "invariants", "steps", "depends_on",
                "convention", "change_reason",
                "step", "status", "analysis", "references"}
# A step says how it is checked: `verify: the month-end test passes`.
VERIFY = re.compile(r"(?i)\bverify:")
OUTPUTS = {"findings.json", "dashboard.html", "report.md"}
TEMPORARY = re.compile(r"\.findings-[0-9a-f]{32}\.tmp")
# ASCII digits only: `\d` would also accept other scripts' digits.
FINDING_ID = re.compile(r"F-[0-9]{3}")
CONVENTION_ID = re.compile(r"C-[0-9]{2,}")
# Two digits at most, so `int()` never meets a huge value; no perspective has
# more than nine steps.
STEP_ID = re.compile(r"([A-Z]{2})([1-9][0-9]?)")
# A `path:line` candidate: it starts after a blank, opening punctuation or a
# label's colon (`根拠:job.py:58`), but not as the `//host` of a URL, so a port
# is not a line; it has a letter (`10:30` is not one) and a line from 1. A
# Windows drive (`C:\repo\a.py:3`) is allowed. `evidence_paths` finds them in
# one pass, so a long list of names in evidence stays linear.
PATH_RUN = re.compile(r"[^\s:]+")
LINE_AFTER = re.compile(r":[1-9][0-9]*")
PATH_START_AFTER = set("([{'\"`,;:")
# Extensionless files that hold code or rules (`Makefile` and `*file` match by suffix).
EXTENSIONLESS = {"BUILD", "BUILD.bazel", "WORKSPACE", "CODEOWNERS", "OWNERS", "LICENSE",
                 "VERSION", "MODULE.bazel", "README", "CHANGELOG", "NOTICE", "AUTHORS",
                 "CONTRIBUTING", "gradlew", "mvnw"}
# A file extension starts with a letter; `v1.2` and `e.g.` have none. A token
# ending in an unmistakable host suffix (`db.internal`, `api.example.com`) is a
# host and port. The list stays short on purpose: refusing a real file
# (`notes.org`, `.env.local`) fails a valid record, while passing a host only
# lets weak evidence through.
FILE_EXTENSION = re.compile(r"\.([A-Za-z][A-Za-z0-9_+-]{0,15})$")
HOST_SUFFIXES = {"com", "net", "io", "internal", "localhost"}
# At most nine digits per line number, so `int()` never meets a huge value.
LOCATION = re.compile(r"[^\r\n]+:([0-9]{1,9})(?:-([0-9]{1,9}))?")


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
    except (OSError, ValueError, RecursionError) as exc:
        # RecursionError: nesting too deep for the parser, e.g. a hand edit.
        raise SchemaError(f"{path}: {exc}") from exc


# Characters that render as nothing: Unicode's Default_Ignorable_Code_Point
# set (soft hyphen, joiners, variation selectors, Hangul fillers, Khmer
# inherent vowels, tags …) and the blank Braille pattern, beside the format,
# control, separator and unassigned categories `visible` skips.
BLANK_LOOKING = re.compile(
    "[\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180b-\u180f\u200b-\u200f"
    "\u202a-\u202e\u2060-\u206f\u2800\u3164\ufe00-\ufe0f\ufeff\uffa0\ufff0-\ufff8"
    "\U0001bca0-\U0001bca3\U0001d173-\U0001d17a\U000e0000-\U000e0fff]")


def visible(value):
    """True when value shows at least one character (`\u200b` alone does not)."""
    return any(not BLANK_LOOKING.match(c) and unicodedata.category(c)[0] not in "CZ"
               for c in value)


# C0 controls but tab, LF and CR; DEL; C1 controls. A terminal acts on them
# (`ESC[8m` hides the text after it, OSC 8 plants a link), so text copied from
# an audited repo shows them as code points wherever it is printed.
CONTROL = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")


def shown(text):
    """text with each control character written as `[U+001B]`."""
    return CONTROL.sub(lambda m: f"[U+{ord(m[0]):04X}]", str(text))


def shown_line(text):
    """shown(), with line breaks and tabs too: a message stays one line."""
    return re.sub("[\t\n\r]", lambda m: f"[U+{ord(m[0]):04X}]", shown(text))


def _text(value, where):
    if not isinstance(value, str) or not visible(value):
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


def _location(loc, where):
    parts = split_location(loc)
    if not parts:
        raise SchemaError(f"{where}: {loc!r} must be path:line")
    path, start, end = parts
    if not visible(path):
        raise SchemaError(f"{where}: {loc!r} must name a file before :line")
    if re.search("[\x00-\x1f\x7f-\x9f]", path):
        raise SchemaError(f"{where}: {loc!r} holds a control character")
    # Relative to the checkout root, so the record reads the same for anyone
    # who checks it, and names no one's home directory.
    if re.match(r"/|~(?:/|$)|[A-Za-z]:", path) or ".." in path.split("/"):
        raise SchemaError(f"{where}: {loc!r} must be relative to the repository root, "
                          "without ..")
    if "\\" in path:
        raise SchemaError(f"{where}: {loc!r} must separate directories with /, not \\")
    # `a.py/` and `a.py/.` name a directory, yet resolve to the file `a.py`.
    if path.rsplit("/", 1)[-1] in ("", "."):
        raise SchemaError(f"{where}: {loc!r} must name a file, not end in / or /.")
    # `path:line:col` would read as path `path:line`, and `path:l:c-l:c` as path
    # `path:l:c-l`; a column is not a location.
    if re.search(r":[0-9]+(?:-[0-9]+)?$", path):
        raise SchemaError(f"{where}: {loc!r} must be path:line, without a column")
    if not 1 <= start <= end:
        raise SchemaError(f"{where}: {loc!r} needs lines from 1, start <= end")


def validate_finding(f, where):
    if not isinstance(f, dict):
        raise SchemaError(f"{where}: must be an object")
    for key in FINDING_REQUIRED:
        if key not in f:
            raise SchemaError(f"{where}: missing {key}")
    _known(f, FINDING_KEYS, where)
    if not FINDING_ID.fullmatch(str(f["id"])):
        raise SchemaError(f"{where}.id: {f['id']!r} must look like F-001")
    for key in TEXT_FIELDS:
        _text(f[key], f"{where}.{key}")
    for key in ("convention", "exposure"):
        if key in f and not isinstance(f[key], str):
            raise SchemaError(f"{where}.{key}: must be a string")
    if "change_reason" in f:
        _text(f["change_reason"], f"{where}.change_reason")
    _choice(f["severity"], SEVERITIES, f"{where}.severity")
    _choice(f["change"], CHANGES, f"{where}.change")
    _choice(f["effort"], EFFORTS, f"{where}.effort")
    _choice(f["confidence"], CONFIDENCES, f"{where}.confidence")
    _choice(f["category"], PERSPECTIVES, f"{where}.category")
    _choice(f["remedy"], REMEDIES, f"{where}.remedy")
    _choice(f.get("status", "Open"), STATUSES, f"{where}.status")
    locations = as_locations(f["location"])
    if not locations:
        raise SchemaError(f"{where}.location: at least one path:line")
    for loc in locations:
        _location(loc, f"{where}.location")
    if "enforcement" in f:
        s = f["enforcement"]
        if not isinstance(s, dict):
            raise SchemaError(f"{where}.enforcement: must be an object")
        _known(s, ENFORCEMENT_KEYS, f"{where}.enforcement")
        _choice(s.get("net"), NETS, f"{where}.enforcement.net")
        for i, site in enumerate(_list(s.get("sites"), f"{where}.enforcement.sites")):
            _location(site, f"{where}.enforcement.sites[{i}]")
        _text(s.get("gaps"), f"{where}.enforcement.gaps")
    if "counterexample" in f:
        c = f["counterexample"]
        if not isinstance(c, dict):
            raise SchemaError(f"{where}.counterexample: must be an object")
        _known(c, set(COUNTEREXAMPLE_KEYS), f"{where}.counterexample")
        for key in COUNTEREXAMPLE_KEYS:
            _text(c.get(key), f"{where}.counterexample.{key}")
    for key in ("invariants", "steps"):
        for i, item in enumerate(_list(f.get(key, []), f"{where}.{key}")):
            _text(item, f"{where}.{key}[{i}]")
    deps = _list(f.get("depends_on", []), f"{where}.depends_on")
    for i, dep in enumerate(deps):
        if not isinstance(dep, str) or not FINDING_ID.fullmatch(dep):
            raise SchemaError(f"{where}.depends_on[{i}]: {dep!r} must look like F-001")
        if dep == f["id"]:
            raise SchemaError(f"{where}.depends_on: {dep} cannot depend on itself")
    if len(set(deps)) != len(deps):
        raise SchemaError(f"{where}.depends_on: duplicate IDs")
    if "step" in f:
        step = STEP_ID.fullmatch(f["step"]) if isinstance(f["step"], str) else None
        if not step or step[1] not in STEP_PREFIXES:
            raise SchemaError(f"{where}.step: {f['step']!r} must be a hunt step ID like SC2")
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


def evidence_paths(text):
    """Yield each `path:line` candidate's path, left to right, as a regex would.

    Every start inside one run of non-blank, non-colon text ends at the same
    `:line`, so the earliest valid start is found without backtracking.
    """
    def starts_here(i):
        return i == 0 or text[i - 1].isspace() or text[i - 1] in PATH_START_AFTER

    def letter(c):
        return c.isascii() and c.isalpha()

    consumed = 0
    for run in PATH_RUN.finditer(text):
        begin, end = max(run.start(), consumed), run.end()
        if begin >= end:
            continue  # already part of the previous path or its line
        # Without a drive: the earliest start whose path holds a letter.
        line = LINE_AFTER.match(text, end)
        plain = None
        if line:
            last = max((i for i in range(begin, end) if letter(text[i])), default=-1)
            # An opening bracket or quote starts the path after it, never the path.
            plain = next((i for i in range(begin, last + 1)
                          if starts_here(i) and text[i] not in PATH_START_AFTER
                          and not text.startswith("//", i)), None)
        # A Windows drive (`C:` and the next run) can only start at the run's
        # last character; the letter a path needs comes after the drive.
        drive = end - 1
        after = PATH_RUN.match(text, end + 1) if text.startswith(":", end) else None
        drive_line = (LINE_AFTER.match(text, after.end())
                      if after and any(letter(c) for c in after[0]) else None)
        if (drive_line and letter(text[drive]) and starts_here(drive)
                and (plain is None or plain >= drive)):
            consumed = drive_line.end()
            yield text[drive:after.end()]
        elif plain is not None:
            consumed = line.end()
            yield text[plain:end]


def cites_line(evidence, locations=()):
    """True when evidence names a file and a line, e.g. `job.py:58` or `BUILD:12`.

    A path or file name from the finding's own locations always counts
    (`server:9` beside `bin/server:9`). Otherwise a bare name ending in a host
    suffix is a host and port (`db.internal:5432`, `README.com:443`) and never
    counts; then a path with `/` or `\\`, a dotfile, a build or project file
    (`Makefile`, `CODEOWNERS`, `Dockerfile.dev`) or a name with a file extension
    does. `ABC:123`, `ratio:3` and `v1.2:3` do not.
    """
    known = _location_paths(locations)
    for path in evidence_paths(evidence):
        if path in known:
            return True
        has_dir = re.search(r"[/\\]", path) and not path.startswith("//")
        name = re.split(r"[/\\]", path)[-1]
        extension = FILE_EXTENSION.search(name)
        if not has_dir and extension and extension[1].lower() in HOST_SUFFIXES:
            continue  # a host and port, whatever its first label looks like
        stem = name.split(".")[0]
        if (has_dir or name.startswith(".")  # a dotfile: `.env.local`, `.eslintrc`
                or stem in EXTENSIONLESS or stem.lower().endswith("file") or extension):
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


def _batch_number(value):
    # bool is an int in Python; `true` is not batch 1.
    return isinstance(value, int) and not isinstance(value, bool) and value >= 1


def _validate_plan(batches, where):
    numbers = set()
    for i, b in enumerate(_list(batches, where)):
        field = f"{where}[{i}]"
        if not isinstance(b, dict):
            raise SchemaError(f"{field}: must be an object")
        _known(b, BATCH_KEYS, field)
        if not _batch_number(b.get("batch")):
            raise SchemaError(f"{field}.batch: must be an integer from 1")
        if b["batch"] in numbers:
            raise SchemaError(f"{field}.batch: duplicate {b['batch']}")
        numbers.add(b["batch"])
        for key in ("title", "prerequisite", "pr_title"):
            _text(b.get(key), f"{field}.{key}")
        ids = _list(b.get("findings"), f"{field}.findings")
        if not ids:
            raise SchemaError(f"{field}.findings: a batch holds at least one finding")
        for j, fid in enumerate(ids):
            if not isinstance(fid, str) or not FINDING_ID.fullmatch(fid):
                raise SchemaError(f"{field}.findings[{j}]: {fid!r} must look like F-001")
        if len(set(ids)) != len(ids):
            raise SchemaError(f"{field}.findings: duplicate IDs")
    return numbers


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
    for key in ("method", "commit", "window"):
        if key in meta and not isinstance(meta[key], str):
            raise SchemaError(f"meta.{key}: must be a string")
    seen = set()
    for i, f in enumerate(_list(doc.get("findings", []), "findings")):
        try:
            validate_finding(f, f"findings[{i}]")
        except SchemaError as exc:
            # The index is the merged record's; the ID is what a fragment names.
            if isinstance(f, dict) and isinstance(f.get("id"), str):
                raise SchemaError(f"{f['id']}: {exc}") from exc
            raise
        if f["id"] in seen:
            raise SchemaError(f"findings[{i}].id: duplicate {f['id']}")
        seen.add(f["id"])
    convention_ids = set()
    for i, r in enumerate(_list(doc.get("conventions", []), "conventions")):
        where = f"conventions[{i}]"
        if not isinstance(r, dict) or not CONVENTION_ID.fullmatch(str(r.get("id"))):
            raise SchemaError(f"{where}.id: must look like C-01")
        if r["id"] in convention_ids:
            raise SchemaError(f"{where}.id: duplicate {r['id']}")
        convention_ids.add(r["id"])
        _known(r, CONVENTION_KEYS, where)
        for key in ("idiom", "source"):
            _text(r.get(key), f"{where}.{key}")
        _choice(r.get("status"), CONVENTION_STATUSES, f"{where}.status")
        if "reason" in r and not isinstance(r["reason"], str):
            raise SchemaError(f"{where}.reason ({r['id']}): must be a string")
        if "concern" in r:
            _choice(r["concern"], CONCERNS, f"{where}.concern")
        if "inferred" in r and not isinstance(r["inferred"], bool):
            raise SchemaError(f"{where}.inferred ({r['id']}): must be true or false")
    _validate_plan(doc.get("plan", []), "plan")
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
    # The same locations in another order are the same finding, reordered.
    return sorted(map(str, as_locations(a))) == sorted(map(str, as_locations(b)))


def _duplicate_of(f):
    """The ID f repeats when it is kept as `NotApplicable`, "Duplicate of F-…"."""
    v = f.get("validation")
    if not isinstance(v, dict) or v.get("verdict") != "NotApplicable":
        return None
    evidence = v.get("evidence")
    m = DUPLICATE_OF.fullmatch(evidence) if isinstance(evidence, str) else None
    return m[1] if m else None


def _twins_allowed(a, a_id, b, b_id):
    """A declared duplicate beside the finding it names, or two of one finding."""
    a_of, b_of = _duplicate_of(a), _duplicate_of(b)
    return a_of == b_id or b_of == a_id or (a_of is not None and a_of == b_of)


def _same_title(a, b):
    return " ".join(str(a).split()) == " ".join(str(b).split())


def _collides(existing, record):
    """A record unlike the finding that holds its ID: another unit's finding.

    Two findings can share a location, so in a complete record either a new
    title or a new location marks a different finding. A partial record that
    changes both title and location is another finding too, even with a field
    missing; a correction changes one of them at a time.
    """
    if "title" not in record or "location" not in record:
        return False
    new_title = not _same_title(record["title"], existing.get("title", ""))
    new_location = not _same_location(record["location"], existing.get("location"))
    if all(key in record for key in FINDING_REQUIRED):
        return new_title or new_location
    return new_title and new_location


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
                hint = ("give the new finding another ID, or send only the fields that change"
                        if all(key in record for key in FINDING_REQUIRED) else
                        "a record changing both title and location is taken for another "
                        "finding; give it another ID, or correct them in separate fragments")
                raise SchemaError(
                    f"{where}: {rid} already holds {index[rid].get('title')!r}; {hint}")
            _apply(index[rid], record, required, f"{where}.{rid}")
        else:
            if required is FINDING_REQUIRED and "title" in record and "location" in record:
                # A fragment written before renumber still names the old ID;
                # appending it would record the finding twice. A duplicate kept
                # as NotApplicable, "Duplicate of F-…", shares the title and
                # location of the finding it names and of its other duplicates.
                twin = next((r for r in current if _same_title(r.get("title"), record["title"])
                             and _same_location(r.get("location"), record["location"])
                             and not _twins_allowed(record, rid, r, r.get("id"))), None)
                if twin is not None:
                    raise SchemaError(
                        f"{where}: {rid} repeats {twin['id']} (same title and location); if "
                        f"renumber renamed it, rewrite the fragment with the new ID or send "
                        f"only the fields that change")
            current.append(_apply({}, record, required, f"{where}.{rid}"))
            index[rid] = current[-1]


def _remove_items(doc, removals, where):
    """Delete the named items; return, per string list, where the first one stood."""
    if not isinstance(removals, dict):
        raise SchemaError(f"{where}: must be an object of list names")
    unknown = set(removals) - set(LISTS) - {"conventions", "plan"}
    if unknown:
        raise SchemaError(f"{where}: only conventions, plan and {', '.join(LISTS)} can be "
                          f"removed from, not {sorted(unknown)} (a finding is never removed: "
                          "mark it FalsePositive or NotApplicable with evidence; a perspective "
                          "is replaced, not removed)")
    slots = {}
    for key, values in removals.items():
        if key in ("conventions", "plan"):
            # A spurious ledger entry by id, or a batch by number; check then
            # catches a finding citing the entry or left without a batch.
            field = "id" if key == "conventions" else "batch"
            for rid in _list(values, f"{where}.{key}"):
                ids = [r.get(field) for r in doc.get(key, [])]
                # `1.0 == 1` and `true == 1`, but neither is batch 1.
                valid = isinstance(rid, str) if key == "conventions" else _batch_number(rid)
                if not valid or rid not in ids:
                    raise SchemaError(f"{where}.{key}: {rid!r} is not recorded")
                del doc[key][ids.index(rid)]
            continue
        for value in _list(values, f"{where}.{key}"):
            if value not in doc.get(key, []):
                raise SchemaError(f"{where}.{key}: {value!r} is not recorded")
            index = doc[key].index(value)
            slots[key] = min(slots.get(key, index), index)
            del doc[key][index]
    return slots


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
    slots = {}
    if "remove" in fragment:
        # First, so one fragment can remove an entry and send its replacement.
        removed = fragment["remove"]
        if isinstance(removed, dict) and isinstance(removed.get("conventions"), list):
            # A removed entry comes back only as a whole new entry, never as a correction.
            partial = {r.get("id") for r in fragment["conventions"] if isinstance(r, dict)
                       and isinstance(r.get("id"), str)
                       and not all(key in r for key in CONVENTION_REQUIRED)} \
                if isinstance(fragment.get("conventions"), list) else set()
            both = sorted(rid for rid in removed["conventions"] if isinstance(rid, str)
                          and rid in partial)
            if both:
                raise SchemaError(f"{where}: {', '.join(both)} is removed, so the convention "
                                  "sent with that ID must be complete; to correct it, send "
                                  "only the fields that change and do not remove it")
        slots = _remove_items(doc, removed, f"{where}.remove")
    for key in ("findings", "conventions", "perspectives", "plan"):
        if key not in fragment:
            continue
        if not isinstance(fragment[key], list):
            raise SchemaError(f"{where}.{key}: must be a list")
        if key == "perspectives":
            names = _validate_perspectives(fragment[key], f"{where}.{key}")
            doc[key] = [q for q in doc.get(key, []) if q.get("name") not in names]
            doc[key].extend(fragment[key])
        elif key == "plan":
            # A batch is replaced whole; the plan stays in batch order.
            numbers = _validate_plan(fragment[key], f"{where}.{key}")
            doc[key] = [b for b in doc.get(key, []) if b.get("batch") not in numbers]
            doc[key].extend(fragment[key])
            doc[key].sort(key=lambda b: b["batch"])
        else:
            required = FINDING_REQUIRED if key == "findings" else CONVENTION_REQUIRED
            _merge_records(doc.setdefault(key, []), fragment[key], f"{where}.{key}", required)
    for key in LISTS:
        if key in fragment:
            if not isinstance(fragment[key], list):
                raise SchemaError(f"{where}.{key}: must be a list")
            target = doc.setdefault(key, [])
            added = []
            for v in fragment[key]:
                if v not in target and v not in added:
                    added.append(v)
            # A replacement keeps the removed item's place: these lists are ordered.
            at = slots.get(key, len(target))
            target[at:at] = added
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


# A run of IDs standing free in prose: one ID, or several joined by `/` or `-`
# (`F-002/F-001`, `F-001-F-002-F-003`). Every ID in a run is a mention. A run
# touching a word, path or ticket (`docs/F-001.md`, `JIRA-F-001`,
# `F-001-F-002.md`) is not prose and stays whole; URLs and e-mail addresses
# are skipped whole by `_url_spans`. ASCII word characters only, so a run
# beside Japanese text (`F-001を`) is still a mention.
ID_RUN = re.compile(
    r"(?<![\w/\\-])F-[0-9]{3}(?:[/-]F-[0-9]{3})*(?![\w/\\-]|\.[A-Za-z0-9])", re.ASCII)


# Where a URL starts in prose: a scheme with `//`, or `urn:`; and, with no
# boundary before them, exactly what render.py's AUTOLINK links even right
# after a word (`seeWWW.example.com`, `1https://x`).
URL_START = re.compile(r"(?i:https?|ftp|mailto|xmpp):|(?i:www)\."
                       r"|(?<![A-Za-z0-9+.-])(?:[A-Za-z][A-Za-z0-9+.-]*://|(?i:urn):)")


# A bare e-mail address: an RFC 5322 dot-atom local part (atoms joined by
# single dots, so `F-001.@x`, `.F-001@x` and `F-001..b@x` are not), `@`, a domain (one
# label, `@mailhost`, or several) that ends the token, so `F-001@scope/pkg`
# is not an address.
# It starts only where a run of local-part characters starts, so a long run
# with no address in it is read once, not once per character. The address is
# ASCII on purpose: Japanese prose has no blanks between words, so a non-ASCII
# local part or domain would swallow the sentence before or after it
# (`F-001の担当はowner@example.com`, `owner@example.comに連絡してF-001を直す`)
# and hide the mention in it.
EMAIL = re.compile(r"((?<![A-Za-z0-9!#$%&'*+/=?^_`{|}~.-])"
                   r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*"
                   r"@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
                   r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*"
                   r"(?![\w/@\\-]|\.[\w.-]))", re.ASCII)


def _url_spans(text):
    """Split text into prose and literals (URLs, e-mail addresses), alternating.

    A URL runs to a blank or to punctuation outside ASCII (`…/x。F-001`,
    `（https://x）F-001`), so an IRI's letters (`?project=案件&key=F-001`) stay
    inside it. Japanese prose often follows a URL without a blank, joined by a
    particle, so an ID right after hiragana starts the prose again
    (`…/7でF-001を`). A trade-off: an IRI with hiragana right before an ID is
    read as prose there, while kanji or katakana (`/wiki/仕様F-001`) stay
    inside the link. An address is taken whole (`owner!F-001!tag@example.com`).
    """
    parts, prose = [], 0
    for start in URL_START.finditer(text):
        if start.start() < prose:
            continue
        end = start.end()
        while end < len(text) and not text[end].isspace() and not (
                ord(text[end]) > 127 and unicodedata.category(text[end])[0] in "PSZ"):
            end += 1
            if "\u3041" <= text[end - 1] <= "\u309f" and FINDING_ID.match(text, end):
                break
        parts += [text[prose:start.start()], text[start.start():end]]
        prose = end
    parts.append(text[prose:])
    # Addresses in the prose parts: EMAIL.split alternates prose and address.
    return [piece for i, part in enumerate(parts)
            for piece in (EMAIL.split(part) if i % 2 == 0 else [part])]


def _first_location(f):
    path, start, _ = split_location(as_locations(f["location"])[0])
    return path, start


# Literal values that only look like prose: a path (`location`, `enforcement.sites`),
# a URL, a command that ran, a convention's source. An `F-001` in them is a
# file, ticket or argument, not a finding.
LITERAL_KEYS = {"location", "sites", "url", "command", "source"}


def _rewrite_ids(value, mapping, key=None):
    if key in LITERAL_KEYS:
        return value
    if isinstance(value, str):
        # A URL in prose (`browse?key=F-001`, `#F-001`) is a link, not a mention.
        return "".join(part if i % 2 else ID_RUN.sub(
            lambda run: re.sub(r"F-[0-9]{3}", lambda m: mapping.get(m[0], m[0]), run[0]), part)
            for i, part in enumerate(_url_spans(value)))
    if isinstance(value, list):
        return [_rewrite_ids(v, mapping, key) for v in value]
    if isinstance(value, dict):
        return {k: _rewrite_ids(v, mapping, k) for k, v in value.items()}
    return value


def renumber(doc):
    """Return (doc, mapping): findings in severity then path order, IDs gapless.

    Excluded findings (FalsePositive, NotApplicable) follow the rest, so a
    duplicate never takes a number between the findings to act on.
    """
    findings = doc.get("findings", [])
    order = sorted(range(len(findings)), key=lambda i: (
        findings[i]["validation"]["verdict"] in EXCLUDED,
        SEVERITIES.index(findings[i]["severity"]), _first_location(findings[i]), i))
    mapping = {findings[i]["id"]: f"F-{n:03d}" for n, i in enumerate(order, 1)}
    # One pass over the old text, so F-001 -> F-002 and F-002 -> F-001 do not chain.
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
def _exclusive(target, create=True):
    """Hold an exclusive lock on target's directory from read to replace.

    Two merges started together would otherwise both read the same record and
    the later replace would drop the other's findings. The lock is on the
    directory, so no lock file joins the outputs; render and check take the
    same lock (`locked_dir`). Without fcntl (Windows), run merges one at a time.
    """
    directory = target.resolve().parent
    # The directory is never removed again: a merge may already hold it open,
    # waiting for the lock, and would then lock a deleted directory. Only merge
    # creates it; renumber on a mistyped path leaves nothing behind.
    if create:
        directory.mkdir(parents=True, exist_ok=True)
    yield from _locked(directory)


def _locked(directory):
    if fcntl is None:
        yield
        return
    try:
        fd = os.open(directory, os.O_RDONLY)
    except PermissionError as exc:
        # Unlocked, parallel merges lose findings while each reports success,
        # and check could not list the directory anyway.
        raise OSError(f"cannot lock {directory}: this user cannot read it; make it "
                      "readable to run merge, renumber, render or check there") from exc
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            # Say why nothing happens: a stopped or slow writer holds it.
            print(f"waiting for the lock on {directory}: a merge, renumber, render or check "
                  "is running there", file=sys.stderr, flush=True)
            fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


@contextmanager
def locked_dir(directory):
    """Hold the output directory's lock, as merge and renumber do."""
    yield from _locked(Path(directory).resolve())


def cmd_renumber(args):
    target = Path(args.findings)
    try:
        if not target.is_file():
            raise SchemaError(f"{target}: no such record")
        with _exclusive(target, create=False):
            changed, rewritten = _renumber_file(target)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"refused: {shown_line(exc)}", file=sys.stderr)
        return 1
    _report_renumber(target, changed, rewritten)
    return 0


def _renumber_file(target):
    """Renumber target in place; return (ID mapping, whether the record changed)."""
    doc = read_json(target)
    validate(doc)
    if len(doc.get("findings", [])) > 999:
        raise SchemaError(f"{target}: more than 999 findings cannot be numbered F-NNN")
    renamed, changed = renumber(doc)
    validate(renamed)
    # IDs that already hold their final names can still sit in the wrong order
    # (fragments merged F-004 before F-001), so compare the whole record.
    rewritten = _serialize(renamed) != _serialize(doc)
    if rewritten:
        _atomic_write(target, _serialize(renamed))
    return changed, rewritten


def _report_renumber(target, changed, rewritten):
    for old, new in sorted(changed.items()):
        print(f"{old} -> {new}")
    if changed:
        print(f"renumbered {len(changed)} finding(s) in {target}")
        # A fragment written before this run still names the old IDs, and merge
        # would apply it to whichever finding holds that ID now.
        print("use only the new IDs from here on; rewrite any unmerged fragment first",
              file=sys.stderr)
    elif rewritten:
        print(f"reordered the findings in {target}; every ID kept its name")
    else:
        print(f"already in order: {target}")


def _merge_all(doc, fragments):
    validate(doc)
    for path in fragments:
        fragment = read_json(path)  # its errors already name the file
        try:
            merge(doc, fragment, "fragment")
        except SchemaError as exc:
            raise SchemaError(f"{path}: {exc}") from exc
        # Each fragment must leave a valid record, even in a batch; name the
        # fragment that broke it.
        try:
            validate(doc)
        except SchemaError as exc:
            raise SchemaError(f"{path}: {exc}") from exc
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
        print(f"refused: {shown_line(exc)}", file=sys.stderr)
        return 1
    print(f"merged {len(args.fragments)} fragment(s) into {target}: "
          f"{len(doc.get('findings', []))} finding(s)")
    return 0


def template_counts(doc):
    """The `n_*` summary counts, counted as report.md counts them."""
    findings = doc.get("findings", [])
    active = [f for f in findings if f["validation"]["verdict"] not in EXCLUDED]
    counts = {}
    for severity in SEVERITIES:
        same = [f for f in active if f["severity"] == severity]
        counts[f"n_{severity.lower()}"] = len(same)
        counts[f"n_{severity.lower()}_valid"] = sum(f["validation"]["verdict"] == "Valid"
                                                    for f in same)
    counts["n_excluded"] = len(findings) - len(active)
    for verdict in ("Likely", "Unverified", "Unlikely"):
        counts[f"n_{verdict.lower()}"] = sum(f["validation"]["verdict"] == verdict
                                             for f in findings)
    # The record describes the assessed revision, so a fixed finding still
    # counts above; these say how many of them have since been closed.
    for status in ("Fixed", "Accepted"):
        counts[f"n_{status.lower()}"] = sum(f.get("status") == status for f in active)
    for change in CHANGES:
        counts[f"n_{change.lower()}"] = sum(f["change"] == change for f in active)
    counts["n_batches"] = len(doc.get("plan", []))
    return counts


def cmd_counts(args):
    try:
        doc = read_json(args.findings)
        validate(doc, complete=True)
    except SchemaError as exc:
        print(f"refused: {shown_line(exc)}", file=sys.stderr)
        return 1
    for name, value in template_counts(doc).items():
        print(f"{name}={value}")
    return 0


def cited_conventions(f):
    """The ledger IDs a finding's `convention` names, in order."""
    return [cid for cid in ID_LIST.split(f.get("convention", "")) if cid]


def _readiness_problems(f):
    """What a High or Medium finding needs before it can be planned (SKILL.md)."""
    problems, fid, sev = [], f["id"], f["severity"]
    if not visible(f.get("exposure", "")):
        problems.append(f"{fid}: a {sev} finding needs exposure: the core flow it breaks, "
                        "the callers that reach it, or fix commits by hash that patched the same rule")
    if "counterexample" not in f:
        problems.append(f"{fid}: a {sev} finding needs counterexample {{input, expected, actual, "
                        "oracle}: one concrete input, the right and the wrong result, and where "
                        "the right one is stated")
    if not f.get("invariants"):
        problems.append(f"{fid}: a {sev} finding needs invariants: the rules that must hold "
                        "once it is fixed, each one an assertion a test could make")
    if not f.get("steps"):
        problems.append(f"{fid}: a {sev} finding needs steps, each ending with production "
                        "working")
    if "enforcement" not in f:
        problems.append(f"{fid}: a {sev} finding needs enforcement {{net, sites, gaps}}: what "
                        "enforces the rule today (a test, a type, a validation)")
    return problems


def _step_problems(f):
    """Every recorded step, at any severity, says how it is checked (reference/plan.md §4)."""
    return [f"{f['id']}: step {i} does not say how it is checked (add `verify: …`)"
            for i, step in enumerate(f.get("steps", []), 1) if not VERIFY.search(step)]


def _enforcement_problems(f):
    """The enforcement record agrees with itself (SKILL.md)."""
    if "enforcement" not in f:
        return []
    s, fid, problems = f["enforcement"], f["id"], []
    if s["net"] == "none" and s["sites"]:
        problems.append(f"{fid}: enforcement.net is none but enforcement.sites lists sites")
    if s["net"] != "none" and not s["sites"]:
        problems.append(f"{fid}: enforcement.net is {s['net']}; name the tests, types or "
                        "validations that enforce the rule today")
    return problems


def _change_problems(f):
    """A Shared or Correction finding names what reaches beyond the one site (SKILL.md)."""
    if f["change"] in ("Shared", "Correction") and "change_reason" not in f:
        return [f"{f['id']}: a {f['change']} finding needs change_reason: "
                + ("the callers whose results the fix changes" if f["change"] == "Shared"
                   else "the results already produced wrong that need correcting")]
    return []


def _dependency_problems(findings):
    """`depends_on` names recorded, kept findings and forms no cycle."""
    by_id = {f["id"]: f for f in findings}
    problems = []
    for f in findings:
        for dep in f.get("depends_on", []):
            if dep not in by_id:
                problems.append(f"{f['id']}: depends_on {dep} is not a recorded finding")
            elif by_id[dep]["validation"]["verdict"] in EXCLUDED:
                problems.append(f"{f['id']}: depends_on {dep}, which is excluded "
                                f"({by_id[dep]['validation']['verdict']})")
    # Depth-first search; a grey node met again closes a cycle. Iterative, so a
    # chain as long as F-NNN allows (999) stays under the recursion limit.
    state, cycles = {}, []
    for root in by_id:
        if root in state:
            continue
        state[root] = "grey"
        path, pending = [root], [iter(by_id[root].get("depends_on", []))]
        while pending:
            dep = next(pending[-1], None)
            if dep is None:
                state[path.pop()] = "black"
                pending.pop()
            elif dep not in by_id:
                continue
            elif state.get(dep) == "grey":
                cycles.append(path[path.index(dep):] + [dep])
            elif dep not in state:
                state[dep] = "grey"
                path.append(dep)
                pending.append(iter(by_id[dep].get("depends_on", [])))
    for cycle in cycles:
        problems.append(f"depends_on forms a cycle: {' -> '.join(cycle)}; findings that depend "
                        "on each other are one remedy, so merge them")
    return problems


def _plan_problems(doc):
    """Every open Medium-or-higher finding is in one batch, after its dependencies."""
    findings = {f["id"]: f for f in doc.get("findings", [])}
    plan = doc.get("plan", [])
    problems = []
    numbers = [b["batch"] for b in plan]
    if numbers != list(range(1, len(plan) + 1)):
        problems.append(f"plan: batches must be numbered 1… without gaps, in order; got "
                        f"{', '.join(map(str, numbers))}")
    where, position = {}, {}
    for b in plan:
        # A fix that must also correct results already produced is decided and reviewed on its own.
        correction = [fid for fid in b["findings"] if fid in findings
                    and findings[fid]["change"] == "Correction"]
        if correction and len(b["findings"]) > 1:
            problems.append(f"plan batch {b['batch']}: a Correction finding stands alone in its "
                            f"batch; split {', '.join(b['findings'])}")
        for i, fid in enumerate(b["findings"]):
            position.setdefault(fid, i)
            f = findings.get(fid)
            if f is None:
                problems.append(f"plan batch {b['batch']}: {fid} is not a recorded finding")
            elif f["validation"]["verdict"] in EXCLUDED:
                problems.append(f"plan batch {b['batch']}: {fid} is excluded "
                                f"({f['validation']['verdict']}) and cannot be planned")
            if fid in where:
                problems.append(f"plan: {fid} is in batch {where[fid]} and batch {b['batch']}")
            else:
                where[fid] = b["batch"]

    def open_kept(f):
        return f.get("status", "Open") == "Open" and f["validation"]["verdict"] not in EXCLUDED

    for fid, f in findings.items():
        if open_kept(f) and f["severity"] in ("High", "Medium") and fid not in where:
            problems.append(f"{fid}: an open {f['severity']} finding needs a plan batch")
        if fid not in where:
            continue
        for dep in f.get("depends_on", []):
            d = findings.get(dep)
            if d is None or not open_kept(d):
                continue  # done, accepted or excluded: nothing to order
            if dep not in where:
                problems.append(f"{fid} (batch {where[fid]}) depends on {dep}, which is in no "
                                "batch; plan it first")
            elif where[dep] > where[fid]:
                problems.append(f"{fid} (batch {where[fid]}) depends on {dep}, planned later in "
                                f"batch {where[dep]}")
            elif where[dep] == where[fid] and position[dep] > position[fid]:
                problems.append(f"{fid} depends on {dep}, listed after it in batch {where[fid]}; "
                                "list the dependency first")
    return problems


def contract_problems(out, allow=()):
    """Return the run-contract violations for an output directory."""
    return _contract(out, allow)[0]


def _contract(out, allow):
    """(violations, the record they were checked against or None)."""
    out = Path(out)
    if not out.is_dir():
        return [f"output directory does not exist or is not a directory: {out}"], None
    try:
        present = {p.name for p in out.iterdir()}
    except OSError as exc:
        return [f"output directory cannot be listed: {exc}"], None
    problems = []
    for name in sorted(OUTPUTS - present):
        problems.append(f"missing output: {name}")
    for name in sorted(present - OUTPUTS - set(allow)):
        if TEMPORARY.fullmatch(name):
            problems.append(f"unexpected output: {name} is a temporary file from an interrupted "
                            "write; delete it once no merge or render is running")
        else:
            problems.append(f"unexpected output: {name} (pass --allow {name} if requested)")
    not_files = {name for name in OUTPUTS & present if not (out / name).is_file()}
    for name in sorted(not_files):
        problems.append(f"output is not a file: {name}")
    # Writes follow a link, so a planted one sends the rendered files elsewhere;
    # a findings.json link is kept by design (_stage).
    for name in sorted({"dashboard.html", "report.md"} & present):
        if (out / name).is_symlink():
            problems.append(f"output is a symlink: {name}; the outputs are plain files in a "
                            "new directory")
    if "findings.json" not in present or "findings.json" in not_files:
        return problems, None
    try:
        doc = read_json(out / "findings.json")
        validate(doc, complete=True)
    except SchemaError as exc:
        return problems + [f"findings.json: {exc}"], None
    findings = doc.get("findings", [])
    expected = [f"F-{i:03d}" for i in range(1, len(findings) + 1)]
    ids_gapless = [f["id"] for f in findings] == expected
    if not ids_gapless:
        problems.append(f"IDs must be gapless in order: expected {', '.join(expected) or 'none'}; "
                        "run renumber")
    ranks = [SEVERITIES.index(f["severity"]) for f in findings if
             f["validation"]["verdict"] not in EXCLUDED]
    if ranks != sorted(ranks):
        problems.append("findings must be numbered in severity order (High first); run renumber")
    excluded = [f["validation"]["verdict"] in EXCLUDED for f in findings]
    if excluded != sorted(excluded):
        problems.append("excluded findings (FalsePositive, NotApplicable) are numbered after "
                        "the rest; run renumber")
    elif ids_gapless and ranks == sorted(ranks) and renumber(doc)[1]:
        # What is left: path order within a severity, or severity order among the
        # excluded findings.
        problems.append("findings must be numbered in renumber's order: severity, then path and "
                        "line of the first location, excluded ones last in the same order; "
                        "run renumber")
    recorded = {p["name"]: p["status"] for p in doc.get("perspectives", [])}
    for name in PERSPECTIVES:
        if name not in recorded:
            problems.append(f"perspective not recorded: {name}")
    convention_status = {r["id"]: r["status"] for r in doc.get("conventions", [])}
    kept = {f["id"] for f in findings if f["validation"]["verdict"] not in EXCLUDED}
    for f in findings:
        verdict, evidence = f["validation"]["verdict"], f["validation"].get("evidence", "")
        for cid in cited_conventions(f):
            status = convention_status.get(cid)
            allowed = ALLOWED_CONVENTION_STATUS.get(verdict)
            if status is None:
                problems.append(f"{f['id']}: convention {cid!r} is not a conventions[] id")
            elif allowed and status not in allowed:
                # A Valid finding is traced drift; a Likely one may still sit on
                # an idiom whose sites were partly read.
                problems.append(f"{f['id']}: {verdict} finding cites {cid}, recorded as "
                                f"{status}, not {' or '.join(allowed)}")
        # A duplicate's evidence is the reported finding that keeps it, whose
        # own evidence cites the line; renumber rewrites the ID with the rest.
        duplicate = verdict == "NotApplicable" and any(
            m[1] in kept for m in [DUPLICATE_OF.fullmatch(evidence)] if m)
        if verdict in DEFINITIVE and not duplicate and not cites_line(evidence, f["location"]):
            problems.append(f"{f['id']}: {verdict} evidence must cite path:line"
                            + (" (or, for a duplicate, the finding it repeats)"
                               if verdict == "NotApplicable" else ""))
        if verdict in EXCLUDED:
            if f.get("depends_on"):
                problems.append(f"{f['id']}: an excluded finding ({verdict}) is not planned, so "
                                "it carries no depends_on; remove it")
            continue
        if f["severity"] == "High" and f["confidence"] != "Confirmed":
            problems.append(f"{f['id']}: a High finding rests on a traced hazard and recorded "
                            f"exposure, so it is Confirmed, not {f['confidence']}; record the "
                            "evidence, or lower the severity")
        if f.get("status") == "Accepted" and not any(
                # ASCII boundaries, as in ID_RUN: "F-003は" names F-003.
                re.search(rf"(?<!\w){f['id']}(?!\w)", item, re.ASCII)
                for item in doc.get("decisions", [])):
            problems.append(f"{f['id']}: Accepted means a person chose to keep the code as it "
                            "is; name the finding, who decided and why in decisions")
        if recorded.get(f["category"], "applied") != "applied":
            problems.append(f"{f['id']}: category {f['category']} is recorded as "
                            f"{recorded[f['category']]}, not applied")
        problems += _enforcement_problems(f) + _change_problems(f) + _step_problems(f)
        if f["severity"] in ("High", "Medium"):
            # SKILL.md: never report a High or Medium finding that was not traced.
            if verdict == "Unverified":
                problems.append(f"{f['id']}: an Unverified {f['severity']} finding was not "
                                "traced; trace it and record the verdict (Valid, Likely or "
                                "Unlikely) with its evidence")
            elif not visible(evidence):
                problems.append(f"{f['id']}: a {f['severity']} finding needs validation.evidence "
                                "naming what the trace found")
            problems += _readiness_problems(f)
    problems += _dependency_problems(findings)
    problems += _plan_problems(doc)
    if any(f["confidence"] == "Confirmed" for f in findings
           if f["validation"]["verdict"] not in EXCLUDED):
        for key, what in (("window", "history window"), ("commit", "assessed revision")):
            if not visible(doc["meta"].get(key) or ""):
                problems.append(f"meta.{key}: a Confirmed exposure follows from recorded history, "
                                f"so name the {what}")
    # Only a finding that establishes the drift, and says so in `convention`,
    # backs a `drifted` entry.
    named = {cid for f in findings if f["validation"]["verdict"] in ("Valid", "Likely")
             for cid in cited_conventions(f)}
    for r in doc.get("conventions", []):
        if r["status"] == "drifted" and r["id"] not in named:
            problems.append(f"{r['id']}: a drifted convention needs a Valid or Likely finding "
                            "that cites it in convention")
        if r.get("inferred") is True and not any(
                re.search(rf"(?<!\w){re.escape(r['id'])}(?!\w)", item, re.ASCII)
                for item in doc.get("decisions", [])):
            # reference/conventions.md §1: no fix is written towards a rule
            # a person has not confirmed.
            problems.append(f"{r['id']}: an inferred rule goes to decisions for a person to "
                            "confirm; name it there")
        if r["status"] in ("holds", "drifted") and visible(r.get("reason", "")):
            # Usually a provisional `not checked` reason left behind by the fragment
            # that closed the entry; it would render under the final status.
            problems.append(f"{r['id']}: a reason explains a not-checked or partly-read "
                            f"convention; send \"reason\": null with its final status, "
                            f"{r['status']}")
        if r["status"] == "not checked":
            reason = r.get("reason")
            if not isinstance(reason, str) or not visible(reason):
                problems.append(f"{r['id']}: a not-checked convention needs a nonblank string "
                                "reason")
    if not doc.get("limitations"):
        problems.append("limitations: state what static reading cannot show")
    if not doc.get("checked_ok"):
        problems.append("checked_ok: list what was examined and judged sound")
    return problems + _stale_outputs(out, doc, not_files | (OUTPUTS - present)), doc


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


def _count_lines(file):
    """Lines in file, ending at LF, CRLF or a lone CR, as editors count them."""
    count, last = 0, b""
    with file.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            count += chunk.count(b"\n") + chunk.count(b"\r") - chunk.count(b"\r\n")
            if last == b"\r" and chunk[:1] == b"\n":
                count -= 1  # a CRLF split across two chunks
            last = chunk[-1:]
    return count + (last not in (b"", b"\n", b"\r"))


def location_problems(doc, repo):
    """Name each location or enforcement site whose file or line is not in the checkout."""
    repo = Path(repo)
    if not repo.is_dir():
        return [f"--repo: not a directory: {repo}"]
    root = repo.resolve()
    problems, lines = [], {}
    for f in doc.get("findings", []):
        named = [("location", loc) for loc in as_locations(f["location"])]
        named += [("enforcement.sites", site) for site in f.get("enforcement", {}).get("sites", [])]
        for field, loc in named:
            path, start, end = split_location(loc)
            file = repo / path
            if path not in lines:
                try:
                    resolved = file.resolve()
                    # A location names a file of the assessed checkout, never one outside it.
                    if resolved != root and root not in resolved.parents:
                        raise FileNotFoundError(path)
                    if not resolved.is_file():
                        raise FileNotFoundError(path)
                    lines[path] = _count_lines(resolved)
                # ValueError: a NUL in the path; RuntimeError: a symlink loop
                # before Python 3.13.
                except (OSError, ValueError, RuntimeError):
                    lines[path] = None
            if lines[path] is None:
                problems.append(f"{f['id']}: {field} {loc}: no such file in {repo}")
            elif max(start, end) > max(lines[path], 1):  # line 1 of an empty file
                problems.append(f"{f['id']}: {field} {loc}: line {max(start, end)} is past "
                                f"the end of {path} ({lines[path]} lines)")
    return problems


def cmd_check(args):
    out = Path(args.out)
    try:
        # A merge or render in progress has a staged temporary file in the
        # directory; wait for it instead of calling it an interrupted write.
        # The locations are read from the same locked record as the rest.
        with locked_dir(out) if out.is_dir() else contextlib.nullcontext():
            problems, doc = _contract(out, args.allow)
            if args.repo is not None and doc is not None:  # else the record is named above
                problems += location_problems(doc, args.repo)
    except (OSError, RuntimeError) as exc:
        problems = [f"output directory cannot be checked: {exc}"]
    for problem in problems:
        print(shown_line(problem), file=sys.stderr)
    if problems:
        return 1
    print(f"contract ok: {args.out}")
    return 0


def safe_output():
    """Print paths that are not valid UTF-8 (`o\\xff/`) instead of crashing after the work."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="backslashreplace")
        except (AttributeError, ValueError, OSError):
            pass  # not a text stream (StringIO, None) or already closed


def run(main):
    """Exit with main's code; a stdout that cannot be written is one line, not a traceback.

    Only a closing summary goes to stdout, after the work is done. A closed
    pipe (`| head`) exits quietly with 1, a full device says so. A file the
    scripts open reports its own errors, so an error naming no file is stdout's.
    """
    try:
        code = main()
        if sys.stdout is not None:  # None when the process started with fd 1 closed
            sys.stdout.flush()
    except BrokenPipeError:
        _discard_stdout()
        return 1
    except OSError as exc:
        if exc.filename is not None:
            raise
        print(f"stdout: {shown_line(exc)}", file=sys.stderr)
        _discard_stdout()
        return 1
    return code


def _discard_stdout():
    """Python flushes stdout again at exit, and a failure there would replace the
    exit code with 120; point what is left at the null device instead."""
    os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())


def nonempty(value):
    """An argparse type: an empty path would silently mean the current directory."""
    if not value:
        raise argparse.ArgumentTypeError("must not be empty")
    return value


def main(argv=None):
    safe_output()
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("merge", help="merge fragments into findings.json")
    m.add_argument("findings", type=nonempty)
    m.add_argument("fragments", nargs="+", type=nonempty)
    r = sub.add_parser("renumber", help="order findings by severity and path, IDs gapless")
    r.add_argument("findings", type=nonempty)
    n = sub.add_parser("counts", help="print the n_* summary counts")
    n.add_argument("findings", type=nonempty)
    c = sub.add_parser("check", help="check the run contract of an output directory")
    c.add_argument("out", type=nonempty)
    c.add_argument("--allow", action="append", default=[], metavar="NAME",
                   help="an extra file or directory the requester asked for in OUT")
    c.add_argument("--repo", metavar="CHECKOUT", type=nonempty,
                   help="also check that each location's and enforcement site's file and "
                        "line exist in this checkout of the assessed revision")
    args = parser.parse_args(argv)
    return {"merge": cmd_merge, "renumber": cmd_renumber, "counts": cmd_counts,
            "check": cmd_check}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(run(main))
