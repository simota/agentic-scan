#!/usr/bin/env python3
"""Merge finding fragments into findings.json and check a run's output directory.

    python3 findings.py merge FINDINGS FRAGMENT [FRAGMENT ...]
    python3 findings.py renumber FINDINGS
    python3 findings.py counts FINDINGS
    python3 findings.py triage FINDINGS IDS [--status S] [--note TEXT] [--issue URL] [--no-render]
    python3 findings.py check OUT_DIR [--repo CHECKOUT] [--allow NAME]...

A fragment is a JSON file written with the host's file-write tool (never a
shell heredoc or a generated script). It holds any of these top-level keys:
`meta` is merged key by key; `findings` and `rules` records are matched by
`id`, a known record updated key by key and a new one appended; `perspectives`
are matched by `name` and replaced whole; the string lists (`checked_ok`,
`decisions`, `limitations`, `next_steps`) are appended without duplicates;
`architecture` holds the `before` and `after` diagrams, each replaced whole.
A `null` value removes an optional key from `meta`, a finding or a rule, and
`remove` deletes list items (`{"next_steps": ["exact text"]}`) or ledger
entries by id (`{"rules": ["R-05"]}`) before the fragment's own items are
added; those items take the earliest place an item was removed from in their
list. A finding is never removed: a wrong one is marked `FalsePositive` or
`NotApplicable` with evidence, as SKILL.md requires.
A complete finding whose ID already holds a finding with another title or
location is refused as an ID collision; a correction sends only the fields
that change.
FINDINGS is created when absent. The merged record must pass the schema check
(`reference/findings-schema.md`) before anything is written.

`renumber` orders the findings by severity, then path and line of their first
location, excluded verdicts last, and renames them `A-001`… without gaps. Every whole-word mention of
an old ID in the record's prose is rewritten in the same pass, so `next_steps`
and traces keep pointing at the same finding; `meta`, locations, URLs,
commands and rule sources keep theirs. A mention of an ID no finding holds is
refused when renumber would give that ID to a finding.

`counts` prints the `n_*` values the report templates use, one `name=value`
per line, counted as report.md counts them (excluded verdicts apart).

`triage` records what people decide after the review, without a hand-written
fragment: `--status` (`Open`, `Fixed`, `Accepted`), `--note` the reason (an
`Accepted` finding needs one; moving back to `Open` drops the old one), and
`--issue` the URL where the fix is tracked (drafts.py then stops drafting it).
It takes several IDs at once (`A-001,A-003`), refuses an excluded finding, and,
when `dashboard.html` and `report.md` sit beside FINDINGS, renders them again
in `meta.lang` in the same atomic write, so `check` still passes.

`check` is the run contract: the output directory holds exactly
`findings.json`, `dashboard.html` and `report.md` (plus `--allow` names), the
record is complete, IDs are gapless in severity order, then path, with excluded verdicts
last, every perspective in
`reference/perspectives.md` is recorded, every cited rule exists, every
violated rule is cited in the `rule` of a Valid or Likely finding (which may
list several, `R-01, R-02`) and carries no
stale `reason`, no finding
outside the excluded verdicts sits under a perspective not applied, High and
Medium findings are traced (not Unverified) and carry evidence, definitive
evidence cites a `path:line` (a duplicate may name the finding it repeats),
every finding ID mentioned in prose names a recorded finding, every
location names a file, both architecture diagrams (before and after) are
recorded, and both
rendered files match what `render.py` produces from the current record
in `meta.lang`. With `--repo`, each location's file must exist in that
checkout and its line must be within the file.

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
import shutil
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
# Evidence that is the duplicate statement and nothing else: `Duplicate of
# A-004`, `Duplicates A-004.`, `重複: A-004。`. Any other text, which could
# qualify or contradict it, needs a `path:line` like any other evidence; the
# reasons live in the finding it repeats. The ID stands apart from an English
# label (`ofA-004` is no mention, so renumber would not rewrite it).
# A full-width or no-break space, as an input method types it, is a blank too.
DUPLICATE_OF = re.compile(r"(?i)[\s\u3000\u00a0]*(?:duplicates?(?: of)?[\s\u3000\u00a0]+|重複[:：][\s\u3000\u00a0]*)"
                          r"(A-[0-9]{3})[\s\u3000\u00a0]*[.。]?[\s\u3000\u00a0]*", re.ASCII)
# `findings[].rule` names one rule or several (`R-01, R-02`) when one root
# cause breaks more than one.
RULE_LIST = re.compile(r"[\s,、，;；]+")
LISTS = ("checked_ok", "decisions", "limitations", "next_steps")
TOP_KEYS = {"meta", "findings", "rules", "perspectives", "architecture", *LISTS}
META_REQUIRED = ("project", "scope", "date", "assessor", "lang")
RULE_REQUIRED = ("id", "statement", "source", "status")
ALLOWED_RULE_STATUS = {"Valid": ("violated",), "Likely": ("violated", "partly read")}
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
FINDING_KEYS = {*FINDING_REQUIRED, "contrast", "rule", "step", "status", "status_note", "issue",
                "analysis", "references"}
OUTPUTS = {"findings.json", "dashboard.html", "report.md"}
TEMPORARY = re.compile(r"\.findings-[0-9a-f]{32}\.tmp")
# ASCII digits only: `\d` would also accept other scripts' digits.
FINDING_ID = re.compile(r"A-[0-9]{3}")
# renumber names findings A-001 to A-999.
MAX_FINDINGS = 999
RULE_ID = re.compile(r"R-[0-9]{2,}")
STEP_ID = re.compile(r"([A-Z]{2})([1-9][0-9]{0,2})")
# A `path:line` candidate: it starts after a blank, opening punctuation or a
# label's colon (`根拠:job.py:58`, `根拠：Makefile:12`), never on that
# punctuation (`` `Makefile:12` `` names `Makefile`), and not as the `//host`
# of a URL, so a port is not a line; it has a letter (`10:30` is not one) and
# a line from 1. A Windows drive (`C:\repo\a.py:3`) is allowed.
# `evidence_paths` finds them in one pass, so a long list of names in evidence
# stays linear.
# A full-width colon ends a label as an ASCII one does.
PATH_RUN = re.compile(r"[^\s:：]+")
LINE_AFTER = re.compile(r":[1-9][0-9]*")
PATH_START_AFTER = set("([{'\"`,;:「『（【〔［｛〈《、，；：")
# From `://` to the next blank or punctuation that can open a path, a colon
# separates a user, password or port (`postgres://app:pw@db:5432`).
URL_TAIL = re.compile(r"://[^\s,;()\[\]{}'\"`|<>]*")
# Extensionless files that hold code or rules. A capitalised name ending in
# `file` is one too (`Dockerfile`, `Jenkinsfile`), and so are the lowercase
# names their tools also read; `file`, `profile` are words.
LOWERCASE_FILES = {"makefile", "gnumakefile", "justfile", "rakefile", "vagrantfile"}
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
# The before/after architecture diagrams: the module graph at the assessed
# revision and the same graph with the recorded fix directions applied.
DIAGRAMS = ("before", "after")
DIAGRAM_KEYS = {"nodes", "edges", "note"}
NODE_KEYS = {"id", "label", "kind"}
NODE_KINDS = ("module", "store", "external")
EDGE_KEYS = {"from", "to", "label", "finding"}
# A node ID is a short name the edges refer to; the label is what is shown.
NODE_ID = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,63}")
# Enough for a module map; past this a diagram stops being readable.
MAX_NODES, MAX_EDGES = 60, 150
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
    if "status_note" in f:
        # Why the finding is Fixed or Accepted (or was reopened): a decision with no reason
        # cannot be reviewed later, so a recorded note is never blank.
        _text(f["status_note"], f"{where}.status_note")
    if "issue" in f:
        # Where the fix is tracked (the filed issue or ticket): one URL, shown as a link.
        _text(f["issue"], f"{where}.issue")
        if any(c.isspace() for c in f["issue"].strip()):
            raise SchemaError(f"{where}.issue: one URL, without blanks")
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


def evidence_paths(text):
    """Yield each `path:line` candidate's path, left to right, as a regex would.

    Every start inside one run of non-blank, non-colon text ends at the same
    `:line`, so the earliest valid start is found without backtracking.
    """
    in_url = bytearray(len(text))
    for url in URL_TAIL.finditer(text):
        in_url[url.start():url.end()] = b"\x01" * (url.end() - url.start())

    def starts_here(i):
        return not in_url[i] and (i == 0 or text[i - 1].isspace() or text[i - 1] in PATH_START_AFTER)

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
                or stem in EXTENSIONLESS or stem.lower() in LOWERCASE_FILES
                or (stem[:1].isupper() and stem.endswith("file") and len(stem) > 4)
                or extension):
            return True
    return False


def _validate_diagram(diagram, where):
    if not isinstance(diagram, dict):
        raise SchemaError(f"{where}: must be an object")
    _known(diagram, DIAGRAM_KEYS, where)
    if "note" in diagram:
        _text(diagram["note"], f"{where}.note")
    nodes = _list(diagram.get("nodes"), f"{where}.nodes")
    if not nodes:
        raise SchemaError(f"{where}.nodes: at least one node")
    if len(nodes) > MAX_NODES:
        raise SchemaError(f"{where}.nodes: more than {MAX_NODES}; draw modules, not files")
    ids = set()
    for i, n in enumerate(nodes):
        field = f"{where}.nodes[{i}]"
        if not isinstance(n, dict):
            raise SchemaError(f"{field}: must be an object")
        _known(n, NODE_KEYS, field)
        if not isinstance(n.get("id"), str) or not NODE_ID.fullmatch(n["id"]):
            raise SchemaError(f"{field}.id: {n.get('id')!r} must look like billing or api.orders")
        if ID_RUN.search(n["id"]):
            # renumber would read it as a finding mention and rename it.
            raise SchemaError(f"{field}.id: {n['id']!r} looks like a finding ID")
        if n["id"] in ids:
            raise SchemaError(f"{field}.id: duplicate {n['id']}")
        ids.add(n["id"])
        _text(n.get("label"), f"{field}.label")
        if "kind" in n:
            _choice(n["kind"], NODE_KINDS, f"{field}.kind")
    edges = _list(diagram.get("edges", []), f"{where}.edges")
    if len(edges) > MAX_EDGES:
        raise SchemaError(f"{where}.edges: more than {MAX_EDGES}")
    pairs = set()
    for i, e in enumerate(edges):
        field = f"{where}.edges[{i}]"
        if not isinstance(e, dict):
            raise SchemaError(f"{field}: must be an object")
        _known(e, EDGE_KEYS, field)
        for key in ("from", "to"):
            if not isinstance(e.get(key), str) or e[key] not in ids:
                raise SchemaError(f"{field}.{key}: {e.get(key)!r} is not a node id of {where}")
        if e["from"] == e["to"]:
            raise SchemaError(f"{field}: an edge joins two different nodes")
        if (e["from"], e["to"]) in pairs:
            raise SchemaError(f"{field}: duplicate edge {e['from']} -> {e['to']}; "
                              "put both labels on one edge")
        pairs.add((e["from"], e["to"]))
        if "label" in e:
            _text(e["label"], f"{field}.label")
        if "finding" in e:
            # The findings this edge shows; renumber rewrites them with the rest.
            cited = [x for x in RULE_LIST.split(e["finding"]) if x] \
                if isinstance(e["finding"], str) else []
            if not cited or not all(FINDING_ID.fullmatch(x) for x in cited):
                raise SchemaError(f"{field}.finding: finding IDs such as \"A-001\" or "
                                  "\"A-001, A-003\"")


def _validate_architecture(arch):
    if not isinstance(arch, dict):
        raise SchemaError("architecture: must be an object")
    _known(arch, set(DIAGRAMS), "architecture")
    for key in DIAGRAMS:
        if key in arch:
            _validate_diagram(arch[key], f"architecture.{key}")


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


META_DEPTH = 32


def _depth(value):
    """Nesting depth of a JSON value, iteratively so deep input cannot recurse."""
    deepest, stack = 0, [(value, 1)]
    while stack:
        item, depth = stack.pop()
        if isinstance(item, (dict, list)):
            deepest = max(deepest, depth)
            if depth <= META_DEPTH:
                stack.extend((v, depth + 1) for v in (item.values() if isinstance(item, dict) else item))
    return deepest


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
    for key, value in meta.items():
        # Extra run context is small; deep nesting would inflate the indented record.
        if _depth(value) > META_DEPTH:
            raise SchemaError(f"meta.{key}: nested more than {META_DEPTH} levels deep")
    if len(_list(doc.get("findings", []), "findings")) > MAX_FINDINGS:
        # Refused at merge, so no record is written that renumber cannot number.
        raise SchemaError(f"findings: more than {MAX_FINDINGS} cannot be numbered A-001 to "
                          f"A-{MAX_FINDINGS}")
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
    if "architecture" in doc:
        _validate_architecture(doc["architecture"])
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
    """A record unlike the finding that holds its ID: another unit's finding.

    Two findings can share a location, so in a complete record either a new
    title or a new location marks a different finding. A partial record that
    changes both title and location is another finding too, even with a field
    missing; a correction changes one of them at a time.
    """
    if "title" not in record or "location" not in record:
        return False
    new_title = (" ".join(str(record["title"]).split())
                 != " ".join(str(existing.get("title", "")).split()))
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
            current.append(_apply({}, record, required, f"{where}.{rid}"))
            index[rid] = current[-1]


class _Slot(dict):
    """Where a removed rule stood, so a rule sent back with its ID keeps that place."""


def _fill_slots(rules):
    """Turn refilled slots into rules and drop the ones nothing was sent for."""
    return [dict(r) if isinstance(r, _Slot) else r for r in rules
            if not (isinstance(r, _Slot) and len(r) == 1)]


def _remove_items(doc, removals, where):
    """Delete the named items; return, per string list, where the first one stood."""
    if not isinstance(removals, dict):
        raise SchemaError(f"{where}: must be an object of list names")
    unknown = set(removals) - set(LISTS) - {"rules"}
    if unknown:
        raise SchemaError(f"{where}: only rules and {', '.join(LISTS)} can be removed from, "
                          f"not {sorted(unknown)} (a finding is never removed: mark it "
                          "FalsePositive or NotApplicable with evidence; a perspective "
                          "is replaced, not removed)")
    slots = {}
    for key, values in removals.items():
        if key == "rules":
            # A spurious ledger entry, by id; check then catches a finding citing it.
            for rid in _list(values, f"{where}.rules"):
                rules = doc.get("rules", [])
                at = next((i for i, r in enumerate(rules) if r.get("id") == rid
                           and not isinstance(r, _Slot)), None)
                if at is None:
                    raise SchemaError(f"{where}.rules: {rid!r} is not recorded")
                rules[at] = _Slot(id=rid)
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
    if "architecture" in fragment:
        # Each diagram is replaced whole: its edges refer to its own nodes.
        if not isinstance(fragment["architecture"], dict):
            raise SchemaError(f"{where}.architecture: must be an object")
        arch = doc.setdefault("architecture", {})
        _apply(arch, fragment["architecture"], (), f"{where}.architecture")
        if not arch:
            del doc["architecture"]
    slots = {}
    if "remove" in fragment:
        # First, so one fragment can remove an entry and send its replacement.
        removed = fragment["remove"]
        if isinstance(removed, dict) and isinstance(removed.get("rules"), list):
            # A removed rule comes back only as a whole new entry, never as a correction.
            partial = {r.get("id") for r in fragment["rules"] if isinstance(r, dict)
                       and isinstance(r.get("id"), str)
                       and not all(key in r for key in RULE_REQUIRED)} \
                if isinstance(fragment.get("rules"), list) else set()
            both = sorted(rid for rid in removed["rules"] if isinstance(rid, str)
                          and rid in partial)
            if both:
                raise SchemaError(f"{where}: {', '.join(both)} is removed, so the rule sent "
                                  "with that ID must be complete; to correct it, send only "
                                  "the fields that change and do not remove it")
        slots = _remove_items(doc, removed, f"{where}.remove")
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
    if "rules" in doc:
        doc["rules"] = _fill_slots(doc["rules"])
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
    atomic_write_all({target: data})


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


def _backup(target):
    """Keep target's current content beside it, or None when there is none."""
    if not target.exists():
        return None
    while True:
        backup = target.parent / f".findings-{secrets.token_hex(16)}.tmp"
        try:
            # A hard link keeps the old file itself; copy where links are not supported.
            os.link(target, backup)
        except FileExistsError:
            continue
        except OSError:
            try:
                shutil.copy2(target, backup)
            except BaseException:
                backup.unlink(missing_ok=True)  # a partial copy is no backup
                raise
        return backup


def atomic_write_all(files):
    """Replace every target only after all of them are staged, keeping links and modes.

    When one replacement fails, those already made are undone, so a failed
    write keeps the previous set of files rather than a mix of old and new.
    """
    staged, backups, replaced = [], [], []
    try:
        for target, data in files.items():
            staged.append(_stage(target, data))
        if len(staged) > 1:
            # One at a time, so the finally below removes those made before a failure.
            for _, target in staged:
                backups.append(_backup(target))
        for i, (temporary, target) in enumerate(staged):
            os.replace(temporary, target)
            replaced.append(i)
    except BaseException:
        for i in reversed(replaced if backups else []):
            target, backup = staged[i][1], backups[i]
            try:
                if backup is None:
                    target.unlink(missing_ok=True)
                else:
                    os.replace(backup, target)
            except OSError:
                pass
        raise
    finally:
        for temporary, _ in staged:
            temporary.unlink(missing_ok=True)
        for backup in backups:
            if backup is not None:
                backup.unlink(missing_ok=True)


# A run of IDs standing free in prose: one ID, or several joined by `/` or `-`
# (`A-002/A-001`, `A-001-A-002-A-003`). Every ID in a run is a mention. A run
# touching a word, path or ticket (`docs/A-001.md`, `JIRA-A-001`,
# `A-001-A-002.md`) is not prose and stays whole; URLs and e-mail addresses
# are skipped whole by `_url_spans`. ASCII word characters only, so a run
# beside Japanese text (`A-001を`) is still a mention.
ID_RUN = re.compile(
    r"(?<![\w/\\-])A-[0-9]{3}(?:[/-]A-[0-9]{3})*(?![\w/\\-]|\.[A-Za-z0-9])", re.ASCII)


# ASCII URL characters only, so `…/x。A-001と` ends the URL at `。`.
# Where a URL starts in prose: a scheme with `//`, or `urn:`; and, with no
# boundary before them, exactly what render.py's AUTOLINK links even right
# after a word (`seeWWW.example.com`, `1https://x`).
URL_START = re.compile(r"(?i:https?|ftp|mailto|xmpp):|(?i:www)\."
                       r"|(?<![A-Za-z0-9+.-])(?:[A-Za-z][A-Za-z0-9+.-]*://|(?i:urn):)")


# A bare e-mail address: an RFC 5322 dot-atom local part (atoms joined by
# single dots, so `A-001.@x`, `.A-001@x` and `A-001..b@x` are not), `@`, a domain (one
# label, `@mailhost`, or several) that ends the token, so `A-001@scope/pkg`
# is not an address.
# It starts only where a run of local-part characters starts, so a long run
# with no address in it is read once, not once per character. The address is
# ASCII on purpose: Japanese prose has no blanks between words, so a non-ASCII
# local part or domain would swallow the sentence before or after it
# (`A-001の担当はowner@example.com`, `owner@example.comに連絡してA-001を直す`)
# and hide the mention in it.
EMAIL = re.compile(r"((?<![A-Za-z0-9!#$%&'*+/=?^_`{|}~.-])"
                   r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*"
                   r"@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
                   r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*"
                   r"(?![\w/@\\-]|\.[\w.-]))", re.ASCII)


def _url_spans(text):
    """Split text into prose and literals (URLs, e-mail addresses), alternating.

    A URL runs to a blank or to punctuation outside ASCII (`…/x。A-001`,
    `（https://x）A-001`), so an IRI's letters (`?project=案件&key=A-001`) stay
    inside it. An address is taken whole (`owner!A-001!tag@example.com`).
    """
    parts, prose = [], 0
    for start in URL_START.finditer(text):
        if start.start() < prose:
            continue
        end = start.end()
        while end < len(text) and not text[end].isspace() and not (
                ord(text[end]) > 127 and unicodedata.category(text[end])[0] in "PSZ"):
            end += 1
        parts += [text[prose:start.start()], text[start.start():end]]
        prose = end
    parts.append(text[prose:])
    # Addresses in the prose parts: EMAIL.split alternates prose and address.
    # An address holds an `@`, so prose without one is a single piece.
    return [piece for i, part in enumerate(parts)
            for piece in (EMAIL.split(part) if i % 2 == 0 and "@" in part else [part])]


def _first_location(f):
    path, start, _ = split_location(as_locations(f["location"])[0])
    return path, start


# Literal values that only look like prose: a path, a URL, a command that ran,
# a rule's source. An `A-001` in them is a file, ticket or argument, not a finding.
# A diagram edge's ends name node IDs.
LITERAL_KEYS = {"location", "url", "issue", "command", "source", "from", "to"}


def _rewrite_ids(value, mapping, key=None):
    if key in LITERAL_KEYS:
        return value
    if isinstance(value, str):
        if "A-" not in value:
            return value  # no ID to rewrite, and the spans would rejoin to value
        # A URL in prose (`browse?key=A-001`, `#A-001`) is a link, not a mention.
        return "".join(part if i % 2 else ID_RUN.sub(
            lambda run: FINDING_ID.sub(lambda m: mapping.get(m[0], m[0]), run[0]), part)
            for i, part in enumerate(_url_spans(value)))
    if isinstance(value, list):
        return [_rewrite_ids(v, mapping, key) for v in value]
    if isinstance(value, dict):
        return {k: _rewrite_ids(v, mapping, k) for k, v in value.items()}
    return value


def _mentions(value, where, key=None):
    """Yield (where, ID) for each finding ID the prose of value mentions, as renumber reads it."""
    if key in LITERAL_KEYS:
        return
    if isinstance(value, str):
        if "A-" not in value:
            return  # every mention holds `A-`
        for part in _url_spans(value)[::2]:
            for run in ID_RUN.finditer(part):
                for fid in FINDING_ID.findall(run[0]):
                    yield where, fid
    elif isinstance(value, list):
        for i, v in enumerate(value):
            yield from _mentions(v, f"{where}[{i}]", key)
    elif isinstance(value, dict):
        for k, v in value.items():
            yield from _mentions(v, f"{where}.{k}", k)


def unknown_mentions(doc):
    """Each (field, ID) where prose names a finding ID that no finding holds, once.

    A field is named by its record (`A-002.trace`, `R-01.statement`,
    `next_steps[0]`); `meta` describes the run and may name an earlier one's IDs.
    """
    ids = {f["id"] for f in doc.get("findings", [])}
    found = {}
    for key, value in doc.items():
        if key == "meta":
            continue
        if key in ("findings", "rules", "perspectives"):
            pairs = (pair for r in value for k, v in r.items() if k not in ("id", "name")
                     for pair in _mentions(v, f"{r.get('id', r.get('name'))}.{k}", k))
        else:
            pairs = _mentions(value, key)
        found.update((pair, None) for pair in pairs if pair[1] not in ids)
    return list(found)


def renumber(doc):
    """Return (doc, mapping): findings in severity then path order, IDs gapless.

    Excluded findings (FalsePositive, NotApplicable) follow the rest, so a
    duplicate never takes a number between the findings to act on.
    """
    findings = doc.get("findings", [])
    order = sorted(range(len(findings)), key=lambda i: (
        findings[i]["validation"]["verdict"] in EXCLUDED,
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
def _exclusive(target, create=True):
    """Hold an exclusive lock on target's directory from read to replace.

    Two merges started together would otherwise both read the same record and
    the later replace would drop the other's findings. The lock is on the
    directory, so no lock file joins the outputs. Without fcntl (Windows), run
    merges one at a time.
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
        if not target.is_file():
            raise SchemaError(f"{target}: no such record")
        with _exclusive(target, create=False):
            changed, rewritten = _renumber_file(target)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 1
    _report_renumber(target, changed, rewritten)
    return 0


def _renumber_file(target):
    """Renumber target in place; return (ID mapping, whether the record changed)."""
    doc = read_json(target)
    validate(doc)
    renamed, changed = renumber(doc)
    # A mention of an ID no finding holds is left as written; once that ID is
    # given to a finding, the mention would name it and check could not tell.
    new_ids = set(changed.values())
    taken = [(where, fid) for where, fid in (unknown_mentions(doc) if new_ids else [])
             if fid in new_ids]
    if taken:
        raise SchemaError("; ".join(f"{where} mentions {fid}, which no finding holds"
                                    for where, fid in taken)
                          + " - renumber would give that ID to another finding; correct the "
                          "mention with a fragment first")
    validate(renamed)
    # IDs that already hold their final names can still sit in the wrong order
    # (fragments merged A-004 before A-001), so compare the whole record.
    data = _serialize(renamed)
    rewritten = data != _serialize(doc)
    if rewritten:
        _atomic_write(target, data)
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


def _merge_all(doc, fragments, record=None):
    try:
        validate(doc)
    except SchemaError as exc:
        # The record, not a fragment, is what no fragment can be merged into.
        raise SchemaError(f"{record}: existing record is invalid: {exc}") from exc
    for path in fragments:
        fragment = read_json(path)  # its errors name the file already
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
            if target.exists() and not target.is_file():
                # A FIFO would block the read while holding the lock.
                raise SchemaError(f"{target}: not a regular file")
            doc = _merge_all(read_json(target) if target.exists() else {}, args.fragments, target)
            # Serialize before staging any output.
            _atomic_write(target, _serialize(doc))
    except (OSError, ValueError, RuntimeError) as exc:
        # RuntimeError: Path.resolve() on a symlink loop before Python 3.13.
        print(f"refused: {exc}", file=sys.stderr)
        return 1
    print(f"merged {len(args.fragments)} fragment(s) into {target}: "
          f"{len(doc.get('findings', []))} finding(s)")
    return 0


def template_counts(doc):
    """The `{{n_*}}` values of templates/report.*.md, counted as report.md counts."""
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
    return counts


def cmd_counts(args):
    try:
        doc = read_json(args.findings)
        validate(doc, complete=True)
    except SchemaError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 1
    for name, value in template_counts(doc).items():
        print(f"{name}={value}")
    return 0


def triage_fragment(doc, ids, status=None, note=None, issue=None):
    """The fragment that records a human's decision on findings, or SchemaError.

    A finding moved to `Accepted` needs a reason (`note`, or the one already
    recorded): an accepted risk with no reason cannot be reviewed later. A
    finding moved back to `Open` drops its earlier reason unless a new one is
    given. An `issue` of `""` removes the recorded one. Excluded findings
    (`FalsePositive`, `NotApplicable`) are never acted on, so they take no status.
    """
    if status is None and note is None and issue is None:
        raise SchemaError("nothing to record: give --status, --note or --issue")
    by_id = {f["id"]: f for f in doc.get("findings", [])}
    updates = []
    for fid in ids:
        f = by_id.get(fid)
        if f is None:
            raise SchemaError(f"{fid} is not a recorded finding")
        if f["validation"]["verdict"] in EXCLUDED:
            raise SchemaError(f"{fid} is excluded ({f['validation']['verdict']}): "
                              "an excluded finding is not acted on")
        update = {"id": fid}
        if status is not None:
            _choice(status, STATUSES, "--status")
            update["status"] = status
            if status == "Open" and note is None and f.get("status", "Open") != "Open":
                update["status_note"] = None  # the earlier reason no longer applies
        if note is not None:
            update["status_note"] = note if visible(note) else None
        final_status = status or f.get("status", "Open")
        final_note = update["status_note"] if "status_note" in update else f.get("status_note")
        # Checked when this call sets Accepted or changes the reason, so an older record's
        # Accepted finding without one can still be given its issue.
        deciding = status == "Accepted" or (note is not None and final_status == "Accepted")
        if deciding and final_note is None:
            raise SchemaError(f"{fid}: Accepted needs --note with the reason the risk is accepted")
        if issue is not None:
            update["issue"] = issue.strip() or None
        updates.append(update)
    return {"findings": updates}


def cmd_triage(args):
    """Record status, reason and tracking issue for findings, then re-render beside them."""
    target = Path(args.findings)
    ids = [x for x in RULE_LIST.split(args.ids) if x]
    bad = [x for x in ids if not FINDING_ID.fullmatch(x)]
    if bad or not ids:
        print(f"refused: IDS takes finding IDs such as A-001,A-003, not "
              f"{', '.join(bad) or 'nothing'}", file=sys.stderr)
        return 2
    ids = list(dict.fromkeys(ids))
    out = target.resolve().parent
    rendered = [out / name for name in ("dashboard.html", "report.md")]
    try:
        with _exclusive(target, create=False):
            if not target.is_file():
                raise SchemaError(f"{target}: no such record")
            doc = read_json(target)
            validate(doc, complete=True)
            before = set(unknown_mentions(doc))
            merge(doc, triage_fragment(doc, ids, args.status, args.note, args.issue), "triage")
            validate(doc, complete=True)
            added = [pair for pair in unknown_mentions(doc) if pair not in before]
            if added:
                raise SchemaError("; ".join(f"{where} names {fid}, which no finding holds"
                                            for where, fid in added))
            files = {target: _serialize(doc)}
            render_too = not args.no_render and all(p.is_file() for p in rendered)
            if render_too:
                outputs = _renderer().rendered_outputs(doc, doc["meta"]["lang"])
                files.update({out / name: data for name, data in outputs.items()})
            # The record and its rendering are replaced together, so check never sees one
            # without the other.
            atomic_write_all(files)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 1
    by_id = {f["id"]: f for f in doc["findings"]}
    for fid in ids:
        f = by_id[fid]
        parts = [f.get("status", "Open")]
        if "status_note" in f:
            parts.append(f"reason: {' '.join(f['status_note'].split())}")
        if "issue" in f:
            parts.append(f"tracked in {f['issue']}")
        print(f"{fid}: {' · '.join(parts)}")
    if render_too:
        print(f"re-rendered {rendered[0]} and {rendered[1]}")
    else:
        print(f"render again: scripts/render.py {target} --out {out}")
    return 0


def cited_rules(f):
    """The rule IDs a finding's `rule` names, in order."""
    return [rid for rid in RULE_LIST.split(f.get("rule", "")) if rid]


def _order_problems(findings):
    """IDs gapless and in renumber's order: severity, then path and line, excluded last."""
    problems = []
    expected = [f"A-{i:03d}" for i in range(1, len(findings) + 1)]
    if [f["id"] for f in findings] != expected:
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
    elif ranks == sorted(ranks):
        # renumber's order: within one severity, by path and line of the first location.
        keys = [(x, SEVERITIES.index(f["severity"]), _first_location(f))
                for x, f in zip(excluded, findings)]
        if keys != sorted(keys):
            problems.append("findings must be numbered by severity, then path and line of "
                            "the first location (excluded ones too); run renumber")
    return problems


def _finding_problems(doc):
    """Per finding: locations name a file, cited rules exist and fit the verdict, evidence, tracing."""
    problems = []
    findings = doc.get("findings", [])
    recorded = {p["name"]: p["status"] for p in doc.get("perspectives", [])}
    rule_status = {r["id"]: r["status"] for r in doc.get("rules", [])}
    kept = {f["id"] for f in findings if f["validation"]["verdict"] not in EXCLUDED}
    for f in findings:
        verdict, evidence = f["validation"]["verdict"], f["validation"].get("evidence", "")
        for loc in as_locations(f["location"]):
            # Not a schema error: merge validates the record before a fragment
            # can correct it, so refusing it there would leave only a hand edit.
            path = split_location(loc)[0]
            # `api/` or `api/.` names a directory, even where `--repo` is not given.
            if not visible(path) or re.split(r"[/\\]", path)[-1] in ("", ".", ".."):
                problems.append(f"{f['id']}: location {loc!r} names no file; give its path "
                                "from the repository root")
        for rid in cited_rules(f):
            status = rule_status.get(rid)
            if status is None:
                problems.append(f"{f['id']}: rule {rid!r} is not a rules[] id")
            elif verdict in ("Valid", "Likely") and status not in ALLOWED_RULE_STATUS[verdict]:
                # A Valid finding is a traced break, so its rule is violated; a
                # Likely one may still sit on a rule whose edges were partly read.
                problems.append(f"{f['id']}: {verdict} finding cites {rid}, recorded as "
                                f"{status}, not {' or '.join(ALLOWED_RULE_STATUS[verdict])}")
        # A duplicate's evidence is the reported finding that keeps it, whose
        # own evidence cites the line; renumber rewrites the ID with the rest.
        duplicate = verdict == "NotApplicable" and any(
            m[1] in kept for m in [DUPLICATE_OF.fullmatch(evidence)] if m)
        if verdict in DEFINITIVE and not duplicate and not cites_line(evidence, f["location"]):
            problems.append(f"{f['id']}: {verdict} evidence must cite path:line"
                            + (" (or, for a duplicate, the finding it repeats)"
                               if verdict == "NotApplicable" else ""))
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
            elif not visible(evidence):
                problems.append(f"{f['id']}: a {f['severity']} finding needs validation.evidence "
                                "naming what the trace found")
    return problems


def _ledger_problems(doc):
    """Per rule: a violated rule is cited, a reason only where the rule is not closed."""
    problems = []
    findings = doc.get("findings", [])
    # Only a finding that establishes the break, and says so in `rule`, backs
    # a `violated` entry; prose in a trace can mention a rule it does not break.
    named = {rid for f in findings if f["validation"]["verdict"] in ("Valid", "Likely")
             for rid in cited_rules(f)}
    for r in doc.get("rules", []):
        if r["status"] == "violated" and r["id"] not in named:
            # The ledger says an edge breaks it, so a finding must say which.
            problems.append(f"{r['id']}: a violated rule needs a Valid or Likely finding that "
                            "cites it in rule (list several, `R-01, R-02`, when one root "
                            "cause breaks them all)")
        if r["status"] in ("holds", "violated") and visible(r.get("reason", "")):
            # Usually a provisional `not checked` reason left behind by the fragment
            # that closed the rule; it would render under the final status.
            problems.append(f"{r['id']}: a reason explains a not-checked or partly-read rule; "
                            f"send \"reason\": null with its final status, {r['status']}")
        if r["status"] == "not checked":
            reason = r.get("reason")
            if not isinstance(reason, str) or not visible(reason):
                problems.append(f"{r['id']}: a not-checked rule needs a nonblank string reason")
    return problems


def _completeness_problems(doc):
    """The run records what held, what could not be checked and both diagrams."""
    problems = []
    if not doc.get("limitations"):
        problems.append("limitations: state what static reading cannot show")
    if not doc.get("checked_ok"):
        problems.append("checked_ok: list what was examined and held")
    for key in DIAGRAMS:
        if key not in doc.get("architecture", {}):
            problems.append(f"architecture.{key}: draw the {key} diagram (module graph "
                            + ("at the assessed revision)" if key == "before" else
                               "with the recorded fix directions applied)"))
    return problems


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
    # `drafts/` and `./drafts`, as a shell completes them, name `drafts`.
    allow = {os.path.normpath(name) for name in allow}
    for name in sorted(present - OUTPUTS - allow):
        if TEMPORARY.fullmatch(name):
            problems.append(f"unexpected output: {name} is a temporary file from an interrupted "
                            "write; delete it once no merge or render is running")
        else:
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
    problems += _order_problems(doc.get("findings", []))
    recorded = {p["name"] for p in doc.get("perspectives", [])}
    for name in PERSPECTIVES:
        if name not in recorded:
            problems.append(f"perspective not recorded: {name}")
    problems += _finding_problems(doc)
    problems += _ledger_problems(doc)
    for where, fid in unknown_mentions(doc):
        problems.append(f"{where}: mentions {fid}, which no finding holds; name a recorded "
                        "finding (after renumber, only the new IDs)")
    problems += _completeness_problems(doc)
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


def _as_on_disk(repo, path, listings):
    """The file `path` names, each part spelled as its directory entry, or None.

    A case-insensitive filesystem (macOS, Windows) opens `WORKER/JOB.PY` for
    `worker/job.py`, a path the assessed revision does not hold, so a part must
    match an entry exactly, up to Unicode normalisation: either form of an
    accented name names the same file, whichever form the filesystem stores.
    A directory that can be searched but not listed takes the part as given.
    """
    given = Path(path)
    current, parts = (Path(given.anchor), given.parts[1:]) if given.anchor else (repo, given.parts)
    for part in parts:
        if part not in (".", ".."):
            if current not in listings:
                try:
                    names = os.listdir(current)
                except PermissionError:
                    listings[current] = None
                else:
                    listings[current] = (set(names), {unicodedata.normalize("NFC", n): n for n in names})
            if listings[current] is not None:
                exact, normalised = listings[current]
                if part not in exact:
                    part = normalised.get(unicodedata.normalize("NFC", part))
                    if part is None:
                        return None
        current = current / part
    return current


def location_problems(doc, repo):
    """Name each finding location whose file or line is not in the checkout."""
    repo = Path(repo)
    if not repo.is_dir():
        return [f"--repo: not a directory: {repo}"]
    root = repo.resolve()
    problems, lines, listings = [], {}, {}
    for f in doc.get("findings", []):
        for loc in as_locations(f["location"]):
            path, start, end = split_location(loc)
            if path not in lines:
                try:
                    file = _as_on_disk(repo, path, listings)
                    if file is None:
                        raise FileNotFoundError(path)
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
                problems.append(f"{f['id']}: location {loc}: no such file in {repo}")
            elif max(start, end) > max(lines[path], 1):  # line 1 of an empty file
                problems.append(f"{f['id']}: location {loc}: line {max(start, end)} is past "
                                f"the end of {path} ({lines[path]} lines)")
    return problems


def cmd_check(args):
    problems = contract_problems(args.out, args.allow)
    # Not a regular file (a FIFO would block the read): contract_problems has named it.
    if args.repo is not None and (Path(args.out) / "findings.json").is_file():
        try:
            doc = read_json(Path(args.out) / "findings.json")
            validate(doc, complete=True)
        except (OSError, ValueError):
            pass  # contract_problems has named it
        else:
            problems += location_problems(doc, args.repo)
    for problem in problems:
        print(problem, file=sys.stderr)
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


def main(argv=None):
    safe_output()
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("merge", help="merge fragments into findings.json")
    m.add_argument("findings")
    m.add_argument("fragments", nargs="+")
    r = sub.add_parser("renumber", help="order findings by severity and path, IDs gapless")
    r.add_argument("findings")
    n = sub.add_parser("counts", help="print the n_* values the report templates use")
    n.add_argument("findings")
    t = sub.add_parser("triage", help="record a status, its reason and the tracking issue")
    t.add_argument("findings")
    t.add_argument("ids", metavar="IDS", help="finding IDs, comma-separated (A-001,A-003)")
    t.add_argument("--status", choices=STATUSES)
    t.add_argument("--note", metavar="TEXT",
                   help="why: the accepted trade-off, the fixing change; \"\" removes it")
    t.add_argument("--issue", metavar="URL",
                   help="where the fix is tracked; \"\" removes it")
    t.add_argument("--no-render", action="store_true",
                   help="leave dashboard.html and report.md as they are")
    c = sub.add_parser("check", help="check the run contract of an output directory")
    c.add_argument("out")
    c.add_argument("--allow", action="append", default=[], metavar="NAME",
                   help="an extra file or directory the requester asked for in OUT")
    c.add_argument("--repo", metavar="CHECKOUT",
                   help="also check that each location's file and line exist in this "
                        "checkout of the assessed revision")
    args = parser.parse_args(argv)
    return {"merge": cmd_merge, "renumber": cmd_renumber, "counts": cmd_counts,
            "triage": cmd_triage, "check": cmd_check}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
