#!/usr/bin/env python3
"""Merge finding fragments into findings.json and check a run's output directory.

    python3 findings.py merge FINDINGS FRAGMENT [FRAGMENT ...]
    python3 findings.py renumber FINDINGS
    python3 findings.py check OUT_DIR [--allow NAME ...]

A fragment is a JSON file written with the host's file-write tool (never a
shell heredoc or a generated script). It holds any of these top-level keys:
`meta` is merged key by key; `findings` and `commitments` records are matched by
`id`, a known record updated key by key and a new one appended; `perspectives`
are matched by `name` and replaced whole; the string lists (`checked_ok`,
`decisions`, `limitations`, `next_steps`) are appended without duplicates.
Nested `validation` and `analysis` objects of a known finding also merge key by
key. FINDINGS is created when absent. The merged record must pass the schema check
(`reference/findings-schema.md`) before anything is written.

`renumber` numbers findings PV-001… in severity order (excluded findings
last) and rewrites every `PV-NNN` reference in the record, so a changed
severity needs no manual rebuild.

`check` is the run contract: the output directory holds exactly
`findings.json`, `dashboard.html` and `report.md` (plus `--allow` names), the
record is complete, IDs are gapless in severity order, every perspective in
`reference/perspectives.md` is recorded, every ledger ID a finding cites exists,
every reported finding's perspective is recorded as applied, and both reports
are the current rendering of `findings.json`.

Exit codes: 0 ok, 1 a fragment was refused, the input was unreadable or the
contract failed (reasons on stderr).

Findings describe where personal data goes, never the data itself: public
prose or evidence containing an e-mail address (other than the reserved
example domains) or a run of 12 or more digits is refused.
"""
import argparse
from html import unescape
import json
from pathlib import Path
import re
import sys
import unicodedata
from urllib.parse import parse_qsl, unquote, unquote_plus, urlsplit

# Keep source-only CLI runs from writing imported helpers into the skill tree.
sys.dont_write_bytecode = True


def _import_sibling(name):
    """Import a helper beside this script, even in isolated (-I) or -P runs."""
    here = str(Path(__file__).resolve().parent)
    if here not in sys.path:
        sys.path.insert(0, here)
    return __import__(name)


write_utf8_files = _import_sibling("output_io").write_utf8_files

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
FINDING_ID = re.compile(r"^PV-\d{3}$")
# Bounded so a long digit run cannot pass as an exempt technical identifier.
COMMITMENT_ID = re.compile(r"^C-\d{2,6}$")
COMMITMENT_REF = re.compile(r"(?<![\w-])C-\d{2,6}(?![\w-])")
COMMIT_HASH = re.compile(r"[0-9a-fA-F]{4,64}\Z")
# Spaces are valid in source paths; control characters and line breaks are not.
LOCATION = re.compile(r"^[^:\x00-\x1f\x7f-\x9f\u2028\u2029]+:\d{1,9}(?:-\d{1,9})?$")
# Values that look like real personal data. Field names and placeholders such
# as `<email>` or `user@example.com` are fine; the value itself never is.
EMAIL_MARKERS = re.compile(r'["@]')
EMAIL_LOCAL_CHAR = re.compile(r'[^\s"(),:;<>@\[\]\\]')
EMAIL_LITERAL_DOMAIN = re.compile(r"\[(?:[^\[\]\r\n]|(?:\r\n|\n)[ \t])+\]")
EMAIL_FWS = re.compile(r"[ \t]+|(?:\r\n|\n)[ \t]+")
EMAIL_COMMENT_MARKERS = re.compile(r"[()\\\r\n]")
IDNA_DOTS = str.maketrans("\u3002\uff0e\uff61", "...")
# IDNA exceptions and join controls (RFC 5892, sections 2.6 and 2.8) can
# occur in labels too. Candidate detection need not validate their context.
IDNA_LABEL_EXTRAS = frozenset("\u00b7\u0375\u05f3\u05f4\u06fd\u06fe\u0f0b\u200c\u200d\u30fb")
EXAMPLE_DOMAINS = re.compile(r"(?:^|\.)example\.(?:com|org|net)$|\.(?:example|test|invalid)$",
                             re.IGNORECASE)
# Horizontal Unicode whitespace and hyphens, including Unicode dashes, the minus
# sign and the katakana prolonged sound mark, may separate the digits; line
# boundaries still separate unrelated numbers in prose.
LONG_NUMBER = re.compile(
    r"\d(?:(?:[^\S\r\n\v\f\x1c-\x1e\x85\u2028\u2029]|[-\u2010-\u2015\u2212\u30fc])*\d){11}")
# Card-style groups joined by one repeated '.', '/', '_' or '+' (4-4-4-2..4 or
# 4-6-5). Groups of at most three digits, as in IP addresses, never match.
GROUPED_NUMBER = re.compile(r"(?<!\d)\d{4}([./_+])\d{4}\1\d{4}\1\d{2,4}(?!\d)"
                            r"|(?<!\d)\d{4}([./_+])\d{6}\2\d{5}(?!\d)")
# ISO dates, compact date-times, UUIDs and hex digests (a whole token of 32 or more hex digits with
# at least one letter: SHA-1/256 values, dashless UUIDs) are technical values;
# mask them before counting digits so they are not mistaken for personal
# numbers. A UUID next to a dash-joined digit is not masked, so masking cannot
# split a longer number.
NOT_PERSONAL_NUMBERS = re.compile(
    r"(?<!\d)(?:19|20)\d{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])(?!\d)"
    # Compact date-times (YYYYMMDDhhmmss), as in timestamped migration files.
    r"|(?<!\d)(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])"
    r"(?:[01]\d|2[0-3])[0-5]\d[0-5]\d(?!\d)"
    r"|(?<![0-9A-Fa-f])(?<!\d-)[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}"
    r"(?![0-9A-Fa-f])(?!-\d)"
    r"|(?<![0-9A-Za-z])(?=[0-9]*[A-Fa-f])[0-9A-Fa-f]{32,128}(?![0-9A-Za-z])")
# Percent and entity decoding passes over prose (covers double encoding).
DECODE_ROUNDS = 3


class SchemaError(ValueError):
    pass


def read_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except UnicodeDecodeError as exc:
        raise SchemaError(f"{path}: must contain UTF-8 JSON") from exc
    except (OSError, json.JSONDecodeError) as exc:
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


def _email_fold(value, pos):
    """A header line continues only when the next line begins with space/tab."""
    if value[pos:pos + 2] == "\r\n":
        pos += 1
    return value[pos:pos + 1] == "\n" and value[pos + 1:pos + 2] in (" ", "\t")


def _email_cfws(value):
    """Index complete comments and folding whitespace in linear passes.

    Only email-candidate boundaries use these jumps. Comments stay in the
    original text, so mailboxes inside them are still inspected, and unrelated
    prose and digit runs are never joined. The stack handles nested comments
    without recursion; cached boundary jumps avoid rescanning comment chains.
    """
    spans = {m.start(): m.end() for m in EMAIL_FWS.finditer(value)}
    stack = []
    escaped_until = 0
    for marker in EMAIL_COMMENT_MARKERS.finditer(value):
        pos = marker.start()
        if pos < escaped_until:
            continue
        char = value[pos]
        if char == "(":
            stack.append(pos)
        elif char == ")":
            if stack:
                spans[stack.pop()] = pos + 1
        elif char == "\\":
            if stack:
                if value[pos + 1:pos + 2] in ("\r", "\n"):
                    stack.clear()
                else:
                    escaped_until = pos + 2
        elif not _email_fold(value, pos):
            # An ordinary line boundary cannot extend a comment or address.
            stack.clear()
    starts = {end: start for start, end in spans.items()}
    before, after = {}, {}
    for pos in range(len(value) + 1):
        if pos in starts:
            start = starts[pos]
            before[pos] = before.get(start, start)
    for pos in range(len(value) - 1, -1, -1):
        if pos in spans:
            end = spans[pos]
            after[pos] = after.get(end, end)
    return before, after


def _email_starts(value, before, after):
    """Yield domain starts without rescanning local parts or adjacent CFWS."""
    quoted = {}
    if '"' in value:
        # Work backwards so every quote's closing quote is found once, even
        # when many escaped quotes could start overlapping candidates. The
        # two suffix results let a backslash skip exactly one character.
        next_end = after_next_end = None
        for pos in range(len(value) - 1, -1, -1):
            char = value[pos]
            if char == '"':
                if next_end is not None:
                    at = after.get(next_end + 1, next_end + 1)
                    if value[at:at + 1] == "@":
                        quoted[pos] = (next_end + 1, at)
                end = pos
            elif char in "\r\n":
                end = next_end if _email_fold(value, pos) else None
            elif char == "\\":
                end = after_next_end if value[pos + 1:pos + 2] not in ("\r", "\n") else None
            else:
                end = next_end
            next_end, after_next_end = end, next_end
    consumed = 0
    quoted_ats = set()
    for marker in EMAIL_MARKERS.finditer(value):
        pos = marker.start()
        if pos < consumed:
            continue
        # Suppress only @ signs inside a complete quoted local part, never
        # those in its trailing comments. Handle the outer @ just once.
        if pos in quoted:
            consumed, at = quoted[pos]
            quoted_ats.add(at)
        # For an unquoted local part, its last character suffices to establish
        # a candidate; rescanning the earlier characters adds no information.
        elif value[pos] == "@" and pos not in quoted_ats:
            local_end = before.get(pos, pos)
            # Earlier @ signs may belong to trailing comments, so their
            # positions must not invalidate the local part before that CFWS.
            if not local_end or not EMAIL_LOCAL_CHAR.fullmatch(value[local_end - 1]):
                continue
            at = pos
        else:
            continue
        yield after.get(at + 1, at + 1)


def _email_domains(value):
    """Read bracketed literals or complete Unicode domain labels."""
    if "@" not in value:
        return
    before, after = _email_cfws(value)
    for start in _email_starts(value, before, after):
        end = start
        literal = EMAIL_LITERAL_DOMAIN.match(value, end)
        if literal:
            # Keep brackets so literal addresses cannot match example domains.
            # This is candidate detection, not IP or SMTP syntax validation.
            yield literal.group()
            continue
        while end < len(value):
            char = value[end]
            # Unlike \w, Unicode marks remain part of the current label. Do
            # not exempt an example-domain prefix followed by such a mark.
            if (char not in ".-_" and char not in IDNA_LABEL_EXTRAS
                    and unicodedata.category(char)[0] not in "LMN"):
                break
            end += 1
        domain = value[start:end].rstrip(".")
        # Malformed trailing labels must not hide a preceding address in prose.
        if "." in domain:
            yield domain


def _no_personal_values(value, where):
    if value is None:
        return
    # Keep this guard safe for callers that have not checked the shape yet.
    value = str(value)
    _scan_personal_values(value, where)
    # Quoted request lines and markup carry values percent- or entity-encoded
    # (`%40`, `&#64;`), sometimes twice. Inspect a few decoded copies as well.
    for _ in range(DECODE_ROUNDS):
        if "%" not in value and "&" not in value:
            break
        decoded = unescape(unquote(value))
        if decoded == value:
            break
        value = decoded
        _scan_personal_values(value, where)


def _scan_personal_values(value, where):
    # Inspect a normalised copy: non-breaking spaces and width variants must
    # not evade the guard, and accepted text must keep its original spelling.
    # Invisible format characters (zero-width spaces, word joiners, soft
    # hyphens) are dropped so they cannot split an address or a number.
    value = unicodedata.normalize("NFKC", value).translate(IDNA_DOTS)
    value = "".join(c for c in value if unicodedata.category(c) != "Cf")
    for domain in _email_domains(value):
        if not EXAMPLE_DOMAINS.search(domain):
            raise SchemaError(f"{where}: contains an e-mail address; name the field, not the value")
    if GROUPED_NUMBER.search(value) or LONG_NUMBER.search(NOT_PERSONAL_NUMBERS.sub("#", value)):
        raise SchemaError(f"{where}: contains a long number shaped like personal data; use a placeholder")


def _check_prose(record, keys, where):
    """Check the schema's public text without scanning technical identifiers."""
    for key in keys:
        _no_personal_values(record.get(key), f"{where}.{key}")


def _check_reference_url(value, where):
    """Inspect raw and decoded URL values without changing the saved spelling."""
    _no_personal_values(value, where)
    try:
        parts = urlsplit(value)
    except ValueError:
        # Malformed references are still displayed as text by the renderer.
        _no_personal_values(unquote(value), where)
        _no_personal_values(unquote_plus(value), where)
        return
    for part in parts:
        _no_personal_values(unquote(part), where)
    # Query values also use '+' for spaces. Decode the original query once;
    # keep its names and values separate so unrelated numbers are not joined.
    for name, item in parse_qsl(parts.query, keep_blank_values=True):
        _no_personal_values(name, where)
        _no_personal_values(item, where)


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
    locations = f["location"] if isinstance(f["location"], list) else [f["location"]]
    if not locations:
        raise SchemaError(f"{where}.location: at least one path:line")
    for i, loc in enumerate(locations):
        if not isinstance(loc, str) or not LOCATION.fullmatch(loc):
            raise SchemaError(f"{where}.location[{i}]: must be path:line")
        # The parsed line range is technical metadata; the path can hold PII.
        path = loc.rsplit(":", 1)[0]
        _text(path, f"{where}.location[{i}]")
        _no_personal_values(path, f"{where}.location[{i}]")
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


PV_REFERENCE = re.compile(r"(?<![\w-])PV-\d{3}(?![\w-])")


def renumber(doc):
    """Number findings PV-001… in severity order and rewrite every PV- reference.

    Reported findings keep their relative order within a severity; excluded
    findings follow them. Returns the old-to-new ID mapping.
    """
    findings = doc.get("findings", [])
    active = [f for f in findings if f["validation"]["verdict"] not in EXCLUDED]
    ordered = sorted(active, key=lambda f: SEVERITIES.index(f["severity"]))
    ordered += [f for f in findings if f["validation"]["verdict"] in EXCLUDED]
    mapping = {f["id"]: f"PV-{i:03d}" for i, f in enumerate(ordered, 1)}

    def rewrite(value):
        if isinstance(value, str):
            return PV_REFERENCE.sub(lambda m: mapping.get(m.group(), m.group()), value)
        if isinstance(value, list):
            return [rewrite(item) for item in value]
        if isinstance(value, dict):
            return {key: rewrite(item) for key, item in value.items()}
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
    for name in sorted(present - OUTPUTS - set(allow)):
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
    findings = doc.get("findings", [])
    expected = [f"PV-{i:03d}" for i in range(1, len(findings) + 1)]
    if [f["id"] for f in findings] != expected:
        problems.append(f"IDs must be gapless in order: expected {', '.join(expected) or 'none'}; "
                        "run scripts/findings.py renumber")
    ranks = [SEVERITIES.index(f["severity"]) for f in findings if
             f["validation"]["verdict"] not in EXCLUDED]
    if ranks != sorted(ranks):
        order = ", ".join(f"{f['id']} {f['severity']}" for f in findings
                          if f["validation"]["verdict"] not in EXCLUDED)
        problems.append(f"findings must be numbered in severity order (High first): {order}; "
                        "run scripts/findings.py renumber")
    for i, f in enumerate(findings):
        if (f["confidence"] == "Environment-dependent" and f["validation"]["verdict"] not in EXCLUDED
                and not f.get("conditions", "").strip()):
            problems.append(f"findings[{i}].conditions: name the runtime setting an "
                            "Environment-dependent finding assumes")
    recorded = {p["name"]: p["status"] for p in doc.get("perspectives", [])}
    for name in PERSPECTIVES:
        if name not in recorded:
            problems.append(f"perspective not recorded: {name}")
    ledger = {r["id"] for r in doc.get("commitments", [])}
    for i, f in enumerate(findings):
        # Ledger IDs are technical identifiers; other prose was checked by validate.
        for cited in COMMITMENT_REF.findall(f.get("commitment", "")):
            if cited not in ledger:
                problems.append(f"findings[{i}].commitment: {cited} is not in the commitments ledger")
        status = recorded.get(f["category"])
        if f["validation"]["verdict"] not in EXCLUDED and status not in (None, "applied"):
            problems.append(f"findings[{i}].category: its perspective is recorded as {status}, "
                            "not applied")
    for i, r in enumerate(doc.get("commitments", [])):
        if r["status"] == "not checked" and not r.get("reason", "").strip():
            problems.append(f"commitments[{i}]: a not-checked commitment needs a nonblank reason")
    if not doc.get("limitations"):
        problems.append("limitations: state what static reading cannot show")
    if not doc.get("checked_ok"):
        problems.append("checked_ok: list what was examined and held")
    return problems + _stale_outputs(out, doc, unusable | (OUTPUTS - present))


def _stale_outputs(out, doc, skip):
    """Report rendered outputs that no longer match the record they came from."""
    names = ("report.md", "dashboard.html")
    if any(name in skip for name in names):
        return []
    render = _import_sibling("render")  # render imports this module, so load it lazily

    try:
        current = {name: (out / name).read_bytes() for name in names}
    except OSError:
        return [f"unreadable output: {name}" for name in names]
    # Either language is a valid rendering (render.py --lang may override meta.lang).
    for lang in render.LABELS:
        expected = {"report.md": render.render_markdown(doc, lang),
                    "dashboard.html": render.render_html(doc, lang)}
        if all(current[name] == expected[name].encode("utf-8") for name in names):
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


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("merge", help="merge fragments into findings.json")
    m.add_argument("findings")
    m.add_argument("fragments", nargs="+")
    r = sub.add_parser("renumber", help="number findings in severity order and rewrite PV- references")
    r.add_argument("findings")
    c = sub.add_parser("check", help="check the run contract of an output directory")
    c.add_argument("out")
    c.add_argument("--allow", action="append", default=[])
    args = parser.parse_args(argv)
    return {"merge": cmd_merge, "renumber": cmd_renumber, "check": cmd_check}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
