#!/usr/bin/env python3
"""Validate and merge ux-scan records (reference/findings-schema.md, reference/flows.md).

    python3 findings.py check    <out>/findings.json
    python3 findings.py merge    <out>/findings.json FRAGMENT...
    python3 findings.py flows    <out>/flows.json    FRAGMENT...
    python3 findings.py renumber <out>/findings.json

merge updates findings by id, appends new lines to checked_ok, limitations,
decisions and next_steps (a fragment's "remove" deletes exact lines), and
replaces perspectives by name. flows adds or replaces flows by id and replaces
the other top-level keys (app, viewports, locales, tokens). Both check the
result before replacing anything, then write it atomically; a refused fragment
changes nothing. merge accepts findings in any order; renumber then numbers
them U-001.. by severity, then path and line (FalsePositive / NotApplicable
last), and rewrites U-* finding references while preserving source locations
and reference URLs. check, render.py and
contract_check.py require that order. Standard library only.
Exit status: 0 ok, 2 invalid input or unwritable output (reasons on stderr).
"""

import hashlib
import json
import math
import re
import sys
import unicodedata
from datetime import date
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan_report_kit.output import unsafe_target, write_output  # noqa: E402

SEVERITIES = ("High", "Medium", "Low", "Info")
CONFIDENCES = ("Confirmed", "Runtime-dependent", "Suspected")
STATUSES = ("Open", "Fixed", "Accepted")
VERDICTS = ("Valid", "Likely", "Unverified", "Unlikely", "FalsePositive", "NotApplicable")
EXCLUDED = ("FalsePositive", "NotApplicable")
PRIORITIES = ("primary", "secondary", "shared")
SOURCES = ("documented", "stated", "inferred")
TOKEN_SCALES = ("spacing", "font_sizes", "breakpoints", "z_index")
LIST_KEYS = ("checked_ok", "limitations", "decisions", "next_steps")
RECORD_KEYS = ("schema_version", "meta", "summary", "perspectives", "findings", *LIST_KEYS)
FLOWS_KEYS = ("app", "viewports", "locales", "tokens", "flows")
FLOW_KEYS = ("id", "name", "priority", "actor", "goal", "source", "evidence", "screens")
SCREEN_KEYS = ("name", "route", "location")
META_KEYS = ("project", "date", "assessor", "scope", "method", "commit", "viewports", "locales")
FINDING_KEYS = ("id", "title", "severity", "confidence", "status", "perspective", "category", "flow_ref", "screen",
                "viewport", "criterion", "location", "occurrences", "observed", "expected", "impact", "fix",
                "validation", "references")
VALIDATION_KEYS = ("verdict", "evidence", "intent_checked")
REFERENCE_KEYS = ("type", "title", "url")
HUNT_STEPS = {"IA": 4, "LG": 5, "RS": 5, "VH": 4, "CC": 4, "ST": 4, "FM": 5,
              "FB": 5, "CP": 4, "AX": 6, "MO": 3, "IN": 4, "PP": 4}
FAMILIES = tuple(HUNT_STEPS)
FINDING_ID = re.compile(r"^U-[0-9]{3}\Z")
FLOW_ID = re.compile(r"^FL-[0-9]{2,3}\Z")
PERSPECTIVE = re.compile(r"^(?:%s)\Z" % "|".join(f"{family}[1-{last}]" for family, last in HUNT_STEPS.items()))
LOCATION = re.compile(r"^(?!/)(?!.*(?:^|/)\.\.(?:/|:))[^\s:][^:\n]*:[1-9][0-9]*(?:-[1-9][0-9]*)?\Z")
VIEWPORT = re.compile(r"^[1-9][0-9]{2,3}x[1-9][0-9]{2,3}\Z")
TEXT_FIELDS = ("title", "category", "screen", "viewport", "criterion", "observed", "expected", "impact", "fix")


class RecordError(Exception):
    pass


def _known_keys(obj, allowed, where):
    """Refuse a misspelled section instead of keeping it where nothing reads it."""
    unknown = sorted(str(k) for k in set(obj) - set(allowed))
    if unknown:
        raise RecordError(f"{where}: unknown key {unknown[0]!r}; expected {', '.join(allowed)}")


def _str(obj, key, where, required=False):
    value = obj.get(key, "")
    if not isinstance(value, str):
        raise RecordError(f"{where}.{key}: expected a string")
    if required and not value.strip():
        raise RecordError(f"{where}.{key}: required")
    return value


def _strings(value, where, nonempty=True):
    if not isinstance(value, list) or not all(isinstance(x, str) and (x.strip() or not nonempty) for x in value):
        raise RecordError(f"{where}: expected a list of {'non-empty ' if nonempty else ''}strings")
    return value


def _location(value, where):
    if (not isinstance(value, str) or not LOCATION.match(value) or "\\" in value
            or any(unicodedata.category(c) in ("Cc", "Cf", "Zl", "Zp") for c in value)
            or value.rpartition(":")[0] != value.rpartition(":")[0].strip()):
        raise RecordError(f"{where}: {value!r} is not a repository-relative path:line")
    path, _, lines = value.rpartition(":")
    if path.rsplit("/", 1)[-1] in ("", "."):
        raise RecordError(f"{where}: {value!r} is not a repository-relative file:line")
    try:
        start, _, end = lines.partition("-")
        if end and int(end) < int(start):
            raise RecordError(f"{where}: line range ends before it starts")
        int(start)  # Also reject numbers too large for the numeric ordering below.
    except ValueError:
        raise RecordError(f"{where}: invalid line number") from None
    return value


def _http(url, where):
    if isinstance(url, str) and not any(c.isspace() or ord(c) < 32 or ord(c) == 127 or c in '\\<>"'
                                        for c in url):
        try:
            parts = urlsplit(url)
            if parts.scheme in ("http", "https") and parts.hostname:
                # Python versions differ in whether urlsplit rejects text after an IPv6 host.
                authority = parts.netloc.rsplit("@", 1)[-1]
                if authority.startswith("[") and not re.fullmatch(r"\[[^\]]+\](?::[0-9]*)?", authority):
                    raise ValueError("invalid bracketed host")
                parts.port  # Access checks malformed and out-of-range ports.
                return
        except ValueError:
            pass
    raise RecordError(f"{where}: expected an http(s) URL")


def _viewports(value, where):
    for viewport in _strings(value, where):
        if not VIEWPORT.match(viewport):
            raise RecordError(f"{where}: {viewport!r} is not WIDTHxHEIGHT in CSS px (360x640)")


def _finite_number(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def _indexed(items, where, key, pattern=None):
    """Validate entries before indexing, so malformed or duplicate rows cannot disappear."""
    if not isinstance(items, list):
        raise RecordError(f"{where}: expected a list")
    result = {}
    for i, item in enumerate(items):
        entry = f"{where}[{i}]"
        if not isinstance(item, dict):
            raise RecordError(f"{entry}: expected an object")
        name = _str(item, key, entry, required=True)
        if pattern is not None and not pattern.match(name):
            raise RecordError(f"{entry}.{key}: invalid id {name!r}")
        if name in result:
            raise RecordError(f"{entry}.{key}: duplicate {name}")
        result[name] = item
    return result


def _perspectives(items, where="perspectives"):
    result = _indexed(items, where, "name")
    for name, item in result.items():
        _known_keys(item, ("name", "result", "note"), f"{where} {name}")
        _str(item, "result", f"{where} {name}")
        _str(item, "note", f"{where} {name}")
    return result


def check_flows(flows):
    """Raise RecordError unless flows matches reference/flows.md; return it."""
    if not isinstance(flows, dict):
        raise RecordError("flows: expected an object")
    _known_keys(flows, FLOWS_KEYS, "flows")
    _str(flows, "app", "flows", required=True)
    _viewports(flows.get("viewports", []), "flows.viewports")
    _strings(flows.get("locales", []), "flows.locales")
    tokens = flows.get("tokens", {})
    if not isinstance(tokens, dict):
        raise RecordError("flows.tokens: expected an object")
    if "tokens" in flows:
        _location(_str(tokens, "source", "flows.tokens", required=True), "flows.tokens.source")
        if not any(key in tokens for key in TOKEN_SCALES):
            raise RecordError(f"flows.tokens: expected at least one scale ({', '.join(TOKEN_SCALES)}); "
                              "omit tokens when there is no token source")
    for key in TOKEN_SCALES:
        if key in tokens:
            scale = tokens[key]
            if (not isinstance(scale, list) or not scale
                    or not all(_finite_number(x) for x in scale)):
                raise RecordError(f"flows.tokens.{key}: expected a non-empty list of numbers (finite; px; plain for z_index)")
    unknown = set(tokens) - {"source", *TOKEN_SCALES}
    if unknown:
        raise RecordError(f"flows.tokens: unknown key {sorted(unknown)[0]!r}; use {', '.join(TOKEN_SCALES)}")
    items = flows.get("flows")
    if not isinstance(items, list) or not items:
        raise RecordError("flows.flows: expected a non-empty list")
    seen = set()
    for i, fl in enumerate(items):
        where = f"flows.flows[{i}]"
        if not isinstance(fl, dict):
            raise RecordError(f"{where}: expected an object")
        fid = _str(fl, "id", where, required=True)
        if not FLOW_ID.match(fid):
            raise RecordError(f"{where}.id: expected FL- and two or three digits (FL-01)")
        if fid in seen:
            raise RecordError(f"{where}.id: duplicate {fid}")
        seen.add(fid)
        where = f"flow {fid}"
        _known_keys(fl, FLOW_KEYS, where)
        if fl.get("priority") not in PRIORITIES:
            raise RecordError(f"{where}.priority: expected one of {', '.join(PRIORITIES)}")
        if fl.get("source") not in SOURCES:
            raise RecordError(f"{where}.source: expected one of {', '.join(SOURCES)}")
        for key in ("name", "goal", "evidence"):
            _str(fl, key, where, required=True)
        _str(fl, "actor", where)
        screens = fl.get("screens")
        if not isinstance(screens, list) or not screens:
            raise RecordError(f"{where}.screens: expected a non-empty list")
        for j, s in enumerate(screens):
            if not isinstance(s, dict):
                raise RecordError(f"{where}.screens[{j}]: expected an object")
            _known_keys(s, SCREEN_KEYS, f"{where}.screens[{j}]")
            _str(s, "name", f"{where}.screens[{j}]", required=True)
            _str(s, "route", f"{where}.screens[{j}]")
            _location(s.get("location"), f"{where}.screens[{j}].location")
    if not any(fl["priority"] == "primary" for fl in items):
        raise RecordError("flows.flows: no primary flow; severity is judged against the primary tasks")
    return flows


def check_findings(data, flow_ids=None, ordered=True):
    """Raise RecordError unless data matches reference/findings-schema.md.

    flow_ids is the set of flows.json flow ids; None skips the flow checks.
    ordered=False skips the consecutive ids and canonical order, which renumber restores after merging.
    """
    if not isinstance(data, dict):
        raise RecordError("findings: expected an object")
    _known_keys(data, RECORD_KEYS, "findings")
    if type(data.get("schema_version")) is not int or data["schema_version"] != 1:
        raise RecordError("schema_version: expected 1")
    meta = data.get("meta")
    if not isinstance(meta, dict):
        raise RecordError("meta: expected an object")
    _known_keys(meta, META_KEYS, "meta")
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
    if "viewports" in meta:
        _viewports(meta["viewports"], "meta.viewports")
    if "locales" in meta:
        _strings(meta["locales"], "meta.locales")
    _str(data, "summary", "findings")
    for key in LIST_KEYS:
        if key in data:
            _strings(data[key], key, nonempty=False)
    _perspectives(data.get("perspectives", []))
    findings = data.get("findings")
    if not isinstance(findings, list):
        raise RecordError("findings: expected a list")
    if len(findings) > 999:
        raise RecordError("findings: at most 999 findings can be numbered U-001 through U-999")
    seen = set()
    for i, f in enumerate(findings):
        where = f"findings[{i}]"
        if not isinstance(f, dict):
            raise RecordError(f"{where}: expected an object")
        fid = _str(f, "id", where, required=True)
        if not FINDING_ID.match(fid):
            raise RecordError(f"{where}.id: expected U- and three digits, got {fid!r}")
        if fid in seen:
            raise RecordError(f"{where}.id: duplicate {fid}")
        seen.add(fid)
        where = f"finding {fid}"
        _known_keys(f, FINDING_KEYS, where)
        for key, allowed in (("severity", SEVERITIES), ("confidence", CONFIDENCES), ("status", STATUSES)):
            if f.get(key) not in allowed:
                raise RecordError(f"{where}.{key}: expected one of {', '.join(allowed)}")
        for key in TEXT_FIELDS:
            _str(f, key, where, required=key in ("title", "screen", "criterion"))
        if f.get("viewport"):
            _viewports([f["viewport"]], f"{where}.viewport")
        perspective = _str(f, "perspective", where, required=True)
        if not PERSPECTIVE.match(perspective):
            raise RecordError(f"{where}.perspective: expected a hunt step id such as AX2 or FM3")
        ref = _str(f, "flow_ref", where, required=True)
        if not FLOW_ID.match(ref):
            raise RecordError(f"{where}.flow_ref: expected a flow id such as FL-01")
        if flow_ids is not None and ref not in flow_ids:
            raise RecordError(f"{where}.flow_ref: {ref} is not a flow in flows.json")
        location = _location(_str(f, "location", where, required=True), f"{where}.location")
        if "occurrences" in f and not f["occurrences"]:
            raise RecordError(f"{where}.occurrences: omit it or list every path:line the fix covers")
        for loc in _strings(f.get("occurrences", [location]), f"{where}.occurrences"):
            _location(loc, f"{where}.occurrences")
        validation = f.get("validation")
        if not isinstance(validation, dict):
            raise RecordError(f"{where}.validation: required")
        _known_keys(validation, VALIDATION_KEYS, f"{where}.validation")
        if validation.get("verdict") not in VERDICTS:
            raise RecordError(f"{where}.validation.verdict: expected one of {', '.join(VERDICTS)}")
        _str(validation, "evidence", f"{where}.validation", required=validation["verdict"] != "Unverified")
        _str(validation, "intent_checked", f"{where}.validation")
        refs = f.get("references", [])
        if not isinstance(refs, list):
            raise RecordError(f"{where}.references: expected a list")
        for j, ref_ in enumerate(refs):
            if not isinstance(ref_, dict):
                raise RecordError(f"{where}.references[{j}]: expected an object")
            _known_keys(ref_, REFERENCE_KEYS, f"{where}.references[{j}]")
            _http(ref_.get("url"), f"{where}.references[{j}].url")
            for key in ("type", "title"):
                _str(ref_, key, f"{where}.references[{j}]")
    if ordered:
        mapping = renumber_map(findings)
        if any(old != new for old, new in mapping.items()) or [f["id"] for f in findings] != list(mapping):
            raise RecordError("findings: ids must be consecutive in severity order (High first), then path and line; "
                              "excluded findings last; run findings.py renumber <out>/findings.json")
    return data


# An id is not part of a word or snake_case name, but may sit inside _emphasis_.
# Emphasis uses one to three underscores, so foo__U-001 and U-001__bar stay names.
BEFORE_ID = r"(?<![A-Za-z0-9])(?<![A-Za-z0-9]_)(?<![A-Za-z0-9]__)(?<![A-Za-z0-9]___)"
AFTER_ID = r"(?![A-Za-z0-9])(?!_{1,3}[A-Za-z0-9])"
FINDING_REF = re.compile(BEFORE_ID + r"U-[0-9]{3}" + AFTER_ID)
FINDING_RANGE = re.compile(
    BEFORE_ID + r"(?P<first_style>\*{1,3}|_{1,3}|~~|)(?P<first_ticks>`*)"
    r"(?P<first>U-[0-9]{3})(?P=first_ticks)(?P=first_style)"
    # A range stays on one line, so a Markdown bullet list of ids is not a range.
    r"[ \t]*(?:(?i:to|through)|から|[-–—−〜～~])[ \t]*"
    r"(?P<last_style>\*{1,3}|_{1,3}|~~|)(?P<last_ticks>`*)(?P<last>U-[0-9]{3})"
    r"(?P=last_ticks)(?P=last_style)" + AFTER_ID + r"(?:まで)?")
FINDING_MENTION = re.compile(
    FINDING_RANGE.pattern
    + "|" + BEFORE_ID + r"(?P<style>\*{1,3}|_{1,3}|~~)(?P<styled>U-[0-9]{3})(?P=style)" + AFTER_ID
    + "|" + FINDING_REF.pattern)
FINDING_LIST = re.compile(
    r"(?<![A-Za-z0-9_./\\:-])U-[0-9]{3}(?:/U-[0-9]{3})+(?![A-Za-z0-9_./\\:-])")
# Parentheses may be part of a path, especially Next.js route groups. Keep
# balanced path components together without swallowing Markdown link labels.
SOURCE_COMPONENT = r"(?:[^\s`<>\"'(),;/\\，、。；（）「」『』]|\([^()\s`<>\"',;/\\，、。；（）「」『』]*\))+"
def _balanced(open_, close, inner, depth=4):
    """A regex for open_…close nested up to depth levels, each level holding inner or a deeper group."""
    pattern = re.escape(open_) + inner + "*" + re.escape(close)
    for _ in range(depth - 1):
        pattern = re.escape(open_) + "(?:" + inner + "|" + pattern + ")*" + re.escape(close)
    return pattern


TAG_NAME = re.compile(r"[a-z][\w.:-]*", re.IGNORECASE)
# Attribute names: plain, Angular (event)/[prop]/[(model)]/*ngIf (these always
# take a value) and #ref. JSX {…} attributes and values are scanned as JavaScript.
# Vue dynamic arguments (:[key], v-slot:[name], @[event]) follow the name.
PLAIN_ATTRIBUTE = re.compile(r"[a-z_:@][\w.:@-]*(?:\[[^\]\s]*\])?", re.IGNORECASE)
BOUND_ATTRIBUTE = re.compile(r"(?:\[\(?|\(|\*)[a-z][\w.@-]*(?:\)\]?|\])?", re.IGNORECASE)
REF_ATTRIBUTE = re.compile(r"#[a-z][\w-]*", re.IGNORECASE)
UNQUOTED_VALUE = re.compile(r"[^\s\"'=<>`{}]+")
MAX_TAG = 8000  # A tag longer than this stays prose; it also bounds every scan.
# Characters tag scans may read per character of prose, plus a fixed allowance;
# past it, remaining "<" are prose. Only text built to defeat the scanner gets there.
TAG_SCAN_BUDGET = (4, 200_000)
# After these, "/" starts a regular expression rather than a division.
REGEX_AFTER = set("(,=:[!&|?{};+-*%>~^") | {""}
# After these keywords, "/" also starts a regular expression.
REGEX_KEYWORDS = {"return", "typeof", "instanceof", "in", "of", "new", "delete", "void", "throw", "case", "do",
                  "else", "yield", "await"}
IDENTIFIER = re.compile(r"[A-Za-z_$][\w$]*")


def _scan_js(text, i, stop):
    """(end of the {…} JavaScript expression opening at text[i] or None, index reached).

    Strings, template literals (with ${…}), comments and regular-expression
    literals are skipped, so braces inside them do not count. Linear in the
    scanned length.
    """
    depth, stack, previous = 0, [], ""
    while i < stop:
        c = text[i]
        if c in "\"'":
            i += 1
            while i < stop and text[i] != c and text[i] != "\n":
                i += 2 if text[i] == "\\" else 1
            if i >= stop or text[i] != c:
                return None, i
            previous = c
        elif c == "`":
            stack.append(depth)  # Inside a template literal until the next unescaped backtick or ${.
            i += 1
            while i < stop and text[i] != "`" and not text.startswith("${", i):
                i += 2 if text[i] == "\\" else 1
            if i >= stop:
                return None, i
            if text[i] == "`":
                stack.pop()
                previous = "`"
            else:
                depth += 1
                i += 1
                previous = "{"
        elif c == "/" and text.startswith("//", i):
            newline = text.find("\n", i, stop)
            if newline < 0:
                return None, i
            i = newline
            continue
        elif c == "/" and text.startswith("/*", i):
            close = text.find("*/", i + 2, stop)
            if close < 0:
                return None, i
            i = close + 2
            continue
        elif c == "/" and (previous in REGEX_AFTER or previous == "<" and text[i - 1] != "<"):
            # After "<", a regex follows a space (x < /a/.test(y)); "</" closes a JSX element.
            i += 1
            in_class = False
            while i < stop and text[i] != "\n" and (in_class or text[i] != "/"):
                if text[i] == "\\":
                    i += 1
                elif text[i] == "[":
                    in_class = True
                elif text[i] == "]":
                    in_class = False
                i += 1
            if i >= stop or text[i] != "/":
                return None, i
            previous = "/x"  # A regex literal ends an operand.
        elif c == "{":
            depth += 1
            previous = c
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i + 1, i + 1
            if stack and depth == stack[-1]:
                # Back inside a template literal after ${…}: continue to its end.
                i += 1
                while i < stop and text[i] != "`" and not text.startswith("${", i):
                    i += 2 if text[i] == "\\" else 1
                if i >= stop:
                    return None, i
                if text[i] == "`":
                    stack.pop()
                    previous = "`"
                else:
                    depth += 1
                    i += 1
                    previous = "{"
            else:
                previous = c
        elif (c == "+" or c == "-") and text.startswith(c, i + 1):
            previous = ")"  # i++ and i-- end an operand, so a following "/" divides.
            i += 2
            continue
        elif identifier := IDENTIFIER.match(text, i, stop):
            # A keyword after "." is a property (obj.return / 2), so "/" then divides.
            previous = "" if identifier.group(0) in REGEX_KEYWORDS and previous != "." else "a"
            i = identifier.end()
            continue
        elif not c.isspace():
            previous = c
        i += 1
    return None, i


def _scan_tag(text, i):
    """(end of the HTML, JSX or Angular open tag at text[i] or None, index reached).

    Follows the CommonMark tag grammar for names and attributes, with JSX
    {expressions} scanned as JavaScript, so "<640px … >1024px" and
    "<sm (U-001) and >lg" are not tags.
    """
    stop = min(len(text), i + MAX_TAG)
    name = TAG_NAME.match(text, i + 1, stop)
    if not name:
        return None, i + 1
    j = name.end()
    while j < stop:
        k = j
        while k < stop and text[k].isspace():
            k += 1
        if k >= stop:
            return None, k
        if text.startswith("/>", k):
            return k + 2, k + 2
        if text[k] == ">":
            return k + 1, k + 1
        if k == j:
            return None, k  # Attributes are separated by whitespace.
        j = k
        if text[j] == "{":
            end, reached = _scan_js(text, j, stop)
            if end is None:
                return None, reached
            j = end
            continue
        if (m := PLAIN_ATTRIBUTE.match(text, j, stop)) or (m := REF_ATTRIBUTE.match(text, j, stop)):
            needs_value = False
        elif m := BOUND_ATTRIBUTE.match(text, j, stop):
            needs_value = True
        else:
            return None, j
        j = m.end()
        k = j
        while k < stop and text[k].isspace():
            k += 1
        if k < stop and text[k] == "=":
            k += 1
            while k < stop and text[k].isspace():
                k += 1
            if k < stop and text[k] in "\"'":
                close = text.find(text[k], k + 1, stop)
                if close < 0:
                    return None, stop
                j = close + 1
            elif k < stop and text[k] == "{":
                end, reached = _scan_js(text, k, stop)
                if end is None:
                    return None, reached
                j = end
            elif value := UNQUOTED_VALUE.match(text, k, stop):
                j = value.end()
            else:
                return None, k
        elif needs_value:
            return None, k
    return None, j


URL_CHAR = r"[^\s<>\"'`()\[\]{}，、。；（）「」『』]"
PROSE_PART = re.compile(
    r"(?P<fence>^[ \t]{0,3}(?:"
    r"(?P<backtick_marker>`{3,})(?!`)[^\n`]*(?:\n|$).*?"
    r"(?:^[ \t]{0,3}(?P=backtick_marker)`*[ \t]*\r?(?=\n|$)|\Z)"
    r"|(?P<tilde_marker>~{3,})(?!~)[^\n]*(?:\n|$).*?"
    r"(?:^[ \t]{0,3}(?P=tilde_marker)~*[ \t]*\r?(?=\n|$)|\Z)))"
    # A code span closes only at a backtick run of exactly the opening length.
    # Like CommonMark, a code span stays within its paragraph: it never crosses
    # a blank line or a fence opener, so a stray backtick is literal text.
    r"|(?<!`)(?P<ticks>`+)(?!`)(?P<code>(?:(?!\n[ \t]*\r?\n|\n[ \t]{0,3}(?:```|~~~)).)*?)(?<!`)(?P=ticks)(?!`)"
    # A comment opener; its end is found in _rewrite_prose (see there).
    r"|(?P<comment><!--)"
    # Closing tags, declarations and processing instructions; an open tag is
    # only marked here ("<" before a name) and measured by _scan_tag.
    r"|(?P<markup></[a-z][\w.:-]*\s*>|<[!?][^<>]*>)"
    r"|(?P<open_tag><)(?=[a-z])"
    # A URL, including raw Japanese path or query text and balanced (…), runs
    # to whitespace, quotes, an unbalanced bracket or Japanese punctuation.
    r"|(?P<url>https?://(?:" + URL_CHAR + "|" + _balanced("(", ")", r"[^\s()<>]") + r")+)"
    r"|(?P<path>[/\\]?" + SOURCE_COMPONENT + r"(?:[/\\]" + SOURCE_COMPONENT + r")+)"
    r"|(?P<token>[^\s`<>\"'(),;，、。；（）「」『』]+)", re.MULTILINE | re.DOTALL | re.IGNORECASE)
MARKDOWN_DESTINATION = re.compile(
    r"(?P<inline>\]\()[ \t]*(?:\r?\n[ \t]*)?"
    r"|^[ \t]{0,3}\[(?:\\.|[^\]\\\r\n])+\]:[ \t]*(?:\r?\n[ \t]*)?", re.MULTILINE)
MARKDOWN_TITLE = r"(?:\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|\((?:\\.|[^()\\])*\))"
MARKDOWN_LINK_END = re.compile(r"(?:[ \t\r\n]+" + MARKDOWN_TITLE + r")?[ \t\r\n]*\)", re.DOTALL)
MARKDOWN_REFERENCE_END = re.compile(
    r"(?:[ \t]+" + MARKDOWN_TITLE + r")?[ \t]*(?=\r?\n|\Z)", re.DOTALL)


def _markdown_destinations(value, literal_spans):
    """Locate link destinations, including extensionless paths and reference definitions."""
    cursor, literal = 0, 0
    while (match := MARKDOWN_DESTINATION.search(value, cursor)) is not None:
        while literal < len(literal_spans) and literal_spans[literal][1] <= match.start():
            literal += 1
        if literal < len(literal_spans) and literal_spans[literal][0] <= match.start():
            cursor = literal_spans[literal][1]
            continue
        start = end = match.end()
        if start == len(value):
            break
        bracketed = value[start] == "<"
        if bracketed:
            end += 1
        depth, closed = 0, False
        while end < len(value):
            char = value[end]
            if char == "\\" and end + 1 < len(value):
                end += 2
                continue
            if bracketed:
                if char == ">":
                    end += 1
                    closed = True
                    break
                if char in "<\r\n":
                    break
            else:
                if char.isspace() or ord(char) < 32 or char in "<>":
                    break
                if char == "(":
                    depth += 1
                elif char == ")":
                    if not depth:
                        break
                    depth -= 1
            end += 1
        valid = closed if bracketed else not depth and end > start
        if valid and ((match["inline"] and MARKDOWN_LINK_END.match(value, end))
                      or (not match["inline"] and MARKDOWN_REFERENCE_END.match(value, end))):
            yield start, end
        cursor = max(end, match.end())


def _source_token(token):
    """Recognize paths/routes and source locations, without treating an ID list as a path."""
    token = token.rstrip(".!?:").strip("[]{}*_~")
    token = FINDING_LIST.sub("", token)
    return ("/" in token or "\\" in token
            or re.search(r"\.[A-Za-z][A-Za-z0-9_-]*(?::[1-9][0-9]*(?:-[1-9][0-9]*)?)?(?:[#?].*)?$", token)
            or re.search(r":[1-9][0-9]*(?:-[1-9][0-9]*)?$", token))


def _rewrite_prose(value, mapping):
    """Update finding references without changing code, URLs or source-like tokens."""
    def references(text):
        def reference_range(match):
            first, last = (int(match[key][2:]) for key in ("first", "last"))
            step = 1 if first <= last else -1
            old_ids = [f"U-{n:03d}" for n in range(first, last + step, step)]
            if not any(mapping.get(fid, fid) != fid for fid in old_ids):
                return match.group(0)
            missing = next((fid for fid in old_ids if fid not in mapping), None)
            if missing:
                raise RecordError(f"finding range {match.group(0)!r} includes unknown {missing}; "
                                  "replace it with an explicit list of existing finding ids before renumbering")
            ticks = match["first_ticks"] or match["last_ticks"]
            style = match["first_style"] or match["last_style"]
            return ", ".join(f"{style}{ticks}{mapping[fid]}{ticks}{style}" for fid in old_ids)

        def joined(start, end):
            """An underscore run of any length joins the id to a name (foo____U-001, U-001____bar)."""
            before = start
            while before > 0 and text[before - 1] == "_":
                before -= 1
            after = end
            while after < len(text) and text[after] == "_":
                after += 1
            return ((before < start and before > 0 and text[before - 1].isascii() and text[before - 1].isalnum())
                    or (after > end and after < len(text) and text[after].isascii() and text[after].isalnum()))

        # Rewrite ranges and single IDs in one pass so mapped IDs are not mapped again.
        def mention(match):
            if joined(match.start(), match.end()):
                if not match["first"]:
                    return match.group(0)
                # A range with one end joined to a name is not a range: map each free id alone.
                return FINDING_REF.sub(
                    lambda ref: ref[0] if joined(match.start() + ref.start(), match.start() + ref.end())
                    else mapping.get(ref[0], ref[0]), match.group(0))
            if match["first"]:
                return reference_range(match)
            if match["styled"]:
                return match["style"] + mapping.get(match["styled"], match["styled"]) + match["style"]
            return mapping.get(match[0], match[0])

        return FINDING_MENTION.sub(mention, text)

    protected_spans, literal_spans = [], []
    position, budget = 0, TAG_SCAN_BUDGET[0] * len(value) + TAG_SCAN_BUDGET[1]
    next_close = None  # The first "-->" at or after the last opener searched, or -1.
    while (match := PROSE_PART.search(value, position)) is not None:
        position = match.end()
        if match["comment"] is not None:
            # The first "-->" after one opener is also the first after any later
            # opener before it, so each close is searched for once: linear time.
            if next_close is None or (next_close != -1 and next_close < match.end()):
                next_close = value.find("-->", match.end())
            line_start = value.rfind("\n", 0, match.start()) + 1
            if next_close != -1:
                end = next_close + 3
            elif re.fullmatch(r"[ \t]{0,3}", value[line_start:match.start()]):
                end = len(value)  # An unclosed comment opening a line starts an HTML block.
            else:
                continue  # As in CommonMark, an unclosed inline <!-- is literal text.
            protected_spans.append((match.start(), end))
            literal_spans.append((match.start(), end))
            position = end
            continue
        if match["open_tag"] is not None:
            if budget <= 0:
                continue
            end, reached = _scan_tag(value, match.start())
            budget -= reached - match.start()
            if end is not None:
                protected_spans.append((match.start(), end))
                literal_spans.append((match.start(), end))
                position = end
            continue
        literal = (match["fence"] is not None or match["markup"] is not None or match["url"] is not None
                   or (match["code"] is not None and not FINDING_ID.fullmatch(match["code"].strip())))
        protected = (literal
                     or (match["path"] is not None and _source_token(match["path"]))
                     or (match["token"] is not None and _source_token(match["token"])))
        if protected:
            protected_spans.append((match.start(), match.end()))
        if literal:
            literal_spans.append((match.start(), match.end()))
    protected_spans.extend(_markdown_destinations(value, literal_spans))
    parts, start = [], 0
    for left, right in sorted(protected_spans):
        if right <= start:
            continue
        if left > start:
            parts.append(references(value[start:left]))
        parts.append(value[max(start, left):right])
        start = right
    parts.append(references(value[start:]))
    return "".join(parts)


def renumber_map(findings):
    """Old id -> new id: severity, then path and line; excluded findings last, in their old order."""
    if len(findings) > 999:
        raise RecordError("findings: at most 999 findings can be numbered U-001 through U-999")
    def key(f):
        path, _, lines = f["location"].rpartition(":")
        return SEVERITIES.index(f["severity"]), path, int(lines.split("-")[0]), f["id"]
    active = sorted((f for f in findings if f["validation"]["verdict"] not in EXCLUDED), key=key)
    excluded = sorted((f for f in findings if f["validation"]["verdict"] in EXCLUDED), key=lambda f: f["id"])
    return {f["id"]: f"U-{n:03d}" for n, f in enumerate(active + excluded, 1)}


def renumber(data, mapping):
    """Rewrite finding references in prose and ids, preserving source locations and URLs."""
    def rewrite(value, replace=True):
        if isinstance(value, str):
            return _rewrite_prose(value, mapping) if replace else value
        if isinstance(value, dict):
            return {k: rewrite(v, replace and k not in ("location", "occurrences", "url"))
                    for k, v in value.items()}
        if isinstance(value, list):
            return [rewrite(v, replace) for v in value]
        return value
    data = rewrite(data)
    data["findings"].sort(key=lambda f: f["id"])
    return data


def loads_json(text, where="JSON"):
    """Parse UTF-8-compatible JSON with unique object keys and finite numbers."""
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate object key {key!r}")
            result[key] = value
        return result

    def finite_float(value):
        number = float(value)
        if not math.isfinite(number):
            raise ValueError(f"non-finite JSON number {value}")
        return number

    def invalid_constant(value):
        raise ValueError(f"non-finite JSON number {value}")

    try:
        data = json.loads(text, object_pairs_hook=unique_object, parse_float=finite_float,
                          parse_constant=invalid_constant)
        pending = [data]
        while pending:
            value = pending.pop()
            if isinstance(value, str):
                value.encode("utf-8")  # Reject unpaired surrogates, including escaped JSON strings.
            elif isinstance(value, dict):
                pending.extend(value)
                pending.extend(value.values())
            elif isinstance(value, list):
                pending.extend(value)
        return data
    except (ValueError, RecursionError) as e:
        raise RecordError(f"{where}: {e}") from None


def load_json(path):
    try:
        path = Path(path)
        if not path.is_file():
            raise RecordError(f"{path}: expected a regular JSON file")
        return loads_json(path.read_text(encoding="utf-8"), str(path))
    except (OSError, ValueError) as e:
        raise RecordError(f"{path}: {e}") from None


def canonical_digest(data):
    """A stable SHA-256 for the JSON data, independent of whitespace and object key order."""
    try:
        canonical = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
        return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    except (TypeError, ValueError, RecursionError) as e:
        raise RecordError(f"JSON digest: {e}") from None


def flow_ids(flows):
    """The flow ids of a checked flows.json."""
    return {fl["id"] for fl in flows["flows"]}


def flow_ids_beside(findings_path):
    flows = Path(findings_path).with_name("flows.json")
    if not flows.exists() and not flows.is_symlink():
        return None
    return flow_ids(check_flows(load_json(flows)))


def merge_flows(base, fragment):
    """base with fragment's top-level keys replaced and its flows added or replaced by id."""
    if not isinstance(base, dict):
        raise RecordError("flows: expected an object")
    if not isinstance(fragment, dict):
        raise RecordError("flows fragment: expected an object with a flows list")
    _known_keys(fragment, (*FLOWS_KEYS, "remove"), "flows fragment")
    out = {**base, **{k: v for k, v in fragment.items() if k not in ("flows", "remove")}}
    if "tokens" in fragment and fragment["tokens"] is None:  # Drops a token source recorded in error.
        out.pop("tokens", None)
    by_id = _indexed(base.get("flows", []), "flows.flows", "id", FLOW_ID)
    remove = fragment.get("remove", {})
    if (not isinstance(remove, dict) or set(remove) - {"flows"}
            or not isinstance(remove.get("flows", []), list)
            or not all(isinstance(x, str) for x in remove.get("flows", []))):
        raise RecordError('flows fragment.remove: expected {"flows": [flow ids]}')
    for fid in remove.get("flows", []):
        if fid not in by_id:
            raise RecordError(f"flows fragment.remove.flows: no such flow {fid!r}")
        del by_id[fid]
    by_id.update(_indexed(fragment.get("flows", []), "flows fragment.flows", "id", FLOW_ID))
    out["flows"] = list(by_id.values())
    return out


def merge(base, fragment):
    if not isinstance(base, dict):
        raise RecordError("findings: expected an object")
    if not isinstance(fragment, dict):
        raise RecordError("fragment: expected an object")
    _known_keys(fragment, (*RECORD_KEYS, "remove"), "fragment")
    for key in LIST_KEYS:
        if key in base:
            _strings(base[key], key, nonempty=False)
    perspectives = _perspectives(base.get("perspectives", []))
    by_id = {key: dict(value) for key, value in _indexed(base.get("findings", []), "findings", "id", FINDING_ID).items()}
    out = dict(base)
    for key, value in fragment.items():
        if key in LIST_KEYS:
            _strings(value, f"fragment.{key}", nonempty=False)
            out[key] = list(dict.fromkeys([*base.get(key, []), *value]))
        elif key == "perspectives":
            perspectives.update(_perspectives(value, "fragment.perspectives"))
            out[key] = list(perspectives.values())
        elif key not in ("findings", "remove"):
            out[key] = value
    remove = fragment.get("remove", {})
    if not isinstance(remove, dict) or not all(k in LIST_KEYS and isinstance(v, list) for k, v in remove.items()):
        raise RecordError(f"remove: expected {{section: [exact lines]}} for {', '.join(LIST_KEYS)}")
    for key, lines in remove.items():
        _strings(lines, f"remove.{key}", nonempty=False)
        missing = [x for x in lines if x not in out.get(key, [])]
        if missing:
            raise RecordError(f"remove.{key}: no such line {missing[0]!r}")
        out[key] = [x for x in out.get(key, []) if x not in lines]
    for f in _indexed(fragment.get("findings", []), "fragment.findings", "id", FINDING_ID).values():
        by_id[f["id"]] = {**by_id.get(f["id"], {}), **f}
    out["findings"] = sorted(by_id.values(), key=lambda f: f["id"])
    return out


def dump(data):
    return json.dumps(data, ensure_ascii=False, indent=2, allow_nan=False) + "\n"


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if (len(argv) < 2 or argv[0] not in ("check", "merge", "flows", "renumber")
            or (argv[0] in ("merge", "flows") and len(argv) < 3)
            or (argv[0] in ("check", "renumber") and len(argv) != 2)):
        print("usage:\n" + "\n".join(__doc__.splitlines()[2:6]), file=sys.stderr)
        return 2
    cmd, target, fragments = argv[0], Path(argv[1]), argv[2:]
    try:
        if cmd == "check":
            check_findings(load_json(target), flow_ids_beside(target))
            print(f"ok {target}")
            return 0
        if not target.parent.is_dir():
            raise RecordError(f"{target.parent}: output directory does not exist")
        bad = unsafe_target(target.parent, (target.name,))
        if bad is not None:
            raise RecordError(f"refusing to write {bad}: it exists as a symlink or non-regular file")
        if cmd == "flows":
            result = load_json(target) if target.exists() else {}
            for fragment in fragments:
                result = merge_flows(result, load_json(fragment))
                check_flows(result)
            beside = target.with_name("findings.json")
            if beside.exists() or beside.is_symlink():  # Every flow_ref in the record must stay a flow.
                check_findings(load_json(beside), flow_ids(result), ordered=False)
            write_output(target, dump(result))
            print(f"wrote {target} ({len(result['flows'])} flows)")
            return 0
        if cmd == "renumber":
            ids = flow_ids_beside(target)
            data = check_findings(load_json(target), ids, ordered=False)
            mapping = renumber_map(data["findings"])
            moved = ", ".join(f"{old}->{new}" for old, new in sorted(mapping.items()) if old != new)
            normalized = check_findings(renumber(data, mapping), ids)
            if normalized == data:
                print(f"{target}: findings already in order")
                return 0
            write_output(target, dump(normalized))
            print(f"renumbered {target}: {moved or 'restored findings array order'}")
            return 0
        data = load_json(target) if target.exists() else {"schema_version": 1, "findings": []}
        ids = flow_ids_beside(target)
        for fragment in fragments:
            data = merge(data, load_json(fragment))
            check_findings(data, ids, ordered=False)
        write_output(target, dump(data))
        print(f"wrote {target} ({len(data['findings'])} findings)")
        return 0
    except (RecordError, OSError, ValueError, RecursionError) as e:
        print(f"findings.py: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
