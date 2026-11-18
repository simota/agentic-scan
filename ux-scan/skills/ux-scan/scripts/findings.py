#!/usr/bin/env python3
"""Validate and merge ux-scan records (reference/findings-schema.md, reference/flows.md).

    python3 findings.py check    <out>/findings.json
    python3 findings.py merge    <out>/findings.json FRAGMENT...
    python3 findings.py flows    <out>/flows.json    FRAGMENT...
    python3 findings.py renumber <out>/findings.json

merge updates findings by id, appends new lines to checked_ok, limitations,
decisions and next_steps (a fragment's "remove" deletes exact lines, or
perspectives entries by name), replaces perspectives by name, and drops an
optional finding field sent as null. flows adds or replaces flows by id and replaces
the other top-level keys (app, viewports, locales, tokens). Both check the
result before replacing anything, then write it atomically; a refused fragment
changes nothing. merge accepts findings in any order; renumber then numbers
them U-001.. by severity, then path and line (FalsePositive / NotApplicable
last), and rewrites U-* finding references while preserving source locations
and reference URLs. check, render.py and
contract_check.py require that order. Standard library only.
Exit status: 0 ok, 2 invalid input or unwritable output (reasons on stderr).
"""

import contextlib
import hashlib
import json
import math
import re
import shlex
import sys
from datetime import date
from pathlib import Path
from unicodedata import category as unicode_category
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
from report_output import unsafe_target, write_output  # noqa: E402
from report_format import FormatError, LINE_BREAKS, http_url  # noqa: E402
import evidence as evidence_files  # noqa: E402
from prose_ids import FINDING_ID, RenumberError, rewrite_prose as _rewrite_prose  # noqa: E402

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
META_KEYS = ("project", "date", "assessor", "scope", "method", "commit", "viewports", "locales", "axis")
# Whether the requester confirmed the primary tasks severity is judged against.
AXES = ("confirmed", "assumed")
FINDING_KEYS = ("id", "title", "severity", "confidence", "status", "perspective", "category", "flow_ref", "screen",
                "viewport", "criterion", "location", "occurrences", "observed", "expected", "impact", "fix",
                "validation", "references", "mockup", "evidence")
REQUIRED_FINDING_KEYS = ("id", "title", "severity", "confidence", "status", "perspective", "flow_ref", "screen",
                         "criterion", "location", "validation")
MOCKUP_KEYS = ("title", "before", "after", "states", "viewport", "note", "label", "tier", "alternatives")
ALTERNATIVE_KEYS = ("label", "tier", "after", "states", "note")
# 松竹梅: the scope of a proposal's screen change, widest first (reference/mockups.md).
TIERS = ("full", "standard", "minimal")
STATE_KEYS = ("label", "before", "after", "note")
ALTERNATIVE_STATE_KEYS = ("label", "after")
MAX_MOCKUP_BYTES = 64 * 1024
# Every fragment of a finding's mockups is published in one page.
MAX_FINDING_MOCKUP_BYTES = 1024 * 1024
MAX_ALTERNATIVES = 5
MAX_STATES = 4
MAX_MOCKUPS = 4
# Resource hints (preconnect, dns-prefetch, prefetch) reach the network outside the frame's content policy.
LINK_ELEMENT = re.compile(r"(?i)<link[\s/>]")
VALIDATION_KEYS = ("verdict", "evidence", "intent_checked")
REFERENCE_KEYS = ("type", "title", "url")
HUNT_STEPS = {"IA": 4, "LG": 5, "RS": 5, "VH": 4, "CC": 4, "ST": 4, "FM": 5,
              "FB": 5, "CP": 4, "AX": 6, "MO": 3, "IN": 4, "PP": 4}
FAMILIES = tuple(HUNT_STEPS)
# A perspectives entry name opens with its family token: "AX Accessibility".
FAMILY_NAME = re.compile(r"^(%s)(?=\W|$)" % "|".join(FAMILIES))
FLOW_ID = re.compile(r"^FL-[0-9]{2,3}\Z")
PERSPECTIVE = re.compile(r"^(?:%s)\Z" % "|".join(f"{family}[1-{last}]" for family, last in HUNT_STEPS.items()))
LOCATION = re.compile(r"^(?!/)(?!.*(?:^|/)\.\.(?:/|:))[^\s:][^:\n]*:[1-9][0-9]*(?:-[1-9][0-9]*)?\Z")
VIEWPORT = re.compile(r"^[1-9][0-9]{2,3}x[1-9][0-9]{2,3}\Z")
TEXT_FIELDS = ("title", "category", "screen", "viewport", "criterion", "observed", "expected", "impact", "fix")


class RecordError(Exception):
    pass


def _unicode_text(value, where):
    if "\x00" in value or re.search(r"[\ud800-\udfff]", value):
        raise RecordError(f"{where}: expected Unicode text without NUL or surrogate code points")
    return value


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
    return _unicode_text(value, f"{where}.{key}")


def _strings(value, where, nonempty=True):
    if not isinstance(value, list) or not all(isinstance(x, str) and (x.strip() or not nonempty) for x in value):
        raise RecordError(f"{where}: expected a list of {'non-empty ' if nonempty else ''}strings")
    for i, text in enumerate(value):
        _unicode_text(text, f"{where}[{i}]")
    return value


def _location(value, where):
    if (not isinstance(value, str) or not LOCATION.match(value) or "\\" in value
            or any(unicode_category(c) in ("Cc", "Cf", "Zl", "Zp") for c in value)
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
    try:
        # Use the renderer's public URL validator so merge cannot accept a
        # record that its eventual report will reject (notably encoded hosts).
        http_url(url, where)
        if any(c in '<>"' for c in url):
            raise ValueError("unescaped URL delimiter")
        # Join controls (ZWNJ, ZWJ) are part of words in Persian and Indic text, never of a host.
        host = urlsplit(url).netloc
        if any(unicode_category(c) in ("Cc", "Cf", "Zl", "Zp") for c in host) or any(
                unicode_category(c) in ("Cc", "Cf", "Zl", "Zp") and c not in "\u200c\u200d" for c in url):
            raise ValueError("invisible or control character")
        # Python versions differ in whether urlsplit rejects text after an IPv6 host.
        authority = urlsplit(url).netloc.rsplit("@", 1)[-1]
        if authority.startswith("[") and not re.fullmatch(r"\[[^\]]+\](?::[0-9]*)?", authority):
            raise ValueError("invalid bracketed host")
    except (FormatError, ValueError):
        raise RecordError(f"{where}: expected an http(s) URL") from None


def _viewports(value, where):
    for viewport in _strings(value, where):
        if not VIEWPORT.match(viewport):
            raise RecordError(f"{where}: {viewport!r} is not WIDTHxHEIGHT in CSS px (360x640)")


def _mockup(mockup, where):
    """Check a finding's mockup: one object, or a list of titled ones; returns the bytes of its fragments."""
    if isinstance(mockup, list):
        if not 2 <= len(mockup) <= MAX_MOCKUPS:
            raise RecordError(f"{where}: expected one object, or a list of 2 to {MAX_MOCKUPS} objects with title")
        titles, size = [], 0
        for i, item in enumerate(mockup):
            at = f"{where}[{i}]"
            size += _one_mockup(item, at)
            # The page names each mockup of the finding by its title alone.
            title = _str(item, "title", at, required=True).strip()
            if title in titles:
                raise RecordError(f"{at}.title: {title!r} is already used by another mockup of this finding")
            titles.append(title)
    else:
        size = _one_mockup(mockup, where)
    if size > MAX_FINDING_MOCKUP_BYTES:
        raise RecordError(f"{where}: fragments total more than {MAX_FINDING_MOCKUP_BYTES // 1024} KiB as UTF-8; "
                          "use fewer states or alternatives")


def _evidence(items, where, kinds):
    """Check a finding's evidence list (reference/evidence.md); the files themselves are checked by render.py.

    kinds maps each file named so far in the record to its kind: one file has one kind, as render.py reads it.
    """
    if not isinstance(items, list) or not 1 <= len(items) <= evidence_files.MAX_ITEMS:
        raise RecordError(f"{where}: expected a list of 1 to {evidence_files.MAX_ITEMS} evidence objects "
                          "(\"evidence\": null in a fragment removes it)")
    seen = set()
    for i, item in enumerate(items):
        at = f"{where}[{i}]"
        if not isinstance(item, dict):
            raise RecordError(f"{at}: expected an object")
        _known_keys(item, evidence_files.KEYS, at)
        kind = item.get("kind")
        if not isinstance(kind, str) or kind not in evidence_files.KINDS:
            raise RecordError(f"{at}.kind: expected one of {', '.join(evidence_files.KINDS)}")
        name = _str(item, "file", at, required=True)
        m = evidence_files.FILE.match(name)
        if not m or ".." in name:
            raise RecordError(f"{at}.file: {name!r} is not a plain file name inside {evidence_files.DIRECTORY}/")
        if m["ext"] not in evidence_files.KINDS[kind]:
            raise RecordError(f"{at}.file: a {kind} is .{', .'.join(evidence_files.KINDS[kind])}, not .{m['ext']}")
        if name in seen:
            raise RecordError(f"{at}.file: {name!r} is already listed for this finding")
        seen.add(name)
        if kinds.setdefault(name, kind) != kind:
            raise RecordError(f"{at}.file: {name!r} is cited as a {kinds[name]} elsewhere; one file has one kind")
        if LINE_BREAKS.search(_str(item, "caption", at, required=True)):
            raise RecordError(f"{at}.caption: expected one line")
        if item.get("stage", "before") not in evidence_files.STAGES:
            raise RecordError(f"{at}.stage: expected one of {', '.join(evidence_files.STAGES)}")
        if _str(item, "viewport", at):
            _viewports([item["viewport"]], f"{at}.viewport")
        if "url" in item:
            _http(item["url"], f"{at}.url")
        _str(item, "captured", at)


def _one_mockup(mockup, where):
    if not isinstance(mockup, dict):
        raise RecordError(f"{where}: expected an object with before and after, or with states")
    _known_keys(mockup, MOCKUP_KEYS, where)
    _str(mockup, "title", where)
    _str(mockup, "note", where)
    _str(mockup, "label", where)
    _tier(mockup, where)
    if _str(mockup, "viewport", where):
        _viewports([mockup["viewport"]], f"{where}.viewport")
    states = _states(mockup, where)
    sides = mockup["states"] if states else [mockup]
    size = sum(_fragment(side, key, f"{where}.states[{j}]" if states else where)
               for j, side in enumerate(sides) for key in ("before", "after"))
    if "alternatives" not in mockup:
        if "tier" in mockup:
            raise RecordError(f"{where}.tier: a tiered mockup needs two alternatives carrying the other tiers")
        return size
    alternatives = mockup["alternatives"]
    if not isinstance(alternatives, list) or not 0 < len(alternatives) <= MAX_ALTERNATIVES:
        raise RecordError(f"{where}.alternatives: expected a list of 1 to {MAX_ALTERNATIVES} objects "
                          "with label and after")
    # The page tells the proposals apart by their labels alone, the fix's included.
    labels = [_str(mockup, "label", where, required=True).strip()]
    for i, alternative in enumerate(alternatives):
        at = f"{where}.alternatives[{i}]"
        if not isinstance(alternative, dict):
            raise RecordError(f"{at}: expected an object with label and after")
        _known_keys(alternative, ALTERNATIVE_KEYS, at)
        label = _str(alternative, "label", at, required=True).strip()
        if label in labels:
            raise RecordError(f"{at}.label: {label!r} is already used by another proposal of this mockup")
        labels.append(label)
        _str(alternative, "note", at)
        _tier(alternative, at)
        if not states and "states" in alternative:
            raise RecordError(f"{at}.states: the mockup has no states; give this proposal's after side")
        size += _alternative_states(alternative, states, at) if states else _fragment(alternative, "after", at)
    # Tiered proposals are three, one per tier: the recommended after and two alternatives.
    tiers = [mockup.get("tier"), *(a.get("tier") for a in alternatives)]
    if any(tiers) and sorted(tiers, key=str) != sorted(TIERS):
        raise RecordError(f"{where}: tiered proposals are exactly three, one each of {', '.join(TIERS)}: "
                          "the mockup's tier names its after, and two alternatives carry the others")
    return size


def _tier(proposal, where):
    if "tier" in proposal and proposal["tier"] not in TIERS:
        raise RecordError(f"{where}.tier: expected one of {', '.join(TIERS)}")


def _states(mockup, where):
    """The mockup's state labels, or [] when it compares a single before and after."""
    if "states" not in mockup:
        return []
    for side in ("before", "after"):
        if side in mockup:
            raise RecordError(f"{where}.{side}: a mockup with states keeps its sides in each state")
    states = mockup["states"]
    if not isinstance(states, list) or not 2 <= len(states) <= MAX_STATES:
        raise RecordError(f"{where}.states: expected a list of 2 to {MAX_STATES} objects with label, before and after")
    labels = []
    for j, state in enumerate(states):
        at = f"{where}.states[{j}]"
        if not isinstance(state, dict):
            raise RecordError(f"{at}: expected an object with label, before and after")
        _known_keys(state, STATE_KEYS, at)
        label = _str(state, "label", at, required=True).strip()
        if label in labels:
            raise RecordError(f"{at}.label: {label!r} is already used by another state of this mockup")
        labels.append(label)
        _str(state, "note", at)
    return labels


def _alternative_states(alternative, labels, where):
    """An alternative of a mockup with states gives its after side for each state, in the mockup's order."""
    if "after" in alternative:
        raise RecordError(f"{where}.after: the mockup has states; give this proposal's after side in states")
    states = alternative.get("states")
    expected = f"{where}.states: expected one object with label and after per state, in order: {', '.join(labels)}"
    if not isinstance(states, list) or len(states) != len(labels):
        raise RecordError(expected)
    size = 0
    for j, (state, label) in enumerate(zip(states, labels)):
        at = f"{where}.states[{j}]"
        if not isinstance(state, dict):
            raise RecordError(expected)
        _known_keys(state, ALTERNATIVE_STATE_KEYS, at)
        if _str(state, "label", at, required=True).strip() != label:
            raise RecordError(expected)
        size += _fragment(state, "after", at)
    return size


def _fragment(obj, key, where):
    # Measured as UTF-8, the unit of the documented KiB limit and of the published page.
    if len(_str(obj, key, where, required=True).encode("utf-8")) > MAX_MOCKUP_BYTES:
        raise RecordError(f"{where}.{key}: larger than {MAX_MOCKUP_BYTES // 1024} KiB as UTF-8; "
                          "mock the affected region, not the whole page")
    if LINK_ELEMENT.search(obj[key]):
        raise RecordError(f"{where}.{key}: <link> elements can reach the network; "
                          "inline styles in <style> and use data: URLs for images and fonts")
    return len(obj[key].encode("utf-8"))


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
    if "axis" in meta and meta["axis"] not in AXES:
        raise RecordError(f"meta.axis: expected one of {', '.join(AXES)}")
    _str(data, "summary", "findings")
    for key in LIST_KEYS:
        if key in data:
            _strings(data[key], key, nonempty=False)
    for name in _perspectives(data.get("perspectives", [])):
        if not FAMILY_NAME.match(name.strip()):
            raise RecordError(f"perspectives: {name!r} must start with a family token such as 'AX Accessibility'")
    findings = data.get("findings")
    if not isinstance(findings, list):
        raise RecordError("findings: expected a list")
    if len(findings) > 999:
        raise RecordError("findings: at most 999 findings can be numbered U-001 through U-999")
    seen, evidence_kinds = set(), {}
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
        if LINE_BREAKS.search(f["title"]):
            raise RecordError(f"{where}.title: expected one line")
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
            raise RecordError(f"{where}.occurrences: omit it (\"occurrences\": null in a fragment removes it) "
                              "or list every path:line the fix covers")
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
        if "mockup" in f:
            _mockup(f["mockup"], f"{where}.mockup")
        if "evidence" in f:
            _evidence(f["evidence"], f"{where}.evidence", evidence_kinds)
    if ordered:
        mapping = renumber_map(findings)
        if any(old != new for old, new in mapping.items()) or [f["id"] for f in findings] != list(mapping):
            raise RecordError("findings: ids must be consecutive in severity order (High first), then path and line; "
                              "excluded findings last; run findings.py renumber <out>/findings.json")
    return data


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
    def rewrite(value, replace=True, mockup=False, key=None):
        if isinstance(value, str):
            if not replace:
                return value
            if not (mockup and key in ("label", "title")):
                return _rewrite_prose(value, mapping)
            # Mockup labels and titles are compared stripped: read them so, and labels that matched still match.
            start = len(value) - len(value.lstrip())
            end = start + len(value.strip())
            return value[:start] + _rewrite_prose(value[start:end], mapping) + value[end:]
        if isinstance(value, dict):
            # Mockup sides are markup shown to users, not prose that cites findings; evidence
            # file names name files on disk, even when they carry a finding id.
            return {k: rewrite(v, replace and k not in ("location", "occurrences", "url", "before", "after",
                                                        "file", "captured"),
                               mockup or k == "mockup", k)
                    for k, v in value.items()}
        if isinstance(value, list):
            return [rewrite(v, replace, mockup, key) for v in value]
        return value
    try:
        data = rewrite(data)
    except RenumberError as e:
        raise RecordError(str(e)) from None
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


def load_json(path, record=False):
    """Parse the JSON file at path. A record (findings.json, flows.json) must be a regular file,
    not a symlink, as render.py and contract_check.py require; a fragment may be either."""
    try:
        path = Path(path)
        if record:
            from file_io import read_regular
            try:
                source = read_regular(path)
            except (OSError, ValueError) as e:
                raise RecordError(str(e)) from None  # Its message already names the path.
            return loads_json(source.decode("utf-8"), str(path))
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
    return flow_ids(check_flows(load_json(flows, record=True)))


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
    remove = dict(fragment.get("remove", {})) if isinstance(fragment.get("remove", {}), dict) else None
    if remove is None or not all(k in (*LIST_KEYS, "perspectives") and isinstance(v, list) for k, v in remove.items()):
        raise RecordError(f"remove: expected {{section: [exact lines]}} for {', '.join(LIST_KEYS)}, "
                          "or {\"perspectives\": [names]}")
    names = remove.pop("perspectives", [])
    for name in dict.fromkeys(_strings(names, "remove.perspectives", nonempty=False)):
        if name not in perspectives:
            raise RecordError(f"remove.perspectives: no such entry {name!r}")
        del perspectives[name]
    if names:
        out["perspectives"] = list(perspectives.values())
    for key, lines in remove.items():
        _strings(lines, f"remove.{key}", nonempty=False)
        missing = [x for x in lines if x not in out.get(key, [])]
        if missing:
            raise RecordError(f"remove.{key}: no such line {missing[0]!r}")
        out[key] = [x for x in out.get(key, []) if x not in lines]
    for f in _indexed(fragment.get("findings", []), "fragment.findings", "id", FINDING_ID).values():
        merged = {**by_id.get(f["id"], {}), **f}
        # null removes an optional field such as mockup or occurrences; a required one stays null and is refused.
        # A misspelled key stays, so the check refuses it instead of the null hiding the typo.
        for key in [k for k, v in f.items() if v is None and k in FINDING_KEYS and k not in REQUIRED_FINDING_KEYS]:
            del merged[key]
        by_id[f["id"]] = merged
    out["findings"] = sorted(by_id.values(), key=lambda f: f["id"])
    return out


def dump(data):
    return json.dumps(data, ensure_ascii=False, indent=2, allow_nan=False) + "\n"


RECORDS_LOCK = ".ux-scan-records.lock"


@contextlib.contextmanager
def records_lock(directory):
    """Hold the record directory for one read-merge-write, so two concurrent runs cannot
    both read the old records and the last write drop the other's findings or flows.

    mkdir is exclusive across processes. An existing lock is refused rather than
    guessed stale; a killed process leaves it for explicit recovery.
    """
    lock = Path(directory).absolute() / RECORDS_LOCK
    try:
        lock.mkdir(mode=0o700)
    except FileExistsError:
        raise OSError(
            f"records are locked: {lock}; another findings.py merge, flows or renumber may be running. "
            "If a previous run was interrupted, verify that none is running, "
            f"remove the empty lock with 'rmdir {shlex.quote(str(lock))}', and retry") from None
    try:
        yield
    finally:
        lock.rmdir()


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
            check_findings(load_json(target, record=True), flow_ids_beside(target))
            print(f"ok {target}")
            return 0
        if not target.parent.is_dir():
            raise RecordError(f"{target.parent}: output directory does not exist")
        bad = unsafe_target(target.parent, (target.name,))
        if bad is not None:
            raise RecordError(f"refusing to write {bad}: it exists as a symlink or non-regular file")
        with records_lock(target.parent):
            return _update(cmd, target, fragments)
    except (RecordError, OSError, ValueError, RecursionError) as e:
        print(f"findings.py: {e}", file=sys.stderr)
        return 2


def _update(cmd, target, fragments):
    """Run merge, flows or renumber on target while the records lock is held."""
    if cmd == "flows":
        result = load_json(target, record=True) if target.exists() else {}
        for fragment in fragments:
            result = merge_flows(result, load_json(fragment))
            check_flows(result)
        beside = target.with_name("findings.json")
        if beside.exists() or beside.is_symlink():  # Every flow_ref in the record must stay a flow.
            check_findings(load_json(beside, record=True), flow_ids(result), ordered=False)
        write_output(target, dump(result))
        print(f"wrote {target} ({len(result['flows'])} flows)")
        return 0
    if cmd == "renumber":
        ids = flow_ids_beside(target)
        data = check_findings(load_json(target, record=True), ids, ordered=False)
        mapping = renumber_map(data["findings"])
        moved = ", ".join(f"{old}->{new}" for old, new in sorted(mapping.items()) if old != new)
        normalized = check_findings(renumber(data, mapping), ids)
        if normalized == data:
            print(f"{target}: findings already in order")
            return 0
        write_output(target, dump(normalized))
        print(f"renumbered {target}: {moved or 'restored findings array order'}")
        return 0
    data = load_json(target, record=True) if target.exists() else {"schema_version": 1, "findings": []}
    ids = flow_ids_beside(target)
    for fragment in fragments:
        data = merge(data, load_json(fragment))
        check_findings(data, ids, ordered=False)
    write_output(target, dump(data))
    print(f"wrote {target} ({len(data['findings'])} findings)")
    return 0


if __name__ == "__main__":
    from file_io import tolerant_console
    tolerant_console()
    sys.exit(main())
