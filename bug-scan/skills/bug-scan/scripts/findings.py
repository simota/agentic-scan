#!/usr/bin/env python3
"""Build findings.json from JSON fragments, renumber it, and validate its shape and contract.

    findings.py merge <out>/findings.json <fragment.json>...
    findings.py renumber <out>/findings.json
    findings.py counts <out>/findings.json

The record is never edited by hand. `null` removes an optional key; `{"remove": {"next_steps": ["…"]}}`
deletes an exact list item. Standard library only.
"""
import argparse
import contextlib
import hashlib
import json
import os
import re
import sys
from pathlib import Path

try:
    import fcntl
except ImportError:
    fcntl = None

from common import (CHANNELS, CONFIDENCES, DEFECT_TYPES, EVENT_TYPES, EXCLUDED, HEX_REF, ISO_DATE, LEVELS, LOCATION,
                    PATH_STATES, PATTERNS, PERSPECTIVES, RELATION_TYPES, REPRO_STATES, RISK_TABLE, RecordError, SECRET, SEVERITIES,
                    SIBLING_STATES, STAGES, STATUSES, STRENGTHS, YES_NO, as_list, closed, excluded, load_json, location_path,
                    personal_email, walk_strings, write_json)

TOP_KEYS = {"meta", "summary", "gates", "fix_events", "findings", "issues", "imports", "perspectives",
            "checked_ok", "limitations", "decisions", "next_steps"}
STRING_LISTS = ("checked_ok", "limitations", "decisions", "next_steps")
SECTIONS = {"gates": "id", "fix_events": "id", "findings": "id", "issues": "id", "imports": "key"}
FINDING_LISTS = ("relations", "surfaces", "sibling_sites", "path", "events")
META_KEYS = {"project", "scope", "commit", "date", "assessor", "method", "lang", "history_window", "sample"}
FINDING_KEYS = {"id", "key", "variant", "title", "status", "pattern", "module", "first_seen", "last_seen", "status_log", "introduced_in",
                "fixed_in", "severity", "confidence", "validation", "risk", "hazard", "relations", "repro", "surfaces", "actors",
                "conditions", "location", "events", "tests", "tests_missing", "external_refs", "fix", "guard", "regression_test",
                "fix_order", "owner", "sibling_sites", "affected_releases", "data_remediation", "detection", "path"}
EVENT_KEYS = {"id", "commit", "type", "pattern", "module", "file", "origin", "gate_missed", "regression_test", "detected", "note"}
GATE_KEYS = {"id", "kind", "name", "evidence", "status"}
ISSUE_KEYS = {"id", "kind", "at", "feeds"}
IMPORT_KEYS = {"key", "scan", "title", "severity", "location", "impact"}
SUBSHAPES = {
    "validation": ({"verdict", "method", "evidence"}, {"verdict", "method"}),
    "risk": ({"likelihood", "impact", "detectability", "level", "basis"}, {"likelihood", "impact", "level", "basis"}),
    "hazard": ({"classes", "irreversible", "silent", "reach", "recovery"}, {"classes", "irreversible", "silent", "reach"}),
    "repro": ({"state", "preconditions", "fixture", "environment", "steps", "expected", "actual", "last_run"}, {"state", "steps", "expected"}),
    "introduced_in": ({"commit", "strength", "reason"}, {"strength"}),
    "affected_releases": ({"first", "last", "fixed_first", "basis"}, {"first", "last", "basis"}),
    "data_remediation": ({"needed", "locate", "method", "count"}, {"needed", "count"}),
    "detection": ({"source", "stage", "detected_at", "days_to_detect", "days_to_fix", "basis"}, {"source", "stage"}),
}
ALL_OPEN = ("key", "title", "pattern", "module", "first_seen", "last_seen", "severity", "confidence", "validation", "risk", "hazard",
            "relations", "repro", "surfaces", "actors", "conditions", "location", "events", "tests", "tests_missing", "fix", "guard",
            "regression_test", "sibling_sites", "affected_releases", "data_remediation", "detection", "path", "introduced_in")
LOW_OPEN = ("key", "title", "pattern", "module", "first_seen", "last_seen", "severity", "confidence", "validation", "risk", "hazard",
            "surfaces", "location", "events", "tests", "tests_missing", "introduced_in")
CLOSED_REQUIRED = ("key", "title", "pattern", "module", "first_seen", "last_seen", "introduced_in", "fixed_in", "detection")
EXCLUDED_REQUIRED = ("title", "validation")
CITES_LINE = re.compile(r"[\w./-]+\.[A-Za-z0-9]+:[1-9][0-9]*|\b[\w./-]*/[\w.-]+:[1-9][0-9]*|\b(?:Makefile|Dockerfile|BUILD|CODEOWNERS):[1-9][0-9]*")
ID_MENTION = re.compile(r"(?<![A-Za-z0-9_/-])BG-[0-9]{3}(?![A-Za-z0-9_-])")
RENUMBER_LITERAL = {"meta", "location", "key", "external_refs", "imports", "at", "commit"}


def _keys(where, value, known, errors, required=()):
    if not isinstance(value, dict):
        errors.append(f"{where}: must be an object")
        return False
    for key in sorted(set(value) - set(known)):
        errors.append(f"{where}: unknown key {key!r}")
    for key in required:
        if value.get(key) in (None, ""):
            errors.append(f"{where}: {key} is required")
    return True


def _string_list(where, value, errors, nonempty=False):
    if not isinstance(value, list) or any(not isinstance(i, str) or not i.strip() for i in value):
        errors.append(f"{where}: must be a list of nonblank strings")
    elif nonempty and not value:
        errors.append(f"{where}: must not be empty")


def _enum(where, value, allowed, errors):
    if value not in tuple(allowed):
        errors.append(f"{where}: {value!r} is not one of {', '.join(map(str, allowed))}")


def _locations(where, value, errors):
    for item in as_list(value):
        if not isinstance(item, str) or not LOCATION.match(item):
            errors.append(f"{where}: location {item!r} must be path:line")


def key_of(finding):
    """Identity across runs: pattern, file, surfaces and an optional variant. Lines and titles move without changing the defect."""
    locations = as_list(finding.get("location"))
    place = location_path(locations[0]) if locations else finding.get("module", "") + "|" + finding.get("title", "")
    surfaces = sorted(s["id"] if isinstance(s, dict) else str(s) for s in finding.get("surfaces") or [])
    raw = "|".join((str(finding.get("pattern")), place, ",".join(surfaces), str(finding.get("variant", ""))))
    return hashlib.sha256(raw.encode()).hexdigest()[:12]


def _structure_errors(record):
    """The top-level types everything else relies on."""
    errors = [f"{name}: must be a list" for name in (*SECTIONS, "perspectives") if not isinstance(record.get(name, []), list)]
    if not isinstance(record.get("meta", {}), dict):
        errors.append("meta: must be an object")
    if "summary" in record and not isinstance(record["summary"], str):
        errors.append("summary: must be a string")
    return errors


def shape_errors(record):
    """What every merged state must satisfy. Completeness comes later, in contract_errors."""
    errors = _structure_errors(record)
    if errors:
        return errors
    for key in sorted(set(record) - TOP_KEYS):
        errors.append(f"unknown top-level key {key!r}")
    meta = record.get("meta", {})
    _keys("meta", meta, META_KEYS, errors)
    if isinstance(meta, dict):
        if "lang" in meta:
            _enum("meta.lang", meta["lang"], ("ja", "en"), errors)
        if "date" in meta and not ISO_DATE.match(str(meta["date"])):
            errors.append(f"meta.date: {meta['date']!r} must be YYYY-MM-DD")
        sample = meta.get("sample")
        if sample is not None and (not isinstance(sample, dict) or set(sample) != {"read", "candidates"}
                                   or not all(isinstance(v, int) and v >= 0 for v in sample.values())):
            errors.append("meta.sample: must be {read, candidates} with non-negative integers")
    for name in STRING_LISTS:
        if name in record:
            _string_list(name, record[name], errors)
    seen = {}
    for section, known, required in (("gates", GATE_KEYS, ("id", "kind", "name", "status")),
                                     ("fix_events", EVENT_KEYS, ("id", "commit", "type")),
                                     ("issues", ISSUE_KEYS, ("id", "kind", "at", "feeds")),
                                     ("findings", FINDING_KEYS, ("id", "title", "status")),
                                     ("imports", IMPORT_KEYS, ("key", "scan", "title", "severity"))):
        for index, item in enumerate(record.get(section, [])):
            where = f"{section}[{index}]"
            if not _keys(where, item, known, errors, required):
                continue
            identity = str(item.get(SECTIONS[section]))
            if (section, identity) in seen:
                errors.append(f"{where}: duplicate {identity}")
            seen[(section, identity)] = True
    for gate in record.get("gates", []):
        if isinstance(gate, dict):
            _enum(f"{gate.get('id')}.status", gate.get("status"), ("present", "absent", "unknown"), errors)
            if gate.get("status") == "present" and not (isinstance(gate.get("evidence"), str) and LOCATION.match(gate["evidence"])):
                errors.append(f"{gate.get('id')}: a present gate needs evidence as path:line")
    for event in record.get("fix_events", []):
        if isinstance(event, dict):
            _event_shape(event, errors)
    for issue in record.get("issues", []):
        if isinstance(issue, dict):
            for pattern in as_list(issue.get("feeds")):
                _enum(f"{issue.get('id')}.feeds", pattern, PATTERNS, errors)
    for item in record.get("imports", []):
        if isinstance(item, dict):
            _enum(f"{item.get('key')}.severity", item.get("severity"), SEVERITIES, errors)
            _locations(str(item.get("key")), item.get("location"), errors)
    for finding in record.get("findings", []):
        if isinstance(finding, dict):
            _finding_shape(finding, errors)
    for perspective in record.get("perspectives", []):
        if not isinstance(perspective, dict) or set(perspective) - {"name", "status", "note"}:
            errors.append(f"perspectives: bad entry {perspective!r}")
        else:
            _enum(f"perspective {perspective.get('name')}", perspective.get("status"), ("applied", "N/A", "not checked"), errors)
    for where, text in walk_strings(record):
        if "\x00" in text:
            errors.append(f"{where}: contains NUL")
        address = personal_email(text)
        if address:
            errors.append(f"{where}: holds an e-mail address; the record names no people")
        if SECRET.search(text):
            errors.append(f"{where}: looks like a secret; record a masked value")
    return errors


def _event_shape(event, errors):
    where = str(event.get("id"))
    _enum(f"{where}.type", event.get("type"), EVENT_TYPES, errors)
    if not isinstance(event.get("commit"), str) or not HEX_REF.match(event.get("commit", "")):
        errors.append(f"{where}.commit: must be a hex commit reference")
    if event.get("type") not in DEFECT_TYPES:
        return
    _enum(f"{where}.pattern", event.get("pattern"), PATTERNS, errors)
    _enum(f"{where}.detected", event.get("detected"), STAGES, errors)
    if not isinstance(event.get("module"), str) or not event.get("module"):
        errors.append(f"{where}.module: is required")
    origin = event.get("origin")
    if not _keys(f"{where}.origin", origin, {"commits", "channel", "strength", "reason"}, errors, ("channel", "strength")):
        return
    _enum(f"{where}.origin.channel", origin.get("channel"), CHANNELS, errors)
    _enum(f"{where}.origin.strength", origin.get("strength"), STRENGTHS, errors)
    commits = origin.get("commits", [])
    if not isinstance(commits, list) or any(not isinstance(c, str) or not HEX_REF.match(c) for c in commits):
        errors.append(f"{where}.origin.commits: must be a list of hex references")
    if origin.get("strength") == "Traced" and (not commits or not str(origin.get("reason", "")).strip()):
        errors.append(f"{where}: Traced needs origin commits and a reason that explains the cause")
    if origin.get("strength") == "Blamed" and not commits:
        errors.append(f"{where}: Blamed needs origin commits")
    if origin.get("strength") == "Unattributable" and commits:
        errors.append(f"{where}: Unattributable cannot name origin commits")


def _finding_shape(finding, errors):
    where = str(finding.get("id"))
    for name in FINDING_LISTS:
        if not isinstance(finding.get(name, []), list):
            errors.append(f"{where}.{name}: must be a list")
            return
    _string_list(f"{where}.events", finding.get("events", []), errors)
    _enum(f"{where}.status", finding.get("status"), STATUSES, errors)
    if not re.fullmatch(r"BG-[0-9]{3}", str(finding.get("id"))):
        errors.append(f"{where}: id must be BG-NNN")
    for name, allowed in (("severity", SEVERITIES), ("confidence", CONFIDENCES), ("pattern", PATTERNS)):
        if name in finding:
            _enum(f"{where}.{name}", finding[name], allowed, errors)
    for name, (known, required) in SUBSHAPES.items():
        if name in finding:
            _keys(f"{where}.{name}", finding[name], known, errors, required)
    validation = finding.get("validation")
    if isinstance(validation, dict):
        _enum(f"{where}.validation.verdict", validation.get("verdict"), ("Valid", "Likely", "Unverified", "Unlikely", *EXCLUDED), errors)
    risk = finding.get("risk")
    if isinstance(risk, dict):
        _enum(f"{where}.risk.likelihood", risk.get("likelihood"), LEVELS, errors)
        _enum(f"{where}.risk.impact", risk.get("impact"), LEVELS, errors)
        expected = RISK_TABLE.get((risk.get("likelihood"), risk.get("impact")))
        if expected and risk.get("level") != expected:
            errors.append(f"{where}.risk.level: {risk.get('level')!r} disagrees with the fixed table ({expected})")
    hazard = finding.get("hazard")
    if isinstance(hazard, dict) and "classes" in hazard:
        _string_list(f"{where}.hazard.classes", hazard["classes"], errors, nonempty=True)
    if isinstance(hazard, dict):
        _enum(f"{where}.hazard.irreversible", hazard.get("irreversible"), YES_NO, errors)
        _enum(f"{where}.hazard.silent", hazard.get("silent"), YES_NO, errors)
    repro = finding.get("repro")
    if isinstance(repro, dict):
        _enum(f"{where}.repro.state", repro.get("state"), REPRO_STATES, errors)
        _string_list(f"{where}.repro.steps", repro.get("steps", []), errors, nonempty=True)
        if repro.get("state") == "verified" and not str(repro.get("last_run", "")).strip():
            errors.append(f"{where}: a verified reproduction needs last_run naming the result it refers to")
    introduced = finding.get("introduced_in")
    if isinstance(introduced, dict):
        _enum(f"{where}.introduced_in.strength", introduced.get("strength"), STRENGTHS, errors)
        if introduced.get("strength") != "Unattributable" and not HEX_REF.match(str(introduced.get("commit", ""))):
            errors.append(f"{where}.introduced_in: needs a hex commit unless Unattributable")
    if "fixed_in" in finding and not HEX_REF.match(str(finding["fixed_in"])):
        errors.append(f"{where}.fixed_in: must be a hex commit reference")
    if "location" in finding:
        _locations(where, finding["location"], errors)
    for index, relation in enumerate(finding.get("relations", [])):
        if _keys(f"{where}.relations[{index}]", relation, {"type", "to", "strength", "evidence"}, errors, ("type", "to", "strength", "evidence")):
            _enum(f"{where}.relations[{index}].type", relation.get("type"), RELATION_TYPES, errors)
            _enum(f"{where}.relations[{index}].strength", relation.get("strength"), ("Traced", "Blamed"), errors)
    for index, surface in enumerate(finding.get("surfaces", [])):
        _keys(f"{where}.surfaces[{index}]", surface, {"id", "op"}, errors, ("id",))
    for index, site in enumerate(finding.get("sibling_sites", [])):
        if _keys(f"{where}.sibling_sites[{index}]", site, {"location", "state", "evidence"}, errors, ("location", "state", "evidence")):
            _enum(f"{where}.sibling_sites[{index}].state", site.get("state"), SIBLING_STATES, errors)
            _locations(f"{where}.sibling_sites[{index}]", site.get("location"), errors)
    for index, hop in enumerate(finding.get("path", [])):
        if _keys(f"{where}.path[{index}]", hop, {"from", "to", "state", "at", "why"}, errors, ("from", "to", "state")):
            _enum(f"{where}.path[{index}].state", hop.get("state"), PATH_STATES, errors)
    data = finding.get("data_remediation")
    if isinstance(data, dict):
        _enum(f"{where}.data_remediation.needed", data.get("needed"), YES_NO, errors)
    detection = finding.get("detection")
    if isinstance(detection, dict):
        _enum(f"{where}.detection.stage", detection.get("stage"), STAGES, errors)
    for name in ("first_seen", "last_seen"):
        if name in finding and not ISO_DATE.match(str(finding[name])):
            errors.append(f"{where}.{name}: must be YYYY-MM-DD")


def tier_of(finding):
    if excluded(finding):
        return "excluded"
    if closed(finding):
        return "closed"
    return "full" if finding.get("severity") in ("High", "Medium") else "basic"


REQUIRED_BY_TIER = dict(full=ALL_OPEN, basic=LOW_OPEN, closed=CLOSED_REQUIRED, excluded=EXCLUDED_REQUIRED)


def reference_errors(record):
    """IDs inside the record that name nothing. Fragments may arrive in any order, so this holds only for a finished record."""
    errors = []
    gates = {g.get("id") for g in record.get("gates", [])}
    ids = {f.get("id") for f in record.get("findings", [])}
    for event in record.get("fix_events", []):
        for gate in as_list(event.get("gate_missed")):
            if gate not in gates:
                errors.append(f"{event.get('id')}: gate {gate} is not recorded")
    for finding in record.get("findings", []):
        where = finding.get("id")
        for relation in finding.get("relations", []):
            if relation.get("to") not in ids:
                errors.append(f"{where}: relation points at {relation.get('to')}, which is not recorded")
            if relation.get("to") == where:
                errors.append(f"{where}: a record cannot relate to itself")
    return errors


def contract_errors(record, surfaces=None, history=None):
    """Whether a finished run keeps the contract. It checks shape and consistency, not whether a finding is true."""
    if _structure_errors(record):
        return _structure_errors(record)
    errors = shape_errors(record)
    if errors:
        return errors
    errors.extend(reference_errors(record))
    meta = record.get("meta", {})
    for key in ("project", "scope", "date", "assessor", "lang"):
        if not str(meta.get(key, "")).strip():
            errors.append(f"meta.{key}: is required")
    for name in ("checked_ok", "limitations"):
        if not record.get(name):
            errors.append(f"{name}: must not be empty; a report with no negatives or blind spots cannot be told from one that did not look")
    named = {p.get("name") for p in record.get("perspectives", []) if isinstance(p, dict)}
    for perspective in PERSPECTIVES:
        if perspective not in named:
            errors.append(f"perspectives: {perspective} is not recorded (applied, N/A or not checked)")
    events = {e.get("id"): e for e in record.get("fix_events", []) if isinstance(e, dict)}
    findings = [f for f in record.get("findings", []) if isinstance(f, dict)]
    ids = {f.get("id") for f in findings}
    surface_ids = {s.get("id") for s in (surfaces or {}).get("surfaces", [])}
    commits = (history or {}).get("commits", {})

    def known_commit(ref):
        return any(sha.startswith(ref) for sha in commits)

    history_modules = {m.get("module") for m in (history or {}).get("modules", [])}
    for event in events.values():
        if event.get("type") in DEFECT_TYPES and event.get("module") not in history_modules:
            errors.append(f"{event.get('id')}: module {event.get('module')} is not a module in history.json")
        if not known_commit(str(event.get("commit"))):
            errors.append(f"{event.get('id')}: commit {event.get('commit')} is not in history.json")
        for ref in (event.get("origin") or {}).get("commits", []):
            if not known_commit(str(ref)):
                errors.append(f"{event.get('id')}: origin commit {ref} is not in history.json")
    candidates = len((history or {}).get("fix_candidates", []))
    sample = meta.get("sample")
    if not isinstance(sample, dict):
        errors.append("meta.sample: is required, so a partial read cannot pass for a full one")
    else:
        if sample.get("read") != len(events):
            errors.append(f"meta.sample.read: {sample.get('read')} but {len(events)} fix events are recorded")
        if sample.get("candidates") != candidates:
            errors.append(f"meta.sample.candidates: {sample.get('candidates')} but history.json holds {candidates}")
    for issue in record.get("issues", []):
        if isinstance(issue, dict) and not as_list(issue.get("feeds")):
            errors.append(f"{issue.get('id')}: feeds is empty")
    keys = {}
    for finding in findings:
        if finding.get("key") in keys:
            errors.append(f"{finding.get('id')}: same tracking key as {keys[finding['key']]}; a past defect and its regression, or two defects "
                          "at one place, stay apart only with a short stable variant on one of them")
        elif finding.get("key"):
            keys[finding["key"]] = finding.get("id")
    for finding in findings:
        where = finding.get("id")
        for name in REQUIRED_BY_TIER[tier_of(finding)]:
            if name not in finding:
                errors.append(f"{where}: {name} is required for a {tier_of(finding)} record; write UNKNOWN with the reason when it cannot be determined")
        if not excluded(finding) and not closed(finding):
            risk_required = isinstance(finding.get("risk"), dict)
            if not risk_required:
                errors.append(f"{where}: an unresolved record needs a risk judgement")
        for surface in finding.get("surfaces", []):
            if surface.get("id") not in surface_ids:
                errors.append(f"{where}: surface {surface.get('id')} is not in surfaces.json")
        for event_id in finding.get("events", []):
            if event_id not in events:
                errors.append(f"{where}: event {event_id} is not recorded")
        introduced = finding.get("introduced_in")
        if isinstance(introduced, dict) and introduced.get("commit") and not known_commit(str(introduced["commit"])):
            errors.append(f"{where}: introduced_in {introduced['commit']} is not in history.json")
        if finding.get("fixed_in") and not known_commit(str(finding["fixed_in"])):
            errors.append(f"{where}: fixed_in {finding['fixed_in']} is not in history.json")
        if closed(finding) and excluded(finding):
            errors.append(f"{where}: an excluded record cannot also be closed")
        validation = finding.get("validation") or {}
        if excluded(finding) or closed(finding):
            continue
        if finding.get("severity") in ("High", "Medium"):
            if validation.get("verdict") == "Unverified":
                errors.append(f"{where}: High and Medium need a verdict other than Unverified")
            if not CITES_LINE.search(str(validation.get("evidence", ""))):
                errors.append(f"{where}: High and Medium need validation.evidence citing current code as path:line")
            if not as_list(finding.get("location")):
                errors.append(f"{where}: High and Medium need a current location")
        if finding.get("severity") == "High":
            traced = sum(1 for e in finding.get("events", []) if (events.get(e, {}).get("origin") or {}).get("strength") == "Traced")
            if traced < 3:
                errors.append(f"{where}: High needs at least 3 Traced fix events behind it; {traced} are cited")
    errors.extend(_numbering_errors(findings))
    errors.extend(_mention_errors(record, ids))
    return errors


def sort_key(finding):
    locations = as_list(finding.get("location"))
    order = SEVERITIES.index(finding["severity"]) if finding.get("severity") in SEVERITIES else len(SEVERITIES)
    return (2 if excluded(finding) else 1 if closed(finding) else 0, order, locations[0] if locations else "~", finding.get("title", ""))


def _numbering_errors(findings):
    expected = [f"BG-{n:03d}" for n in range(1, len(findings) + 1)]
    current = [f.get("id") for f in findings]
    ordered = sorted(findings, key=sort_key)
    if current != expected or [f.get("id") for f in ordered] != current:
        return ["findings: IDs must run BG-001… without gaps in priority order; run findings.py renumber"]
    return []


def _mention_errors(record, ids):
    errors = []
    for where, text in walk_strings({k: v for k, v in record.items() if k != "meta"}):
        if ".location" in where or where.endswith(".url"):
            continue
        for mention in ID_MENTION.findall(text):
            if mention not in ids:
                errors.append(f"{where}: mentions {mention}, which no record holds")
    return errors


def _check_fragment(fragment):
    """Types the merge itself relies on, so a bad fragment is refused by name instead of crashing or being half-read."""
    for name in (*SECTIONS, "perspectives", *STRING_LISTS):
        if name in fragment and not isinstance(fragment[name], list):
            raise RecordError(f"{name}: must be a list")
    for section, identity in SECTIONS.items():
        for item in fragment.get(section, []):
            if not isinstance(item, dict):
                raise RecordError(f"{section}: entries must be objects")
            if not isinstance(item.get(identity, ""), str):
                raise RecordError(f"{section}: {identity} must be a string")
    if any(not isinstance(item, dict) for item in fragment.get("perspectives", [])):
        raise RecordError("perspectives: entries must be objects")
    if "meta" in fragment and not isinstance(fragment["meta"], dict):
        raise RecordError("meta: must be an object")
    for finding in fragment.get("findings", []):
        if "key" in finding:
            raise RecordError("key is computed from the pattern, file and surfaces; do not send it")


def merge_fragment(record, fragment):
    _check_fragment(fragment)
    removal = fragment.pop("remove", {})
    if not isinstance(removal, dict):
        raise RecordError("remove: must be an object")
    for name, items in removal.items():
        if name not in STRING_LISTS:
            raise RecordError(f"remove: {name} is not a string list")
        if not isinstance(items, list):
            raise RecordError(f"remove.{name}: must be a list")
        for item in items:
            if item not in record.get(name, []):
                raise RecordError(f"remove: {item!r} is not recorded in {name}")
            record[name].remove(item)
    for key, value in fragment.items():
        if key == "meta":
            for name, item in value.items():
                if item is None:
                    record.setdefault("meta", {}).pop(name, None)
                else:
                    record.setdefault("meta", {})[name] = item
        elif key == "summary":
            if value is None:
                record.pop("summary", None)
            else:
                record["summary"] = value
        elif key in SECTIONS:
            identity = SECTIONS[key]
            given = [i.get(identity) for i in value]
            if len(given) != len(set(given)):
                raise RecordError(f"{key}: a fragment repeats an id")
            existing = {i.get(identity): i for i in record.setdefault(key, [])}
            for item in value:
                target = existing.get(item.get(identity))
                if target is None:
                    record[key].append({k: v for k, v in item.items() if v is not None})
                else:
                    for name, entry in item.items():
                        if entry is None:
                            target.pop(name, None)
                        else:
                            target[name] = entry
        elif key == "perspectives":
            by_name = {p.get("name"): i for i, p in enumerate(record.setdefault(key, []))}
            for item in value:
                if item.get("name") in by_name:
                    record[key][by_name[item["name"]]] = item
                else:
                    record[key].append(item)
        elif key in STRING_LISTS:
            bucket = record.setdefault(key, [])
            bucket.extend(item for item in value if item not in bucket)
        else:
            raise RecordError(f"unknown top-level key {key!r}")


def assign_keys(record):
    for finding in record.get("findings", []):
        if isinstance(finding, dict) and finding.get("pattern"):
            finding["key"] = key_of(finding)


@contextlib.contextmanager
def locked(path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    if fcntl is None:
        yield
        return
    lock = Path(path).parent / ".findings.lock"
    while True:
        handle = open(lock, "w", encoding="utf-8")
        fcntl.flock(handle, fcntl.LOCK_EX)
        # The holder before us unlinks the file on release, so this lock may be on a name nobody else will open.
        # Holding it would let a newcomer lock the new file at the same time, and one merge would overwrite the other.
        try:
            if os.fstat(handle.fileno()).st_ino == os.stat(lock).st_ino:
                break
        except FileNotFoundError:
            pass
        handle.close()
    try:
        yield
    finally:
        lock.unlink(missing_ok=True)
        handle.close()


def merge(path, fragments):
    with locked(path):
        record = load_json(path) if Path(path).exists() else {}
        if not isinstance(record, dict):
            raise RecordError(f"{path}: must be a JSON object")
        errors = shape_errors(record)
        if errors:
            raise RecordError(f"{path} is invalid before merging: {errors[0]}")
        for fragment_path in fragments:
            fragment = load_json(fragment_path)
            if not isinstance(fragment, dict):
                raise RecordError(f"{fragment_path}: must be a JSON object")
            try:
                merge_fragment(record, fragment)
            except RecordError as error:
                raise RecordError(f"{fragment_path}: {error}") from None
            errors = shape_errors(record)
            if errors:
                raise RecordError(f"{fragment_path}: " + "; ".join(errors[:8]) + (f" (and {len(errors) - 8} more)" if len(errors) > 8 else ""))
            assign_keys(record)
        write_json(path, record)


def _rewrite(value, mapping, key=None):
    if key in RENUMBER_LITERAL:
        return value
    if isinstance(value, str):
        return ID_MENTION.sub(lambda m: mapping.get(m.group(0), m.group(0)), value)
    if isinstance(value, list):
        return [_rewrite(item, mapping) for item in value]
    if isinstance(value, dict):
        return {k: _rewrite(v, mapping, k) for k, v in value.items()}
    return value


def renumber(path):
    with locked(path):
        record = load_json(path)
        ordered = sorted(record.get("findings", []), key=sort_key)
        mapping = {f["id"]: f"BG-{n:03d}" for n, f in enumerate(ordered, 1)}
        if [f["id"] for f in record.get("findings", [])] == list(mapping.values()) and all(a == b for a, b in mapping.items()):
            print("already in order")
            return
        record["findings"] = ordered
        rewritten = {k: (v if k == "meta" else _rewrite(v, mapping, k)) for k, v in record.items()}
        write_json(path, rewritten)
        for old, new in mapping.items():
            if old != new:
                print(f"{old} -> {new}")


def counts(record):
    findings = record.get("findings", [])
    open_items = [f for f in findings if not excluded(f) and not closed(f)]
    out = {f"n_{s.lower()}": sum(1 for f in open_items if f.get("severity") == s) for s in SEVERITIES}
    events = record.get("fix_events", [])
    out.update(n_open=len(open_items), n_closed=sum(1 for f in findings if closed(f)), n_excluded=sum(1 for f in findings if excluded(f)),
               n_events=len(events), n_defects=sum(1 for e in events if e.get("type") in DEFECT_TYPES),
               n_traced=sum(1 for e in events if (e.get("origin") or {}).get("strength") == "Traced"),
               n_unattributable=sum(1 for e in events if (e.get("origin") or {}).get("strength") == "Unattributable"))
    return out


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    one = sub.add_parser("merge")
    one.add_argument("path")
    one.add_argument("fragments", nargs="+")
    two = sub.add_parser("renumber")
    two.add_argument("path")
    three = sub.add_parser("counts")
    three.add_argument("path")
    args = parser.parse_args(argv)
    try:
        if args.command == "merge":
            merge(args.path, args.fragments)
            print(f"merged {len(args.fragments)} fragment(s) into {args.path}")
        elif args.command == "renumber":
            renumber(args.path)
        else:
            print(json.dumps(counts(load_json(args.path)), indent=2))
    except RecordError as error:
        print(f"findings.py: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
