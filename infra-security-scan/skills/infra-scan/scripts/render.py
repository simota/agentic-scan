#!/usr/bin/env python3
"""Render findings.json into the dashboard, the assessment and its PDF.

    python3 render.py FINDINGS --out DIR [--lang ja|en] [--no-pdf] [--repo REPO]

Writes DIR/dashboard.html (interactive, self-contained), DIR/assessment.html
(the formal, print-oriented report) and DIR/assessment.pdf (headless Chrome,
set CHROME to choose the binary; WeasyPrint is the fallback). With --repo, each finding's `path:line` is
embedded as a short source excerpt; state files, variable files and
secret-looking files are never read, and lines that look like they assign a
secret are redacted. JSON/YAML with sensitive metadata, secret environment
values or unsupported syntax has no excerpt. Other redaction is heuristic:
inspect before sharing.

`validate()` is the executable form of reference/findings-schema.md and is
imported by findings.py and contract_check.py.

Exit codes: 0 rendered (a missing PDF engine is a warning), 2 unreadable input,
schema error, refused or unwritable output directory (every problem on stderr).
"""
import argparse
import datetime
import functools
import hashlib
import html
import json
import os
from pathlib import Path
import posixpath
import re
import shutil
import sys
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))  # also under python -I
from common import (BASELINE_REFERENCE, CARRY_NOTE, MAX_JSON_DEPTH, RECORD_LISTS, RECORD_REFERENCE, SEV_RANK,
                    SEVERITIES, STATE_FILE, STRING_LISTS, find_references, has_symlink_parent, json_depth,
                    meta_prose, reviewer_fields, shape_problems, split_yaml_documents, unique_object)
from iac_scan import MAX_BYTES, SKIP_DIRS, UNKNOWN, _YamlSubset, is_export, literal, parse_hcl
from redaction import (SAFE_VALUE, SETTING_NAME, has_escaped_secret_keys, has_structured_secrets, hide_credentials,
                       is_secret_name, redact_json_values, redact_lines, scrub_line, scrub_lines, split_lines)
from scan_report_kit import pdf as kit_pdf, style as kit_style
from scan_report_kit.output import unsafe_target, write_output

SKILL = Path(__file__).resolve().parents[1]

TOP = {"schema_version", "meta", "inventory", *RECORD_LISTS}
CONFIDENCES = ("Confirmed", "Environment-dependent", "Suspected")
PROVIDERS = ("aws", "gcp", "azure", "kubernetes", "multi")
VERDICTS = ("Valid", "Likely", "Unverified", "Unlikely", "FalsePositive", "NotApplicable")
NEEDS_EVIDENCE = {"Valid", "FalsePositive", "NotApplicable"}
EXCLUDED = {"FalsePositive", "NotApplicable"}
AP_STATUSES = ("open", "blocked", "unknown")
P_STATUSES = ("Applied", "N/A", "Not checked")
INPUT_KINDS = ("iac", "plan", "snapshot", "manifest")
# ASCII digits and \Z: "$" would accept a trailing newline and \d other scripts' digits.
# Numbering starts at 1; nine digits bound int() well below Python's limit.
F_ID = re.compile(r"^F-(?!0+\Z)([0-9]{3,9})\Z")
I_ID = re.compile(r"^I-(?!0+\Z)([0-9]{3,9})\Z")
AP_ID = re.compile(r"^AP-(?!0+\Z)([0-9]{2,9})\Z")
# Repository paths may contain spaces and colons ("env prod/main.tf"); only
# the trailing :line or :line-line is structure.
LOCATION = re.compile(r"^(\S(?:.*\S)?):([0-9]{1,9})(?:-([0-9]{1,9}))?\Z")
# A cited edge names a file: a path with an extension (a dotfile such as
# .env or .terraform-version too), or a known extensionless file such as
# CODEOWNERS, Makefile or Dockerfile.
# The lookbehind starts a match only at a path's first character: searching
# from every offset of a long dotted word was quadratic.
CITED = re.compile(r"(?<![\w./@-])(?:[\w./@-]*\.[A-Za-z][\w-]*|(?:[\w.@-]+/)*(?:CODEOWNERS|[A-Z][A-Za-z]*file)):[0-9]+")
DATE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}\Z")
F_FIELDS = ("actor", "path", "contrast", "impact", "fix", "regression")
# Keys outside these sets are typos or fields no output shows; refuse them
# rather than silently dropping what the reviewer wrote.
META_KEYS = {"project", "scope", "date", "assessor", "method", "providers", "inputs", "commit"}
FINDING_KEYS = {"id", "title", "severity", "confidence", "category", "provider", "resources", "location",
                *F_FIELDS, "controls", "cwe", "attack_paths", "condition", "references", "rule",
                "detail", "validation"}
AP_KEYS = {"id", "entry", "target", "status", "edges", "findings", "note"}
PERSPECTIVE_KEYS = {"name", "status", "note"}
VALIDATION_KEYS = {"verdict", "evidence"}
INPUT_KEYS = {"kind", "path", "note"}
REFERENCE_KEYS = {"title", "url"}
INVENTORY_KEYS = {"resources", "by_provider", "files", "not_run"}
BASE_FIELDS = ("title", "location")

class SchemaError(Exception):
    def __init__(self, problems):
        items = [problems] if isinstance(problems, str) else list(problems)
        self.problems = [hide_credentials(str(item)) for item in items]
        super().__init__("; ".join(self.problems))


@functools.lru_cache(maxsize=None)
def _perspective_names():
    return tuple(_read_perspective_names())


def perspective_names():
    """Canonical names (cached: the file is read once per process)."""
    return list(_perspective_names())


def _read_perspective_names():
    """Canonical names, read from the first table in reference/perspectives.md."""
    names = []
    for line in (SKILL / "reference" / "perspectives.md").read_text(encoding="utf-8").splitlines():
        if not line.startswith("|"):
            if names:
                break  # the end of the first table
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) == 2 and cells[0] not in ("Perspective", "") and not set(cells[0]) <= set("-: "):
            names.append(cells[0])
    return names


def blank(value):
    return not isinstance(value, str) or not value.strip()


MAX_DEPTH = MAX_JSON_DEPTH
depth = json_depth


def load(path):
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=unique_object)
    except (OSError, UnicodeError, ValueError, RecursionError) as e:
        raise SchemaError(f"{path}: {e}") from None
    if depth(data) > MAX_DEPTH:
        raise SchemaError(f"{path}: nested deeper than {MAX_DEPTH} levels")
    return data


# Both HTML reports carry the digest of the record they show, so
# contract_check.py can tell a report rendered before the last merge.
RECORD_STAMP = re.compile(r'<meta name="infra-scan-record" content="sha256:([0-9a-f]{64})">')


def record_digest(data):
    """sha256 of the record's content, independent of its file's formatting."""
    text = json.dumps(data, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def stamp(page, digest):
    return page.replace('<meta charset="utf-8">',
                        f'<meta charset="utf-8"><meta name="infra-scan-record" content="sha256:{digest}">', 1)


def load_record(path):
    """A findings.json whose structure the tools can walk; SchemaError otherwise."""
    data = load(path)
    problems = shape_problems(data)
    if problems:
        raise SchemaError(problems)
    return data


CWE = re.compile(r"^CWE-[0-9]+\Z")
LINE_BREAK = re.compile(r"[\r\n\x85\u2028\u2029]")
URL_UNSAFE = re.compile(r"[\s\x00-\x1f\x7f-\x9f<>`\"']")


def _balanced_parens(text):
    depth_count = 0
    for ch in text:
        if ch == "(":
            depth_count += 1
        elif ch == ")":
            if depth_count == 0:
                return False
            depth_count -= 1
    return depth_count == 0


def valid_date(value):
    if not DATE.match(value):
        return False
    try:
        datetime.date.fromisoformat(value)
    except ValueError:
        return False
    return True


def utf8(text):
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def all_strings(data):
    """(top-level key, text) for every key and string value, without recursion.

    Only the top-level key is named: a nested key may itself be a credential.
    """
    stack = [(value, str(key)) for key, value in data.items()] if isinstance(data, dict) else []
    while stack:
        item, at = stack.pop()
        if isinstance(item, str):
            yield at, item
        elif isinstance(item, list):
            stack.extend((x, at) for x in item)
        elif isinstance(item, dict):
            for key, x in item.items():
                yield at, str(key)
                stack.append((x, at))


def location_problem(location):
    """path:line or path:line-line, with lines counted from 1."""
    if LINE_BREAK.search(location):
        return "location must be path:line or path:line-line"
    m = LOCATION.match(location)
    if not m:
        return "location must be path:line or path:line-line"
    start, end = int(m.group(2)), int(m.group(3) or m.group(2))
    if start < 1 or end < start:
        return "location lines start at 1 and a range must not run backwards"
    return None




def dangling_references(data):
    """[(where, ID)] for F-*, AP-* and I-* IDs named in prose that no record has.

    An ID that no record has was renumbered, removed or dropped by a rescan
    without its mention being updated. URLs and external references are not
    prose. The carry-over notes iac_scan.py writes in limitations name
    baseline IDs from earlier scans on purpose.
    """
    known = {f.get("id") for f in data.get("findings", []) if isinstance(f, dict)}
    known |= {a.get("id") for a in data.get("attack_paths", []) if isinstance(a, dict)}
    out = []

    def walk(value, where, baseline=True):
        if isinstance(value, str):
            out.extend((where, m.group()) for m in find_references(RECORD_REFERENCE, value)
                       if m.group() not in known and (baseline or not m.group().startswith("I-")))
        elif isinstance(value, list):
            for item in value:
                walk(item, where, baseline)
        elif isinstance(value, dict):
            for key, item in value.items():
                if key not in ("id", "references"):
                    walk(item, f"{where}.{key}", baseline)
    for key in ("findings", "attack_paths", "perspectives"):
        for item in data.get(key, []):
            if isinstance(item, dict):
                walk(reviewer_fields(item), str(item.get("id") or item.get("name") or key))
    for key in STRING_LISTS:
        lines = data.get(key, [])
        for line in lines if isinstance(lines, list) else [lines]:
            walk(line, key, baseline=not (key == "limitations" and isinstance(line, str)
                                          and CARRY_NOTE.fullmatch(line)))
    walk(meta_prose(data.get("meta")), "meta")
    return out


def untriaged(data):
    """Findings still Unverified: an I-* not yet triaged, or any finding a rescan reopened."""
    return [f for f in data.get("findings", []) if isinstance(f, dict) and isinstance(f.get("validation"), dict)
            and f["validation"].get("verdict") == "Unverified"]


def location_key(location):
    """Order path:line numerically within a file: storage.tf:9 before :10."""
    m = LOCATION.match(location) if isinstance(location, str) else None
    if not m:
        return (str(location), 0, 0)
    return (m.group(1), int(m.group(2)), int(m.group(3) or m.group(2)))


def empty_record():
    return {"schema_version": 1, "meta": {}, **{key: [] for key in RECORD_LISTS}}


def validate(data, partial=False):
    """Raise SchemaError listing every problem. partial=True skips the meta fields
    a record only needs once complete (used while fragments are still merging)."""
    if not isinstance(data, dict):
        raise SchemaError("record: must be a JSON object")
    p = []
    add = p.append
    unknown = set(data) - TOP
    if unknown:
        add(f"record: unknown top-level keys {sorted(unknown)}")
    if type(data.get("schema_version")) is not int or data["schema_version"] != 1:
        add("record: schema_version must be 1")

    meta = data.get("meta", {})
    if not isinstance(meta, dict):
        add("meta: must be an object")
        meta = {}
    unknown = sorted(k for k in meta if k not in META_KEYS)
    if unknown:
        add(f"meta: unknown keys {unknown}")
    if not partial:
        for key in ("project", "scope", "date", "assessor"):
            if blank(meta.get(key)):
                add(f"meta.{key}: required")
    if not blank(meta.get("date")) and not valid_date(meta["date"]):
        add("meta.date: must be a calendar date, YYYY-MM-DD")
    for key in ("project", "scope", "date", "assessor", "method", "commit"):
        if key in meta and not isinstance(meta[key], str):
            add(f"meta.{key}: must be a string")
        elif isinstance(meta.get(key), str) and LINE_BREAK.search(meta[key].strip()):
            add(f"meta.{key}: must be one line")
    if "providers" in meta:
        prov = meta["providers"]
        if not isinstance(prov, list) or any(x not in PROVIDERS[:4] for x in prov):
            add("meta.providers: must be a list of aws, gcp, azure, kubernetes")
    if "inputs" in meta:
        if not isinstance(meta["inputs"], list):
            add("meta.inputs: must be a list")
        else:
            for i, item in enumerate(meta["inputs"]):
                if not isinstance(item, dict) or item.get("kind") not in INPUT_KINDS or blank(item.get("path")):
                    add(f"meta.inputs[{i}]: needs kind ({'|'.join(INPUT_KINDS)}) and path")
                elif set(item) - INPUT_KEYS:
                    add(f"meta.inputs[{i}]: unknown keys {sorted(set(item) - INPUT_KEYS)}; "
                        "put capture times and other details in note")
                elif not isinstance(item["path"], str) or not isinstance(item.get("note", ""), str):
                    add(f"meta.inputs[{i}]: path and note must be strings")

    if "inventory" in data and not isinstance(data["inventory"], dict):
        add("inventory: must be an object")
    elif isinstance(data.get("inventory"), dict):
        inv = data["inventory"]
        if set(inv) - INVENTORY_KEYS:
            add(f"inventory: unknown keys {sorted(set(inv) - INVENTORY_KEYS)}")
        for key in ("resources", "files"):
            if key in inv and (type(inv[key]) is not int or inv[key] < 0):
                add(f"inventory.{key}: must be a count")
        if "by_provider" in inv and not (isinstance(inv["by_provider"], dict) and all(
                type(v) is int and v >= 0 for v in inv["by_provider"].values())):
            add("inventory.by_provider: must map providers to counts")
        if "not_run" in inv and not (isinstance(inv["not_run"], list) and all(
                isinstance(x, str) for x in inv["not_run"])):
            add("inventory.not_run: must be a list of strings")
    unencodable = sorted({where for where, text in all_strings(data) if not utf8(text)})
    if unencodable:
        add(f"record: text with a lone surrogate (not valid UTF-8) in {', '.join(unencodable)}")

    findings = data.get("findings", [])
    if not isinstance(findings, list):
        add("findings: must be a list")
        findings = []
    paths = data.get("attack_paths", [])
    if not isinstance(paths, list):
        add("attack_paths: must be a list")
        paths = []
    # Only string IDs can be referenced; other types are reported below
    # instead of crashing set membership.
    finding_ids = {f.get("id") for f in findings if isinstance(f, dict) and isinstance(f.get("id"), str)}
    ap_ids = {a.get("id") for a in paths if isinstance(a, dict) and isinstance(a.get("id"), str)}
    names = perspective_names()

    seen = set()
    for n, f in enumerate(findings):
        if not isinstance(f, dict):
            add(f"findings[{n}]: must be an object")
            continue
        fid = f.get("id")
        where = fid if isinstance(fid, str) else f"findings[{n}]"
        is_f = isinstance(fid, str) and bool(F_ID.match(fid))
        is_i = isinstance(fid, str) and bool(I_ID.match(fid))
        if not (is_f or is_i):
            add(f"{where}: id must be F-NNN or I-NNN (at least three digits)")
        else:
            # F-001 and F-0001 are the same number; IDs are compared numerically.
            if id_key(fid) in seen:
                add(f"{where}: duplicate id")
            seen.add(id_key(fid))
        unknown = sorted(str(k) for k in f if k not in FINDING_KEYS)
        if unknown:
            add(f"{where}: unknown keys {unknown}")
        for key in BASE_FIELDS:
            if blank(f.get(key)):
                add(f"{where}: {key} required")
        if isinstance(f.get("title"), str) and LINE_BREAK.search(f["title"].strip()):
            add(f"{where}: title must be one line")
        if f.get("severity") not in SEVERITIES:
            add(f"{where}: severity must be one of {', '.join(SEVERITIES)}")
        if f.get("confidence") not in CONFIDENCES:
            add(f"{where}: confidence must be one of {', '.join(CONFIDENCES)}")
        if f.get("category") not in names:
            add(f"{where}: category must be a perspective name from reference/perspectives.md")
        if f.get("provider") not in PROVIDERS:
            add(f"{where}: provider must be one of {', '.join(PROVIDERS)}")
        res = f.get("resources")
        if not isinstance(res, list) or not res or any(blank(r) or LINE_BREAK.search(r) for r in res):
            add(f"{where}: resources must be a nonempty list of resource addresses")
        if not blank(f.get("location")):
            problem = location_problem(f["location"])
            if problem:
                add(f"{where}: {problem}")
        if is_f:
            for key in F_FIELDS:
                if blank(f.get(key)):
                    add(f"{where}: {key} required for F-* findings")
        if is_i and blank(f.get("rule")):
            add(f"{where}: rule required for I-* findings")
        if f.get("confidence") == "Environment-dependent" and blank(f.get("condition")):
            add(f"{where}: condition required when confidence is Environment-dependent")
        for key in ("actor", "path", "contrast", "impact", "fix", "regression", "condition", "cwe", "rule",
                    "detail"):
            if key in f and not isinstance(f[key], str):
                add(f"{where}: {key} must be a string")
        if "controls" in f and (not isinstance(f["controls"], list) or any(
                blank(c) or LINE_BREAK.search(c) for c in f["controls"])):
            add(f"{where}: controls must be a list of strings")
        if isinstance(f.get("cwe"), str) and not CWE.match(f["cwe"]):
            add(f"{where}: cwe must look like CWE-284")
        if "attack_paths" in f:
            if not isinstance(f["attack_paths"], list):
                add(f"{where}: attack_paths must be a list")
            else:
                for ap in f["attack_paths"]:
                    if not isinstance(ap, str) or ap not in ap_ids:
                        add(f"{where}: attack path {ap} does not exist (merge linked records in one call, or add the link later)")
        for i, ref in enumerate(f.get("references", []) if isinstance(f.get("references", []), list) else [None]):
            if not isinstance(ref, dict) or blank(ref.get("url")) or blank(ref.get("title")) or \
                    LINE_BREAK.search(ref["title"]):
                add(f"{where}: references[{i}] needs title and url")
                continue
            if set(ref) - REFERENCE_KEYS:
                add(f"{where}: references[{i}] unknown keys {sorted(set(ref) - REFERENCE_KEYS)}")
            try:
                u = urlparse(ref["url"])
                hostname = u.hostname
            except (ValueError, AttributeError):
                u, hostname = None, None
            if u is None or u.scheme != "https" or not hostname or "@" in u.netloc or \
                    URL_UNSAFE.search(ref["url"]) or not _balanced_parens(ref["url"]):
                add(f"{where}: references[{i}] must be an https URL without credentials")
        val = f.get("validation")
        if not isinstance(val, dict) or val.get("verdict") not in VERDICTS:
            add(f"{where}: validation.verdict must be one of {', '.join(VERDICTS)}")
        else:
            if set(val) - VALIDATION_KEYS:
                add(f"{where}: validation unknown keys {sorted(set(val) - VALIDATION_KEYS)}")
            if "evidence" in val and not isinstance(val["evidence"], str):
                add(f"{where}: validation.evidence must be a string")
            elif val["verdict"] in NEEDS_EVIDENCE and blank(val.get("evidence")):
                add(f"{where}: validation.evidence required for {val['verdict']}")
            if is_f and val["verdict"] == "Valid" and f.get("confidence") == "Confirmed" \
                    and isinstance(f.get("path"), str):
                for line in (x for x in f["path"].splitlines() if x.strip()):
                    if not CITED.search(line):
                        add(f"{where}: Valid + Confirmed needs path:line on every edge; missing in {line.strip()!r}")

    seen = set()
    for n, a in enumerate(paths):
        if not isinstance(a, dict):
            add(f"attack_paths[{n}]: must be an object")
            continue
        aid = a.get("id")
        where = aid if isinstance(aid, str) else f"attack_paths[{n}]"
        if not isinstance(aid, str) or not AP_ID.match(aid):
            add(f"{where}: id must be AP-NN (at least two digits)")
        else:
            if id_key(aid) in seen:
                add(f"{where}: duplicate id")
            seen.add(id_key(aid))
        unknown = sorted(str(k) for k in a if k not in AP_KEYS)
        if unknown:
            add(f"{where}: unknown keys {unknown}")
        for key in ("entry", "target"):
            if blank(a.get(key)):
                add(f"{where}: {key} required")
            elif LINE_BREAK.search(a[key].strip()):
                add(f"{where}: {key} must be one line")
        if a.get("status") not in AP_STATUSES:
            add(f"{where}: status must be one of {', '.join(AP_STATUSES)}")
        elif a["status"] != "open" and blank(a.get("note")):
            add(f"{where}: note must name the blocking or unknown edge when status is {a['status']}")
        edges = a.get("edges")
        if not isinstance(edges, list) or not edges or any(blank(e) for e in edges):
            add(f"{where}: edges must be a nonempty list of strings")
        else:
            unread = [n for n, e in enumerate(edges, 1) if not CITED.search(e)]
            for n in unread:
                if "UNKNOWN" not in edges[n - 1]:
                    add(f"{where}: edge {n} cites no path:line and is not marked UNKNOWN")
            if unread and a.get("status") == "open":
                add(f"{where}: an UNKNOWN edge makes the path unknown, not open")
        if "note" in a and not isinstance(a["note"], str):
            add(f"{where}: note must be a string")
        refs = a.get("findings", [])
        if not isinstance(refs, list):
            add(f"{where}: findings must be a list")
        else:
            for fid in refs:
                if not isinstance(fid, str) or fid not in finding_ids:
                    add(f"{where}: finding {fid} does not exist (merge linked records in one call, or add the link later)")
    if not partial:
        # An unknown edge is unread: a High or Medium on that path cannot be Confirmed.
        unknown_paths = {a["id"] for a in paths if isinstance(a, dict) and isinstance(a.get("id"), str)
                         and a.get("status") == "unknown"}
        linked = {(fid, a["id"]) for a in paths if isinstance(a, dict) and isinstance(a.get("id"), str)
                  and a["id"] in unknown_paths
                  and isinstance(a.get("findings"), list) for fid in a["findings"] if isinstance(fid, str)}
        for f in findings:
            if isinstance(f, dict) and isinstance(f.get("id"), str) and isinstance(f.get("attack_paths"), list):
                linked |= {(f["id"], ap) for ap in f["attack_paths"] if isinstance(ap, str) and ap in unknown_paths}
        for f in findings:
            if isinstance(f, dict) and isinstance(f.get("id"), str) and f.get("severity") in ("High", "Medium") \
                    and f.get("confidence") == "Confirmed":
                for ap in sorted(ap for fid, ap in linked if fid == f["id"]):
                    add(f"{f['id']}: a {f['severity']} on {ap}, whose status is unknown, is Environment-dependent "
                        "or Suspected, never Confirmed")

    persp = data.get("perspectives", [])
    if not isinstance(persp, list):
        add("perspectives: must be a list")
        persp = []
    seen = set()
    for n, item in enumerate(persp):
        if not isinstance(item, dict):
            add(f"perspectives[{n}]: must be an object")
            continue
        name = item.get("name")
        if not isinstance(name, str) or name not in names:
            add(f"perspectives[{n}]: unknown perspective {name!r}")
        elif name in seen:
            add(f"perspectives: {name} listed twice")
        else:
            seen.add(name)
        if set(item) - PERSPECTIVE_KEYS:
            add(f"perspectives[{n}]: unknown keys {sorted(str(k) for k in set(item) - PERSPECTIVE_KEYS)}")
        if item.get("status") not in P_STATUSES:
            add(f"perspectives[{n}]: status must be one of {', '.join(P_STATUSES)}")
        if "note" in item and not isinstance(item["note"], str):
            add(f"perspectives[{n}]: note must be a string")
        if item.get("status") in ("N/A", "Not checked") and blank(item.get("note")):
            add(f"perspectives[{n}]: {item.get('status')} needs a reason in note")
    for key in STRING_LISTS:
        value = data.get(key, [])
        if not isinstance(value, list) or any(not isinstance(x, str) for x in value):
            add(f"{key}: must be a list of strings")
    if p:
        raise SchemaError(p)


# ---------------------------------------------------------------- model

LABELS = {
    "en": {
        "doc_title": "Infrastructure security assessment", "brand": "INFRA-SCAN",
        "running_footer": "INFRASTRUCTURE SECURITY ASSESSMENT",
        "assessment": "Assessment report", "theme": "Theme",
        "summary": "Summary", "findings": "Findings", "attack_paths": "Attack paths",
        "perspectives": "Perspective coverage", "checked_ok": "Checked and sound",
        "decisions": "Decisions for a human", "limitations": "Limitations", "next_steps": "Next steps",
        "excluded": "Excluded findings", "none": "None recorded.",
        "severity": "Severity", "confidence": "Confidence", "verdict": "Verdict", "provider": "Provider",
        "category": "Perspective", "resources": "Resources", "location": "Location", "actor": "Actor",
        "path": "Attack path", "contrast": "Contrast (sound sibling)", "impact": "Impact",
        "fix": "Fix direction", "regression": "Regression check",
        "controls": "Controls", "cwe": "CWE", "condition": "Assumed condition", "references": "References",
        "rule": "Baseline rule", "evidence": "Evidence", "detail": "Detail", "source": "Source excerpt",
        "status": "Status", "note": "Note",
        "linked": "Findings", "id": "ID", "title": "Title",
        "project": "Project", "scope": "Scope", "date": "Date", "assessor": "Assessor",
        "method": "Method", "commit": "Commit", "inputs": "Inputs", "inventory": "Inventory",
        "resources_n": "resources", "files_n": "files", "not_run": "Not run",
        "all": "All", "search": "Search", "shown": "shown", "copy": "Copy for LLM", "copied": "Copied",
        "excluded_n": "excluded", "unverified_n": "unverified",
        "covered_n": "covered by review findings", "covered": "Covered by",
        "static_note": "Static review of configuration. No cloud API was called and no deployed resource was contacted.",
        "pdf_missing": "PDF not generated: no headless Chrome or WeasyPrint found.",
        "pdf_failed": "PDF not generated: the PDF engine was found but failed.",
        "cover_note": "Confidential — for the owner of the assessed estate.",
        "scope_method": "Scope and method", "counts": "Counts by severity (excluded findings and those covered by review findings not counted)",
        "md_intro": "Infrastructure security finding from a static configuration review. Propose a minimal IaC change that restores the boundary, and a policy-as-code test for it.",
        "md_excluded": "Infrastructure configuration hit from a static review, excluded after triage (see the verdict). It needs no change; use it only as context.",
        "md_covered": "Infrastructure configuration hit from a static review, covered by review finding %s: fix that finding's root cause instead.",
        "contents": "Contents", "nav_lists": "Decisions, limits, next steps", "shortcuts": "Keyboard",
        "key_search": "Search", "key_move": "Next / previous finding", "key_toggle": "Show or hide details",
    },
    "ja": {
        "doc_title": "インフラ セキュリティ診断", "brand": "INFRA-SCAN",
        "running_footer": "インフラ セキュリティ診断",
        "assessment": "診断報告書", "theme": "テーマ",
        "summary": "概要", "findings": "検出事項", "attack_paths": "攻撃経路",
        "perspectives": "観点ごとの実施状況", "checked_ok": "確認して問題なし",
        "decisions": "判断が必要な事項", "limitations": "制約事項", "next_steps": "次の対応",
        "excluded": "除外した検出事項", "none": "記録なし。",
        "severity": "深刻度", "confidence": "確度", "verdict": "判定", "provider": "プロバイダ",
        "category": "観点", "resources": "リソース", "location": "場所", "actor": "攻撃主体",
        "path": "攻撃経路", "contrast": "対照（健全な同種設定）", "impact": "影響",
        "fix": "修正の方向", "regression": "回帰チェック",
        "controls": "対応コントロール", "cwe": "CWE", "condition": "前提条件", "references": "参考",
        "rule": "ベースラインルール", "evidence": "根拠", "detail": "詳細", "source": "ソース抜粋",
        "status": "状態", "note": "備考",
        "linked": "関連する検出事項", "id": "ID", "title": "タイトル",
        "project": "対象", "scope": "範囲", "date": "診断日", "assessor": "診断者",
        "method": "方法", "commit": "コミット", "inputs": "入力", "inventory": "インベントリ",
        "resources_n": "リソース", "files_n": "ファイル", "not_run": "未実施",
        "all": "すべて", "search": "検索", "shown": "件表示", "copy": "LLM用にコピー", "copied": "コピーしました",
        "excluded_n": "除外", "unverified_n": "未検証",
        "covered_n": "検出事項に統合", "covered": "統合先",
        "static_note": "設定の静的レビューです。クラウド API の呼び出しや稼働中リソースへの通信は行っていません。",
        "pdf_missing": "PDF は生成されませんでした（ヘッドレス Chrome / WeasyPrint が見つかりません）。",
        "pdf_failed": "PDF は生成されませんでした（PDF エンジンは見つかりましたが失敗しました）。",
        "cover_note": "機密 — 診断対象の所有者向け。",
        "scope_method": "範囲と方法", "counts": "深刻度別の件数（除外分と検出事項に統合した分を除く）",
        "md_intro": "設定の静的レビューで見つかったインフラのセキュリティ検出事項です。境界を回復する最小限の IaC 変更と、それを守る policy-as-code テストを提案してください。",
        "md_excluded": "設定の静的レビューで検出し、精査の結果除外した項目です（判定を参照）。変更は不要で、文脈としてのみ使ってください。",
        "md_covered": "設定の静的レビューで検出した項目で、検出事項 %s に統合されています。その根本原因を修正してください。",
        "contents": "目次", "nav_lists": "判断事項・制約・次の対応", "shortcuts": "キー操作",
        "key_search": "検索", "key_move": "次・前の検出事項", "key_toggle": "詳細の表示・非表示",
    },
}

DISPLAY = {
    "en": {},
    "ja": {
        "High": "高", "Medium": "中", "Low": "低", "Info": "情報",
        "Confirmed": "確認済み", "Environment-dependent": "環境依存", "Suspected": "疑い",
        "Valid": "妥当", "Likely": "可能性高", "Unverified": "未検証", "Unlikely": "可能性低",
        "FalsePositive": "誤検知", "NotApplicable": "対象外",
        "open": "成立", "blocked": "遮断", "unknown": "不明",
        "Applied": "実施", "N/A": "該当なし", "Not checked": "未確認",
        # Perspective names from reference/perspectives.md and meta.inputs kinds.
        "Network exposure": "ネットワーク露出", "Identity and privilege": "アイデンティティと権限",
        "Trust and federation": "信頼とフェデレーション", "Data protection": "データ保護",
        "Compute and workload": "コンピュートとワークロード", "Kubernetes": "Kubernetes",
        "Serverless and API edge": "サーバーレスと API エッジ", "Secrets and keys": "シークレットと鍵",
        "Logging and detection": "ログと検知", "Resilience and recovery": "回復性と復旧",
        "Governance and guardrails": "ガバナンスとガードレール", "Pipeline and state": "パイプラインと state",
        "Coverage and drift": "カバレッジとドリフト",
        "iac": "IaC", "plan": "プラン JSON", "snapshot": "スナップショット", "manifest": "マニフェスト",
        # Baseline rule titles (iac_scan.RULES); review titles are written in the requester's language.
        "Security group allows internet ingress to an admin or data port": "セキュリティグループが管理用・データ用ポートへのインターネットからの受信を許可している",
        "S3 bucket ACL grants public access": "S3 バケットの ACL が公開アクセスを許可している",
        "S3 public access block leaves a protection off": "S3 パブリックアクセスブロックに無効な保護がある",
        "Resource policy allows any principal without a narrowing condition": "リソースポリシーが絞り込み条件なしに任意のプリンシパルを許可している",
        "IAM policy grants all actions on all resources": "IAM ポリシーが全リソースに全アクションを許可している",
        "IAM policy grants iam:PassRole on any role": "IAM ポリシーが任意のロールへの iam:PassRole を許可している",
        "Role trust policy lets any AWS principal assume the role": "ロールの信頼ポリシーが任意の AWS プリンシパルに引き受けを許可している",
        "GitHub OIDC trust does not pin the repository subject": "GitHub OIDC の信頼がリポジトリの subject を固定していない",
        "IAM user with long-lived credentials managed in IaC": "長期認証情報を持つ IAM ユーザーが IaC で管理されている",
        "Database or data service is publicly accessible": "データベースまたはデータサービスが公開アクセス可能",
        "Machine image or database snapshot shared publicly": "マシンイメージまたはデータベーススナップショットが公開共有されている",
        "CloudFront serves viewers over plaintext HTTP or outdated TLS": "CloudFront が平文 HTTP または古い TLS で閲覧者に配信している",
        "Bucket, object or dataset ACL grants public access": "バケット・オブジェクト・データセットの ACL が公開アクセスを許可している",
        "Database storage not encrypted": "データベースのストレージが暗号化されていない",
        "Instance metadata service does not require IMDSv2": "インスタンスメタデータサービスが IMDSv2 を必須にしていない",
        "EBS volume not encrypted": "EBS ボリュームが暗号化されていない",
        "Lambda function URL requires no authentication": "Lambda 関数 URL が認証を要求しない",
        "Lambda permission lets any principal invoke the function": "Lambda の権限が任意のプリンシパルに関数の呼び出しを許可している",
        "CloudTrail not multi-region or without log file validation": "CloudTrail がマルチリージョンでない、またはログファイル検証がない",
        "KMS key rotation not enabled": "KMS キーのローテーションが有効でない",
        "EKS API endpoint public to any address": "EKS API エンドポイントが任意のアドレスに公開されている",
        "Firewall allows internet ingress to an admin or data port": "ファイアウォールが管理用・データ用ポートへのインターネットからの受信を許可している",
        "IAM binding grants a role to allUsers or allAuthenticatedUsers": "IAM バインディングが allUsers または allAuthenticatedUsers にロールを付与している",
        "Basic role roles/owner or roles/editor granted": "基本ロール roles/owner または roles/editor が付与されている",
        "User-managed service account key created": "ユーザー管理のサービスアカウントキーが作成されている",
        "Service account impersonation role granted above the service account": "サービスアカウントより上位の階層で権限借用ロールが付与されている",
        "Bucket without uniform access or enforced public access prevention": "バケットに均一なアクセス制御または公開アクセス防止の強制がない",
        "Cloud SQL reachable from any address or without required TLS": "Cloud SQL が任意のアドレスから到達可能、または TLS が必須でない",
        "Instance runs as the default compute service account": "インスタンスがデフォルトのコンピュートサービスアカウントで動作している",
        "Instance metadata enables serial port or project-wide SSH keys": "インスタンスメタデータがシリアルポートまたはプロジェクト全体の SSH 鍵を有効にしている",
        "GKE cluster control plane or identity hardening missing": "GKE クラスタのコントロールプレーンまたは ID の強化が不足している",
        "Workload identity provider without an attribute condition": "Workload Identity プロバイダに属性条件がない",
        "Literal secret committed to the repository": "リテラルのシークレットがリポジトリにコミットされている",
        "Terraform state file committed to the repository": "Terraform の state ファイルがリポジトリにコミットされている",
        "Module source not pinned to a version or commit": "モジュールのソースがバージョンまたはコミットに固定されていない",
        "Terraform state backend unencrypted or local": "Terraform の state バックエンドが暗号化されていない、またはローカル",
        "Provider block configures static credentials": "プロバイダブロックに静的な認証情報が設定されている",
        "Pod runs privileged or with host access": "Pod が特権モードまたはホストへのアクセス付きで動作している",
        "RBAC binding grants cluster-admin or binds every authenticated user": "RBAC バインディングが cluster-admin を付与している、または認証済みの全ユーザーをバインドしている",
        "Kubernetes Secret with data committed": "データを含む Kubernetes Secret がコミットされている",
    },
}


# Bidirectional controls can make a path or ID display as something else.
BIDI = re.compile("[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]")


def esc(value):
    text = html.escape("" if value is None else str(value), quote=True)
    return BIDI.sub(lambda m: f"[U+{ord(m.group()):04X}]", text)


def shown(value, lang):
    return DISPLAY[lang].get(value, value)


def is_excluded(f):
    return f.get("validation", {}).get("verdict") in EXCLUDED


def id_key(identifier):
    """Sort a validated ID by prefix and number, including IDs beyond 999."""
    prefix, number = identifier.rsplit("-", 1)
    return prefix, int(number)


def ordered(findings):
    return sorted(findings, key=lambda f: (SEV_RANK.get(f.get("severity"), 9), id_key(f["id"])))




def covered_by(data):
    """{I-ID: [F-IDs]} for baseline hits whose root cause is a review finding.

    reference/validation.md has the root-cause F-* name the I-* in its
    evidence. Counting both would report one root cause twice.
    """
    out = {}
    for f in data.get("findings", []):
        if not F_ID.match(str(f.get("id", ""))) or is_excluded(f):
            continue
        evidence = f.get("validation", {}).get("evidence", "")
        for iid in (m.group() for m in find_references(BASELINE_REFERENCE, evidence if isinstance(evidence, str) else "")):
            out.setdefault(iid, []).append(f["id"])
    return out


def counts(data):
    covered = covered_by(data)
    findings = data.get("findings", [])
    active = [f for f in findings if not is_excluded(f) and f.get("id") not in covered]
    c = {s: sum(1 for f in active if f.get("severity") == s) for s in SEVERITIES}
    c["excluded"] = sum(1 for f in findings if is_excluded(f))
    c["covered"] = sum(1 for f in findings if not is_excluded(f) and f.get("id") in covered)
    # Every finding status and contract_check.py still wait on, covered I-* included.
    c["unverified"] = len(untriaged(data))
    return c


# ---------------------------------------------------------------- source excerpts

# Terraform names state backups terraform.tfstate.<timestamp>.backup; dotenv
# files carry an environment suffix (.env.production).
SENSITIVE_NAME = re.compile(r"(\.tfvars(\.json)?|\.pem|\.key|\.p12|\.pfx|\.ppk|\.jks|\.keystore|\.env)$|"
                            + STATE_FILE.pattern + r"|\.env\.[^/]*$|\.envrc$|secret|credential|"
                            r"id_(rsa|dsa|ecdsa|ed25519)|netrc|\.npmrc|\.pypirc|\.pgpass|kubeconfig|"
                            r"\.dockercfg|(^|/)\.docker/config\.json$|htpasswd|(^|/)g?shadow-?$", re.IGNORECASE)


def hcl_declares_sensitive(text):
    """Only a known false variable/output declaration permits its source."""
    for block in parse_hcl(text):
        if block.type in ("variable", "output") and "sensitive" in block.attrs:
            raw, _ = block.attrs["sensitive"]
            if literal(raw) is not False:
                return True
    return False


HCL_MARKED_SECRET = re.compile(
    r'(?<![\w.])sensitive\s*\(|\bephemeral\s*=\s*true\b|"SecureString"|'
    r'resource\s+"(?:kubernetes_secret(?:_v1)?|aws_secretsmanager_secret_version|'
    r'google_secret_manager_secret_version)"')
HCL_NAME = re.compile(r'(?i)(?<![\w.-])"?(?:name|key|parameter_?key)"?\s*[=:]\s*"([^"\n]*)"')
HCL_VALUE = re.compile(r'(?i)(?<![\w.-])"?(?:value|parameter_?value)"?\s*[=:]')
# A name computed by an expression (var.db_password_env_name): it may name a secret.
HCL_EXPR_NAME = re.compile(r'(?i)(?<![\w.-])"?(?:name|key|parameter_?key)"?\s*[=:]\s*[^"\s]')


def hcl_has_paired_secret(text):
    """Name/value pairs (env blocks, jsonencode lists) and secret-named variables.

    Line redaction sees `value = "..."`, not that its sibling `name` is
    DB_PASSWORD. Treat a secret-shaped name with a value nearby as a secret.
    """
    # Values Terraform itself treats as secret, wherever their names point.
    if HCL_MARKED_SECRET.search(text):
        return True
    lines = text.split("\n")
    for n, line in enumerate(lines):
        for match in HCL_NAME.finditer(line):
            if is_secret_name(match.group(1)) and any(
                    HCL_VALUE.search(near) for near in lines[max(0, n - 15):n + 16]):
                return True
        # As for blocks below: an object literal (jsonencode environment lists)
        # whose name is an expression and whose value beside it is not a reference.
        name = HCL_EXPR_NAME.search(line)
        if name:
            for k in range(max(0, n - 3), min(len(lines), n + 4)):
                value = HCL_VALUE.search(lines[k])
                # Only a literal can leak: a string, heredoc or number, not an
                # iterator (for k, v in ...: { name = k, value = v }) or each.value.
                if not value or not re.match(r'\s*(?:"|<<|[0-9])', lines[k][value.end():]):
                    continue
                # The same object only: no brace between them (a resource's
                # name and a nested setting { value = ... } are not a pair).
                if k < n or (k == n and value.start() < name.start()):
                    between = "\n".join(lines[k:n + 1])[value.end():len("\n".join(lines[k:n])) + name.start()
                                                           + (1 if k < n else 0)]
                else:
                    between = "\n".join(lines[n:k + 1])[name.end():len("\n".join(lines[n:k])) + value.start()
                                                           + (1 if k > n else 0)]
                if "{" not in between and "}" not in between:
                    return True
    top = parse_hcl(text)
    if hcl_secret_indirection(top):
        return True
    pending = list(top)
    while pending:
        block = pending.pop()
        pending.extend(block.blocks)
        # A secret-named parameter or env block with its value anywhere in the block.
        names = [literal(block.attrs[k][0]) for k in ("name", "key", "parameter_key") if k in block.attrs]
        if ("value" in block.attrs or "parameter_value" in block.attrs) and any(
                not isinstance(x, str) or is_secret_name(x) for x in names):
            return True
    for block in top:
        if block.type == "variable" and block.labels and "default" in block.attrs and \
                is_secret_name(block.labels[0]):
            default = literal(block.attrs["default"][0])
            # A number (secret_recovery_window_in_days = 7) or an empty string is no secret.
            if not isinstance(default, (int, float, bool)) and default not in (None, ""):
                return True
        if block.type == "output" and block.labels and "value" in block.attrs and \
                is_secret_name(block.labels[0]):
            raw_val = block.attrs["value"][0].strip()
            val = literal(raw_val)
            if not SAFE_VALUE.fullmatch(raw_val) and isinstance(val, str) and val != "":
                return True
        if block.type == "locals":
            for attr_name, (raw_val, _) in block.attrs.items():
                if is_secret_name(attr_name):
                    val = literal(raw_val.strip())
                    if not SAFE_VALUE.fullmatch(raw_val.strip()) and isinstance(val, str) and val != "":
                        return True
    return False


HCL_INDIRECT = re.compile(r"(?<![\w.])(var|local)\.([A-Za-z_][\w-]*)")
# What such an attribute reads through a file function is a path, and a
# *_id, *_name or *_arn names a secret held elsewhere (secret_id = "prod/db").
HCL_FILE_CALL = re.compile(r"\b(?:file|filebase64|templatefile|pathexpand|abspath|dirname|basename)\s*\([^()]*\)")
HCL_NAMES_A_SECRET = re.compile(r"(?i)(?:_id|_ids|_name|_names|_arn|_arns|_file|_path)$")


def _holds_value(value):
    """A literal that could be the secret: text, a number or a non-empty collection."""
    return value not in (None, "", [], {}) and value is not UNKNOWN and not isinstance(value, bool)


def hcl_secret_indirection(blocks):
    """A secret-named attribute that reads a variable or local holding a literal.

    `password = var.db_admin` is safe to show; `variable "db_admin" { default
    = "..." }` is then the password, though its own name says nothing. So is
    `password = local.creds.admin` over a literal object, or a number."""
    literals, wanted = set(), set()
    pending = list(blocks)
    while pending:
        block = pending.pop()
        pending.extend(block.blocks)
        if block.type == "variable" and block.labels and "default" in block.attrs:
            if _holds_value(literal(block.attrs["default"][0])):
                literals.add(("var", block.labels[0]))
        for name, (raw, _) in block.attrs.items():
            if block.type == "locals" and _holds_value(literal(raw.strip())) and \
                    not SAFE_VALUE.fullmatch(raw.strip()):
                literals.add(("local", name))
            # password_length = var.n reads a setting, not a secret.
            if is_secret_name(name) and not HCL_NAMES_A_SECRET.search(name) and not SETTING_NAME.search(name):
                wanted.update(HCL_INDIRECT.findall(HCL_FILE_CALL.sub("", raw)))
    return bool(literals & wanted)


def hcl_module_sensitive(directory):
    """Conservatively include declarations inherited through override files.

    Do not evaluate override order or read symlink targets. Unknown sibling
    context makes the module's excerpts unsafe, even when this file looks public.
    """
    blocks = []
    try:
        for sibling in directory.iterdir():
            if sibling.name.lower().endswith((".tf.json", ".tofu.json")):
                return True  # Unsupported Terraform JSON can also override sensitivity.
            if sibling.suffix.lower() not in (".tf", ".tofu", ".hcl"):
                continue
            if sibling.is_symlink():
                return True
            # A file the scanner skipped as too large is unknown context too.
            if sibling.is_file() and (sibling.stat().st_size > MAX_BYTES or
                                      hcl_declares_sensitive(sibling.read_text(encoding="utf-8-sig"))):
                return True
            if sibling.is_file():
                blocks.extend(parse_hcl(sibling.read_text(encoding="utf-8-sig")))
    except (OSError, ValueError, TypeError, RecursionError):
        return True
    # The secret may be read in one file and written in another.
    return hcl_secret_indirection(blocks)


def source_lines(path):
    """Preserve source line numbers, or return None if an excerpt is unsafe.

    Reuse the scanner's conservative YAML subset. A tag, alias or other
    unsupported construct must not fall back to raw text near another finding.
    JSON sensitivity and env name/value relationships require the whole document;
    line-oriented redaction alone cannot enforce them.
    """
    if path.stat().st_size > MAX_BYTES:
        return None  # the scanner did not read it either
    # Match the scanner's BOM handling before checking sensitivity or line numbers.
    text = path.read_text(encoding="utf-8-sig")
    lines = split_lines(text)
    suffix = path.suffix.lower()
    syntax = "text"
    try:
        if suffix == ".json" or (suffix == ".template" and text.lstrip().startswith("{")):
            syntax = "json"
            docs = [json.loads(text, object_pairs_hook=unique_object)]
        elif suffix in (".yaml", ".yml", ".template"):
            syntax = "yaml"
            cfn_hint = suffix == ".template" or "AWSTemplateFormatVersion" in text or "Resources:" in text
            # The scanner's document split and YAML subset, so both read the same documents.
            docs = []
            for rows in split_yaml_documents(lines):
                try:
                    docs.append(_YamlSubset(rows).parse())
                except ValueError:
                    if not cfn_hint:
                        raise
                    docs.append(_YamlSubset(rows, cfn=True).parse())
        else:
            docs = []
            if suffix in (".tf", ".tofu", ".hcl"):
                syntax = "hcl"
                # Sensitivity belongs to the block, not to the default/value
                # line. Only a known false declaration permits an excerpt.
                if hcl_declares_sensitive(text) or hcl_has_paired_secret(text):
                    return None
        if has_escaped_secret_keys(text, docs) or any(has_structured_secrets(doc) for doc in docs):
            return None
        # Exports committed into the repository are snapshots wherever they sit:
        # deployed values (emails, IPs, environment) never become excerpts.
        if any(is_export(doc) for doc in docs):
            return None
        lines = redact_lines(lines, syntax=syntax)
        if syntax == "json":
            lines = redact_json_values(text, lines)
        # Last, broad pass over free text: comments, script bodies, flags,
        # connection strings and opaque tokens (redaction.scrub_lines).
        lines = scrub_lines(lines, syntax="hcl" if syntax == "text" else syntax, original=split_lines(text))
    except (ValueError, TypeError, RecursionError):
        return None
    return lines


def attach_sources(data, repo, context=3):
    """Return {finding id: [(lineno, text, hit)]} for readable, non-sensitive locations."""
    root = Path(repo).resolve()
    out = {}
    hcl_modules = {}
    # Kubernetes Secret values can have arbitrary keys and remain secret even
    # when base64-encoded. Do not expose them through a neighboring finding.
    secret_manifests = set()
    for f in data.get("findings", []):
        # A state file is secret whatever its name (SEC-002 also reads content).
        if f.get("rule") in ("K8S-003", "SEC-002"):
            match = LOCATION.match(f.get("location", ""))
            if match:
                secret_manifests.add(posixpath.normpath(match.group(1)))
    for f in data.get("findings", []):
        if f.get("rule") in ("SEC-001", "SEC-002", "K8S-003"):
            continue
        m = LOCATION.match(f.get("location", ""))
        if not m:
            continue
        rel, start = posixpath.normpath(m.group(1)), int(m.group(2))
        end = int(m.group(3) or start)
        # Judge the file that will be opened, not the spelling of the path:
        # "terraform.tfstate/." names the state file too.
        if rel in secret_manifests or SENSITIVE_NAME.search(rel) or rel.startswith(("../", "/")) or rel == "..":
            continue
        if any(part in SKIP_DIRS for part in Path(rel).parts):
            continue
        cand = root / rel
        try:
            if any(p.is_symlink() for p in (cand, *cand.parents) if p != root and root in p.parents) or not cand.is_file():
                continue
            real = cand.resolve().relative_to(root).as_posix()
            if real in secret_manifests or SENSITIVE_NAME.search(real) or any(part in SKIP_DIRS for part in Path(real).parts):
                continue
            if cand.suffix.lower() in (".tf", ".tofu", ".hcl") or cand.name.lower().endswith((".tf.json", ".tofu.json")):
                directory = cand.parent.resolve()
                directory.relative_to(root)
                if directory not in hcl_modules:
                    hcl_modules[directory] = hcl_module_sensitive(directory)
                if hcl_modules[directory]:
                    continue
            lines = source_lines(cand)
        except (OSError, ValueError, RecursionError):
            continue
        if lines is None:
            continue
        end = min(end, start + 40)
        lo, hi = max(1, start - context), min(len(lines), end + context)
        if start <= len(lines):  # a line past the end of the file (an edited file) has nothing to show
            out[f["id"]] = [(i, lines[i - 1], start <= i <= end) for i in range(lo, hi + 1)]
    return out


def snippet_html(rows):
    if not rows:
        return ""
    body = "".join(f'<span class="{"hit" if hit else ""}"><b>{n:>4}</b>  {esc(t)}</span>' for n, t, hit in rows)
    return f'<pre class="snippet">{body}</pre>'


# ---------------------------------------------------------------- shared pieces

FIELD_ORDER = ("actor", "path", "contrast", "impact", "condition", "fix", "regression", "detail",
               "rule", "controls", "cwe")


def field_text(f, key):
    value = f.get(key)
    if isinstance(value, list):
        return ", ".join(value)
    return value


def _md_code_span(value):
    text = LINE_BREAK.sub(" ", str(value or ""))
    return f"`{text.replace('`', chr(39))}`"


def _md_link_title(value):
    text = LINE_BREAK.sub(" ", str(value or ""))
    return text.replace("\\", "\\\\").replace("[", "\\[").replace("]", "\\]")


def _md_link_url(value):
    return str(value or "").replace("(", "%28").replace(")", "%29")


def finding_markdown(f, L, lang, covered=()):
    """Single-line fields as one list, then each multi-line field under its own heading."""
    # An excluded or covered finding needs no change of its own.
    intro = L["md_excluded"] if is_excluded(f) else (L["md_covered"] % ", ".join(covered) if covered else L["md_intro"])
    title = LINE_BREAK.sub(" ", str(shown(f.get("title", ""), lang)))
    lines = [intro, "", f"## {f['id']} {title}", ""]
    lines.append(f"- {L['severity']}: {shown(f.get('severity'), lang)} / "
                 f"{L['confidence']}: {shown(f.get('confidence'), lang)}")
    lines.append(f"- {L['category']}: {shown(f.get('category'), lang)} / {L['provider']}: {f.get('provider')}")
    lines.append(f"- {L['location']}: {_md_code_span(f.get('location'))}")
    lines.append(f"- {L['resources']}: " + ", ".join(_md_code_span(r) for r in f.get("resources", [])))
    if f.get("attack_paths"):
        lines.append(f"- {L['attack_paths']}: " + ", ".join(f["attack_paths"]))
    blocks = []
    for key in FIELD_ORDER:
        value = field_text(f, key)
        if value:
            if LINE_BREAK.search(str(value)):
                blocks += ["", f"### {L[key]}", "", str(value)]
            else:
                lines.append(f"- {L[key]}: {value}")
    lines += blocks
    val = f.get("validation", {})
    verdict = shown(val.get("verdict"), lang)
    lines += ["", f"### {L['verdict']}", "", f"{verdict}: {val['evidence']}" if val.get("evidence") else verdict]
    if f.get("references"):
        lines += ["", f"### {L['references']}", ""]
        lines += [f"- [{_md_link_title(ref.get('title') or ref['url'])}]({_md_link_url(ref['url'])})"
                  for ref in f["references"]]
    return "\n".join(lines).strip() + "\n"


def detail_dl(f, L, lang, sources, covered=()):
    rows = [(L["resources"], "<br>".join(f"<code>{esc(r)}</code>" for r in f.get("resources", []))),
            (L["location"], f"<code>{esc(f.get('location'))}</code>")]
    if covered:
        rows.append((L["covered"], ", ".join(f'<a href="#{esc(x)}">{esc(x)}</a>' for x in covered)))
    for key in FIELD_ORDER:
        value = field_text(f, key)
        if value:
            rows.append((L[key], esc(value)))
    if f.get("attack_paths"):
        rows.append((L["attack_paths"], ", ".join(f'<a href="#{esc(a)}">{esc(a)}</a>' for a in f["attack_paths"])))
    val = f.get("validation", {})
    rows.append((L["verdict"], esc(shown(val.get("verdict"), lang))))
    if val.get("evidence"):
        rows.append((L["evidence"], esc(val["evidence"])))
    if f.get("references"):
        rows.append((L["references"], "<br>".join(
            f'<a href="{esc(r["url"])}" rel="noopener noreferrer">{esc(r.get("title") or r["url"])}</a>'
            for r in f["references"])))
    if f.get("id") in sources:
        rows.append((L["source"], snippet_html(sources[f["id"]])))
    return "<dl>" + "".join(f"<dt>{k}</dt><dd>{v}</dd>" for k, v in rows) + "</dl>"


def ap_html(a, L, lang):
    edges = "".join(f"<li>{esc(e)}</li>" for e in a.get("edges", []))
    links = ", ".join(f'<a href="#{esc(x)}">{esc(x)}</a>' for x in a.get("findings", [])) or "—"
    note = f'<p class="note">{esc(a["note"])}</p>' if a.get("note") else ""
    return (f'<article class="ap st-{esc(a.get("status"))}" id="{esc(a.get("id"))}">'
            f'<div class="ap-head"><strong>{esc(a.get("id"))}</strong>'
            f'<span class="pill st-{esc(a.get("status"))}">{esc(shown(a.get("status"), lang))}</span></div>'
            f'<p class="ap-route"><span>{esc(a.get("entry"))}</span> <span aria-hidden="true">→</span> '
            f'<span>{esc(a.get("target"))}</span></p><ol class="edges">{edges}</ol>{note}'
            f'<p class="muted">{L["linked"]}: {links}</p></article>')


def list_block(items, L, empty="muted"):
    if not items:
        return f'<p class="{empty}">{L["none"]}</p>'
    return "<ul>" + "".join(f"<li>{esc(x)}</li>" for x in items) + "</ul>"


def meta_rows(data, L, lang="en"):
    """Scope and method as <dt>/<dd> pairs (the dashboard's scope list)."""
    return "".join(f"<dt>{k}</dt><dd>{v}</dd>" for k, v in meta_pairs(data, L, lang))


def meta_pairs(data, L, lang="en"):
    """[(label, value HTML)] for the scope, method, inputs and inventory."""
    meta = data.get("meta", {})
    rows = [(L[k], esc(meta.get(k))) for k in ("project", "scope", "date", "assessor", "method", "commit")
            if meta.get(k)]
    if meta.get("inputs"):
        rows.append((L["inputs"], "<br>".join(
            f'{esc(shown(i.get("kind"), lang))}: <code>{esc(i.get("path"))}</code>' + (f' — {esc(i["note"])}' if i.get("note") else "")
            for i in meta["inputs"])))
    inv = data.get("inventory")
    if inv:
        parts = []
        if "resources" in inv:
            parts.append(f'{esc(inv["resources"])} {L["resources_n"]}')
        if "files" in inv:
            parts.append(f'{esc(inv["files"])} {L["files_n"]}')
        if isinstance(inv.get("by_provider"), dict):
            parts.append(", ".join(f"{esc(k)} {esc(v)}" for k, v in inv["by_provider"].items()))
        rows.append((L["inventory"], " · ".join(parts)))
        if inv.get("not_run"):
            rows.append((L["not_run"], "<br>".join(esc(x if isinstance(x, str) else json.dumps(x, ensure_ascii=False))
                                                   for x in inv["not_run"])))
    return rows


# Shared stylesheets (scan_report_kit/assets, docs: scan-report-kit) come first;
# these add only the rules for infra-scan record types: attack paths, the
# perspective status, covered/excluded rows and the scope list.
# Attack-path status inks: open is the High ink, unknown the Medium ink, blocked muted.
DASH_CSS = """
.aps{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,360px),1fr));gap:12px 28px}
.ap{border-top:2px solid var(--line);padding:12px 0;min-width:0}
.ap.st-open{border-top-color:var(--high)}.ap.st-unknown{border-top-color:var(--medium)}.ap.st-blocked{border-top-color:var(--muted)}
.ap-head{display:flex;gap:10px;align-items:baseline}
.ap-route{font-weight:700;margin:6px 0}
.pill{font-family:var(--sans);font-size:11px;font-weight:700;letter-spacing:.1em;white-space:nowrap}
.pill.st-open{color:var(--high)}.pill.st-unknown{color:var(--medium)}.pill.st-blocked{color:var(--muted)}
.edges{margin:6px 0;padding-left:22px}.edges li{margin:2px 0}
.note{color:var(--muted)}
.card .n{color:var(--text)}.card.High .n{color:var(--high)}.card.Medium .n{color:var(--medium)}.card.Low .n{color:var(--low)}
.perspective .st{font-family:var(--sans);font-size:11px;font-weight:700;letter-spacing:.06em;color:var(--muted);margin-left:8px}
.lists section{min-width:0}
tr.excluded td{color:var(--muted)}tr.excluded .finding-toggle{text-decoration:line-through}
@media print{.detail-actions{display:none}tr.row:not([hidden])+tr.detail{display:table-row!important}}
/* Application shell: the kit styles the shell; these cover infra-scan's own sections and its five filter controls. */
.app-shell #attack-paths:focus,.app-shell #perspectives-section:focus,.app-shell #scope-section:focus{outline:0}
.app-shell .filters{grid-template-columns:minmax(0,2.2fr) repeat(4,minmax(0,1fr))}
@media(max-width:1099px){.app-shell .filters{grid-template-columns:repeat(3,minmax(0,1fr))}}
@media(max-width:850px){.app-shell .filters{grid-template-columns:repeat(2,minmax(0,1fr))}}
"""

ASSESSMENT_CSS = """
.ap{margin:4mm 0 0;padding:0 0 0 4mm;border-left:.6pt solid var(--hair)}
.ap{break-inside:avoid-page}
.ap.st-open{border-left:2.4pt solid var(--high)}.ap.st-unknown{border-left:1.2pt solid var(--medium)}
.ap-head{display:flex;gap:3mm;align-items:baseline;font:400 8pt/1.4 var(--mono)}
.ap-head strong{font-weight:400;color:var(--muted)}
.ap-route{font-weight:700;margin:1mm 0 1.5mm}
.pill{font:700 7.2pt/1.5 var(--sans);letter-spacing:.1em;color:var(--muted);white-space:nowrap}
.pill.st-open{color:var(--high)}.pill.st-unknown{color:var(--medium)}
.edges{margin:1mm 0 2mm;padding-left:6mm;font-size:9pt}
.muted,.note{color:var(--muted)}
.ap .muted,.ap .note{font-size:8.5pt}
.report-header .small{margin:3mm 0 0}
.finding.covered{border-left-style:dashed}
.finding-state code{font-size:7.8pt}
"""

DASH_JS = r"""
(function(){
var root=document.documentElement;
try{var t=localStorage.getItem('infra-scan-theme');if(t)root.setAttribute('data-theme',t);}catch(e){}
document.getElementById('theme').addEventListener('click',function(){
  var dark=root.getAttribute('data-theme')==='dark'||(!root.getAttribute('data-theme')&&matchMedia('(prefers-color-scheme: dark)').matches);
  var next=dark?'light':'dark';root.setAttribute('data-theme',next);
  try{localStorage.setItem('infra-scan-theme',next);}catch(e){}
});
var md=JSON.parse(document.getElementById('md').textContent);
var rows=[].slice.call(document.querySelectorAll('tr.row'));
var f={sev:document.getElementById('f-sev'),prov:document.getElementById('f-prov'),cat:document.getElementById('f-cat'),ver:document.getElementById('f-ver'),q:document.getElementById('f-q')};
var count=document.getElementById('result-count');
function aside(r){return r.classList.contains('excluded')||r.classList.contains('covered');}
var active=rows.filter(function(r){return !aside(r);}).length;
function apply(){
  var q=f.q.value.trim().toLowerCase(),n=0,xe=0,xc=0;
  rows.forEach(function(r){
    var ok=(!f.sev.value||r.dataset.sev===f.sev.value)&&(!f.prov.value||r.dataset.prov===f.prov.value)&&
      (!f.cat.value||r.dataset.cat===f.cat.value)&&(!f.ver.value||r.dataset.ver===f.ver.value)&&
      (!q||r.dataset.text.indexOf(q)>=0);
    r.hidden=!ok;var d=r.nextElementSibling;if(!ok)d.hidden=true;else if(r.querySelector('.finding-toggle').getAttribute('aria-expanded')==='true')d.hidden=false;
    if(ok){if(r.classList.contains('excluded'))xe++;else if(r.classList.contains('covered'))xc++;else n++;}
  });
  // Match the severity cards: excluded and covered findings are counted on their own.
  count.textContent=n+' / '+active+' '+count.dataset.l+(xe?' + '+xe+' '+count.dataset.e:'')+
    (xc?' + '+xc+' '+count.dataset.c:'');
  facets.forEach(function(b){b.setAttribute('aria-pressed',String(f.sev.value===b.dataset.sev));});
}
// Sidebar facets: a press filters the register by severity, a second press clears it.
var facets=[].slice.call(document.querySelectorAll('.facet'));
facets.forEach(function(b){b.addEventListener('click',function(){
  f.sev.value=b.getAttribute('aria-pressed')==='true'?'':b.dataset.sev;apply();document.getElementById('findings').scrollIntoView();
});});
function reveal(){
  var h='';try{h=location.hash?decodeURIComponent(location.hash.slice(1)):'';}catch(e){return;}
  var el=h&&document.getElementById(h);
  if(!el||!el.classList.contains('row'))return;
  if(el.hidden){Object.keys(f).forEach(function(k){f[k].value='';});apply();}
  var b=el.querySelector('.finding-toggle');if(b.getAttribute('aria-expanded')!=='true')b.click();
  el.scrollIntoView({block:'start'});
}
window.addEventListener('hashchange',reveal);
Object.keys(f).forEach(function(k){f[k].addEventListener('input',apply);});
document.querySelectorAll('.finding-toggle').forEach(function(b){b.addEventListener('click',function(){
  var open=b.getAttribute('aria-expanded')==='true';b.setAttribute('aria-expanded',String(!open));
  b.closest('tr').nextElementSibling.hidden=open;
});});
document.querySelectorAll('.copy').forEach(function(b){b.addEventListener('click',function(){
  var text=md[b.dataset.id],done=function(){var o=b.textContent;b.textContent=b.dataset.done;setTimeout(function(){b.textContent=o;},1500);};
  if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(text).then(done,fallback);}else fallback();
  function fallback(){var ta=document.createElement('textarea');ta.value=text;document.body.appendChild(ta);ta.select();try{document.execCommand('copy');done();}catch(e){}ta.remove();}
});});
// Keyboard: "/" searches, j/k step through the visible findings (Enter on the focused title toggles it), Escape clears the search.
document.addEventListener('keydown',function(e){
  if(e.altKey||e.ctrlKey||e.metaKey||e.isComposing)return;var t=e.target;
  if(t&&t.closest&&t.closest('input,select,textarea')){if(e.key==='Escape'&&t===f.q&&f.q.value){f.q.value='';apply();}return;}
  if(e.key==='/'){e.preventDefault();f.q.focus();}
  else if(e.key==='j'||e.key==='k'){
    var toggles=rows.filter(function(r){return !r.hidden;}).map(function(r){return r.querySelector('.finding-toggle');});if(!toggles.length)return;
    var current=document.activeElement&&document.activeElement.closest('tr.row'),at=toggles.findIndex(function(b){return b.closest('tr.row')===current;});
    var next=at<0?0:Math.min(toggles.length-1,Math.max(0,at+(e.key==='j'?1:-1)));
    e.preventDefault();toggles[next].focus();toggles[next].closest('tr.row').scrollIntoView({block:'nearest'});
  }
});
// The register's column heads pin below the filter bar, whose height depends on the language and viewport.
if(window.ResizeObserver)new ResizeObserver(function(entries){document.getElementById('findings').style.setProperty('--filters-h',entries[0].target.offsetHeight+'px');}).observe(document.querySelector('.filters-panel'));
// Mark the section in view in the sidebar contents.
var navLinks=[].slice.call(document.querySelectorAll('#nav a[href^="#"]'));
if(window.IntersectionObserver){var visible={},spy=new IntersectionObserver(function(entries){
  entries.forEach(function(en){visible[en.target.id]=en.isIntersecting;});
  var first=navLinks.find(function(a){return visible[a.getAttribute('href').slice(1)];});
  navLinks.forEach(function(a){if(a===first)a.setAttribute('aria-current','location');else a.removeAttribute('aria-current');});
},{rootMargin:'-35% 0px -60% 0px'});navLinks.forEach(function(a){var s=document.getElementById(a.getAttribute('href').slice(1));if(s)spy.observe(s);});}
apply();
reveal();
})();
"""


def options(values, L, lang):
    return f'<option value="">{L["all"]}</option>' + "".join(
        f'<option value="{esc(v)}">{esc(shown(v, lang))}</option>' for v in values)


def render_dashboard(data, L, lang, sources):
    meta = data.get("meta", {})
    c = counts(data)
    covered = covered_by(data)
    fs = ordered(data.get("findings", []))
    md = {f["id"]: BIDI.sub(lambda m: f"[U+{ord(m.group()):04X}]", finding_markdown(f, L, lang, covered.get(f["id"], ())))
          for f in fs}
    # Escape every markup character: "<!--<script>" in a finding would
    # otherwise keep the real </script> from closing this block.
    md_json = (json.dumps(md, ensure_ascii=False).replace("<", "\\u003c")
               .replace(">", "\\u003e").replace("&", "\\u0026")
               .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029"))
    banner = " · ".join(f"{shown(s, lang)} {c[s]}" for s in SEVERITIES) + \
        f" — {L['excluded_n']} {c['excluded']}, {L['covered_n']} {c['covered']}, {L['unverified_n']} {c['unverified']}"
    cards = "".join(f'<div class="card {s}"><span class="l">{esc(shown(s, lang))}</span><span class="n">{c[s]}</span></div>'
                    for s in SEVERITIES)
    aps = "".join(ap_html(a, L, lang) for a in data.get("attack_paths", [])) or f'<p class="muted">{L["none"]}</p>'
    rows = []
    for f in fs:
        val = f.get("validation", {}).get("verdict", "")
        val_raw = f.get("validation", {})
        searchable = [f.get("id"), f.get("title"), shown(f.get("title"), lang), f.get("location"), " ".join(f.get("resources", [])),
                      f.get("rule", ""), f.get("cwe", ""), " ".join(f.get("controls", [])),
                      " ".join(f.get("attack_paths", [])), val_raw.get("evidence", "")]
        searchable += [f.get(k, "") for k in FIELD_ORDER if isinstance(f.get(k), str)]
        # Canonical and displayed spellings: "High" and "高" both match.
        for key in ("severity", "confidence", "category", "provider"):
            searchable += [f.get(key), shown(f.get(key), lang)]
        searchable += [val, shown(val, lang)]
        text = " ".join(str(x) for x in searchable if x).lower()
        cls = "row excluded" if is_excluded(f) else "row covered" if f["id"] in covered else "row"
        rows.append(
            f'<tr class="{cls}" id="{esc(f["id"])}" data-sev="{esc(f.get("severity"))}" data-prov="{esc(f.get("provider"))}" '
            f'data-cat="{esc(f.get("category"))}" data-ver="{esc(val)}" data-text="{esc(text)}">'
            f'<td data-label="{L["id"]}">{esc(f["id"])}</td>'
            f'<td data-label="{L["severity"]}"><span class="badge {esc(f.get("severity"))}">{esc(shown(f.get("severity"), lang))}</span></td>'
            f'<td data-label="{L["confidence"]}">{esc(shown(f.get("confidence"), lang))}</td>'
            f'<td data-label="{L["provider"]}">{esc(f.get("provider"))}</td>'
            f'<td data-label="{L["verdict"]}">{esc(shown(val, lang))}</td>'
            f'<td><button class="finding-toggle" type="button" aria-expanded="false" '
            f'aria-controls="{esc(f["id"])}-detail">{esc(shown(f.get("title"), lang))}</button>'
            f'<span class="location">{esc(f.get("location"))}</span></td>'
            f'<td data-label="{L["category"]}">{esc(shown(f.get("category"), lang))}</td></tr>'
            f'<tr class="detail" id="{esc(f["id"])}-detail" hidden><td colspan="7">{detail_dl(f, L, lang, sources, covered.get(f["id"], ()))}'
            f'<div class="detail-actions"><button class="copy" type="button" data-id="{esc(f["id"])}" '
            f'data-done="{esc(L["copied"])}">{L["copy"]}</button></div></td></tr>')
    table = "".join(rows) or f'<tr><td colspan="7" class="empty">{L["none"]}</td></tr>'
    names = perspective_names()
    present = {p.get("name"): p for p in data.get("perspectives", [])}
    persp = "".join(
        f'<div class="perspective"><strong>{esc(shown(n, lang))}<span class="st">{esc(shown(present[n].get("status"), lang)) if n in present else "—"}</span></strong>'
        f'<p>{esc(present.get(n, {}).get("note", ""))}</p></div>' for n in names)
    used = lambda key: sorted({f.get(key) for f in fs if f.get(key)})
    lists = "".join(f'<section><h2>{L[k]}</h2>{list_block(data.get(k, []), L)}</section>' for k in STRING_LISTS)
    title = f'{L["doc_title"]} — {meta.get("project", "")}'
    # Severity facets count what the cards count: excluded and covered findings stay out.
    facets = "".join(f'<button class="facet" type="button" data-sev="{s}" aria-controls="findings" aria-pressed="false">'
                     f'<span class="facet-name {s}">{esc(shown(s, lang))}</span><span class="facet-n">{c[s]}</span></button>'
                     for s in SEVERITIES)
    nav = "".join(f'<li><a href="#{anchor}">{L[key]}</a></li>' for anchor, key in (
        ("overview", "summary"), ("attack-paths", "attack_paths"), ("findings", "findings"),
        ("perspectives-section", "perspectives"), ("scope-section", "scope_method"), ("lists", "nav_lists")))
    return f"""<!doctype html>
<html lang="{lang}" class="app-shell">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(title)}</title><style>{kit_style.dashboard_css()}{DASH_CSS}</style></head>
<body>
<header class="appbar"><div class="appbar-in"><span class="brand"><span>{L["brand"]}</span><span class="appbar-project">{esc(meta.get("project", ""))}</span></span><div class="tools">
<a class="button" href="assessment.html">{L["assessment"]}</a><button id="theme" type="button">{L["theme"]}</button></div></div></header>
<div class="shell">
<nav class="sidebar" id="nav" aria-label="{L["contents"]}"><h2 class="nav-title">{L["contents"]}</h2><ol class="nav-links">{nav}</ol>
<div class="facets"><h2 class="nav-title">{L["severity"]}</h2>{facets}</div>
<dl class="keys"><dt class="nav-title">{L["shortcuts"]}</dt><dd><kbd>/</kbd> {L["key_search"]}</dd><dd><kbd>j</kbd> <kbd>k</kbd> {L["key_move"]}</dd><dd><kbd>Enter</kbd> {L["key_toggle"]}</dd></dl></nav>
<main>
<section id="overview" tabindex="-1" aria-labelledby="h">
<div class="hero"><div><div class="eyebrow">{L["doc_title"]}</div><h1 id="h">{esc(meta.get("project", ""))}</h1>
<div class="meta">{esc(meta.get("scope", ""))} · {esc(meta.get("date", ""))} · {esc(meta.get("assessor", ""))}{(" · " + esc(meta["commit"][:12])) if meta.get("commit") else ""}</div></div></div>
<div class="summary-banner"><strong>{esc(banner)}</strong></div>
<div class="cards">{cards}</div>
</section>
<section id="attack-paths" tabindex="-1"><div class="section-head"><div><h2>{L["attack_paths"]}</h2></div></div><div class="aps">{aps}</div></section>
<section id="findings" tabindex="-1"><div class="section-head"><div><h2 id="findings-h">{L["findings"]}</h2></div></div>
<div class="panel filters-panel"><div class="filters">
<label>{L["severity"]}<select id="f-sev">{options(SEVERITIES, L, lang)}</select></label>
<label>{L["provider"]}<select id="f-prov">{options(used("provider"), L, lang)}</select></label>
<label>{L["category"]}<select id="f-cat">{options(used("category"), L, lang)}</select></label>
<label>{L["verdict"]}<select id="f-ver">{options(VERDICTS, L, lang)}</select></label>
<label class="search">{L["search"]}<input id="f-q" type="search"></label>
</div><div class="filter-bottom"><p class="result-count" id="result-count" data-l="{L["shown"]}" data-e="{L["excluded_n"]}" data-c="{L["covered_n"]}" aria-live="polite"></p></div></div>
<div class="tablewrap"><table class="register" aria-labelledby="findings-h"><thead><tr><th scope="col">{L["id"]}</th><th scope="col">{L["severity"]}</th>
<th scope="col">{L["confidence"]}</th><th scope="col">{L["provider"]}</th><th scope="col">{L["verdict"]}</th><th scope="col">{L["title"]}</th>
<th scope="col">{L["category"]}</th></tr></thead>
<tbody>{table}</tbody></table></div></section>
<section id="perspectives-section" tabindex="-1"><div class="section-head"><div><h2>{L["perspectives"]}</h2></div></div><div id="perspectives">{persp}</div></section>
<section id="scope-section" tabindex="-1"><div class="section-head"><div><h2>{L["scope_method"]}</h2></div></div><dl class="scope-meta">{meta_rows(data, L, lang)}</dl></section>
<div class="lists" id="lists" tabindex="-1">{lists}</div>
<footer class="footer">{L["static_note"]}</footer>
</main>
</div>
<script type="application/json" id="md">{md_json}</script>
<script>{DASH_JS}</script>
</body></html>
"""


# Long-text fields are set as headed paragraphs; the rest go in the state table.
DOC_FIELDS = ("actor", "path", "contrast", "impact", "condition", "fix", "regression", "detail")


def doc_finding(f, L, lang, sources, covered=()):
    """One finding entry in the assessment, in the shared document vocabulary."""
    state = [(L["severity"], f'<span class="badge {esc(f.get("severity"))}">{esc(shown(f.get("severity"), lang))}</span>'),
             (L["confidence"], esc(shown(f.get("confidence"), lang))),
             (L["verdict"], esc(shown(f.get("validation", {}).get("verdict"), lang))),
             (L["category"], esc(shown(f.get("category"), lang))),
             (L["provider"], esc(f.get("provider"))),
             (L["location"], f"<code>{esc(f.get('location'))}</code>"),
             (L["resources"], "<br>".join(f"<code>{esc(r)}</code>" for r in f.get("resources", [])))]
    if covered:
        state.append((L["covered"], ", ".join(f'<a href="#{esc(x)}">{esc(x)}</a>' for x in covered)))
    for key in ("rule", "controls", "cwe"):
        value = field_text(f, key)
        if value:
            state.append((L[key], esc(value)))
    if f.get("attack_paths"):
        state.append((L["attack_paths"], ", ".join(f'<a href="#{esc(a)}">{esc(a)}</a>' for a in f["attack_paths"])))
    fields = [(L[key], field_text(f, key)) for key in DOC_FIELDS if field_text(f, key)]
    if f.get("validation", {}).get("evidence"):
        fields.append((L["evidence"], f["validation"]["evidence"]))
    body = "".join(f'<div class="finding-field"><h4>{k}</h4><p class="prose">{esc(v)}</p></div>' for k, v in fields)
    if f.get("id") in sources:
        body += f'<div class="finding-field"><h4>{L["source"]}</h4>{snippet_html(sources[f["id"]])}</div>'
    if f.get("references"):
        body += (f'<div class="finding-field"><h4>{L["references"]}</h4><ul class="refs">' + "".join(
            f'<li><a href="{esc(r["url"])}" rel="noopener noreferrer">{esc(r.get("title") or r["url"])}</a></li>'
            for r in f["references"]) + "</ul></div>")
    cls = "finding excluded" if is_excluded(f) else f"finding sev-{esc(f.get('severity'))}" + (" covered" if covered else "")
    rows = "".join(f'<tr><th scope="row">{k}</th><td>{v}</td></tr>' for k, v in state)
    return (f'<article class="{cls}" id="{esc(f["id"])}"><div class="finding-header">'
            f'<span class="finding-id">{esc(f["id"])}</span><h3>{esc(shown(f.get("title"), lang))}</h3>'
            f'<table class="finding-state"><tbody>{rows}</tbody></table></div>{body}</article>')


def render_assessment(data, L, lang, sources, pdf_note=""):
    meta = data.get("meta", {})
    c = counts(data)
    covered = covered_by(data)
    fs = ordered(data.get("findings", []))
    active = [f for f in fs if not is_excluded(f)]
    excluded = [f for f in fs if is_excluded(f)]
    none = f'<p class="small">{L["none"]}</p>'

    by_sev = "".join(
        f'<h3>{esc(shown(s, lang))}</h3>' + "".join(doc_finding(f, L, lang, sources, covered.get(f["id"], ()))
                                                   for f in active if f.get("severity") == s)
        for s in SEVERITIES if any(f.get("severity") == s for f in active)) or none
    excl = "".join(doc_finding(f, L, lang, sources, covered.get(f["id"], ())) for f in excluded) or none
    present = {p.get("name"): p for p in data.get("perspectives", [])}
    persp = "".join(f'<tr><td>{esc(shown(n, lang))}</td><td>{esc(shown(present[n].get("status"), lang)) if n in present else "—"}</td>'
                    f'<td>{esc(present.get(n, {}).get("note", ""))}</td></tr>' for n in perspective_names())
    sev_head = "".join(f'<th scope="col" class="{s}">{esc(shown(s, lang))}</th>' for s in SEVERITIES)
    sev_cells = "".join(f'<td class="metric-urgent">{c[s]}</td>' if s in ("High", "Medium") and c[s] else f"<td>{c[s]}</td>"
                        for s in SEVERITIES)
    metrics = (f'<table class="metrics"><caption>{L["counts"]}</caption><thead><tr><th scope="col"></th>{sev_head}</tr></thead>'
               f'<tbody><tr><th scope="row">{L["findings"]}</th>{sev_cells}</tr></tbody></table>')
    aps = "".join(ap_html(a, L, lang) for a in data.get("attack_paths", [])) or none
    scope = "".join(f'<p class="meta-line"><strong>{k}</strong><span>{v}</span></p>' for k, v in meta_pairs(data, L, lang))
    sections = [
        ("summary", L["summary"], f'<p><strong>{" · ".join(f"{shown(s, lang)} {c[s]}" for s in SEVERITIES)}</strong> — '
                                  f'{L["excluded_n"]} {c["excluded"]}, {L["covered_n"]} {c["covered"]}, '
                                  f'{L["unverified_n"]} {c["unverified"]}</p>{metrics}<p>{L["static_note"]}</p>'
                                  + (f'<p class="small">{esc(pdf_note)}</p>' if pdf_note else "")),
        ("scope", L["scope_method"], scope),
        ("attack-paths", L["attack_paths"], aps),
        ("finding-details", L["findings"], by_sev),
        ("excluded", L["excluded"], excl),
        ("perspectives", L["perspectives"],
         f'<table class="coverage"><caption>{L["perspectives"]}</caption>'
         '<colgroup><col class="perspective-col"><col class="result-col"><col class="note-col"></colgroup>'
         f'<thead><tr><th scope="col">{L["category"]}</th><th scope="col">{L["status"]}</th><th scope="col">{L["note"]}</th></tr></thead>'
         f'<tbody>{persp}</tbody></table>'),
    ] + [(k.replace("_", "-"), L[k], list_block(data.get(k, []), L, "small")) for k in STRING_LISTS]
    body = "".join(f'<section id="{sid}"' + (' class="excluded-section"' if sid == "excluded" else "") +
                   f"><h2>{t}</h2>{b}</section>" for sid, t, b in sections)
    cover = "".join(f'<p class="meta-line"><strong>{L[k]}</strong><span>{esc(meta.get(k))}</span></p>'
                    for k in ("scope", "date", "assessor", "commit") if meta.get(k))
    return f"""<!doctype html>
<html lang="{lang}">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(L["assessment"])} — {esc(meta.get("project", ""))}</title><style>{kit_style.document_css(L["running_footer"])}{ASSESSMENT_CSS}</style></head>
<body>
<header class="report-header"><p class="kicker">{L["brand"]}</p><h1>{L["doc_title"]}</h1>
<p class="project">{esc(meta.get("project", ""))}</p>{cover}
<p class="small">{L["cover_note"]}</p></header>
<main>
{body}
</main>
</body></html>
"""


def to_pdf(html_path, pdf_path, failed=None, timeout=None):
    """Print with scan_report_kit.pdf.to_pdf (Chrome, else WeasyPrint); leave no PDF when neither succeeds.

    Engines that were found but did not produce a PDF, and a CHROME that does
    not exist, are appended to `failed` as one readable string each. Engine
    stderr is scrubbed (redaction.scrub_line) before it is recorded.
    """
    failed = [] if failed is None else failed
    chrome = os.environ.get("CHROME")
    if chrome and not (os.path.isabs(chrome) and os.path.exists(chrome)) and not shutil.which(chrome):
        failed.append(f"CHROME={chrome} (not found)")
    failures = []
    engine = kit_pdf.to_pdf(html_path, pdf_path, failures, kit_pdf.pdf_timeout() if timeout is None else timeout,
                            redact=scrub_line)
    failed.extend(f"{name} ({reason})" + (f": {detail}" if detail else "") for name, reason, detail in failures)
    if engine is None:
        Path(pdf_path).unlink(missing_ok=True)  # A failed engine's partial output is not an assessment.
    return engine


OUTPUTS = ("dashboard.html", "assessment.html", "assessment.pdf")


def output_dir_problem(out, repo):
    """Refuse outputs inside the assessed repository or through symlinks."""
    out = Path(out)
    if out.is_symlink() or has_symlink_parent(out):
        return f"{out} is a symlink or has a symlinked parent directory; refusing to write through it"
    if repo:
        root, target = Path(repo).resolve(), out.resolve()
        if target == root or root in target.parents:
            return f"{out} is inside the assessed repository {repo}; write outputs elsewhere"
    target = unsafe_target(out, OUTPUTS)
    if target:
        return f"{target} is a symlink or not a regular file; refusing to write through it"
    return None


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("findings")
    p.add_argument("--out", required=True)
    p.add_argument("--lang", choices=sorted(LABELS), default="en")
    p.add_argument("--no-pdf", action="store_true", help="skip PDF generation and remove any previous PDF")
    p.add_argument("--repo", help="assessed repository root: embeds redacted source excerpts for path:line locations")
    a = p.parse_args(argv)
    try:
        data = load_record(a.findings)
        validate(data)
    except SchemaError as e:
        for problem in e.problems:
            print(f"schema: {problem}", file=sys.stderr)
        return 2
    digest = record_digest(data)  # before anything below can touch data
    L = LABELS[a.lang]
    out = Path(a.out)
    if a.repo and not Path(a.repo).is_dir():
        print(f"render: --repo {a.repo} is not a directory", file=sys.stderr)
        return 2
    problem = output_dir_problem(out, a.repo)
    if problem:
        print(f"render: {problem}", file=sys.stderr)
        return 2
    sources = attach_sources(data, a.repo) if a.repo else {}
    pdf, assessment = out / "assessment.pdf", out / "assessment.html"
    # Build both pages before touching the output directory, so a failure
    # leaves the previous outputs as they were.
    dashboard = stamp(render_dashboard(data, L, a.lang, sources), digest)
    page = stamp(render_assessment(data, L, a.lang, sources), digest)
    try:
        out.mkdir(parents=True, exist_ok=True)
        pdf.unlink(missing_ok=True)  # Previous findings must not survive an HTML-only render.
        write_output(out / "dashboard.html", dashboard)
        write_output(assessment, page)
    except OSError as e:
        print(f"render: cannot write {out}: {e.strerror or e}", file=sys.stderr)
        return 2
    print(f"wrote {out / 'dashboard.html'}\nwrote {assessment}")
    if not a.no_pdf:
        failed = []
        engine = to_pdf(assessment, pdf, failed, kit_pdf.pdf_timeout(len(data.get("findings", []))))
        if engine:
            print(f"wrote {pdf} ({engine})")
        else:
            note = L["pdf_failed"] if failed else L["pdf_missing"]
            try:
                write_output(assessment, stamp(render_assessment(data, L, a.lang, sources, note), digest))
            except OSError as e:
                print(f"render: cannot write {assessment}: {e.strerror or e}", file=sys.stderr)
                return 2
            print(f"warning: {note}" + (f" Tried: {', '.join(failed)}" if failed else "")
                  + " Next: merge a limitations line saying so, re-render with --no-pdf, then run "
                    "contract_check.py OUT --no-pdf", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
