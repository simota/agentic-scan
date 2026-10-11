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
last), and rewrites every U-* reference in the record. check, render.py and
contract_check.py require that order. Standard library only.
Exit status: 0 ok, 2 invalid input (reasons on stderr).
"""

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan_report_kit.output import write_output  # noqa: E402

SEVERITIES = ("High", "Medium", "Low", "Info")
CONFIDENCES = ("Confirmed", "Runtime-dependent", "Suspected")
STATUSES = ("Open", "Fixed", "Accepted")
VERDICTS = ("Valid", "Likely", "Unverified", "Unlikely", "FalsePositive", "NotApplicable")
EXCLUDED = ("FalsePositive", "NotApplicable")
PRIORITIES = ("primary", "secondary", "shared")
SOURCES = ("documented", "stated", "inferred")
TOKEN_SCALES = ("spacing", "font_sizes", "breakpoints", "z_index")
LIST_KEYS = ("checked_ok", "limitations", "decisions", "next_steps")
FAMILIES = ("IA", "LG", "RS", "VH", "CC", "ST", "FM", "FB", "CP", "AX", "MO", "IN", "PP")
FINDING_ID = re.compile(r"^U-[0-9]{3}\Z")
FLOW_ID = re.compile(r"^FL-[0-9]{2,3}\Z")
PERSPECTIVE = re.compile(r"^(?:%s)[0-9]\Z" % "|".join(FAMILIES))
LOCATION = re.compile(r"^(?!/)(?!.*(?:^|/)\.\.(?:/|:))[^\s:][^:\n]*:[1-9][0-9]*(?:-[1-9][0-9]*)?\Z")
VIEWPORT = re.compile(r"^[1-9][0-9]{2,3}x[1-9][0-9]{2,3}\Z")
TEXT_FIELDS = ("title", "category", "screen", "viewport", "criterion", "observed", "expected", "impact", "fix")


class RecordError(Exception):
    pass


def _str(obj, key, where, required=False):
    value = obj.get(key, "")
    if not isinstance(value, str):
        raise RecordError(f"{where}.{key}: expected a string")
    if required and not value.strip():
        raise RecordError(f"{where}.{key}: required")
    return value


def _strings(value, where):
    if not isinstance(value, list) or not all(isinstance(x, str) and x.strip() for x in value):
        raise RecordError(f"{where}: expected a list of non-empty strings")
    return value


def _location(value, where):
    if not isinstance(value, str) or not LOCATION.match(value):
        raise RecordError(f"{where}: {value!r} is not a repository-relative path:line")
    return value


def _http(url, where):
    if not isinstance(url, str) or not re.match(r"^https?://[^\s/]+", url):
        raise RecordError(f"{where}: expected an http(s) URL")


def check_flows(flows):
    """Raise RecordError unless flows matches reference/flows.md; return it."""
    if not isinstance(flows, dict):
        raise RecordError("flows: expected an object")
    _str(flows, "app", "flows", required=True)
    for v in _strings(flows.get("viewports", []), "flows.viewports"):
        if not VIEWPORT.match(v):
            raise RecordError(f"flows.viewports: {v!r} is not WIDTHxHEIGHT in CSS px (360x640)")
    _strings(flows.get("locales", []), "flows.locales")
    tokens = flows.get("tokens", {})
    if not isinstance(tokens, dict):
        raise RecordError("flows.tokens: expected an object")
    if tokens:
        _location(_str(tokens, "source", "flows.tokens", required=True), "flows.tokens.source")
    for key in TOKEN_SCALES:
        if key in tokens:
            scale = tokens[key]
            if (not isinstance(scale, list) or not scale
                    or not all(isinstance(x, (int, float)) and not isinstance(x, bool) for x in scale)):
                raise RecordError(f"flows.tokens.{key}: expected a non-empty list of numbers (px; plain for z_index)")
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
            _str(s, "name", f"{where}.screens[{j}]", required=True)
            _str(s, "route", f"{where}.screens[{j}]")
            _location(s.get("location"), f"{where}.screens[{j}].location")
    if not any(fl["priority"] == "primary" for fl in items):
        raise RecordError("flows.flows: no primary flow; severity is judged against the primary tasks")
    return flows


def check_findings(data, flow_ids=None, ordered=True):
    """Raise RecordError unless data matches reference/findings-schema.md.

    flow_ids is the set of flows.json flow ids; None skips the flow checks.
    ordered=False skips the severity order, which renumber restores after merging.
    """
    if not isinstance(data, dict):
        raise RecordError("findings: expected an object")
    if data.get("schema_version") != 1:
        raise RecordError("schema_version: expected 1")
    meta = data.get("meta")
    if not isinstance(meta, dict):
        raise RecordError("meta: expected an object")
    for key in ("project", "date", "assessor"):
        _str(meta, key, "meta", required=True)
    if not re.match(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}\Z", meta["date"]):
        raise RecordError("meta.date: expected YYYY-MM-DD")
    for key in ("scope", "method", "commit"):
        _str(meta, key, "meta")
    for key in ("viewports", "locales"):
        if key in meta:
            _strings(meta[key], f"meta.{key}")
    _str(data, "summary", "findings")
    for key in LIST_KEYS:
        if key in data:
            if not isinstance(data[key], list) or not all(isinstance(x, str) for x in data[key]):
                raise RecordError(f"{key}: expected a list of strings")
    perspectives = data.get("perspectives", [])
    if not isinstance(perspectives, list):
        raise RecordError("perspectives: expected a list")
    for i, p in enumerate(perspectives):
        if not isinstance(p, dict):
            raise RecordError(f"perspectives[{i}]: expected an object")
        _str(p, "name", f"perspectives[{i}]", required=True)
        _str(p, "result", f"perspectives[{i}]")
        _str(p, "note", f"perspectives[{i}]")
    findings = data.get("findings")
    if not isinstance(findings, list):
        raise RecordError("findings: expected a list")
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
        for key, allowed in (("severity", SEVERITIES), ("confidence", CONFIDENCES), ("status", STATUSES)):
            if f.get(key) not in allowed:
                raise RecordError(f"{where}.{key}: expected one of {', '.join(allowed)}")
        for key in TEXT_FIELDS:
            _str(f, key, where, required=key in ("title", "screen", "criterion"))
        perspective = _str(f, "perspective", where, required=True)
        if not PERSPECTIVE.match(perspective):
            raise RecordError(f"{where}.perspective: expected a hunt step id such as AX2 or FM3")
        ref = _str(f, "flow_ref", where, required=True)
        if not FLOW_ID.match(ref):
            raise RecordError(f"{where}.flow_ref: expected a flow id such as FL-01")
        if flow_ids is not None and ref not in flow_ids:
            raise RecordError(f"{where}.flow_ref: {ref} is not a flow in flows.json")
        location = _location(_str(f, "location", where, required=True), f"{where}.location")
        for loc in _strings(f.get("occurrences", [location]), f"{where}.occurrences"):
            _location(loc, f"{where}.occurrences")
        validation = f.get("validation")
        if not isinstance(validation, dict):
            raise RecordError(f"{where}.validation: required")
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
            _http(ref_.get("url"), f"{where}.references[{j}].url")
    order = [f for f in findings if f["validation"]["verdict"] not in EXCLUDED]
    ranks = [SEVERITIES.index(f["severity"]) for f in order]
    if ordered and ranks != sorted(ranks):
        raise RecordError("findings: included findings must be numbered in severity order (High first); "
                          "run findings.py renumber <out>/findings.json")
    return data


FINDING_REF = re.compile(r"\bU-[0-9]{3}\b")


def renumber_map(findings):
    """Old id -> new id: severity, then path and line; excluded findings last, in their old order."""
    def key(f):
        path, _, lines = f["location"].rpartition(":")
        return SEVERITIES.index(f["severity"]), path, int(lines.split("-")[0]), f["id"]
    active = sorted((f for f in findings if f["validation"]["verdict"] not in EXCLUDED), key=key)
    excluded = sorted((f for f in findings if f["validation"]["verdict"] in EXCLUDED), key=lambda f: f["id"])
    return {f["id"]: f"U-{n:03d}" for n, f in enumerate(active + excluded, 1)}


def renumber(data, mapping):
    """Rewrite every U-* reference in data's strings at once, then order the findings by id."""
    def rewrite(value):
        if isinstance(value, str):
            return FINDING_REF.sub(lambda m: mapping.get(m.group(0), m.group(0)), value)
        if isinstance(value, dict):
            return {k: rewrite(v) for k, v in value.items()}
        if isinstance(value, list):
            return [rewrite(v) for v in value]
        return value
    data = rewrite(data)
    data["findings"].sort(key=lambda f: f["id"])
    return data


def load_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise RecordError(f"{path}: {e}") from None


def flow_ids(flows):
    """The flow ids of a checked flows.json."""
    return {fl["id"] for fl in flows["flows"]}


def flow_ids_beside(findings_path):
    flows = Path(findings_path).with_name("flows.json")
    if not flows.exists():
        return None
    return flow_ids(check_flows(load_json(flows)))


def merge_flows(base, fragment):
    """base with fragment's top-level keys replaced and its flows added or replaced by id."""
    if not isinstance(fragment, dict) or not isinstance(fragment.get("flows", []), list):
        raise RecordError("flows fragment: expected an object with a flows list")
    out = {**base, **{k: v for k, v in fragment.items() if k != "flows"}}
    by_id = {fl.get("id"): fl for fl in base.get("flows", []) if isinstance(fl, dict)}
    for fl in fragment.get("flows", []):
        if not isinstance(fl, dict) or "id" not in fl:
            raise RecordError("flows fragment: flow without an id")
        by_id[fl["id"]] = fl
    out["flows"] = list(by_id.values())
    return out


def merge(base, fragment):
    if not isinstance(fragment, dict):
        raise RecordError("fragment: expected an object")
    out = dict(base)
    for key, value in fragment.items():
        if key in LIST_KEYS and isinstance(value, list):
            out[key] = list(dict.fromkeys([*base.get(key, []), *value]))
        elif key == "perspectives" and isinstance(value, list):
            by_name = {p.get("name"): p for p in base.get("perspectives", []) if isinstance(p, dict)}
            by_name.update((p.get("name"), p) for p in value if isinstance(p, dict))
            out[key] = list(by_name.values())
        elif key not in ("findings", "remove"):
            out[key] = value
    remove = fragment.get("remove", {})
    if not isinstance(remove, dict) or not all(k in LIST_KEYS and isinstance(v, list) for k, v in remove.items()):
        raise RecordError(f"remove: expected {{section: [exact lines]}} for {', '.join(LIST_KEYS)}")
    for key, lines in remove.items():
        missing = [x for x in lines if x not in out.get(key, [])]
        if missing:
            raise RecordError(f"remove.{key}: no such line {missing[0]!r}")
        out[key] = [x for x in out[key] if x not in lines]
    by_id = {f["id"]: dict(f) for f in base.get("findings", [])}
    for f in fragment.get("findings", []):
        if not isinstance(f, dict) or "id" not in f:
            raise RecordError("fragment finding without an id")
        by_id[f["id"]] = {**by_id.get(f["id"], {}), **f}
    out["findings"] = sorted(by_id.values(), key=lambda f: f["id"])
    return out


def dump(data):
    return json.dumps(data, ensure_ascii=False, indent=2) + "\n"


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
        if cmd == "flows":
            result = load_json(target) if target.exists() else {}
            for fragment in fragments:
                result = merge_flows(result, load_json(fragment))
            check_flows(result)
            beside = target.with_name("findings.json")
            if beside.exists():  # Every flow_ref in the record must stay a flow.
                check_findings(load_json(beside), flow_ids(result), ordered=False)
            write_output(target, dump(result))
            print(f"wrote {target} ({len(result['flows'])} flows)")
            return 0
        if cmd == "renumber":
            data = check_findings(load_json(target), flow_ids_beside(target), ordered=False)
            mapping = renumber_map(data["findings"])
            moved = ", ".join(f"{old}->{new}" for old, new in sorted(mapping.items()) if old != new)
            if not moved:
                print(f"{target}: findings already in order")
                return 0
            data = check_findings(renumber(data, mapping), flow_ids_beside(target))
            write_output(target, dump(data))
            print(f"renumbered {target}: {moved}")
            return 0
        data = load_json(target) if target.exists() else {"schema_version": 1, "findings": []}
        for fragment in fragments:
            data = merge(data, load_json(fragment))
        check_findings(data, flow_ids_beside(target), ordered=False)
        write_output(target, dump(data))
        print(f"wrote {target} ({len(data['findings'])} findings)")
        return 0
    except RecordError as e:
        print(f"findings.py: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
