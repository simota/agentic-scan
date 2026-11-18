#!/usr/bin/env python3
"""Export findings.json as SARIF 2.1.0 for code-scanning tools and editors.

    python3 sarif.py FINDINGS --out FILE.sarif [--baseline OLD_FINDINGS]
                     [--min-severity High|Medium|Low|Info]

SARIF puts each finding on its `path:line` in tools that read it: GitHub code
scanning (`github/codeql-action/upload-sarif`) annotates pull requests and
lists alerts, and SARIF viewers in editors jump to the line. The record stays
the source; this is one more read-only view of it.

- One rule per hunt step (`DB1` …) named from `reference/perspectives.md`; a
  finding without a `step` uses its perspective's prefix (`DB`).
- Results are the active findings (not `Fixed`, not `FalsePositive` or
  `NotApplicable`). Levels: High `error`, Medium `warning`, Low and Info `note`.
  An `Accepted` finding carries an external, accepted suppression whose
  justification is the `decisions` lines naming it, so tools show it as
  dismissed rather than open.
- Every location is listed; relative paths resolve against `%SRCROOT%` (the
  repository root). `partialFingerprints` hash the category, step, location
  files and title, so an unchanged finding keeps its fingerprint across runs
  even when its ID or line moves.
- `--baseline` sets `baselineState` from `compare.py`'s matching: `new`,
  `unchanged` or `updated` (severity, confidence, verdict, status or files
  changed).
- Record text is plain text in SARIF `message.text`; square brackets are
  escaped so text from the audited repository cannot form SARIF embedded links,
  and control and bidi characters are shown as `\\uXXXX`.

FILE must not be in the directory holding FINDINGS (the run contract allows
only the three outputs there). It is replaced atomically.

Exit codes: 0 written, 1 the file could not be written, 2 bad input or usage.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).resolve().parent))
from findings import (EXCLUDED, FINDING_MENTION, LOCATION, SEVERITIES,  # noqa: E402
                      STEP_PERSPECTIVES, SchemaError, escape_unencodable_console,
                      finding_locations, finding_status, resolve_path, write_atomic)
from render import text_lines  # noqa: E402
import compare  # noqa: E402

SKILL = Path(__file__).resolve().parents[1]
PERSPECTIVES_DOC = SKILL / "reference" / "perspectives.md"
INFORMATION_URI = "https://github.com/simota/performance-scan"
LEVELS = {"High": "error", "Medium": "warning", "Low": "note", "Info": "note"}
FINGERPRINT = "performanceScanRootCause/v1"
STEP_ROW = re.compile(r"^\| (?P<step>[A-Z]{2}[0-9]+) \| (?P<text>[^|]+?) \|")
SOUND_MARK = "*(sound constructs)* "
BRACKET = re.compile(r"(\\*)([\[\]])")
DRIVE = re.compile(r"[A-Za-z]:/")
# The prefix of a perspective's hunt steps (Database access -> DB).
PREFIXES = {name: step.rstrip("0123456789") for step, name in STEP_PERSPECTIVES.items()}


def hunt_steps(doc_path=PERSPECTIVES_DOC):
    """{step: description} from the hunt-step tables of reference/perspectives.md."""
    steps = {}
    try:
        lines = doc_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return steps
    inside = False
    for line in lines:
        if line.startswith("## "):
            inside = line.startswith("## Hunt steps")
            continue
        match = STEP_ROW.match(line) if inside else None
        if match and match["step"] in STEP_PERSPECTIVES:
            steps.setdefault(match["step"], match["text"].replace(SOUND_MARK, "").strip())
    return steps


def short_name(description):
    """'N+1: a query inside a loop …' -> 'N+1'; a row without a colon keeps its text."""
    head = description.split(": ", 1)[0].strip()
    return head if len(head) <= 80 else head[:79].rstrip() + "…"


def sarif_text(value):
    """Plain SARIF message text: visible escapes, and no embedded [text](link)."""
    text = "\n".join(text_lines(value))
    # Double the backslashes before a bracket, then escape it: no reading of
    # the escapes can leave a bare bracket.
    return BRACKET.sub(lambda m: m.group(1) * 2 + "\\" + m.group(2), text)


def artifact_location(path):
    path = path.strip().replace("\\", "/")
    if DRIVE.match(path):
        return {"uri": "file:///" + quote(path, safe="/:")}
    if path.startswith("/"):
        return {"uri": "file://" + quote(path, safe="/")}
    while path.startswith("./"):
        path = path[2:]
    # ":" is encoded, so a relative path never reads as a URI scheme.
    return {"uri": quote(path, safe="/"), "uriBaseId": "%SRCROOT%"}


def physical_location(location):
    match = LOCATION.fullmatch(location)
    region = {"startLine": int(match["start"])}
    if match["end"]:
        region["endLine"] = int(match["end"])
    return {"physicalLocation": {"artifactLocation": artifact_location(match["path"]),
                                 "region": region}}


def rule_id(f):
    step = f.get("step", "").strip()
    return step if step in STEP_PERSPECTIVES else PREFIXES[f["category"]]


def make_rule(rid, category, descriptions):
    description = descriptions.get(rid)
    name = short_name(description) if description else category
    rule = {"id": rid, "name": name,
            "shortDescription": {"text": f"{category}: {name}"},
            "help": {"text": f"Hunt step {rid} of the {category} perspective in "
                             "reference/perspectives.md of the performance-scan skill."
                     if description else f"The {category} perspective in "
                     "reference/perspectives.md of the performance-scan skill."},
            "properties": {"tags": ["performance", category]}}
    if description:
        rule["fullDescription"] = {"text": description}
    return rule


def fingerprint(f):
    files = sorted(compare.location_files(f))
    key = "\0".join([f["category"], f.get("step", "").strip(), *files,
                     compare.normalized_title(f)])
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]


def baseline_states(doc, baseline):
    """{current ID: baselineState} from compare.py's buckets."""
    found = compare.compare(baseline, doc)["findings"]
    states = {e["current_id"]: "new" for e in found["new"]}
    for e in found["persisting"]:
        states[e["current_id"]] = "updated" if e["changes"] else "unchanged"
    return states


def to_sarif(doc, baseline=None, min_severity=None, descriptions=None):
    descriptions = hunt_steps() if descriptions is None else descriptions
    limit = SEVERITIES.index(min_severity) if min_severity else len(SEVERITIES)
    states = baseline_states(doc, baseline) if baseline is not None else None
    decided = {}
    for line in doc.get("decisions", []):
        for fid in dict.fromkeys(FINDING_MENTION.findall(line)):
            decided.setdefault(fid, []).append(line)
    rules, rule_index, results = [], {}, []
    for f in doc.get("findings", []):
        if (f["validation"]["verdict"] in EXCLUDED or finding_status(f) == "Fixed"
                or SEVERITIES.index(f["severity"]) > limit):
            continue
        rid = rule_id(f)
        if rid not in rule_index:
            rule_index[rid] = len(rules)
            rules.append(make_rule(rid, f["category"], descriptions))
        # The first line is the alert title in GitHub code scanning.
        message = f"{f['title']} ({f['id']})\n{f['impact']}\nFix: {f['fix']}"
        properties = {"findingId": f["id"], "severity": f["severity"],
                      "confidence": f["confidence"], "verdict": f["validation"]["verdict"],
                      "method": f["validation"]["method"], "status": finding_status(f),
                      "category": f["category"]}
        for key in ("workload", "scale_driver", "cost_model", "regression_test", "budget"):
            if f.get(key, "").strip():
                properties[key] = sarif_text(f[key])
        result = {"ruleId": rid, "ruleIndex": rule_index[rid], "level": LEVELS[f["severity"]],
                  "message": {"text": sarif_text(message)},
                  "locations": [physical_location(loc) for loc in finding_locations(f)],
                  "partialFingerprints": {FINGERPRINT: fingerprint(f)},
                  "properties": properties}
        if finding_status(f) == "Accepted":
            justification = " | ".join(decided.get(f["id"], [])) or "Accepted by the owner"
            result["suppressions"] = [{"kind": "external", "status": "accepted",
                                       "justification": sarif_text(justification)}]
        if states is not None:
            result["baselineState"] = states.get(f["id"], "unchanged")
        results.append(result)
    meta = doc["meta"]
    run_properties = {key: sarif_text(meta[key]) for key in
                      ("project", "scope", "commit", "date", "assessor", "method")
                      if isinstance(meta.get(key), str) and meta[key].strip()}
    run = {"tool": {"driver": {"name": "performance-scan", "informationUri": INFORMATION_URI,
                               "rules": rules}},
           "automationDetails": {"id": "performance-scan/"},
           "originalUriBaseIds": {"%SRCROOT%": {"description": {
               "text": "The root of the assessed repository"}}},
           "columnKind": "unicodeCodePoints",
           "results": results, "properties": run_properties}
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0", "runs": [run]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("findings")
    parser.add_argument("--out", required=True, help="the .sarif file to write")
    parser.add_argument("--baseline", help="an earlier run's findings.json, for baselineState")
    parser.add_argument("--min-severity", choices=SEVERITIES)
    args = parser.parse_args(argv)
    escape_unencodable_console()
    if not args.out.strip():
        parser.error("--out must name a file")
    try:
        doc = compare.load(args.findings)
        baseline = compare.load(args.baseline) if args.baseline else None
    except SchemaError as exc:
        print(f"schema: {exc}", file=sys.stderr)
        return 2
    try:
        target = resolve_path(args.out)
        if target.parent == resolve_path(args.findings).parent:
            print(f"sarif: --out {args.out}: the record's own directory holds only the three "
                  "run outputs; write the SARIF file elsewhere", file=sys.stderr)
            return 2
        sarif = to_sarif(doc, baseline, args.min_severity)
        content = (json.dumps(sarif, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        target.parent.mkdir(parents=True, exist_ok=True)
        write_atomic(target, content)
    except (OSError, UnicodeError) as exc:
        print(f"sarif: {exc}", file=sys.stderr)
        return 1
    results = sarif["runs"][0]["results"]
    suppressed = sum(1 for r in results if "suppressions" in r)
    print(f"wrote {args.out}: {len(results)} result(s), {suppressed} suppressed as Accepted")
    return 0


if __name__ == "__main__":
    sys.exit(main())
