#!/usr/bin/env python3
"""Export findings.json as SARIF 2.1.0, for code scanning tools and IDE viewers.

    python3 sarif.py FINDINGS [--out FILE] [--repo CHECKOUT] [--min-severity High|Medium|Low|Info]

Each finding a team would act on becomes one result at its first location
(further locations are related locations), so a viewer such as GitHub code
scanning or an IDE's SARIF viewer shows it on the line it names:

- level: High `error`, Medium `warning`, Low and Info `note`
- rule: the finding's hunt step (`DM1`), or its perspective when it has none,
  described by the perspective's name
- message: the title, what happens and the fix direction; every other field
  (scenario, blast radius, trace, guard, verdict, cited rules) under
  `properties`
- a stable `partialFingerprints` entry from the perspective and title, so the
  same finding in a later run is the same alert

Left out: excluded verdicts (`FalsePositive`, `NotApplicable`), `Unlikely`
findings, findings whose status is `Fixed`, and findings below
`--min-severity`. An `Accepted` finding is kept as a suppressed result
(`kind: external`, `status: accepted`), so the trade-off stays visible without
an open alert. Locations are relative to the repository root, as the record
holds them; with `--repo`, an absolute path inside that checkout is made
relative to it.

Uploading the file, which carries the record's text to that service, stays
with the requester.

Exit codes: 0 written, 1 FILE could not be written, 2 the record cannot be
read or does not match the schema, or the command line is wrong.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import sys
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.dont_write_bytecode = True  # leave no __pycache__ beside the skill
from findings import (EXCLUDED, PERSPECTIVES, SEVERITIES, STEP_PREFIXES, SchemaError,  # noqa: E402
                      atomic_write_all, as_locations, cited_rules, read_json, safe_output,
                      split_location, validate)

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
LEVELS = {"High": "error", "Medium": "warning", "Low": "note", "Info": "note"}
LEFT_OUT_VERDICTS = (*EXCLUDED, "Unlikely")
FINGERPRINT = "architectureScan/v1"
DETAIL_FIELDS = ("scenario", "blast_radius", "trace", "contrast", "impact", "fix", "guard")


def slug(text):
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def rule_id(f):
    """The hunt step, or the perspective as a slug: `DM1`, `coupling`."""
    return f.get("step") or slug(f["category"])


def descriptor(f):
    category = f["category"]
    prefix = STEP_PREFIXES[PERSPECTIVES.index(category)]
    name = f"{category} ({f['step']})" if f.get("step") else category
    pascal = "".join(word[:1].upper() + word[1:] for word in re.findall(r"[A-Za-z0-9]+", category))
    return {"id": rule_id(f), "name": pascal + (f.get("step") or ""),
            "shortDescription": {"text": name},
            "fullDescription": {"text": f"architecture-scan perspective: {category} "
                                        f"(hunt steps {prefix}1…)"},
            "properties": {"tags": ["architecture", category]}}


def uri(path, repo):
    """A location's path as a SARIF URI, relative to the repository root when it can be."""
    windows = PureWindowsPath(path)
    if repo is not None and (Path(path).is_absolute() or windows.drive):
        try:
            path = Path(path).resolve().relative_to(Path(repo).resolve()).as_posix()
        except ValueError:
            pass
    if windows.drive or "\\" in path:
        path = windows.as_posix()
    if PurePosixPath(path).is_absolute() or re.match(r"[A-Za-z]:/", path):
        return "file://" + ("" if path.startswith("/") else "/") + quote(path, safe="/:")
    while path.startswith("./"):
        path = path[2:]
    return quote(path, safe="/")


def physical(loc, repo):
    path, start, end = split_location(loc)
    region = {"startLine": start}
    if end != start:
        region["endLine"] = end
    return {"physicalLocation": {"artifactLocation": {"uri": uri(path, repo)}, "region": region}}


def sentence(text):
    text = " ".join(str(text).split())
    return text if re.search(r"[.!?。！？]$", text) else text + "."


def message(f):
    v = f["validation"]
    return " ".join((f"[{f['severity']}][{f['confidence']}][{v['verdict']}]",
                     sentence(f["title"]), sentence(f["impact"]),
                     "Fix direction: " + sentence(f["fix"])))


def result(f, doc, repo):
    locations = as_locations(f["location"])
    rules = {r["id"]: r for r in doc.get("rules", [])}
    out = {
        "ruleId": rule_id(f), "level": LEVELS[f["severity"]], "message": {"text": message(f)},
        "locations": [physical(locations[0], repo)],
        "partialFingerprints": {FINGERPRINT: hashlib.sha256(
            f"{f['category']}\n{' '.join(f['title'].split()).casefold()}".encode("utf-8")
        ).hexdigest()[:32]},
        "properties": {
            "findingId": f["id"], "severity": f["severity"], "confidence": f["confidence"],
            "verdict": f["validation"]["verdict"], "verification": f["validation"]["method"],
            "status": f.get("status", "Open"), "perspective": f["category"],
            **{key: f[key] for key in DETAIL_FIELDS if key in f},
            "designRules": [{"id": rid, "statement": rules[rid]["statement"],
                             "source": rules[rid]["source"]}
                            for rid in cited_rules(f) if rid in rules],
        },
    }
    if len(locations) > 1:
        out["relatedLocations"] = [dict(physical(loc, repo), id=i)
                                   for i, loc in enumerate(locations[1:], 1)]
    if f.get("references"):
        out["properties"]["references"] = [r["url"] for r in f["references"]]
    if f.get("status") == "Accepted":
        out["suppressions"] = [{"kind": "external", "status": "accepted",
                                "justification": "Accepted in the architecture assessment"}]
    return out


def exported(f, min_severity):
    return (f["validation"]["verdict"] not in LEFT_OUT_VERDICTS and f.get("status") != "Fixed"
            and SEVERITIES.index(f["severity"]) <= SEVERITIES.index(min_severity))


def sarif(doc, repo=None, min_severity="Info"):
    findings = [f for f in doc.get("findings", []) if exported(f, min_severity)]
    descriptors = {}
    for f in findings:
        descriptors.setdefault(rule_id(f), descriptor(f))
    meta = doc["meta"]
    run = {
        "tool": {"driver": {"name": "architecture-scan", "rules": list(descriptors.values())}},
        # One category for every run, so a later upload closes the alerts it no longer has.
        "automationDetails": {"id": "architecture-scan/"},
        "results": [result(f, doc, repo) for f in findings],
        "properties": {k: meta[k] for k in ("project", "scope", "commit", "date", "assessor",
                                            "method") if k in meta},
    }
    return {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [run]}


def main(argv=None):
    safe_output()
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("findings")
    parser.add_argument("--out", metavar="FILE", help="write here instead of standard output")
    parser.add_argument("--repo", metavar="CHECKOUT",
                        help="make absolute locations inside this checkout relative to it")
    parser.add_argument("--min-severity", choices=SEVERITIES, default="Info")
    args = parser.parse_args(argv)
    try:
        doc = read_json(args.findings)
        validate(doc, complete=True)
    except SchemaError as exc:
        print(f"schema: {exc}", file=sys.stderr)
        return 2
    output = json.dumps(sarif(doc, args.repo, args.min_severity), ensure_ascii=False,
                        indent=2) + "\n"
    if args.out is None:
        sys.stdout.write(output)
        return 0
    try:
        atomic_write_all({Path(args.out): output.encode("utf-8")})
    except (OSError, RuntimeError) as exc:
        print(f"write failed: {exc}", file=sys.stderr)
        return 1
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
