#!/usr/bin/env python3
"""Export a prune-scan findings.json as SARIF 2.1.0, for code scanning tools and IDE viewers.

    python3 sarif.py FINDINGS [--out FILE] [--repo REPO] [--min-severity High|Medium|Low|Info]

FINDINGS is a review's findings.json (or its output directory); units.json
beside it is read too. Each finding a team would act on becomes one result, so
a viewer such as GitHub code scanning or an IDE's SARIF viewer shows it on the
line where the subtraction starts:

- level, from severity (the cost of keeping): High `error`, Medium `warning`,
  Low and Info `note`
- rule: the hunt step in `perspective` (`DC1`, `PX2`), described by its family
  name ("Dead code", "Purpose fit")
- location: the finding's `location`; every other `occurrences` entry, and
  the location of the entry point named by `entry_ref` (from units.json), are
  related locations
- message: severity, confidence and verdict, the title, the subtraction
  (action and what) and what remains; the element, basis, impact, risk, the
  whole subtraction, the validation evidence and dynamic-use check, unit,
  entry point and purpose ids under `properties`
- a stable `partialFingerprints` entry (`pruneScan/v1`) from the perspective
  and the whitespace-normalised, case-folded title, so the same finding in a
  later review is the same alert even though ids are renumbered every time

Left out: excluded verdicts (`FalsePositive`, `NotApplicable`), `Unlikely`
(evidence points to use: kept, never a subtraction), `Unverified` (a working
state, not settled), findings whose status is `Fixed` (removed since), and
findings below `--min-severity`. An `Accepted` finding (kept by decision) is
a suppressed result (`kind: external`, `status: accepted`), so the decision
stays visible without an open alert.

Locations are relative to the repository root, as the record holds them, under
the `SRCROOT` base id. With `--repo`, SRCROOT is bound to that checkout (a
local `file://` URI, for IDE viewers) and FILE must lie outside it. Uploading
the file, which carries the record's text to that service, stays with the
requester. Nothing is deleted. Standard library only.
Exit status: 0 written, 2 invalid input or unwritable output (reasons on stderr).
"""

import argparse
import hashlib
import json
import os
import re
import sys
from contextlib import ExitStack
from pathlib import Path
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.dont_write_bytecode = True  # leave no __pycache__ beside the skill
from findings import EXCLUDED, SEVERITIES, RecordError, check_findings, load_json, units_beside  # noqa: E402
from render import FAMILIES  # noqa: E402
from report_output import write_output  # noqa: E402
from safe_output import SAFE_OUTPUT, tolerant_stdout, write_output_at  # noqa: E402
from safe_paths import descriptor_within, open_directory, within  # noqa: E402

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
LEVELS = {"High": "error", "Medium": "warning", "Low": "note", "Info": "note"}
LEFT_OUT_VERDICTS = (*EXCLUDED, "Unlikely", "Unverified")
FINGERPRINT = "pruneScan/v1"
BASE = "SRCROOT"
DETAIL_FIELDS = ("element", "observed", "basis", "impact", "risk", "category")


def descriptor(step):
    family = FAMILIES["en"][step[:2]]
    return {"id": step, "name": "".join(w[:1].upper() + w[1:] for w in re.findall(r"[A-Za-z0-9]+", family)) + step,
            "shortDescription": {"text": f"{family} ({step})"},
            "fullDescription": {"text": f"prune-scan perspective: {family}, hunt step {step}"},
            "properties": {"tags": ["prune", family]}}


def physical(loc):
    path, _, lines = loc.rpartition(":")
    start, _, end = lines.partition("-")
    region = {"startLine": int(start)}
    if end and end != start:
        region["endLine"] = int(end)
    while path.startswith("./"):
        path = path[2:]
    return {"physicalLocation": {"artifactLocation": {"uri": quote(path, safe="/"), "uriBaseId": BASE},
                                 "region": region}}


def sentence(text):
    text = " ".join(str(text).split())
    return text if re.search(r"[.!?。！？]$", text) else text + "."


def message(f):
    sub = f["subtraction"]
    return " ".join((f"[{f['severity']}][{f['confidence']}][{f['validation']['verdict']}]",
                     sentence(f["title"]), f"{sub['action'].capitalize()}: " + sentence(sub["what"]),
                     "Remains: " + sentence(sub["remains"])))


def result(f, entry_points):
    v = f["validation"]
    out = {
        "ruleId": f["perspective"], "level": LEVELS[f["severity"]], "message": {"text": message(f)},
        "locations": [physical(f["location"])],
        "partialFingerprints": {FINGERPRINT: hashlib.sha256(
            f"{f['perspective']}\n{' '.join(f['title'].split()).casefold()}".encode("utf-8")
        ).hexdigest()[:32]},
        "properties": {
            "findingId": f["id"], "severity": f["severity"], "confidence": f["confidence"],
            "verdict": v["verdict"], "status": f["status"], "perspective": f["perspective"],
            "family": FAMILIES["en"][f["perspective"][:2]], "unit": f["unit_ref"],
            **{key: f[key] for key in DETAIL_FIELDS if f.get(key)},
            "subtraction": f["subtraction"],
            **{key: v[key] for key in ("evidence", "dynamic_checked") if v.get(key)},
        },
    }
    for key, prop in (("entry_ref", "entryPoint"), ("purpose_ref", "purpose")):
        if f.get(key):
            out["properties"][prop] = f[key]
    if f.get("references"):
        out["properties"]["references"] = [r["url"] for r in f["references"]]
    related = [(loc, None) for loc in dict.fromkeys(f.get("occurrences", [])) if loc != f["location"]]
    ep = entry_points.get(f.get("entry_ref"))
    if ep is not None and ep["location"] != f["location"]:
        related.append((ep["location"], f"Entry point {ep['id']}: {ep['name']}"))
    if related:
        out["relatedLocations"] = [dict(physical(loc), id=i, **({"message": {"text": text}} if text else {}))
                                   for i, (loc, text) in enumerate(related, 1)]
    if f["status"] == "Accepted":
        out["suppressions"] = [{"kind": "external", "status": "accepted",
                                "justification": "Accepted (kept by decision) in the prune-scan review"}]
    return out


def exported(f, min_severity):
    return (f["validation"]["verdict"] not in LEFT_OUT_VERDICTS and f["status"] != "Fixed"
            and SEVERITIES.index(f["severity"]) <= SEVERITIES.index(min_severity))


def sarif(doc, units=None, repo=None, min_severity="Info"):
    findings = [f for f in doc["findings"] if exported(f, min_severity)]
    entry_points = {ep["id"]: ep for ep in (units or {}).get("entry_points", [])}
    rules = {}
    for f in findings:
        rules.setdefault(f["perspective"], descriptor(f["perspective"]))
    meta = doc["meta"]
    run = {
        "tool": {"driver": {"name": "prune-scan", "rules": list(rules.values())}},
        # One category for every run, so a later upload closes the alerts it no longer has.
        "automationDetails": {"id": "prune-scan/"},
        "results": [result(f, entry_points) for f in findings],
        "properties": {k: meta[k] for k in ("project", "scope", "commit", "date", "assessor", "method")
                       if meta.get(k)},
    }
    if repo is not None:
        run["originalUriBaseIds"] = {BASE: {"uri": Path(repo).resolve().as_uri().rstrip("/") + "/"}}
    return {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [run]}


def main(argv=None):
    tolerant_stdout()
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("findings", help="the review's findings.json or its output directory (units.json beside it is read too)")
    p.add_argument("--out", metavar="FILE", help="write the SARIF log here instead of stdout (outside the reviewed repository)")
    p.add_argument("--repo", metavar="REPO",
                   help="the reviewed checkout: binds SRCROOT to it, and --out must lie outside it")
    p.add_argument("--min-severity", choices=SEVERITIES, default="Info",
                   help="leave out findings below this severity (default: Info, everything)")
    a = p.parse_args(argv)
    target = Path(a.findings)
    if target.is_dir():
        target = target / "findings.json"
    try:
        units = units_beside(target)
        doc = check_findings(load_json(target), units, ordered=False)
        if a.repo is not None and not Path(a.repo).is_dir():
            raise RecordError(f"--repo {a.repo}: not a directory")
    except (RecordError, OSError) as e:
        print(f"sarif.py: {e}", file=sys.stderr)
        return 2
    log = sarif(doc, units, a.repo, a.min_severity)
    text = json.dumps(log, ensure_ascii=False, indent=2) + "\n"
    if a.out is None:
        sys.stdout.write(text)
        return 0
    output = Path(a.out)
    if a.repo is not None and within(output.parent, a.repo):
        print(f"sarif.py: {a.out} must be outside the reviewed repository", file=sys.stderr)
        return 2
    protected = []
    for path in (target, target.with_name("units.json")):
        try:
            protected.append(os.stat(path))
        except OSError:
            pass
    try:
        with ExitStack() as resources:
            if SAFE_OUTPUT:
                selected = output.parent.stat()
                directory = open_directory(output.parent.resolve(strict=True), readable=False, expected_stat=selected)
                resources.callback(os.close, directory)
                if a.repo is not None and descriptor_within(directory, a.repo):
                    raise OSError("output must be outside the reviewed repository")
                write_output_at(directory, output.name, text, protected=tuple(protected))
            else:
                if output.exists() and any(os.path.samestat(os.stat(output), s) for s in protected):
                    raise OSError("output would overwrite an input")
                write_output(output, text)
    except (OSError, ValueError) as e:
        print(f"sarif.py: cannot write {a.out}: {e}", file=sys.stderr)
        return 2
    print(f"wrote {a.out}: {len(log['runs'][0]['results'])} results")
    return 0


if __name__ == "__main__":
    sys.exit(main())
