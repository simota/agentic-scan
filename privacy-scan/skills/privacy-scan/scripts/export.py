#!/usr/bin/env python3
"""Export findings.json for code scanning, trackers and a data inventory.

    python3 export.py FINDINGS --format sarif|csv|datamap-csv --out FILE

| Format        | What it holds | For |
|---------------|---------------|-----|
| `sarif`       | SARIF 2.1.0: one result per active finding (reported, not `Fixed`) at its locations; `Accepted` findings carry an external suppression | Code scanning upload, IDE SARIF viewers |
| `csv`         | One row per finding, reported and excluded, with severity, confidence, verdict, status and the remedy | A tracker or spreadsheet |
| `datamap-csv` | One row per data map element: category, subjects, sensitive flag, where collected, stores, recipients, retention, citing findings | The personal data inventory a DPO keeps (a starting point for records of processing) |

Every value is copied from the record, which the personal-value guard has
already accepted. Each SARIF result has a `partialFingerprints` value built
from the perspective, the first location's path and the title, so a viewer can
follow a finding across runs although its `PV-NNN` ID is renumbered. CSV cells
that a spreadsheet would read as a formula (starting with `=`, `+`, `-`, `@`,
a tab or a carriage return) are prefixed with `'`; files start with a UTF-8 BOM
so spreadsheet applications read Japanese text correctly.

FILE must not be inside the run's output directory (the run contract allows
exactly three files there): use scratch or another directory. Uploading or
importing the file stays with the requester; an unfixed High belongs in a
private tracker, so check who can see an upload target before using it.

Exit codes: 0 written, 1 the record was refused or the file could not be saved,
2 the command line is invalid.
"""
import argparse
import csv
from hashlib import sha256
import io
import json
from pathlib import Path
import sys
from urllib.parse import quote

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from findings import (STEP_PREFIXES, SchemaError, element_citations, excluded,  # noqa: E402
                      locations, prepare_cli, read_json, validate)
from output_io import write_utf8_files  # noqa: E402
import render  # noqa: E402

RUN_OUTPUTS = ("findings.json", "dashboard.html", "report.md")
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/simota/privacy-scan"
LEVELS = {"High": "error", "Medium": "warning", "Low": "note", "Info": "note"}
FORMULA_START = ("=", "+", "-", "@", "\t", "\r")
CSV_COLUMNS = ("id", "severity", "confidence", "verdict", "status", "excluded", "perspective",
               "step", "title", "location", "data", "elements", "subjects", "commitment",
               "impact", "fix", "guard", "conditions", "evidence")
DATAMAP_COLUMNS = ("id", "element", "category", "subjects", "sensitive", "collected", "stores",
                   "recipients", "retention", "note", "findings")


def active(f):
    return not excluded(f) and f.get("status", "Open") != "Fixed"


def rule_id(f):
    """The hunt step, or the perspective's step prefix when no step is recorded."""
    step = f.get("step", "").strip()
    return f"privacy/{step or STEP_PREFIXES[f['category']]}"


def fingerprint(f):
    """Stable across renumbering: perspective, first path and title, normalised."""
    path = locations(f)[0].rsplit(":", 1)[0]
    title = " ".join(f["title"].split()).casefold()
    return sha256("\x1f".join((f["category"], path, title)).encode("utf-8")).hexdigest()[:32]


def sarif_location(location):
    path, _, lines = location.rpartition(":")
    physical = {"artifactLocation": {"uri": quote(path, safe="/"), "uriBaseId": "%SRCROOT%"}}
    start, _, end = lines.partition("-")
    # `path:0` names a file to create; SARIF regions start at line 1.
    if int(start) >= 1:
        region = {"startLine": int(start)}
        if end and int(end) >= int(start):
            region["endLine"] = int(end)
        physical["region"] = region
    return {"physicalLocation": physical}


def sarif_message(f, t):
    text = render.as_text
    parts = [f"{f['id']} {text(f['title'])}"]
    for key in ("data", "subjects", "impact", "fix"):
        if render.shown(f.get(key, "")):
            parts.append(f"{t[key]}: {text(f[key])}")
    return "\n".join(parts)


def sarif(doc, lang):
    t = render.LABELS[lang]
    rules, results = {}, []
    for f in doc.get("findings", []):
        if not active(f):
            continue
        rid = rule_id(f)
        if rid not in rules:
            name = f["category"] + (f" ({f['step'].strip()})" if f.get("step", "").strip() else "")
            rules[rid] = {"id": rid, "name": name,
                          "shortDescription": {"text": name},
                          "helpUri": INFORMATION_URI,
                          "properties": {"tags": ["privacy", f["category"]]}}
        v = f["validation"]
        result = {"ruleId": rid, "level": LEVELS[f["severity"]],
                  "message": {"text": sarif_message(f, t)},
                  "locations": [sarif_location(x) for x in locations(f)],
                  "partialFingerprints": {"privacyScan/v1": fingerprint(f)},
                  "properties": {"id": f["id"], "severity": f["severity"],
                                 "confidence": f["confidence"], "verdict": v["verdict"],
                                 "status": f.get("status", "Open"),
                                 "commitment": f.get("commitment", ""),
                                 "elements": f.get("elements", "")}}
        if f.get("status") == "Accepted":
            result["suppressions"] = [{"kind": "external", "status": "accepted",
                                       "justification": "Accepted in the privacy-scan record"}]
        results.append(result)
    meta = doc["meta"]
    run = {"tool": {"driver": {"name": "privacy-scan", "informationUri": INFORMATION_URI,
                               "rules": list(rules.values())}},
           "results": results,
           "properties": {"project": meta["project"], "scope": meta["scope"], "date": meta["date"],
                          "assessor": meta["assessor"], "revision": render.revision(meta),
                          "disclaimer": t["disclaimer"]}}
    return json.dumps({"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [run]},
                      ensure_ascii=False, indent=2) + "\n"


def cell(value):
    text = render.as_text(value)
    return "'" + text if text.startswith(FORMULA_START) else text


def table(columns, rows):
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\r\n")
    writer.writerow(columns)
    writer.writerows([cell(v) for v in row] for row in rows)
    return "﻿" + buffer.getvalue()


def findings_csv(doc):
    rows = []
    for f in doc.get("findings", []):
        v = f["validation"]
        rows.append((f["id"], f["severity"], f["confidence"], v["verdict"], f.get("status", "Open"),
                     "yes" if excluded(f) else "no", f["category"], f.get("step", ""), f["title"],
                     "\n".join(locations(f)), f["data"], f.get("elements", ""), f["subjects"],
                     f.get("commitment", ""), f["impact"], f.get("fix", ""), f.get("guard", ""),
                     f.get("conditions", ""), v.get("evidence", "")))
    return table(CSV_COLUMNS, rows)


def datamap_csv(doc):
    citing = element_citations(doc)
    rows = [(r["id"], r["element"], r["category"], r["subjects"], "yes" if r["sensitive"] else "no",
             "\n".join(r.get("collected", [])), "\n".join(r["stores"]), "\n".join(r["recipients"]),
             r.get("retention", ""), r.get("note", ""), ", ".join(citing.get(r["id"], [])))
            for r in doc.get("data_map", [])]
    return table(DATAMAP_COLUMNS, rows)


def _inside_run_output(out, record):
    """Whether FILE would land in the record's directory or one holding run outputs."""
    try:
        parent = out.resolve().parent
        if parent == Path(record).resolve().parent:
            return True
        return any((parent / name).exists() for name in RUN_OUTPUTS)
    except OSError:
        return True


def main(argv=None):
    prepare_cli()
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("findings")
    parser.add_argument("--format", required=True, choices=("sarif", "csv", "datamap-csv"))
    parser.add_argument("--out", required=True, help="a file outside the run's output directory")
    parser.add_argument("--lang", choices=("ja", "en"), help="SARIF message labels; defaults to meta.lang")
    args = parser.parse_args(argv)
    if not args.out.strip():
        parser.error("--out must name the export file")
    out = Path(args.out)
    try:
        doc = read_json(args.findings)
        validate(doc, complete=True)
        if _inside_run_output(out, args.findings):
            raise SchemaError("--out is inside the run's output directory; the run contract allows "
                              "exactly findings.json, dashboard.html and report.md there, so export "
                              "to scratch or another directory")
        if args.format == "datamap-csv" and not doc.get("data_map"):
            raise SchemaError("the record has no data_map to export; record the recon data map "
                              "first (reference/findings-schema.md)")
        lang = args.lang or doc["meta"]["lang"]
        content = {"sarif": lambda: sarif(doc, lang), "csv": lambda: findings_csv(doc),
                   "datamap-csv": lambda: datamap_csv(doc)}[args.format]()
    except SchemaError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 1
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        write_utf8_files({out: content}, protected_paths=(args.findings,))
    except (OSError, UnicodeError) as exc:
        print(f"write failed: could not save the export ({type(exc).__name__})", file=sys.stderr)
        return 1
    print(f"wrote {args.format} to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
