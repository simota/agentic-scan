#!/usr/bin/env python3
"""Score a logic-scan findings.json against the seeded fixture's ground truth.

    python3 benchmarks/score.py path/to/findings.json                      # fixture-shop
    python3 benchmarks/score.py path/to/findings.json --truth ground-truth-console.json
    python3 benchmarks/score.py path/to/findings.json --json               # JSON only

A finding matches a case when one of its locations names a case site's file and
lands within `line_tolerance` lines of the site's anchor. Findings whose verdict
is FalsePositive or NotApplicable are ignored, as the report excludes them.
A finding that matches a decoy and no case is a false positive. Findings that
match neither are listed as unseeded: they may be genuine, and are judged by hand.
"""
import argparse
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
EXCLUDED = {"FalsePositive", "NotApplicable"}
LOCATION = re.compile(r"^(?P<path>.+?):(?P<start>[0-9]+)(?:-(?P<end>[0-9]+))?$")


def load_truth(path=HERE / "ground-truth.json"):
    truth = json.loads(Path(path).read_text(encoding="utf-8"))
    root = HERE / truth["fixture"]
    for entry in truth["cases"] + truth["decoys"]:
        for site in entry["sites"]:
            lines = (root / site["file"]).read_text(encoding="utf-8").splitlines()
            hits = [n for n, text in enumerate(lines, 1) if site["anchor"] in text]
            if len(hits) != 1:
                raise SystemExit(f"{entry['id']}: anchor {site['anchor']!r} found {len(hits)} times in {site['file']}")
            site["line"] = hits[0]
    return truth


def locations(finding):
    value = finding.get("location") or []
    for item in [value] if isinstance(value, str) else value:
        match = LOCATION.match(str(item).strip().strip("`"))
        if match:
            start = int(match["start"])
            yield match["path"], start, int(match["end"] or start)


def hits(finding, entry, tolerance):
    for path, start, end in locations(finding):
        for site in entry["sites"]:
            same_file = path == site["file"] or path.endswith("/" + site["file"])
            if same_file and start - tolerance <= site["line"] <= end + tolerance:
                return True
    return False


def score(findings_doc, truth):
    tolerance = truth["line_tolerance"]
    findings = [f for f in findings_doc.get("findings", [])
                if (f.get("validation") or {}).get("verdict") not in EXCLUDED]
    cases, matched_ids = [], set()
    for case in truth["cases"]:
        found = [f for f in findings if hits(f, case, tolerance)]
        matched_ids.update(f["id"] for f in found)
        cases.append({"id": case["id"], "title": case["title"], "detected": bool(found),
                      "step_correct": any(f.get("step") in case["steps"] for f in found),
                      "findings": [f["id"] for f in found]})
    decoys = []
    for decoy in truth["decoys"]:
        found = [f["id"] for f in findings if f["id"] not in matched_ids and hits(f, decoy, tolerance)]
        decoys.append({"id": decoy["id"], "title": decoy["title"], "flagged_by": found})
    flagged = {fid for d in decoys for fid in d["flagged_by"]}
    unseeded = [{"id": f["id"], "step": f.get("step"), "title": f.get("title"), "location": f.get("location")}
                for f in findings if f["id"] not in matched_ids and f["id"] not in flagged]
    detected = sum(c["detected"] for c in cases)
    return {
        "recall": round(detected / len(cases), 3),
        "detected": detected,
        "cases": len(cases),
        "step_correct": sum(c["step_correct"] for c in cases),
        "decoys_flagged": sum(bool(d["flagged_by"]) for d in decoys),
        "decoys": len(decoys),
        "findings": len(findings),
        "case_results": cases,
        "decoy_results": decoys,
        "unseeded": unseeded,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("findings")
    parser.add_argument("--truth", default="ground-truth.json", help="file name under benchmarks/")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    result = score(json.loads(Path(args.findings).read_text(encoding="utf-8")), load_truth(HERE / args.truth))
    if not args.json:
        for case in result["case_results"]:
            mark = "HIT " if case["detected"] else "MISS"
            print(f"{mark} {case['id']} {case['title']} {' '.join(case['findings'])}")
        for decoy in result["decoy_results"]:
            if decoy["flagged_by"]:
                print(f"FP   {decoy['id']} {decoy['title']} {' '.join(decoy['flagged_by'])}")
        for item in result["unseeded"]:
            print(f"??   {item['id']} {item['step']} {item['title']}")
        print(f"recall {result['detected']}/{result['cases']}  step-correct {result['step_correct']}  "
              f"decoys flagged {result['decoys_flagged']}/{result['decoys']}  unseeded {len(result['unseeded'])}")
    else:
        json.dump(result, sys.stdout, ensure_ascii=False, indent=2)
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
