#!/usr/bin/env python3
"""Check a finished scan against the run contract in SKILL.md.

    python3 contract_check.py OUT_DIR [--no-pdf] [--allow NAME ...]

OUT_DIR holds findings.json and the rendered outputs. The check covers shape
and provenance only: schema, ID scheme and order, the fields every F-* finding
carries, a verdict on every I-*, every perspective recorded once, the
inventory written by iac_scan.py, and the exact output file set. It cannot
tell whether a finding is true.

Exit codes: 0 contract holds, 1 violations listed on stderr, 2 unreadable input.
"""
import argparse
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import render  # noqa: E402

OUTPUTS = {"findings.json", "iac.json", "dashboard.html", "assessment.html", "assessment.pdf"}
F_ID = render.F_ID
FORBIDDEN = re.compile(r"\.tfstate(\.backup)?$|\.tfvars(\.json)?$")


def check(data, out_dir, pdf=True, allow=()):
    problems = []
    add = problems.append
    notes = []
    try:
        render.validate(data)
    except render.SchemaError as e:
        problems += [f"schema: {p}" for p in e.problems]
    findings = [f for f in data.get("findings", []) if isinstance(f, dict)]

    fs = [f for f in findings if F_ID.match(str(f.get("id", "")))]
    by_id = sorted(fs, key=lambda f: render.id_key(f["id"]))
    numbers = [int(F_ID.match(f["id"]).group(1)) for f in by_id]
    if numbers != list(range(1, len(fs) + 1)):
        add(f"F-*: IDs must run F-001..F-{len(fs):03d} without gaps; found {[f['id'] for f in by_id]}")
    expected = sorted(fs, key=lambda f: (render.SEV_RANK.get(f.get("severity"), 9), str(f.get("location", ""))))
    if [f["id"] for f in expected] != [f["id"] for f in by_id]:
        add("F-*: IDs must follow severity order (High, Medium, Low, Info), then location; expected "
            + ", ".join(f"{f['id']}={f.get('severity')}@{f.get('location')}" for f in expected))
    for f in fs:
        for key in render.F_FIELDS:
            if render.blank(f.get(key)):
                add(f"{f['id']}: {key} required")
        if not isinstance(f.get("validation"), dict) or "verdict" not in f["validation"]:
            add(f"{f['id']}: explicit validation.verdict required")
    for f in findings:
        fid = str(f.get("id", ""))
        if not (F_ID.match(fid) or render.I_ID.match(fid)):
            add(f"{fid}: only F-* and I-* IDs are allowed")
    unverified = [f["id"] for f in findings if str(f.get("id", "")).startswith("I-")
                  and f.get("validation", {}).get("verdict") == "Unverified"]
    if unverified:
        notes.append(f"{len(unverified)} I-* finding(s) still Unverified: {', '.join(unverified)}")

    names = render.perspective_names()
    recorded = [p.get("name") for p in data.get("perspectives", []) if isinstance(p, dict)]
    for name in names:
        n = recorded.count(name)
        if n != 1:
            add(f"perspectives: {name!r} recorded {n} times; every perspective exactly once")
    for a in data.get("attack_paths", []):
        if isinstance(a, dict) and a.get("status") not in render.AP_STATUSES:
            add(f"{a.get('id')}: attack path status must be open, blocked or unknown")
    if not isinstance(data.get("inventory"), dict):
        add("inventory: missing; run iac_scan.py --into findings.json")

    out = Path(out_dir)
    required = OUTPUTS - (set() if pdf else {"assessment.pdf"})
    present = {p.name for p in out.iterdir()}
    for name in sorted(required - present):
        add(f"outputs: {name} missing")
    for name in sorted(present - OUTPUTS - set(allow)):
        add(f"outputs: unexpected {name} (pass --allow {name} if the requester asked for it)")
    for p in out.rglob("*"):
        if FORBIDDEN.search(p.name):
            add(f"outputs: {p.relative_to(out)} is a state or variable file; never copy it into the output")
    return problems, notes


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("out")
    p.add_argument("--no-pdf", action="store_true", help="assessment.pdf is not required")
    p.add_argument("--allow", action="append", default=[], metavar="NAME", help="extra output file the requester asked for")
    a = p.parse_args(argv)
    out = Path(a.out)
    try:
        if not out.is_dir():
            raise render.SchemaError(f"{out}: not a directory")
        data = render.load(out / "findings.json")
    except render.SchemaError as e:
        print(f"unreadable: {e}", file=sys.stderr)
        return 2
    problems, notes = check(data, out, pdf=not a.no_pdf, allow=a.allow)
    for n in notes:
        print(f"note: {n}")
    if problems:
        for problem in problems:
            print(problem, file=sys.stderr)
        return 1
    print(f"contract ok - {len(data.get('findings', []))} findings, {len(data.get('attack_paths', []))} attack paths")
    return 0


if __name__ == "__main__":
    sys.exit(main())
