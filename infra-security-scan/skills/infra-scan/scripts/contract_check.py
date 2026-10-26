#!/usr/bin/env python3
"""Check a finished scan against the run contract in SKILL.md.

    python3 contract_check.py OUT_DIR [--no-pdf] [--allow NAME ...]

OUT_DIR holds findings.json and the rendered outputs. The check covers shape
and provenance only: schema, ID scheme and order, the fields every F-* finding
carries, a verdict other than `Unverified` on every finding, every perspective
recorded once, references that name existing records, the merge gate's
credential and exploit-string checks over the whole record, I-* findings and
meta.commit and the inventory identical to iac.json, and the exact output file set, each output
nonempty and of its kind (HTML, iac_scan JSON, %PDF), with both HTML reports
rendered from this findings.json. It cannot tell whether a finding is true.

Exit codes: 0 contract holds, 1 violations listed on stderr, 2 unreadable input.
"""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import findings as record_gate  # noqa: E402
import render  # noqa: E402
from common import REVIEW_FIELDS, STATE_OR_VARS, inventory, reviewer_fields  # noqa: E402

OUTPUTS = {"findings.json", "iac.json", "dashboard.html", "assessment.html", "assessment.pdf"}
F_ID = render.F_ID
FORBIDDEN = STATE_OR_VARS


def output_problem(path):
    """Catch placeholders: an output must hold what its producer writes."""
    if path.is_symlink() or not path.is_file():
        return "is not a regular file"
    if path.stat().st_size == 0:
        return "is empty"
    if path.name == "assessment.pdf":
        with path.open("rb") as fh:
            if fh.read(5) != b"%PDF-":
                return "is not a PDF"
    elif path.name == "iac.json":
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, ValueError, RecursionError):
            return "is not valid JSON"
        if not isinstance(doc, dict) or doc.get("tool") != "iac_scan" or not isinstance(doc.get("findings"), list):
            return "was not written by iac_scan.py --out"
    elif path.suffix == ".html":
        with path.open("rb") as fh:
            if not fh.read(64).lstrip().lower().startswith(b"<!doctype html"):
                return "is not an HTML report written by render.py"
    return None


def baseline_problems(data, iac_path):
    """Every I-* must be the one iac_scan.py wrote with this inventory, and no more."""
    try:
        iac = json.loads(iac_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError, RecursionError):
        return []  # reported by output_problem
    if not isinstance(iac, dict) or not isinstance(iac.get("findings"), list):
        return []

    def key(f):
        # Everything the scanner wrote; the fields a fragment may set are the reviewer's.
        return json.dumps({k: v for k, v in f.items() if k not in REVIEW_FIELDS}, sort_keys=True, default=str)
    record = {str(f.get("id")): key(f) for f in data.get("findings", [])
              if isinstance(f, dict) and str(f.get("id", "")).startswith("I-")}
    scanned = {str(f.get("id")): key(f) for f in iac["findings"] if isinstance(f, dict)}
    problems = []
    if record != scanned:
        ids = sorted({i for i in record.keys() | scanned.keys() if record.get(i) != scanned.get(i)},
                     key=lambda i: render.id_key(i) if render.I_ID.match(i) else ("", 0))
        problems.append(f"I-*: differ from iac.json ({', '.join(map(str, ids[:10]))}); I-* come only from one "
                        "iac_scan.py run with both --out and --into")
    if all(isinstance(iac.get(k), list) for k in ("resources", "files", "not_run")):
        expected = inventory(iac["resources"], iac["files"], iac["not_run"])
        held = data.get("inventory") if isinstance(data.get("inventory"), dict) else {}
        differ = [k for k in expected if held.get(k) != expected[k]]
        if differ:
            problems.append(f"inventory: differs from iac.json ({', '.join(differ)}); "
                            "rerun iac_scan.py with both --out and --into")
    meta = data.get("meta") if isinstance(data.get("meta"), dict) else {}
    if iac.get("commit") is not None and meta.get("commit") != iac.get("commit"):
        problems.append("meta.commit: differs from iac.json; rerun iac_scan.py with both --out and --into")
    return problems


def check(data, out_dir, pdf=True, allow=()):
    problems = []
    add = problems.append
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
    # Ties keep ID order: two findings at one location may take either ID.
    expected = sorted(fs, key=lambda f: (render.SEV_RANK.get(str(f.get("severity")), 9),
                                         render.location_key(f.get("location")), render.id_key(f["id"])))
    if [f["id"] for f in expected] != [f["id"] for f in by_id]:
        add("F-*: IDs must follow severity order (High, Medium, Low, Info), then location; expected "
            + ", ".join(f"{f['id']}={f.get('severity')}@{f.get('location')}" for f in expected))
    # Required fields, verdicts, ID shapes and path statuses are schema checks
    # (render.validate above); only what the schema cannot see follows.
    # "Done when" requires a verdict on every finding; Unverified means not
    # triaged (I-*) or reopened by a rescan (F-*).
    unverified = [str(f.get("id")) for f in render.untriaged(data)]
    if unverified:
        add(f"findings: {len(unverified)} still Unverified; triage or recheck each one "
            f"(reference/validation.md): {', '.join(unverified)}")

    names = render.perspective_names()
    recorded = [p.get("name") for p in data.get("perspectives", []) if isinstance(p, dict)]
    for name in names:
        n = recorded.count(name)
        if n != 1:
            add(f"perspectives: {name!r} recorded {n} times; every perspective exactly once")
    for where, rid in render.dangling_references(data):
        add(f"{where}: names {rid}, which no finding or attack path has (renumbered or removed?)")
    if not isinstance(data.get("inventory"), dict):
        add("inventory: missing; run iac_scan.py <repo> --out <out>/iac.json --into <out>/findings.json "
            "(both in one run)")
    # The merge gate, over the whole record: it may have been written by hand.
    problems += [f"record: {p}" for p in record_gate.credential_problems(data, "findings.json")]
    # An I-* is the scanner's words about the configuration (titles, details
    # and resource addresses quote its values); only its triage is a fragment's.
    written = {**data, "findings": [reviewer_fields(f) for f in data.get("findings", []) if isinstance(f, dict)]}
    problems += [f"record: {p}" for p in record_gate.payload_problems(written, "findings.json")]
    problems += baseline_problems(data, Path(out_dir) / "iac.json")

    out = Path(out_dir)
    required = OUTPUTS - (set() if pdf else {"assessment.pdf"})
    present = {p.name for p in out.iterdir()}
    for name in sorted(required - present):
        add(f"outputs: {name} missing")
    digest = render.record_digest(data)
    for name in sorted(required & present):
        problem = output_problem(out / name)
        if problem:
            add(f"outputs: {name} {problem}")
        elif name.endswith(".html"):
            stamp = render.RECORD_STAMP.search((out / name).read_text(encoding="utf-8", errors="replace"))
            if not stamp or stamp.group(1) != digest:
                add(f"outputs: {name} was not rendered from this findings.json; re-render with render.py")
    if not pdf and "assessment.pdf" in present:
        # render.py --no-pdf removes it: this one is stale or a placeholder.
        add("outputs: assessment.pdf is present although --no-pdf; re-render with render.py --no-pdf")
    for name in sorted(present - OUTPUTS - set(allow)):
        add(f"outputs: unexpected {name} (pass --allow {name} if the requester asked for it)")
    for p in out.rglob("*"):
        if FORBIDDEN.search(p.name):
            add(f"outputs: {p.relative_to(out)} is a state or variable file; never copy it into the output")
    return problems


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
        data = render.load_record(out / "findings.json")
    except render.SchemaError as e:
        print(f"unreadable: {e}", file=sys.stderr)
        return 2
    problems = check(data, out, pdf=not a.no_pdf, allow=a.allow)
    if problems:
        for problem in problems:
            print(problem, file=sys.stderr)
        return 1
    print(f"contract ok - {len(data.get('findings', []))} findings, {len(data.get('attack_paths', []))} attack paths")
    return 0


if __name__ == "__main__":
    sys.exit(main())
