#!/usr/bin/env python3
"""Check a finished review against the run contract in SKILL.md.

    python3 contract_check.py OUT_DIR [--no-pdf] [--allow NAME ...]

OUT_DIR holds findings.json and the rendered outputs. Checks the output file
set, ID scheme, where L-* findings come from, the fields every F-* finding
carries, perspective coverage, the limitations the contract requires, and that
each rendered page was rendered from the current findings.json. It checks shape
and provenance markers only; it cannot tell whether a finding is true.

Exit codes: 0 contract holds, 1 violations listed on stderr, 2 unreadable input.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import render  # noqa: E402

SKILL = Path(__file__).resolve().parents[1]
OUTPUTS = {"findings.json", "inventory.json", "dashboard.html", "report.html", "report.pdf"}
RENDERED = ("dashboard.html", "report.html")
CODE_ID = re.compile(r"F-([0-9]{3})")
REQUIRED_TEXT = ("symptom", "cause", "impact", "fix")
NO_PDF = "report.pdf not produced: no PDF engine"
NO_EVAL = "model behaviour not executed: static review only"
STAMP = re.compile(rb'<meta name="prompt-scan-source" content="sha256:([0-9a-f]{64})">')


def perspective_names():
    """Canonical names, from the first table in reference/perspectives.md."""
    names, in_table = [], False
    for line in (SKILL / "reference" / "perspectives.md").read_text(encoding="utf-8").splitlines():
        if not line.startswith("|"):
            if names:
                break
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if cells[0] == "Perspective":
            in_table = True
        elif in_table and not set(cells[0]) <= set("-: "):
            names.append(cells[0])
    return names


def stamp_problems(directory, digest, label):
    problems = []
    for name in RENDERED:
        page = directory / name
        if not page.is_file():
            continue
        m = STAMP.search(page.read_bytes()[:4096])
        if not m:
            problems.append(f"{label}{name} has no prompt-scan source stamp; re-render it with render.py")
        elif m.group(1).decode() != digest:
            problems.append(f"{label}{name} was rendered from an older findings.json; re-render after the last merge")
    return problems


def check(out, no_pdf=False, allow=()):
    problems = []
    raw = (out / "findings.json").read_bytes()
    data = render.load(out / "findings.json", raw)
    digest = hashlib.sha256(raw).hexdigest()

    present = {p.name for p in out.iterdir()}
    expected = OUTPUTS - ({"report.pdf"} if no_pdf else set())
    for name in sorted(expected - present):
        problems.append(f"missing output {name}")
    for name in sorted(present - OUTPUTS - set(allow)):
        problems.append(f"unexpected file {name} in the output directory (contract_check.py --allow {name} if asked for)")
    if no_pdf and "report.pdf" in present:
        problems.append("--no-pdf given but report.pdf exists")
    problems += stamp_problems(out, digest, "")
    for name in allow:
        if (out / name).is_dir():
            problems += stamp_problems(out / name, digest, f"{name}/")

    if (out / "inventory.json").is_file():
        try:
            inventory = json.loads((out / "inventory.json").read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            problems.append(f"inventory.json is unreadable: {e}")
            inventory = {}
        if inventory.get("tool") != "inventory.py":
            problems.append("inventory.json was not written by inventory.py")
        elif inventory.get("prompt_files") and not data.get("prompts"):
            problems.append("inventory.json lists prompt files but findings.json records no prompts")

    meta = data.get("meta", {})
    for key in ("target", "date", "assessor"):
        if not str(meta.get(key) or "").strip():
            problems.append(f"meta.{key} is missing")
    if "commit" not in meta:
        problems.append("meta.commit is missing: run inventory.py <repo> --into <out>/findings.json")

    findings = data.get("findings", [])
    code = [f for f in findings if f["id"].startswith("F-")]
    numbers = sorted(int(CODE_ID.fullmatch(f["id"]).group(1)) for f in code)
    if numbers != list(range(1, len(code) + 1)):
        problems.append(f"F-* ids must run F-001..F-{len(code):03d} without gaps")
    active = sorted((f for f in code if f["validation"]["verdict"] not in render.EXCLUDED), key=lambda f: f["id"])
    ranks = [render.SEVERITIES.index(f["severity"]) for f in active]
    if ranks != sorted(ranks):
        problems.append("F-* ids are not in severity order (excluded findings are exempt)")
    for f in findings:
        if f["id"].startswith("L-") and f.get("source") != "inventory.py":
            problems.append(f"{f['id']}: L-* findings come only from inventory.py --into")

    canonical = perspective_names()
    has_prompts = bool(data.get("prompts"))
    for f in code:
        ident = f["id"]
        for key in REQUIRED_TEXT:
            if not str(f.get(key) or "").strip():
                problems.append(f"{ident}: {key} is missing")
        test = f.get("test")
        if not (test.strip() if isinstance(test, str) else any(str(t).strip() for t in test or [])):
            problems.append(f"{ident}: test (an eval or test assertion of the good outcome) is missing")
        if not render.LOC_RE.match(f["location"]):
            problems.append(f"{ident}: location must be path:line")
        if f["kind"] == "improvement" and not str((f.get("proposal") or {}).get("after") or "").strip():
            problems.append(f"{ident}: an improvement needs proposal.after")
        if has_prompts and not f.get("prompt"):
            problems.append(f"{ident}: prompt (the P-NN it affects) is missing")
        if f["category"] not in canonical:
            problems.append(f"{ident}: category {f['category']!r} is not a perspective name")
        if f["severity"] in ("High", "Medium") and not str(f["validation"].get("evidence") or "").strip():
            problems.append(f"{ident}: a {f['severity']} finding needs validation.evidence")

    recorded = [p["name"] for p in data.get("perspectives", [])]
    for name in canonical:
        if recorded.count(name) != 1:
            problems.append(f"perspective {name!r} must be recorded exactly once (applied, N/A or not checked)")
    for name in sorted(set(recorded) - set(canonical)):
        problems.append(f"unknown perspective {name!r}")
    for p in data.get("perspectives", []):
        if p["result"] != "applied" and not str(p.get("note") or "").strip():
            problems.append(f"perspective {p['name']!r} is {p['result']} without a reason in note")

    limitations = data.get("limitations", [])
    has_line = lambda text: any(text in line for line in limitations)  # noqa: E731
    if data.get("eval_runs"):
        if has_line(NO_EVAL):
            problems.append(f"eval_runs are recorded, so drop the limitation {NO_EVAL!r}")
    elif not has_line(NO_EVAL):
        problems.append(f"no eval_runs: limitations must say {NO_EVAL!r}")
    if no_pdf and not has_line(NO_PDF):
        problems.append(f"--no-pdf: limitations must say {NO_PDF!r}")
    if not no_pdf and has_line(NO_PDF):
        problems.append(f"report.pdf is expected, so drop the limitation {NO_PDF!r}")
    return problems


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("out", type=Path)
    p.add_argument("--no-pdf", action="store_true")
    p.add_argument("--allow", action="append", default=[], metavar="NAME")
    a = p.parse_args(argv)
    try:
        problems = check(a.out, a.no_pdf, a.allow)
    except (render.SchemaError, OSError) as e:
        print(f"contract_check.py: {e}", file=sys.stderr)
        return 2
    if problems:
        print("\n".join(problems), file=sys.stderr)
        return 1
    print(f"contract ok - {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
