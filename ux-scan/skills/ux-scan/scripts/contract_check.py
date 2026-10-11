#!/usr/bin/env python3
"""Check a ux-scan output directory against the run contract (SKILL.md).

    python3 contract_check.py OUT [--no-pdf] [--allow NAME]...

Passes when OUT holds exactly findings.json, flows.json, inventory.json,
dashboard.html, report.html and report.pdf (no PDF with --no-pdf, which then
requires the "report.pdf not produced" limitation); the record and flows are
valid; every perspective family is recorded in perspectives; no finding is
left Unverified; and both pages carry the SHA-256 of the current findings.json.
Exit status: 0 ok, 1 contract not met (each problem on stderr), 2 bad arguments.
"""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from findings import FAMILIES, RecordError, check_findings, check_flows, flow_ids  # noqa: E402
from render import STAMP  # noqa: E402

REQUIRED = ("findings.json", "flows.json", "inventory.json", "dashboard.html", "report.html")
NO_PDF = "report.pdf not produced"


def rendered_lang(out):
    """The language the existing pages were rendered in, so a re-render keeps it."""
    for name in ("report.html", "dashboard.html"):
        try:
            m = re.search(r'<html lang="([a-z]{2})"', (out / name).read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
        if m:
            return m.group(1)
    return "<ja|en>"


def problems(out, no_pdf=False, allow=()):
    out = Path(out)
    found = {p.name for p in out.iterdir()} if out.is_dir() else set()
    expected = set(REQUIRED) | ({"report.pdf"} if not no_pdf else set())
    rerender = (f"render.py {out}/findings.json --out {out} --lang {rendered_lang(out)} --repo <repo>"
                + (" --no-pdf" if no_pdf else ""))
    for name in sorted(expected - found):
        hint = {"findings.json": "merge fragments with findings.py merge",
                "flows.json": "write the flows with findings.py flows",
                "inventory.json": f"run inventory.py <repo> --flows {out}/flows.json --out {out}/inventory.json",
                "report.pdf": "render where Chrome works, or follow the no-PDF path in SKILL.md"}.get(
                    name, f"run {rerender}")
        yield f"{name}: missing; {hint}"
    for name in sorted(found - expected - set(allow)):
        yield f"{name}: not part of the contract (contract_check.py --allow {name} if it was asked for)"
    for name in found & expected:
        path = out / name
        if path.is_symlink() or not path.is_file():
            yield f"{name}: must be a regular file"
    if "findings.json" not in found:
        return
    source = (out / "findings.json").read_bytes()
    try:
        ids = None
        if "flows.json" in found:
            ids = flow_ids(check_flows(json.loads((out / "flows.json").read_text(encoding="utf-8"))))
        data = check_findings(json.loads(source.decode("utf-8")), ids)
    except (ValueError, RecordError) as e:
        yield f"record: {e}"
        return
    recorded = {p["name"][:2] for p in data.get("perspectives", [])}
    missing = [f for f in FAMILIES if f not in recorded]
    if missing:
        yield (f"perspectives: no entry for {', '.join(missing)}; record each family as applied, "
               "N/A with the reason, or not checked")
    unverified = [f["id"] for f in data["findings"] if f["validation"]["verdict"] == "Unverified"]
    if unverified:
        yield f"findings: {', '.join(unverified)} still Unverified; settle the verdict in VERIFY"
    if "inventory.json" in found:
        try:
            if json.loads((out / "inventory.json").read_text(encoding="utf-8")).get("tool") != "inventory.py":
                yield "inventory.json: not written by inventory.py"
        except ValueError:
            yield "inventory.json: not valid JSON"
    digest = "sha256:" + hashlib.sha256(source).hexdigest()
    for name in ("dashboard.html", "report.html"):
        if name in found:
            page = (out / name).read_text(encoding="utf-8", errors="replace")
            m = re.search(r'<meta name="%s" content="([^"]+)">' % STAMP, page)
            if not m or m.group(1) != digest:
                yield f"{name}: stale; re-render after the last merge ({rerender})"
    limited = any(line.startswith(NO_PDF) for line in data.get("limitations", []))
    if no_pdf and not limited:
        yield f"limitations: --no-pdf needs the line '{NO_PDF}: <reason>'"
    if not no_pdf and limited:
        yield f"limitations: says '{NO_PDF}' but report.pdf is expected; remove that line"


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("out")
    p.add_argument("--no-pdf", action="store_true")
    p.add_argument("--allow", action="append", default=[])
    a = p.parse_args(argv)
    if not Path(a.out).is_dir():
        print(f"contract_check.py: {a.out} is not a directory", file=sys.stderr)
        return 2
    found = list(problems(a.out, a.no_pdf, a.allow))
    for problem in found:
        print(f"contract_check.py: {problem}", file=sys.stderr)
    if found:
        return 1
    print(f"contract ok: {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
