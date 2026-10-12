#!/usr/bin/env python3
"""Check a prune-scan output directory against the run contract (SKILL.md).

    python3 contract_check.py OUT [--no-pdf] [--allow NAME]...

Passes when OUT holds exactly findings.json, units.json, inventory.json,
dashboard.html, report.html and report.pdf (no PDF with --no-pdf, which then
requires the "report.pdf not produced" limitation); the record and units are
valid; every perspective family is recorded in perspectives; no finding is
left Unverified; every open Purpose-dependent finding is named in decisions;
and both pages carry the SHA-256 of the current findings.json and units.json.
Exit status: 0 ok, 1 contract not met (each problem on stderr), 2 bad arguments.
"""

import argparse
import hashlib
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from findings import (EXCLUDED, FAMILIES, FINDING_REF, RecordError, check_findings,  # noqa: E402
                      check_units, parse_json, read_json_source)
from render import STAMP, UNITS_STAMP, pdf_complete  # noqa: E402

REQUIRED = ("findings.json", "units.json", "inventory.json", "dashboard.html", "report.html")
NO_PDF = "report.pdf not produced"


def rendered_lang(out):
    """The language the existing pages were rendered in, so a re-render keeps it."""
    for name in ("report.html", "dashboard.html"):
        try:
            path = out / name
            if path.is_symlink() or not path.is_file():
                continue
            m = re.search(r'<html lang="(ja|en)"', path.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
        if m:
            return m.group(1)
    return "<ja|en>"


def problems(out, no_pdf=False, allow=()):
    out = Path(out)
    try:
        found = {p.name for p in out.iterdir()} if out.is_dir() else set()
    except OSError as e:
        yield f"{out}: cannot inspect directory: {e.strerror or e}"
        return
    expected = set(REQUIRED) | ({"report.pdf"} if not no_pdf else set())
    rerender = (f"render.py {out}/findings.json --out {out} --lang {rendered_lang(out)} --repo <repo>"
                + (" --no-pdf" if no_pdf else ""))
    for name in sorted(expected - found):
        hint = {"findings.json": "merge fragments with findings.py merge",
                "units.json": "write the purpose, entry points, consumers and units with findings.py units",
                "inventory.json": f"run inventory.py <repo> --units {out}/units.json --out {out}/inventory.json",
                "report.pdf": "render where Chrome works, or follow the no-PDF path in SKILL.md"}.get(
                    name, f"run {rerender}")
        yield f"{name}: missing; {hint}"
    for name in sorted(found - expected - set(allow)):
        yield f"{name}: not part of the contract (contract_check.py --allow {name} if it was asked for)"
    regular = set()
    for name in sorted(found & expected):
        path = out / name
        try:
            if path.is_symlink() or not path.is_file():
                yield f"{name}: must be a regular file"
            else:
                regular.add(name)
        except OSError as e:
            yield f"{name}: cannot inspect file: {e.strerror or e}"
    if "findings.json" not in regular:
        return
    try:
        source = read_json_source(out / "findings.json")
        units = None
        units_source = None
        if "units.json" in regular:
            units_source = read_json_source(out / "units.json")
            units = check_units(parse_json(units_source, "units.json"))
        data = check_findings(parse_json(source, "findings.json"), units)
    except (OSError, ValueError, RecordError) as e:
        yield f"record: {e}"
        return
    recorded = {p["name"][:2] for p in data.get("perspectives", [])}
    missing = [f for f in FAMILIES if f not in recorded]
    if missing:
        yield (f"perspectives: no entry for {', '.join(missing)}; record each family as applied, "
               "N/A with the reason, or not checked")
    unfinished = [p["name"] for p in data.get("perspectives", []) if not p.get("result", "").strip()]
    if unfinished:
        yield (f"perspectives: no result for {', '.join(unfinished)}; record applied, "
               "N/A with the reason, or not checked")
    unverified = [f["id"] for f in data["findings"] if f["validation"]["verdict"] == "Unverified"]
    if unverified:
        yield f"findings: {', '.join(unverified)} still Unverified; settle the verdict in VERIFY"
    decisions = set(FINDING_REF.findall("\n".join(data.get("decisions", []))))
    undecided = [f["id"] for f in data["findings"] if f["confidence"] == "Purpose-dependent" and f["status"] == "Open"
                 and f["validation"]["verdict"] not in EXCLUDED and f["id"] not in decisions]
    if undecided:
        yield (f"decisions: {', '.join(undecided)} rest on an inferred purpose; name each in a decisions line "
               "so a human makes the keep or remove call")
    if "inventory.json" in regular:
        try:
            inventory = parse_json(read_json_source(out / "inventory.json"), "inventory.json")
            if not isinstance(inventory, dict) or inventory.get("tool") != "inventory.py":
                yield "inventory.json: not written by inventory.py"
        except (ValueError, RecordError) as e:
            yield f"inventory.json: not valid JSON: {e}"
        except OSError as e:
            yield f"inventory.json: cannot read file: {e.strerror or e}"
    digests = {STAMP: "sha256:" + hashlib.sha256(source).hexdigest()}
    if units_source is not None:
        digests[UNITS_STAMP] = "sha256:" + hashlib.sha256(units_source).hexdigest()
    for name in ("dashboard.html", "report.html"):
        if name not in regular:
            continue
        try:
            page = (out / name).read_text(encoding="utf-8")
        except (OSError, UnicodeError) as e:
            yield f"{name}: cannot read file: {e}"
            continue
        for stamp, digest in digests.items():
            m = re.search(r'<meta name="%s" content="([^"]+)">' % stamp, page)
            if not m or m.group(1) != digest:
                yield f"{name}: stale; re-render after the last findings or units change ({rerender})"
                break
    if "report.pdf" in regular and not pdf_complete(out / "report.pdf"):
        yield "report.pdf: empty, invalid or incomplete; re-render the PDF"
    pdf_limitations = [line for line in data.get("limitations", []) if line.startswith(NO_PDF)]
    limited = any(re.match(re.escape(NO_PDF) + r":\s*\S", line) for line in pdf_limitations)
    if no_pdf and not limited:
        yield f"limitations: --no-pdf needs the line '{NO_PDF}: <reason>'"
    if not no_pdf and pdf_limitations:
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
