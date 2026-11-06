#!/usr/bin/env python3
"""Check a finished run against the bug-scan contract. Exit 1 lists every violation.

    contract_check.py <out> [--repo <checkout>] [--no-pdf] [--allow NAME]

It checks shape and consistency, not whether a finding is true. Standard library only.
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import LOCATION, RecordError, as_list, load_json  # noqa: E402
from findings import closed, contract_errors, excluded  # noqa: E402
import render  # noqa: E402

REQUIRED = ("findings.json", "surfaces.json", "history.json", "dashboard.html", "report.html")


def location_errors(record, repo):
    errors = []
    root = Path(repo).resolve()
    if not root.is_dir():
        return [f"--repo {repo} is not a directory"]
    for finding in record.get("findings", []):
        if excluded(finding) or closed(finding):
            continue
        cited = as_list(finding.get("location")) + [s["location"] for s in finding.get("sibling_sites", [])]
        for location in cited:
            match = LOCATION.match(location)
            path = (root / match.group("path")).resolve()
            try:
                path.relative_to(root)
            except ValueError:
                errors.append(f"{finding['id']}: {location} is outside the checkout")
                continue
            if not path.is_file():
                errors.append(f"{finding['id']}: {location} does not exist in the checkout")
                continue
            with open(path, "rb") as handle:
                count = sum(1 for _ in handle)
            if int(match.group("end") or match.group("line")) > count:
                errors.append(f"{finding['id']}: {location} is past the end of the file ({count} lines)")
    return errors


def check(out, repo=None, no_pdf=False, allow=()):
    out = Path(out)
    errors = []
    expected = set(REQUIRED) | set(allow) | ({"report.pdf"} if not no_pdf else set())
    present = {p.name for p in out.iterdir()} if out.is_dir() else set()
    for name in sorted(expected - present):
        errors.append(f"missing {name}")
    for name in sorted(present - expected):
        if name != ".findings.lock":
            errors.append(f"unexpected {name}; use --allow to keep it")
    if any(name not in present for name in REQUIRED[:3]):
        return errors
    try:
        record = load_json(out / "findings.json")
        surfaces = load_json(out / "surfaces.json")
        history = load_json(out / "history.json")
    except RecordError as error:
        return errors + [str(error)]
    errors.extend(contract_errors(record, surfaces, history))
    if repo:
        errors.extend(location_errors(record, repo))
    if no_pdf and not any("report.pdf" in line for line in record.get("limitations", [])):
        errors.append("limitations: --no-pdf needs the limitation 'report.pdf not produced: <reason>'")
    if "report.pdf" in present and not no_pdf:
        with open(out / "report.pdf", "rb") as handle:
            if handle.read(5) != b"%PDF-":
                errors.append("report.pdf is not a PDF")
    lang = record.get("meta", {}).get("lang")
    if lang in ("ja", "en") and not errors:
        dashboard, document = render.build(record, surfaces, history, lang)
        for name, text in (("dashboard.html", dashboard), ("report.html", document)):
            if name in present and (out / name).read_text(encoding="utf-8") != text:
                errors.append(f"{name} does not match a fresh render of findings.json; render again after the last merge")
    return errors


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("out")
    parser.add_argument("--repo", help="a checkout of the assessed revision; cited files and lines must exist in it")
    parser.add_argument("--no-pdf", action="store_true")
    parser.add_argument("--allow", action="append", default=[], metavar="NAME")
    args = parser.parse_args(argv)
    try:
        errors = check(args.out, args.repo, args.no_pdf, args.allow)
    except (RecordError, OSError) as error:
        errors = [str(error)]
    for line in errors:
        print(line, file=sys.stderr)
    if errors:
        print(f"contract_check.py: {len(errors)} violation(s)", file=sys.stderr)
        return 1
    print("contract ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
