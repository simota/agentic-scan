#!/usr/bin/env python3
"""Turn another *-scan's findings.json into a fragment that overlays it on this run's figures.

    import_findings.py <other>/findings.json --scan security-scan --out <scratch>/import.json

Run this only when the requester names the other assessment. Only the fields every findings-type
scan shares are read, and nothing is regraded. IDs repeat across scans (F-001, P-001), so an import
is keyed `<scan>:<id>`. Excluded verdicts are left out. Standard library only.
"""
import argparse
import re
import sys

from common import EXCLUDED, LOCATION, RecordError, SEVERITIES, as_list, clean, load_json, write_json

SCAN = re.compile(r"^[a-z0-9][a-z0-9-]*$")


def to_fragment(data, scan):
    if not SCAN.match(scan):
        raise RecordError(f"--scan {scan!r}: use the scan's name, such as security-scan")
    findings = data.get("findings") if isinstance(data, dict) else None
    if not isinstance(findings, list):
        raise RecordError("the input has no findings list; only findings-type scans can be imported")
    imports = []
    skipped = 0
    for finding in findings:
        if not isinstance(finding, dict) or (finding.get("validation") or {}).get("verdict") in EXCLUDED:
            skipped += 1
            continue
        if finding.get("severity") not in SEVERITIES or not finding.get("id") or not finding.get("title"):
            raise RecordError(f"{finding.get('id')}: id, title and severity are required to import a finding")
        locations = [str(item) for item in as_list(finding.get("location")) if LOCATION.match(str(item))]
        entry = dict(key=f"{scan}:{finding['id']}", scan=scan, title=clean(finding["title"]), severity=finding["severity"], location=locations)
        if finding.get("impact"):
            entry["impact"] = clean(finding["impact"])
        imports.append(entry)
    return dict(imports=imports), skipped


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("findings")
    parser.add_argument("--scan", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    try:
        fragment, skipped = to_fragment(load_json(args.findings), args.scan)
        write_json(args.out, fragment)
    except RecordError as error:
        print(f"import_findings.py: {error}", file=sys.stderr)
        return 2
    print(f"wrote {args.out}: {len(fragment['imports'])} imported, {skipped} excluded records left out")
    return 0


if __name__ == "__main__":
    sys.exit(main())
