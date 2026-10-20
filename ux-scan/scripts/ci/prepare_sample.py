#!/usr/bin/env python3
"""Prepare validated sample records without following planted output symlinks."""
import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "skills" / "ux-scan" / "scripts"))

from findings import RecordError, check_findings, check_flows, dump, flow_ids, load_json, merge  # noqa: E402
from render import OUTPUT_GENERATION  # noqa: E402
from scan_report_kit.output import unsafe_target, write_outputs  # noqa: E402

OUTPUTS = ("flows.json", "findings.json", "inventory.json", "dashboard.html", "report.html", "report.pdf",
           "mockups.html", OUTPUT_GENERATION)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sample")
    parser.add_argument("--out", required=True)
    parser.add_argument("--no-pdf", action="store_true")
    args = parser.parse_args(argv)
    try:
        flows = check_flows(load_json(ROOT / "examples" / "flows.sample.json"))
        data = check_findings(load_json(args.sample), flow_ids(flows))
        if args.no_pdf:
            data = merge(data, load_json(ROOT / "examples" / "no-pdf.fragment.json"))
            check_findings(data, flow_ids(flows))
        out = Path(args.out)
        source = Path(args.sample).resolve()
        for name in OUTPUTS:
            target = out / name
            if source == target.resolve() or (target.exists() and source.samefile(target)):
                raise RecordError("sample input must be different from every demo output")
        if out.is_symlink():
            raise RecordError(f"{out}: output directory must not be a symlink")
        if out.resolve().is_relative_to((ROOT / "examples" / "tasklane").resolve()):
            raise RecordError("--out must be outside examples/tasklane; the reviewed repository is read-only")
        out.mkdir(parents=True, exist_ok=True)
        bad = unsafe_target(out, OUTPUTS)
        if bad:
            raise RecordError(f"{bad}: output must be a regular file, not a symlink or directory")
        write_outputs(out, {"flows.json": dump(flows), "findings.json": dump(data)})
    except (OSError, RuntimeError, RecordError) as error:
        print(f"prepare_sample.py: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
