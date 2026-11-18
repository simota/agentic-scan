"""Read a checked findings.json (with the flows.json beside it) and write a derived file
that can never replace the record, its pages or its evidence.

export.py and compare.py build on it. Standard library only.
"""

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from report_output import unsafe_target, write_output  # noqa: E402
from findings import EXCLUDED, SEVERITIES, RecordError, check_findings, check_flows, flow_ids, load_json  # noqa: E402
from evidence import DIRECTORY, PAGE as EVIDENCE_PAGE  # noqa: E402
from mockups import PAGE as MOCKUPS_PAGE  # noqa: E402

# Everything a review directory holds by contract (SKILL.md *Outputs*); a derived file never replaces one.
RECORD_OUTPUTS = ("findings.json", "flows.json", "inventory.json", "dashboard.html", "report.html", "report.pdf",
                  MOCKUPS_PAGE, EVIDENCE_PAGE, ".ux-scan-render-generation", ".ux-scan-render.lock",
                  ".ux-scan-records.lock", DIRECTORY)
SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}


def load_record(path):
    """(findings, flows or None) from a findings.json that passes findings.py check.

    The flows beside it are read when present, so flow names can be shown; numbering order is not
    required, as merge leaves it until renumber."""
    path = Path(path)
    flows_path = path.with_name("flows.json")
    flows = None
    if flows_path.exists() or flows_path.is_symlink():
        flows = check_flows(load_json(flows_path, record=True))
    data = check_findings(load_json(path, record=True), flow_ids(flows) if flows else None, ordered=False)
    return data, flows


def counted(finding):
    """Whether a finding counts: FalsePositive and NotApplicable are excluded from every count."""
    return finding["validation"]["verdict"] not in EXCLUDED


def at_least(finding, severity):
    return SEVERITY_RANK[finding["severity"]] <= SEVERITY_RANK[severity]


def flow_label(finding, flows):
    """'FL-02: Manage tasks (primary)', or the bare id without flows.json."""
    for flow in (flows or {}).get("flows", []):
        if flow["id"] == finding["flow_ref"]:
            return f"{flow['id']}: {flow['name']} ({flow['priority']})"
    return finding["flow_ref"]


def split_location(location):
    """('src/a.tsx', 15, 18) from 'src/a.tsx:15-18'; the end equals the start for one line."""
    path, _, lines = location.rpartition(":")
    start, _, end = lines.partition("-")
    return path, int(start), int(end or start)


def code(text):
    """text as one Markdown code span, whatever backticks it holds."""
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    fence = "`" * (longest + 1)
    pad = " " if text.startswith("`") or text.endswith("`") else ""
    return f"{fence}{pad}{text}{pad}{fence}"


def write_derived(out, text, inputs):
    """Write text to out ('-' is stdout), atomically and never over a record file, an input or a link."""
    if out == "-":
        sys.stdout.write(text)
        return None
    target = Path(out)
    if not target.parent.is_dir():
        raise RecordError(f"{target.parent}: output directory does not exist")
    if not target.name or target.name in (".", ".."):
        raise RecordError(f"{out}: expected a file name")
    for source in inputs:
        source = Path(source)
        if target.resolve() == source.resolve() or (target.exists() and source.exists() and target.samefile(source)):
            raise RecordError(f"{target}: output must be different from every input")
        record_dir = source.resolve().parent
        if target.resolve().parent == record_dir and target.name in RECORD_OUTPUTS:
            raise RecordError(f"{target}: refusing to replace a review output; write it elsewhere")
        if (record_dir / DIRECTORY).resolve() in target.resolve().parents:
            raise RecordError(f"{target}: evidence/ holds exactly the cited files; write it elsewhere")
    if unsafe_target(target.parent, (target.name,)) is not None:
        raise RecordError(f"refusing to write {target}: it exists as a symlink or non-regular file")
    write_output(target, text)
    return target


def allow_note(target, inputs):
    """The contract-checker hint when a derived file lands inside a review directory."""
    if target is None:
        return ""
    for source in inputs:
        if target.resolve().parent == Path(source).resolve().parent:
            return f" (inside the review directory: pass --allow {target.name} to contract_check.py)"
    return ""
