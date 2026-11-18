#!/usr/bin/env python3
"""Print the chat summary of a run from its findings.json (reference/report.md).

    python3 summary.py FINDINGS [--lang ja|en] [--scratch DIR] [--baseline OLD_FINDINGS]

The chat summary is the third delivery beside dashboard.html and report.md.
Printing it from the record keeps every count, verdict and ID in chat identical
to the record: first the status line (severity counts, review basis,
verification counts and High findings not yet Valid), then the evidence line
(revision, method, severity axis, scratch directory), one line per finding by
severity, the full block of each High finding, checked and sound items,
decisions, next steps and the rendered files beside FINDINGS.

`--baseline` adds one line with what changed since an earlier run of the same
application (`compare.py` has the full comparison). The agent adds what only it
knows, such as what it read and traced end to end, after the printed lines.
Record strings are escaped as in report.md.

Exit codes: 0 printed, 2 an input could not be read or does not match the
schema, or a usage error.
"""
import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from findings import (AXES, SEVERITIES, SchemaError, escape_unencodable_console,  # noqa: E402
                      finding_locations)
from render import (LABELS as RENDER_LABELS, counts, is_excluded, markdown_code,  # noqa: E402
                    markdown_finding, markdown_text, review_note, verification_summary)
import compare  # noqa: E402

LABELS = {
    "en": {"evidence_line": "Revision {commit} · {method}", "scratch": "scratch: {path}",
           "by_severity": "Findings by severity", "high_blocks": "High findings",
           "files": "Files", "since": "Since the baseline ({commit}, {date})",
           "since_counts": "{new} new, {resolved} resolved, {unchecked} not re-checked, "
                           "{escalated} escalated", "default_method": "Static review"},
    "ja": {"evidence_line": "リビジョン {commit} · {method}", "scratch": "スクラッチ: {path}",
           "by_severity": "深刻度別の検出事項", "high_blocks": "High の検出事項",
           "files": "ファイル", "since": "ベースライン（{commit}、{date}）から",
           "since_counts": "新規 {new}・解消 {resolved}・未再確認 {unchecked}・"
                           "深刻化 {escalated}", "default_method": "静的レビュー"},
}


def finding_line(f):
    location = finding_locations(f)
    where = markdown_code(location[0]) + (f" (+{len(location) - 1})" if len(location) > 1 else "")
    grade = (f"[{f['validation']['verdict']}]" if is_excluded(f)
             else f"[{f['severity']}][{f['confidence']}] {f['validation']['verdict']}")
    return f"- {f['id']} {grade} {markdown_text(f['title'])} — {where}"


def baseline_line(doc, baseline, s):
    result = compare.compare(baseline, doc)
    found = result["findings"]
    commit = baseline["meta"].get("commit", "").strip() or "UNKNOWN"
    counts_text = s["since_counts"].format(
        new=len(found["new"]), resolved=len(found["resolved"]),
        unchecked=len(found["unchecked"]),
        escalated=sum(1 for e in found["persisting"] if e["escalated"]))
    return (f"**{markdown_text(s['since'].format(commit=commit, date=baseline['meta']['date']))}:** "
            f"{counts_text}")


def render_summary(doc, lang, findings_path, scratch=None, baseline=None):
    t, s = RENDER_LABELS[lang], LABELS[lang]
    meta, findings = doc["meta"], doc.get("findings", [])
    by_sev, excluded = counts(findings)
    verdicts, incomplete_high = verification_summary(findings, t)
    lines = [" / ".join(f"{sev} {by_sev[sev]}" for sev in SEVERITIES)
             + f" · {t['excluded']} {excluded} · {markdown_text(meta['scope'])} · "
             + review_note(findings, t),
             "", f"{verdicts} · {incomplete_high}"]
    evidence = s["evidence_line"].format(
        commit=meta.get("commit", "").strip() or "UNKNOWN",
        method=meta.get("method", "").strip() or s["default_method"])
    if meta.get("axis") in AXES:
        evidence += f" · {t['axis']}: {t['axis_' + meta['axis']]}"
    if scratch:
        evidence += " · " + s["scratch"].format(path=scratch)
    lines += ["", markdown_text(evidence)]
    if baseline is not None:
        lines += ["", baseline_line(doc, baseline, s)]
    lines += ["", f"## {s['by_severity']}", ""]
    lines += [finding_line(f) for f in findings] or [t["none"]]
    highs = [f for f in findings if f["severity"] == "High" and not is_excluded(f)]
    if highs:
        lines += ["", f"## {s['high_blocks']}", ""]
        for f in highs:
            lines += markdown_finding(f, t)
        while lines and lines[-1] == "":
            lines.pop()
    for key in ("checked_ok", "decisions", "next_steps"):
        lines += ["", f"## {t[key]}", ""]
        lines += [f"- {markdown_text(item)}" for item in doc.get(key, [])] or [t["none"]]
    directory = Path(findings_path).parent
    rendered = [directory / name for name in ("dashboard.html", "report.md")
                if (directory / name).is_file()]
    lines += ["", f"## {s['files']}", ""]
    lines += [f"- {markdown_code(str(path))}" for path in [Path(findings_path), *rendered]]
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("findings")
    parser.add_argument("--lang", choices=("ja", "en"))
    parser.add_argument("--scratch", help="the run's scratch directory, named in the summary")
    parser.add_argument("--baseline", help="an earlier run's findings.json to compare with")
    args = parser.parse_args(argv)
    escape_unencodable_console()
    try:
        doc = compare.load(args.findings)
        baseline = compare.load(args.baseline) if args.baseline else None
    except SchemaError as exc:
        print(f"schema: {exc}", file=sys.stderr)
        return 2
    lang = args.lang or doc["meta"]["lang"]
    sys.stdout.write(render_summary(doc, lang, args.findings, args.scratch, baseline))
    return 0


if __name__ == "__main__":
    sys.exit(main())
