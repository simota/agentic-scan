#!/usr/bin/env python3
"""Draft one issue per finding from findings.json, following templates/issue.<lang>.md.

    python3 issues.py FINDINGS --out DIR [--lang ja|en] [--id P-001 ...]
                      [--min-severity High|Medium|Low|Info] [--include-accepted] [--force]

Writes DIR/P-NNN.md for every selected finding and prints one line per draft
(file, then the issue title) so the requester can file them, e.g. with
`gh issue create --title "<title>" --body-file DIR/P-001.md`. Filing stays with
the requester; this script only writes drafts.

Selection: by default every `Open` finding that is not `FalsePositive` or
`NotApplicable`. `--id` picks findings by ID (repeatable); an excluded or
`Fixed` finding is refused, since it has nothing left to fix.
`--min-severity` keeps findings at that severity or above, and
`--include-accepted` adds `Accepted` findings.

The drafts follow the template's sections in order and fill them from the
record: optional lines and sections with nothing to show are left out, the
Measurement log appears only for a recorded measurement, and Open questions
collects what the record leaves unsettled for that finding (an incomplete
verdict, an Environment-dependent condition, `decisions` and `limitations`
lines that name its ID). Record strings are escaped as in report.md, so text
from the audited repository cannot add links, mentions or markup.

DIR must not be the directory holding FINDINGS (the run contract allows only
the three outputs there): use scratch or a directory of its own. An existing
draft is kept unless `--force` is given; a refused run writes nothing.

Exit codes: 0 written, 1 a draft could not be written, 2 bad input, an unknown
or unfileable ID, an existing draft without --force, or a usage error.
"""
import argparse
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from findings import (EXCLUDED, FINDING_MENTION, MEASUREMENT_RUNS, SEVERITIES, SchemaError,  # noqa: E402
                      escape_unencodable_console, file_mode, finding_locations,
                      finding_status, read_json, resolve_path, validate, write_atomic)
from render import (block_fence, markdown_code, markdown_link, markdown_text,  # noqa: E402
                    reference_title, shown, text_lines)

LABELS = {
    "en": {
        "title": "Title", "summary": "Summary", "item": "Item", "value": "Value",
        "severity": "Severity", "confidence": "Confidence", "verdict": "Verdict",
        "method": "method", "perspective": "Perspective", "location": "Location",
        "revision": "Assessed revision", "date": "Date / assessor",
        "what_happens": "What happens", "workload": "Workload", "scale_driver": "Scale driver",
        "cost_model": "Cost model", "budget": "Violated budget",
        "reproduction": "Static reproduction",
        "contrast": "Contrast (the path that keeps the budget)",
        "evidence": "Evidence", "measurement": "Measurement log", "environment": "Environment",
        "before": "Before", "after": "After", "fix": "Fix direction",
        "regression": "Regression test asserts", "references": "References",
        "open_questions": "Open questions", "done_when": "Done when",
        "q_verdict": "The verdict is {verdict}: confirm the link named under Evidence "
                     "before relying on this finding.",
        "q_verdict_bare": "The verdict is {verdict}: trace the finding end to end before "
                          "relying on it.",
        "q_environment": "Confidence is Environment-dependent; the condition and its "
                         "threshold: {scale_driver}",
        "done": ("The fix is merged",
                 "A deterministic regression check fails before the fix and passes after it",
                 "The result of the affected path is unchanged (positive control)",
                 "`status` in findings.json is `Fixed` (`findings.py set … --status Fixed`)"),
        "paren": " ({})", "verdict_line": "{verdict} (method: {method})",
    },
    "ja": {
        "title": "タイトル", "summary": "概要", "item": "項目", "value": "値",
        "severity": "深刻度", "confidence": "確度", "verdict": "検証判定",
        "method": "検証方法", "perspective": "観点", "location": "場所",
        "revision": "対象リビジョン", "date": "診断日 / 診断者",
        "what_happens": "何が起きるか", "workload": "ワークロード", "scale_driver": "規模の要因",
        "cost_model": "コストモデル", "budget": "違反しているバジェット",
        "reproduction": "再現手順（静的）",
        "contrast": "対照（バジェットが守られている経路）",
        "evidence": "根拠", "measurement": "計測ログ", "environment": "実行環境",
        "before": "修正前", "after": "修正後", "fix": "修正方針",
        "regression": "回帰テストで確認すること", "references": "参考",
        "open_questions": "未確定事項", "done_when": "対応完了の条件",
        "q_verdict": "検証判定は {verdict}。この検出事項に基づいて動く前に、根拠に書かれた"
                     "未確認のつながりを確認する。",
        "q_verdict_bare": "検証判定は {verdict}。この検出事項に基づいて動く前に、端から端まで"
                          "追跡して確認する。",
        "q_environment": "確度は Environment-dependent。前提条件としきい値: {scale_driver}",
        "done": ("修正がマージされた",
                 "修正前に失敗し、修正後に成功する決定的な回帰チェックが追加された",
                 "対象経路の結果が変わらないこと（positive control）を確認した",
                 "findings.json の `status` を `Fixed` に更新した（`findings.py set … --status Fixed`）"),
        "paren": "（{}）", "verdict_line": "{verdict}（検証方法: {method}）",
    },
}
# "1. A tenant ... 2. GET /api/..." holds one step per number; split before each.
STEP_START = re.compile(r"(?:(?<=\s)|^)(?=[0-9]{1,3}[.)]\s)")


def issue_title(f):
    return f"[{f['severity']}] {f['title']} ({f['id']})"


def cell(value):
    """A table cell: no line breaks and no column separator."""
    return markdown_text(value).replace("|", "&#124;")


def code_cell(location):
    # A GFM table splits on "|" even inside a code span unless it is backslash-escaped.
    return markdown_code(location).replace("|", "\\|")


def request_steps(request):
    steps = []
    for line in text_lines(request):
        steps += [part.strip() for part in STEP_START.split(line) if part.strip()]
    return steps


def record_index(doc):
    """What every draft looks up in the record, gathered in one pass over it.

    mentioned: finding ID -> the `decisions`, then `limitations`, lines that
    name it, in record order; statements: budget ID -> statement. Scanning the
    lists and budgets once per draft made a run O(findings x lines).
    """
    mentioned = {}
    for key in ("decisions", "limitations"):
        for item in doc.get(key, []):
            for finding_id in dict.fromkeys(FINDING_MENTION.findall(item)):
                mentioned.setdefault(finding_id, []).append(item)
    statements = {}
    for b in doc.get("budgets", []):
        statements.setdefault(b["id"], b["statement"])
    return {"mentioned": mentioned, "statements": statements}


def open_questions(f, doc, t, index=None):
    """index: record_index(doc), when drafting several findings of one record."""
    index = record_index(doc) if index is None else index
    questions = []
    verdict = f["validation"]["verdict"]
    if verdict != "Valid":
        key = "q_verdict" if f["validation"].get("evidence", "").strip() else "q_verdict_bare"
        questions.append(t[key].format(verdict=verdict))
    if f["confidence"] == "Environment-dependent":
        questions.append(t["q_environment"].format(scale_driver=f["scale_driver"]))
    questions += index["mentioned"].get(f["id"], [])
    return questions


def render_issue(f, doc, lang, index=None):
    """index: record_index(doc), when drafting several findings of one record."""
    index = record_index(doc) if index is None else index
    t = LABELS[lang]
    meta = doc["meta"]
    v = f["validation"]
    step = t["paren"].format(markdown_text(f["step"])) if f.get("step", "").strip() else ""
    rows = [
        ("ID", f["id"]), (t["severity"], f["severity"]), (t["confidence"], f["confidence"]),
        (t["verdict"], t["verdict_line"].format(verdict=v["verdict"],
                                                method=shown(v["method"], lang))),
    ]
    lines = [f"**{t['title']}:** {markdown_text(issue_title(f))}", "",
             f"## {t['summary']}", "", f"| {t['item']} | {t['value']} |", "|---|---|"]
    lines += [f"| {label} | {cell(value)} |" for label, value in rows]
    lines.append(f"| {t['perspective']} | {f['category']}{step} |")
    lines.append(f"| {t['location']} | "
                 + "<br>".join(code_cell(loc) for loc in finding_locations(f)) + " |")
    lines.append(f"| {t['revision']} | {cell(meta.get('commit', '').strip() or 'UNKNOWN')} |")
    lines.append(f"| {t['date']} | {cell(meta['date'])} / {cell(meta['assessor'])} |")
    lines += ["", f"## {t['what_happens']}", "", markdown_text(f["impact"]), ""]
    for key in ("workload", "scale_driver", "cost_model"):
        lines.append(f"- **{t[key]}:** {markdown_text(f[key])}")
    budget = f.get("budget", "").strip()
    if budget:
        statement = index["statements"].get(budget, "")
        lines.append(f"- **{t['budget']}:** {markdown_text(budget)}"
                     + (f" — {markdown_text(statement)}" if statement else ""))
    lines += ["", f"## {t['reproduction']}"]
    for step in request_steps(f["request"]):  # one paragraph per numbered step
        lines += ["", markdown_text(step)]
    if f.get("contrast", "").strip():
        lines += ["", f"**{t['contrast']}:** {markdown_text(f['contrast'])}"]
    if v.get("evidence", "").strip():
        lines += ["", f"## {t['evidence']}", "", markdown_text(v["evidence"])]
    if "measurement" in f:
        m = f["measurement"]
        lines += ["", f"## {t['measurement']}", "",
                  f"{t['environment']}: {markdown_text(m['environment'])}"]
        for run in MEASUREMENT_RUNS:
            r = m[run]
            body = [f"$ {line}" if i == 0 else line
                    for i, line in enumerate(text_lines(r["command"]))] + text_lines(r["log"])
            fence = block_fence(body)
            lines += ["", f"{t[run]}: {markdown_text(r['result'])}", "",
                      f"{fence}text", *body, fence]
    lines += ["", f"## {t['fix']}", "", markdown_text(f["fix"]), "",
              f"- **{t['regression']}:** {markdown_text(f['regression_test'])}"]
    if f.get("references"):
        lines += ["", f"## {t['references']}", ""]
        lines += [f"- {markdown_link(reference_title(ref), ref['url'])}"
                  for ref in f["references"]]
    questions = open_questions(f, doc, t, index)
    if questions:
        lines += ["", f"## {t['open_questions']}", ""]
        lines += [f"- {markdown_text(q)}" for q in questions]
    lines += ["", f"## {t['done_when']}", ""]
    lines += [f"- [ ] {item}" for item in t["done"]]
    return "\n".join(lines) + "\n"


def select(doc, ids, min_severity, include_accepted):
    """The findings to draft, in record order; raise SchemaError for an unusable ID."""
    findings = doc.get("findings", [])
    allowed = {"Open", "Accepted"} if include_accepted else {"Open"}
    limit = SEVERITIES.index(min_severity) if min_severity else len(SEVERITIES)
    if ids:
        by_id = {f["id"]: f for f in findings}
        chosen = []
        for fid in dict.fromkeys(ids):
            f = by_id.get(fid)
            if f is None:
                raise SchemaError(f"--id {fid}: no such finding")
            if f["validation"]["verdict"] in EXCLUDED:
                raise SchemaError(f"--id {fid}: excluded as {f['validation']['verdict']}; "
                                  "there is nothing to file")
            if finding_status(f) == "Fixed":
                raise SchemaError(f"--id {fid}: already Fixed")
            chosen.append(f)
        order = {f["id"]: n for n, f in enumerate(findings)}
        return sorted(chosen, key=lambda f: order[f["id"]])
    return [f for f in findings
            if f["validation"]["verdict"] not in EXCLUDED and finding_status(f) in allowed
            and SEVERITIES.index(f["severity"]) <= limit]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("findings")
    parser.add_argument("--out", required=True)
    parser.add_argument("--lang", choices=("ja", "en"))
    parser.add_argument("--id", action="append", default=[], dest="ids", metavar="P-NNN")
    parser.add_argument("--min-severity", choices=SEVERITIES)
    parser.add_argument("--include-accepted", action="store_true")
    parser.add_argument("--force", action="store_true", help="replace existing drafts")
    args = parser.parse_args(argv)
    escape_unencodable_console()
    if not args.out.strip():
        parser.error("--out must name a directory")
    try:
        doc = read_json(args.findings)
        try:
            validate(doc, complete=True)
        except SchemaError as exc:
            raise SchemaError(f"{args.findings}: {exc}") from exc
        chosen = select(doc, args.ids, args.min_severity, args.include_accepted)
        out = Path(args.out)
        if out.exists() and resolve_path(out) == resolve_path(args.findings).parent:
            raise SchemaError(f"--out {out}: the record's own directory holds only the "
                              "three run outputs; write drafts to scratch or a directory "
                              "of their own")
        lang = args.lang or doc["meta"]["lang"]
        index = record_index(doc)
        drafts = [(out / f"{f['id']}.md", render_issue(f, doc, lang, index).encode("utf-8"), f)
                  for f in chosen]
        existing = [str(path) for path, _, _ in drafts
                    if out.exists() and file_mode(resolve_path(path)) is not None]
        if existing and not args.force:
            raise SchemaError("drafts already exist (pass --force to replace them): "
                              + ", ".join(existing))
    except SchemaError as exc:
        print(f"issues: {exc}", file=sys.stderr)
        return 2
    except (OSError, UnicodeError) as exc:
        print(f"issues: {exc}", file=sys.stderr)
        return 1
    if not drafts:
        print("no findings selected; nothing written")
        return 0
    try:
        out.mkdir(parents=True, exist_ok=True)
        for path, content, _ in drafts:
            write_atomic(resolve_path(path), content)
    except OSError as exc:
        print(f"issues: {exc}", file=sys.stderr)
        return 1
    for path, _, f in drafts:
        # The title is record text: show control and bidi characters as escapes.
        print(f"{path}\t{' '.join(text_lines(issue_title(f)))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
