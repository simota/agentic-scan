#!/usr/bin/env python3
"""Export a ux-scan findings.json for the tools that fix and track it (reference/follow-up.md).

    python3 export.py sarif    FINDINGS --out FILE|- [--prefix DIR] [--min-severity S] [--ids U-001,...]
    python3 export.py markdown FINDINGS --out FILE|- [--prefix DIR] [--min-severity S] [--ids ...] [--lang ja|en]
    python3 export.py csv      FINDINGS --out FILE|- [--min-severity S] [--ids ...]

sarif     SARIF 2.1.0 for code scanning (GitHub, IDE viewers): one rule per hunt step, one
          result per Open or Accepted finding at its path:line, occurrences as related
          locations, Accepted findings suppressed, a stable fingerprint per finding.
markdown  One issue draft per Open finding, its heading the issue title, plus a checklist.
csv       Every finding, one row each, for triage in a spreadsheet (cells that a spreadsheet
          would run as a formula are quoted with a leading apostrophe).

FalsePositive and NotApplicable findings are left out of sarif and markdown; csv keeps them
with their verdict. --prefix prepends the reviewed directory's path inside its Git repository
(examples/tasklane) so paths resolve from the repository root. The record must pass
findings.py check; the output never replaces a review output. Standard library only.
Exit status: 0 written, 2 invalid record or unwritable output.
"""

import argparse
import csv
import hashlib
import io
import json
import re
import sys
from pathlib import Path, PurePosixPath
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).resolve().parent))
from findings import FINDING_ID, SEVERITIES, RecordError  # noqa: E402
from record_files import allow_note, at_least, code, counted, flow_label, load_record, split_location, write_derived  # noqa: E402
from render import FAMILIES  # noqa: E402

FORMATS = ("sarif", "markdown", "csv")
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/simota/ux-scan"
LEVEL = {"High": "error", "Medium": "warning", "Low": "note", "Info": "note"}
FINGERPRINT = "uxScanFinding/v1"
CSV_COLUMNS = ("id", "title", "severity", "confidence", "status", "verdict", "perspective", "category", "flow",
               "screen", "viewport", "criterion", "location", "occurrences", "observed", "expected", "impact", "fix",
               "evidence_files", "references")
# A leading =, +, -, @, tab or carriage return makes a spreadsheet evaluate the cell (CSV injection).
FORMULA = re.compile(r"^[=+\-@\t\r]")
LABELS = {
    "en": {"heading": "UX review issues", "intro": "{n} open findings from the review of {date}{commit}. "
                                                   "Each section is one issue: its heading is the title, the rest the body.",
           "none": "No open findings match.", "severity": "Severity", "confidence": "Confidence", "verdict": "Verdict",
           "location": "Location", "occurrences": "Also fix", "flow": "Flow", "screen": "Screen",
           "viewport": "Viewport", "criterion": "Criterion", "observed": "Observed", "expected": "Expected",
           "impact": "Impact", "fix": "Fix", "evidence": "Evidence (in the review's evidence/)",
           "references": "References", "done": "Done when",
           "done_text": "The expected behaviour holds on this screen{viewport}, and a re-review no longer reports it "
                        "(capture an `after` screenshot or log as evidence)."},
    "ja": {"heading": "UX診断 課題一覧", "intro": "{date} の診断{commit}で未対応の指摘 {n} 件。"
                                                 "各節が1件の課題で、見出しがタイトル、残りが本文です。",
           "none": "該当する未対応の指摘はありません。", "severity": "重大度", "confidence": "確度", "verdict": "判定",
           "location": "場所", "occurrences": "同時に直す箇所", "flow": "フロー", "screen": "画面",
           "viewport": "ビューポート", "criterion": "判断基準", "observed": "現状", "expected": "あるべき状態",
           "impact": "影響", "fix": "修正", "evidence": "証跡（診断の evidence/ 内）", "references": "参考資料",
           "done": "完了条件",
           "done_text": "この画面{viewport}であるべき状態が満たされ、再診断で報告されなくなること"
                        "（`after` のスクリーンショットかログを証跡として残す）。"},
}


def fingerprints(findings):
    """id -> a fingerprint stable across renumbering and line moves: the hunt step, the file and the
    title; findings that share all three are told apart by their order in the record."""
    seen, result = {}, {}
    for finding in findings:
        path = split_location(finding["location"])[0]
        title = " ".join(re.sub(r"\W+", " ", finding["title"].casefold()).split())
        key = f"{finding['perspective']}\0{path}\0{title}"
        seen[key] = seen.get(key, 0) + 1
        if seen[key] > 1:
            key += f"\0{seen[key]}"
        result[finding["id"]] = hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]
    return result


def prefixed(path, prefix):
    if not prefix:
        return path
    return str(PurePosixPath(prefix.strip("/")) / path)


def selected(data, args, keep):
    ids = None
    if args.ids:
        ids = [part.strip() for part in args.ids.split(",") if part.strip()]
        known = {f["id"] for f in data["findings"]}
        for fid in ids:
            if not FINDING_ID.match(fid) or fid not in known:
                raise RecordError(f"--ids: {fid!r} is not a finding in the record")
    return [f for f in data["findings"]
            if keep(f) and at_least(f, args.min_severity) and (ids is None or f["id"] in ids)]


def sarif(data, flows, findings, prefix):
    steps = sorted({f["perspective"] for f in findings})
    families = FAMILIES["en"]
    rules = [{"id": step, "name": f"{families[step[:2]]} {step}".replace(" ", ""),
              "shortDescription": {"text": f"{families[step[:2]]} ({step})"},
              "helpUri": f"{INFORMATION_URI}/blob/main/skills/ux-scan/reference/perspectives.md",
              "properties": {"tags": ["ux", families[step[:2]].lower()]}} for step in steps]
    index = {step: i for i, step in enumerate(steps)}
    prints = fingerprints(data["findings"])

    def physical(location):
        path, start, end = split_location(location)
        return {"artifactLocation": {"uri": quote(prefixed(path, prefix), safe="/"), "uriBaseId": "%SRCROOT%"},
                "region": {"startLine": start, "endLine": end}}

    results = []
    for f in findings:
        text = f["title"] + "".join(f"\n\n{label}: {f[key]}" for key, label in
                                    (("impact", "Impact"), ("expected", "Expected"), ("fix", "Fix")) if f.get(key))
        result = {"ruleId": f["perspective"], "ruleIndex": index[f["perspective"]], "level": LEVEL[f["severity"]],
                  "message": {"text": text}, "locations": [{"physicalLocation": physical(f["location"])}],
                  "partialFingerprints": {FINGERPRINT: prints[f["id"]]},
                  "properties": {"id": f["id"], "severity": f["severity"], "confidence": f["confidence"],
                                 "status": f["status"], "verdict": f["validation"]["verdict"],
                                 "flow": flow_label(f, flows), "screen": f["screen"], "criterion": f["criterion"],
                                 **({"viewport": f["viewport"]} if f.get("viewport") else {})}}
        related = [loc for loc in f.get("occurrences", []) if loc != f["location"]]
        if related:
            result["relatedLocations"] = [{"id": i, "physicalLocation": physical(loc),
                                           "message": {"text": "The same fix covers this occurrence."}}
                                          for i, loc in enumerate(related, 1)]
        if f["status"] == "Accepted":
            result["suppressions"] = [{"kind": "external", "status": "accepted",
                                       "justification": f["validation"].get("intent_checked")
                                       or "Accepted in the UX review."}]
        results.append(result)
    meta = data["meta"]
    run = {"tool": {"driver": {"name": "ux-scan", "informationUri": INFORMATION_URI, "rules": rules}},
           "originalUriBaseIds": {"%SRCROOT%": {"description": {"text": "The reviewed repository's root"}}},
           "properties": {k: meta[k] for k in ("project", "date", "assessor", "scope", "commit") if meta.get(k)},
           "results": results}
    return json.dumps({"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [run]}, ensure_ascii=False, indent=2) + "\n"


def one_line(text):
    return " ".join(text.split())


FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})")


def prose(text):
    """Record prose for an issue body: raw tags such as <button onClick={...}> quoted in observed
    would be swallowed by the tracker's HTML sanitizer, so < and & are escaped outside code spans
    and fenced blocks, which already show them literally."""
    out, fence = [], None
    for line in text.split("\n"):
        opener = FENCE.match(line)
        if fence:
            out.append(line)
            if opener and opener.group(1)[0] == fence[0] and len(opener.group(1)) >= len(fence):
                fence = None
            continue
        if opener:
            fence = opener.group(1)
            out.append(line)
            continue
        parts, i = [], 0
        for run in re.finditer(r"`+", line):
            if run.start() < i:
                continue
            close = line.find(run.group(), run.end())
            while close != -1 and (line[close - 1:close] == "`" or line[close + len(run.group()):][:1] == "`"):
                close = line.find(run.group(), close + 1)
            if close == -1:
                continue
            parts.append(_escape(line[i:run.start()]))
            parts.append(line[run.start():close + len(run.group())])
            i = close + len(run.group())
        parts.append(_escape(line[i:]))
        out.append("".join(parts))
    return "\n".join(out)


def _escape(text):
    return text.replace("&", "&amp;").replace("<", "&lt;")


def label(text):
    """One line of link text: brackets would end the link early."""
    return re.sub(r"([\[\]])", r"\\\1", one_line(text))


def markdown(data, flows, findings, prefix, lang):
    L, meta = LABELS[lang], data["meta"]
    commit = f" (commit {code(meta['commit'])})" if meta.get("commit") else ""
    lines = [f"# {meta['project']}: {L['heading']}", ""]
    if not findings:
        return "\n".join(lines + [L["none"], ""])
    lines += [L["intro"].format(n=len(findings), date=meta["date"], commit=commit), ""]
    lines += [f"- [ ] **{f['id']}** {f['severity']}: {prose(one_line(f['title']))} "
              f"({code(prefixed(f['location'], prefix))})" for f in findings]
    for f in findings:
        viewport = f" ({f['viewport']})" if f.get("viewport") else ""
        lines += ["", "---", "", f"## [{f['id']}] {prose(one_line(f['title']))}", "",
                  f"- **{L['severity']}:** {f['severity']} · **{L['confidence']}:** {f['confidence']} · "
                  f"**{L['verdict']}:** {f['validation']['verdict']}",
                  f"- **{L['location']}:** {code(prefixed(f['location'], prefix))}"]
        also = [loc for loc in f.get("occurrences", []) if loc != f["location"]]
        if also:
            lines.append(f"- **{L['occurrences']}:** " + ", ".join(code(prefixed(loc, prefix)) for loc in also))
        lines += [f"- **{L['flow']}:** {flow_label(f, flows)}", f"- **{L['screen']}:** {prose(one_line(f['screen']))}"]
        if f.get("viewport"):
            lines.append(f"- **{L['viewport']}:** {f['viewport']}")
        lines.append(f"- **{L['criterion']}:** {prose(one_line(f['criterion']))}")
        for key in ("observed", "expected", "impact", "fix"):
            if f.get(key, "").strip():
                lines += ["", f"### {L[key]}", "", prose(f[key].strip())]
        lines += ["", f"### {L['done']}", "", L["done_text"].format(viewport=viewport)]
        if f.get("evidence"):
            lines += ["", f"### {L['evidence']}", ""]
            lines += [f"- {code(item['file'])} ({item.get('stage', 'before')}): {prose(one_line(item['caption']))}"
                      for item in f["evidence"]]
        if f.get("references"):
            lines += ["", f"### {L['references']}", ""]
            lines += [f"- [{prose(label(ref.get('title') or ref['url']))}](<{ref['url']}>)" for ref in f["references"]]
    return "\n".join(lines) + "\n"


def cell(value):
    value = str(value)
    return "'" + value if FORMULA.match(value) else value


def csv_text(data, flows, findings):
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\r\n")
    writer.writerow(CSV_COLUMNS)
    families = FAMILIES["en"]
    for f in findings:
        row = {"id": f["id"], "title": f["title"], "severity": f["severity"], "confidence": f["confidence"],
               "status": f["status"], "verdict": f["validation"]["verdict"], "perspective": f["perspective"],
               "category": f.get("category") or families[f["perspective"][:2]], "flow": flow_label(f, flows),
               "screen": f["screen"], "viewport": f.get("viewport", ""), "criterion": f["criterion"],
               "location": f["location"], "occurrences": "\n".join(f.get("occurrences", [])),
               "observed": f.get("observed", ""), "expected": f.get("expected", ""), "impact": f.get("impact", ""),
               "fix": f.get("fix", ""),
               "evidence_files": "\n".join(f"{item['file']} ({item.get('stage', 'before')})"
                                           for item in f.get("evidence", [])),
               "references": "\n".join(ref["url"] for ref in f.get("references", []))}
        writer.writerow([cell(row[column]) for column in CSV_COLUMNS])
    # A byte-order mark lets spreadsheet apps read UTF-8 (Japanese titles) without an import dialog.
    return "﻿" + buffer.getvalue()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("format", choices=FORMATS)
    parser.add_argument("findings")
    parser.add_argument("--out", required=True, help="output file, or - for stdout")
    parser.add_argument("--prefix", default="", help="the reviewed directory inside its Git repository")
    parser.add_argument("--min-severity", choices=SEVERITIES, default="Info")
    parser.add_argument("--ids", default="", help="comma-separated finding ids to export")
    parser.add_argument("--lang", choices=("ja", "en"), default="en", help="markdown labels")
    args = parser.parse_args(argv)
    try:
        prefix = args.prefix.strip()
        if prefix and (prefix.startswith("/") or "\\" in prefix or ".." in PurePosixPath(prefix).parts
                       or any(c.isspace() and c != " " for c in prefix)):
            raise RecordError(f"--prefix: {args.prefix!r} must be a relative path inside the repository")
        data, flows = load_record(args.findings)
        if args.format == "sarif":
            findings = selected(data, args, lambda f: counted(f) and f["status"] in ("Open", "Accepted"))
            text = sarif(data, flows, findings, prefix)
        elif args.format == "markdown":
            findings = selected(data, args, lambda f: counted(f) and f["status"] == "Open")
            text = markdown(data, flows, findings, prefix, args.lang)
        else:
            if prefix:
                raise RecordError("--prefix applies to sarif and markdown; csv keeps the record's paths")
            findings = selected(data, args, lambda f: True)
            text = csv_text(data, flows, findings)
        target = write_derived(args.out, text, [args.findings])
    except (RecordError, OSError, ValueError, RecursionError) as e:
        print(f"export.py: {e}", file=sys.stderr)
        return 2
    if target is not None:
        print(f"wrote {target} ({len(findings)} findings, {args.format}){allow_note(target, [args.findings])}")
    return 0


if __name__ == "__main__":
    from file_io import tolerant_console
    tolerant_console()
    sys.exit(main())
