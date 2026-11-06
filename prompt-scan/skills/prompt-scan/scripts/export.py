#!/usr/bin/env python3
"""Export findings.json for the places findings are acted on: chat, code scanning and issue trackers.

    python3 export.py summary FINDINGS [--out FILE] [--lang ja|en] [--min-severity S] [--fail-on S]
    python3 export.py sarif   FINDINGS [--out FILE] [--min-severity S] [--fail-on S]
    python3 export.py issues  FINDINGS --out DIR [--lang ja|en] [--min-severity S] [--fail-on S]

- `summary` is the chat summary of reference/report.md (first line, evidence line, findings by severity,
  checked and sound, decisions, next steps) with the counts and verdicts of the record, in Markdown
- `sarif` is SARIF 2.1.0, for GitHub code scanning (`github/codeql-action/upload-sarif`), IDE SARIF
  viewers and other tools that read static-analysis results. Each finding is a result at its location;
  an `Accepted` finding carries an accepted suppression, so it is shown as dismissed rather than open
- `issues` writes one Markdown issue body per finding into DIR, filled from templates/issue.<lang>.md
  (`F-001.md`, `L-002.md`…), plus `index.md` listing them, ready for `gh issue create --body-file`

Every format leaves out FalsePositive and NotApplicable findings and findings whose status is `Fixed`;
--min-severity drops findings below that severity. All text has already passed findings.py's checks for
override strings and credential-shaped values, and is masked once more on the way out.

--fail-on SEVERITY exits 1 after writing when an exported finding at SEVERITY or above is still
`Open`, so the same call can publish results and gate a CI job.

Write exports outside the review's output directory: contract_check.py refuses files it does not expect.

Exit codes: 0 written, 1 --fail-on threshold reached, 2 unreadable input, schema error or unwritable output.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import record  # noqa: E402
from record import EXCLUDED, KINDS, LOC_RE, SEVERITIES, SchemaError, id_key  # noqa: E402
from excerpt import mask  # noqa: E402
from scan_report_kit.output import unsafe_target, write_output  # noqa: E402

SKILL = Path(__file__).resolve().parents[1]
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFO_URI = "https://github.com/simota/prompt-scan"
LEVELS = {"High": "error", "Medium": "warning", "Low": "note", "Info": "note"}
TEMPLATE_FIELD = re.compile(r"\{\{\s*([a-z_.]+)\s*\}\}")

LABELS = {
    "en": {
        "first": "{total} findings ({defects} defects, {improvements} improvements): {sev}. {scope}",
        "static": "Static review only.", "evals": "{n} eval run(s) recorded.",
        "not_valid": "High findings not yet Valid: {ids}.",
        "evidence": "Revision {rev}; {prompts} prompt(s) recorded.", "outside_git": "outside Git",
        "dirty": "uncommitted changes present", "dirty_unknown": "uncommitted changes not determined",
        "findings": "Findings", "sound": "Checked and sound", "decisions": "Decisions for a human",
        "next": "Next steps", "limitations": "Limitations", "none": "None recorded.",
        "excluded": "{n} finding(s) excluded with evidence, {fixed} marked Fixed, not listed.",
        "below": "{n} finding(s) below {sev} not listed.",
        "index": "Issue drafts", "index_note": "One file per finding; file each with "
                                                "`gh issue create --title \"<title>\" --body-file <file>`.",
    },
    "ja": {
        "first": "指摘 {total} 件（不具合 {defects} 件、改善提案 {improvements} 件）: {sev}。{scope}",
        "static": "静的レビューのみ。", "evals": "評価の実行記録 {n} 件。",
        "not_valid": "Valid になっていない High: {ids}。",
        "evidence": "リビジョン {rev}。記録したプロンプト {prompts} 件。", "outside_git": "Git 管理外",
        "dirty": "未コミットの変更あり", "dirty_unknown": "未コミットの変更は未確認",
        "findings": "指摘", "sound": "確認して問題がなかった項目", "decisions": "判断が必要な事項",
        "next": "次のステップ", "limitations": "制約事項", "none": "記録なし。",
        "excluded": "根拠付きで除外した {n} 件と Fixed の {fixed} 件は載せていない。",
        "below": "{sev} 未満の {n} 件は載せていない。",
        "index": "Issue の下書き", "index_note": "指摘ごとに 1 ファイル。"
                                                 "`gh issue create --title \"<タイトル>\" --body-file <ファイル>` で登録できる。",
    },
}


def exported(data, min_severity):
    """The findings every format reports: active, not Fixed, at min_severity or above, in report order."""
    limit = SEVERITIES.index(min_severity)
    keep = [f for f in data.get("findings", []) if f["validation"]["verdict"] not in EXCLUDED
            and f.get("status", "Open") != "Fixed" and SEVERITIES.index(f["severity"]) <= limit]
    return sorted(keep, key=lambda f: (SEVERITIES.index(f["severity"]), KINDS.index(f["kind"]), id_key(f["id"])))


def gate(findings, threshold):
    limit = SEVERITIES.index(threshold)
    return [f for f in findings if f.get("status", "Open") == "Open" and SEVERITIES.index(f["severity"]) <= limit]


def prompt_text(f):
    p = f.get("prompt")
    return ", ".join(p) if isinstance(p, list) else (p or "")


def test_list(f):
    t = f.get("test")
    return [t] if isinstance(t, str) else list(t or [])


def flat(text):
    return re.sub(r"\s+", " ", str(text)).strip()


# ---------------------------------------------------------------- summary

def revision(meta, L):
    commit = meta.get("commit")
    if not commit:
        return L["outside_git"]
    state = {True: L["dirty"], None: L["dirty_unknown"]}.get(meta.get("dirty"))
    return commit[:12] + (f" ({state})" if state else "")


def summary(data, findings, min_severity, L):
    every = [f for f in data.get("findings", []) if f["validation"]["verdict"] not in EXCLUDED]
    sev = ", ".join(f"{s} {sum(1 for f in every if f['severity'] == s)}" for s in SEVERITIES)
    runs = data.get("eval_runs", [])
    scope = L["evals"].format(n=len(runs)) if runs else L["static"]
    pending = [f["id"] for f in every if f["severity"] == "High" and f["validation"]["verdict"] != "Valid"]
    first = L["first"].format(total=len(every), defects=sum(f["kind"] == "defect" for f in every),
                              improvements=sum(f["kind"] == "improvement" for f in every), sev=sev, scope=scope)
    if pending:
        first += " " + L["not_valid"].format(ids=", ".join(pending))
    lines = [first, "", L["evidence"].format(rev=revision(data.get("meta", {}), L),
                                             prompts=len(data.get("prompts", []))), "", f"## {L['findings']}", ""]
    for f in findings:
        v = f["validation"]
        block = [f"[{f['severity']}][{f['kind']}][{f['confidence']}] {f['title']}",
                 f"  location: {f['location']}" + (f"   prompt: {prompt_text(f)}" if prompt_text(f) else "")
                 + f"   perspective: {f['category']}"]
        for key in ("symptom", "cause", "impact", "fix"):
            if f.get(key):
                block.append(f"  {key}: {flat(f[key])}")
        if f.get("proposal"):
            block.append(f"  proposal: {flat(f['proposal'].get('before', ''))} → {flat(f['proposal'].get('after', ''))}")
        for t in test_list(f):
            block.append(f"  test: {flat(t)}")
        block.append(f"  verdict: {v['verdict']}" + (f" — {flat(v['evidence'])}" if v.get("evidence") else ""))
        lines += ["```", f"{f['id']} " + block[0], *block[1:], "```", ""]
    if not findings:
        lines += [L["none"], ""]
    excluded = len(data.get("findings", [])) - len(every)
    fixed = sum(f.get("status") == "Fixed" for f in every)
    if excluded or fixed:
        lines += [L["excluded"].format(n=excluded, fixed=fixed), ""]
    below = sum(SEVERITIES.index(f["severity"]) > SEVERITIES.index(min_severity) and f.get("status") != "Fixed"
                for f in every)
    if below:
        lines += [L["below"].format(n=below, sev=min_severity), ""]
    for key, title in (("checked_ok", "sound"), ("decisions", "decisions"), ("next_steps", "next"),
                       ("limitations", "limitations")):
        items = data.get(key, [])
        lines += [f"## {L[title]}", ""] + ([f"- {flat(x)}" for x in items] or [L["none"]]) + [""]
    return mask("\n".join(lines))


# ---------------------------------------------------------------- SARIF

def slug(text):
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "finding"


def rule_id(f):
    if f["id"].startswith("L-"):
        return f"prompt-scan/lint/{f.get('rule') or slug(f['category'])}"
    return f"prompt-scan/{slug(f['category'])}"


def fingerprint(f):
    """Stable across rescans and renumbering: rule, file and title, never the id or the line."""
    path = LOC_RE.match(f["location"])
    key = "\0".join((rule_id(f), path["path"] if path else f["location"], flat(f["title"]).lower()))
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]


def sarif_message(f):
    parts = [f"{f['id']} [{f['severity']}][{f['kind']}] {f['title']}"]
    for key in ("symptom", "cause", "impact", "fix"):
        if f.get(key):
            parts.append(f"{key.capitalize()}: {flat(f[key])}")
    if f.get("proposal"):
        parts.append(f"Proposal: {flat(f['proposal'].get('before', ''))} → {flat(f['proposal'].get('after', ''))}")
    for t in test_list(f):
        parts.append(f"Test: {flat(t)}")
    return mask("\n\n".join(parts))


def sarif(data, findings):
    rules, index = [], {}
    for f in findings:
        rid = rule_id(f)
        if rid in index:
            continue
        index[rid] = len(rules)
        name = f.get("rule") or f["category"]
        rules.append({"id": rid, "name": slug(name).replace("-", "_"),
                      "shortDescription": {"text": f"prompt-scan: {name}"},
                      "fullDescription": {"text": f"Prompt review perspective: {f['category']}"},
                      "helpUri": INFO_URI, "properties": {"tags": ["prompt", "llm", slug(f["category"])]}})
    results = []
    for f in findings:
        m = LOC_RE.match(f["location"])
        result = {"ruleId": rule_id(f), "ruleIndex": index[rule_id(f)], "level": LEVELS[f["severity"]],
                  "message": {"text": sarif_message(f)},
                  "partialFingerprints": {"promptScanFinding/v1": fingerprint(f)},
                  "properties": {"id": f["id"], "kind": f["kind"], "severity": f["severity"],
                                 "confidence": f["confidence"], "verdict": f["validation"]["verdict"],
                                 "status": f.get("status", "Open"), "prompt": prompt_text(f)}}
        if m:
            region = {"startLine": max(int(m["start"]), 1)}
            if m["end"] and int(m["end"]) >= region["startLine"]:
                region["endLine"] = int(m["end"])
            result["locations"] = [{"physicalLocation": {
                "artifactLocation": {"uri": m["path"].replace("\\", "/"), "uriBaseId": "SRCROOT"},
                "region": region}}]
        if f.get("status") == "Accepted":
            result["suppressions"] = [{"kind": "external", "status": "accepted",
                                       "justification": mask(flat(f["validation"].get("evidence") or "Accepted"))}]
        results.append(result)
    meta = data.get("meta", {})
    run = {"tool": {"driver": {"name": "prompt-scan", "informationUri": INFO_URI, "rules": rules}},
           "originalUriBaseIds": {"SRCROOT": {"description": {"text": "The reviewed repository's root"}}},
           "results": results,
           "properties": {k: meta.get(k) for k in ("target", "date", "assessor", "scope") if meta.get(k)}}
    if meta.get("commit"):
        # versionControlProvenance needs the repository's URI, which the record does not hold.
        run["properties"]["commit"] = meta["commit"]
    return json.dumps({"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [run]}, ensure_ascii=False, indent=2) + "\n"


# ---------------------------------------------------------------- issues

def field_value(f, meta, name):
    if name.startswith("meta."):
        return str(meta.get(name[5:]) or "")
    if name.startswith("validation."):
        return str(f["validation"].get(name[11:]) or "")
    if name.startswith("proposal."):
        return str((f.get("proposal") or {}).get(name[9:]) or "")
    if name == "prompt":
        return prompt_text(f)
    if name == "test":
        tests = test_list(f)
        return tests[0] if len(tests) == 1 else "\n".join(f"- {t}" for t in tests)
    if name == "status":
        return f.get("status", "Open")
    value = f.get(name)
    return "" if value is None else str(value)


def fill(template, f, meta):
    """The template with every {{field}} filled; a table row or section whose fields are all empty is dropped."""
    text = re.sub(r"<!--.*?-->\n?", "", template, flags=re.S)

    def empty(chunk):
        names = TEMPLATE_FIELD.findall(chunk)
        return names and all(not field_value(f, meta, n).strip() for n in names)
    sections = re.split(r"(?m)^(?=## )", text)
    kept = [s for s in sections if not (s.startswith("## ") and empty(s))]
    lines = [line for line in "".join(kept).splitlines() if not (line.startswith("|") and empty(line))]
    text = "\n".join(lines)
    text = TEMPLATE_FIELD.sub(lambda m: field_value(f, meta, m.group(1)).strip() or "—", text)
    return mask(re.sub(r"\n{3,}", "\n\n", text).strip() + "\n")


def issue_title(f):
    return mask(f"[{f['severity']}][{f['kind']}] {flat(f['title'])} ({f['id']})")


def issues(data, findings, lang, L):
    template = (SKILL / "templates" / f"issue.{lang}.md").read_text(encoding="utf-8")
    meta = data.get("meta", {})
    pages = {f"{f['id']}.md": fill(template, f, meta) for f in findings}
    index = [f"# {L['index']} — {meta.get('target') or ''}".rstrip(" —"), "", L["index_note"], ""]
    index += [f"- [{f['id']}]({f['id']}.md) {issue_title(f)}" for f in findings] or [L["none"]]
    pages["index.md"] = mask("\n".join(index) + "\n")
    return pages


# ---------------------------------------------------------------- CLI

def write(path, text):
    unsafe = unsafe_target(path.parent, [path.name])
    if unsafe:
        raise OSError(f"refusing to write {unsafe}: it exists as a symlink or non-regular file")
    write_output(path, text)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("format", choices=("summary", "sarif", "issues"))
    p.add_argument("findings", type=Path)
    p.add_argument("--out", type=Path, help="file (summary, sarif; default stdout) or directory (issues, required)")
    p.add_argument("--lang", choices=sorted(LABELS), help="default: meta.lang, else ja")
    p.add_argument("--min-severity", choices=SEVERITIES, default="Info", metavar="SEVERITY",
                   help="leave out findings below this severity (default: Info, i.e. all)")
    p.add_argument("--fail-on", choices=SEVERITIES, metavar="SEVERITY",
                   help="exit 1 when an exported Open finding is at this severity or above")
    a = p.parse_args(argv)
    if a.format == "issues" and not a.out:
        p.error("issues needs --out DIR")
    try:
        data = record.load(a.findings, record.read_regular(a.findings))
    except (SchemaError, OSError) as e:
        print(f"export.py: {e}", file=sys.stderr)
        return 2
    lang = a.lang or data.get("meta", {}).get("lang") or "ja"
    L = LABELS[lang]
    findings = exported(data, a.min_severity)
    try:
        if a.out and a.out.resolve() == a.findings.resolve():
            raise OSError("--out is the findings file itself")
        if a.format == "issues":
            pages = issues(data, findings, lang, L)
            a.out.mkdir(parents=True, exist_ok=True)
            for name, text in pages.items():
                write(a.out / name, text)
            print(f"wrote {len(pages) - 1} issue draft(s) and index.md to {a.out}")
        else:
            text = summary(data, findings, a.min_severity, L) if a.format == "summary" else sarif(data, findings)
            if a.out:
                write(a.out, text)
                print(f"wrote {a.out}: {len(findings)} finding(s)")
            else:
                sys.stdout.write(text)
    except OSError as e:
        print(f"export.py: cannot write {a.out}: {e}", file=sys.stderr)
        return 2
    if a.fail_on:
        found = gate(findings, a.fail_on)
        if found:
            print(f"export.py: {len(found)} Open finding(s) at {a.fail_on} or above: "
                  + ", ".join(f["id"] for f in found), file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
