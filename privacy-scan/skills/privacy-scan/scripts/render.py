#!/usr/bin/env python3
"""Render findings.json into dashboard.html and report.md.

    python3 render.py FINDINGS --out DIR [--lang ja|en]

Both outputs are derived from the one record; neither adds facts of its own.
`dashboard.html` is self-contained and works offline. `report.md` follows the
findings-report shape in `reference/report.md`.

Exit codes: 0 written, 2 the record does not match the schema (the field is
named on stderr).
"""
import argparse
from html import escape
from pathlib import Path
import re
import sys
from urllib.parse import quote, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
from findings import (EXCLUDED, PERSPECTIVES, SEVERITIES, SchemaError,  # noqa: E402
                      read_json, validate)

LABELS = {
    "en": {
        "title": "Privacy assessment", "scope": "Scope and method",
        "findings": "Findings", "commitments": "Privacy commitments", "perspectives": "Perspective coverage",
        "checked_ok": "Checked and sound", "limitations": "What could not be checked",
        "decisions": "Decisions for a human", "next_steps": "Next steps", "excluded": "Excluded",
        "all": "All", "none": "None.",
        "location": "location", "data": "personal data", "subjects": "data subjects",
        "flow": "flow", "contrast": "contrast", "impact": "what happens", "commitment": "commitment",
        "fix": "fix direction", "guard": "guard", "verdict": "recorded verdict",
        "method": "verification", "evidence": "evidence", "analysis": "analysis",
        "references": "references", "status": "status",
        "inferred": "inferred", "not_checked_reason": "reason",
        "static_note": "Static review; no personal data was read from any data store.",
        "analysed_note": "Static review plus read-only tool analysis (data-flow or schema scan, history); no personal data was read.",
        "project": "System", "scope_row": "Scope", "revision": "Revision", "date": "Date / assessor",
    },
    "ja": {
        "title": "プライバシー診断", "scope": "対象と方法",
        "findings": "検出事項", "commitments": "プライバシー上の約束", "perspectives": "観点のカバレッジ",
        "checked_ok": "確認して問題なかった項目", "limitations": "確認できなかったこと",
        "decisions": "人が判断すべき事項", "next_steps": "次の作業", "excluded": "除外",
        "all": "すべて", "none": "なし。",
        "location": "場所", "data": "個人データ", "subjects": "データ主体",
        "flow": "データの流れ", "contrast": "対照", "impact": "何が起きるか", "commitment": "約束",
        "fix": "修正方針", "guard": "再発防止チェック", "verdict": "検証判定",
        "method": "検証の根拠", "evidence": "根拠", "analysis": "解析",
        "references": "参考", "status": "ステータス",
        "inferred": "推定", "not_checked_reason": "未確認の理由",
        "static_note": "静的レビューのみ。データストアから個人データは一切読み取っていない。",
        "analysed_note": "静的レビューに加え、読み取り専用のツール解析（データフロー・スキーマの走査、変更履歴）を実施。個人データは読み取っていない。",
        "project": "システム", "scope_row": "範囲", "revision": "リビジョン", "date": "診断日 / 診断者",
    },
}
FIELDS = ("location", "data", "subjects", "flow", "contrast", "impact", "commitment",
          "fix", "guard")


def counts(findings):
    active = [f for f in findings if f["validation"]["verdict"] not in EXCLUDED]
    return {s: sum(f["severity"] == s for f in active) for s in SEVERITIES}, len(findings) - len(active)


def as_text(value):
    return ", ".join(value) if isinstance(value, list) else str(value)


MARKDOWN_ESCAPES = str.maketrans({c: "\\" + c for c in "\\`*_[]|~#"})


def markdown_text(value):
    """Keep prose literal inside headings, inline text and table cells."""
    text = as_text(value).replace("\r\n", "\n").replace("\r", "\n")
    # Add our own breaks only after escaping the supplied HTML and Markdown.
    return escape(text, quote=False).translate(MARKDOWN_ESCAPES).replace("\n", "<br>")


def markdown_cell(value):
    """Keep literal text and line breaks inside one Markdown table cell."""
    return markdown_text(value)


def markdown_row(values):
    return "| " + " | ".join(markdown_cell(value) for value in values) + " |"


def markdown_item(value):
    """Prevent a literal list marker from starting a nested list or rule."""
    text = markdown_text(value)
    text = re.sub(r"^([ \t]*)([-+])", r"\1\\\2", text)
    return re.sub(r"^([ \t]*[0-9]{1,9})([.)])(?=\s|$)", r"\1\\\2", text)


def markdown_code(value):
    """Keep commands literal, including backticks, padding and line breaks."""
    lines = as_text(value).replace("\r\n", "\n").replace("\r", "\n").split("\n")
    spans = []
    for line in lines:
        if not line:
            spans.append("")
            continue
        fence = "`" * (max((len(run) for run in re.findall(r"`+", line)), default=0) + 1)
        if line.strip(" ") and (line.startswith(("`", " ")) or line.endswith(("`", " "))):
            # CommonMark removes one padding space at each end of a code span.
            line = " " + line + " "
        spans.append(f"{fence}{line}{fence}")
    return "<br>".join(spans)


def reference_destination(url):
    """Encode supported reference URLs before escaping for an output format."""
    try:
        scheme = urlsplit(url).scheme.lower()
    except ValueError:
        return None
    # Unsupported or malformed destinations remain visible as literal text.
    if scheme not in ("", "http", "https"):
        return None
    return quote(url, safe="/:?#[]@!$&'()*+,;=%")


def markdown_reference(ref):
    url = ref["url"]
    title = ref.get("title", url)
    label = markdown_text(title)
    destination = reference_destination(url)
    if destination is None:
        return label if title == url else f"{label} — {markdown_text(url)}"
    return f"[{label}](<{escape(destination, quote=False)}>)"


def html_reference(ref):
    url = ref["url"]
    title = ref.get("title", url)
    label = escape(title)
    destination = reference_destination(url)
    if destination is None:
        return label if title == url else f"{label} — {escape(url)}"
    return f'<a href="{escape(destination)}">{label}</a>'


def commitment_text(record, labels):
    """Keep recorded qualifications visible in both commitment ledgers."""
    statement, status = record["statement"], record["status"]
    if record.get("inferred") is True:
        statement += f" ({labels['inferred']})"
    if status == "not checked" and record.get("reason"):
        status += f" — {labels['not_checked_reason']}: {record['reason']}"
    return statement, status


def render_markdown(doc, lang):
    t = LABELS[lang]
    meta, findings = doc["meta"], doc.get("findings", [])
    by_sev, excluded = counts(findings)
    analysed = any(f["validation"]["method"] == "analysed" for f in findings)
    lines = [f"# {t['title']}: {markdown_text(meta.get('project', ''))}", ""]
    lines.append(" / ".join(f"{s} {by_sev[s]}" for s in SEVERITIES)
                 + f" · {t['excluded']} {excluded} · "
                 + (t["analysed_note"] if analysed else t["static_note"]))
    lines += ["", f"## {t['scope']}", "", "| | |", "|---|---|",
              markdown_row((t['project'], meta.get('project', ''))),
              markdown_row((t['scope_row'], meta.get('scope', ''))),
              markdown_row((t['revision'], meta.get('commit', 'UNKNOWN'))),
              markdown_row((t['date'], f"{meta.get('date', '')} / {meta.get('assessor', '')}")), ""]
    lines += [f"## {t['findings']}", ""]
    if not findings:
        lines += [t["none"], ""]
    for f in findings:
        v = f["validation"]
        lines.append(f"### {f['id']} [{f['severity']}][{f['confidence']}] {markdown_text(f['title'])}")
        lines.append("")
        for key in FIELDS:
            if key in f:
                lines.append(f"- **{t[key]}:** {markdown_text(f[key])}")
        lines.append(f"- **{t['verdict']}:** {v['verdict']} · **{t['method']}:** {v['method']}")
        if v.get("evidence"):
            lines.append(f"- **{t['evidence']}:** {markdown_text(v['evidence'])}")
        if "analysis" in f:
            a = f["analysis"]
            lines.append(f"- **{t['analysis']}:** {markdown_text(a['result'])} "
                         f"({markdown_text(a['tool'])}: {markdown_code(a['command'])})")
        lines.append(f"- **{t['status']}:** {f.get('status', 'Open')}")
        for ref in f.get("references", []):
            lines.append(f"- **{t['references']}:** {markdown_reference(ref)}")
        lines.append("")
    if doc.get("commitments"):
        lines += [f"## {t['commitments']}", "", "| ID | | Source | Status |", "|---|---|---|---|"]
        for r in doc["commitments"]:
            statement, status = commitment_text(r, t)
            cells = (r["id"], statement, r["source"], status)
            lines.append(markdown_row(cells))
        lines.append("")
    lines += [f"## {t['perspectives']}", "", "| | Status | Note |", "|---|---|---|"]
    for p in doc.get("perspectives", []):
        lines.append(markdown_row((p['name'], p['status'], p['note'])))
    lines.append("")
    for key in ("checked_ok", "limitations", "decisions", "next_steps"):
        lines += [f"## {t[key]}", ""]
        lines += [f"- {markdown_item(item)}" for item in doc.get(key, [])] or [t["none"]]
        lines.append("")
    return "\n".join(lines)


CSS = """
:root{--bg:#fafaf9;--fg:#1c1917;--muted:#57534e;--card:#fff;--line:#e7e5e4;
--high:#b91c1c;--medium:#b45309;--low:#1d4ed8;--info:#57534e}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#1c1917;--fg:#f5f5f4;
--muted:#a8a29e;--card:#292524;--line:#44403c;--high:#f87171;--medium:#fbbf24;--low:#93c5fd;--info:#d6d3d1}}
:root[data-theme="dark"]{--bg:#1c1917;--fg:#f5f5f4;--muted:#a8a29e;--card:#292524;--line:#44403c;
--high:#f87171;--medium:#fbbf24;--low:#93c5fd;--info:#d6d3d1}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 system-ui,sans-serif}
main{max-width:1040px;margin:0 auto;padding:24px 16px}
h1{font-size:1.5rem;margin:0 0 4px}h2{font-size:1.1rem;margin:28px 0 8px}
.muted{color:var(--muted)}.cards{display:flex;flex-wrap:wrap;gap:8px;margin:16px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 14px;min-width:96px}
.card b{display:block;font-size:1.4rem}
.High{color:var(--high)}.Medium{color:var(--medium)}.Low{color:var(--low)}.Info{color:var(--info)}
details{background:var(--card);border:1px solid var(--line);border-radius:8px;margin:8px 0;padding:8px 12px}
summary{cursor:pointer;font-weight:600}dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 12px}
dt{color:var(--muted)}dd{margin:0;overflow-wrap:anywhere}
table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid var(--line);padding:6px;text-align:left;vertical-align:top}
button{background:var(--card);color:var(--fg);border:1px solid var(--line);border-radius:6px;padding:4px 10px;cursor:pointer}
button[aria-pressed="true"]{border-color:var(--fg)}
"""

JS = """
document.querySelectorAll('[data-filter]').forEach(b=>b.addEventListener('click',()=>{
const s=b.dataset.filter;document.querySelectorAll('[data-filter]').forEach(x=>x.setAttribute('aria-pressed',x===b));
document.querySelectorAll('details[data-sev]').forEach(d=>{d.hidden=s!=='all'&&d.dataset.sev!==s});}));
"""


def render_html(doc, lang):
    t = LABELS[lang]
    meta, findings = doc["meta"], doc.get("findings", [])
    by_sev, excluded = counts(findings)
    e = lambda v: escape(as_text(v))  # noqa: E731
    out = [f"<!doctype html><html lang='{lang}'><head><meta charset='utf-8'>",
           "<meta name='viewport' content='width=device-width,initial-scale=1'>",
           f"<title>{e(t['title'])}</title><style>{CSS}</style></head><body><main>",
           f"<h1>{e(t['title'])}: {e(meta.get('project', ''))}</h1>",
           f"<p class='muted'>{e(meta.get('scope', ''))} · {e(meta.get('commit', 'UNKNOWN'))} · "
           f"{e(meta.get('date', ''))} · {e(meta.get('assessor', ''))}</p><div class='cards'>"]
    for s in SEVERITIES:
        out.append(f"<div class='card'><span class='{s}'>{s}</span><b>{by_sev[s]}</b></div>")
    out.append(f"<div class='card'><span>{e(t['excluded'])}</span><b>{excluded}</b></div></div>")
    out.append(f"<h2>{e(t['findings'])}</h2><p><button data-filter='all' aria-pressed='true'>"
               f"{e(t['all'])}</button> "
               + " ".join(f"<button data-filter='{s}' aria-pressed='false'>{s}</button>" for s in SEVERITIES)
               + "</p>")
    if not findings:
        out.append(f"<p>{e(t['none'])}</p>")
    for f in findings:
        v = f["validation"]
        rows = [(t[k], f[k]) for k in FIELDS if k in f]
        rows += [(t["verdict"], f"{v['verdict']} ({v['method']})"), (t["evidence"], v.get("evidence", "")),
                 (t["status"], f.get("status", "Open"))]
        if "analysis" in f:
            a = f["analysis"]
            rows.append((t["analysis"], f"{a['result']} — {a['tool']}: {a['command']}"))
        out.append(f"<details data-sev='{f['severity']}'><summary><span class='{f['severity']}'>"
                   f"{f['severity']}</span> {e(f['id'])} {e(f['title'])} "
                   f"<span class='muted'>· {e(f['confidence'])} · {e(f['category'])}</span></summary><dl>"
                   + "".join(f"<dt>{e(k)}</dt><dd>{e(val)}</dd>" for k, val in rows)
                   + "".join(f"<dt>{e(t['references'])}</dt><dd>{html_reference(ref)}</dd>"
                             for ref in f.get("references", []))
                   + "</dl></details>")
    if doc.get("commitments"):
        out.append(f"<h2>{e(t['commitments'])}</h2><table>")
        for r in doc["commitments"]:
            statement, status = commitment_text(r, t)
            out.append(f"<tr><td>{e(r['id'])}</td><td>{e(statement)}</td>"
                       f"<td>{e(r['source'])}</td><td>{e(status)}</td></tr>")
        out.append("</table>")
    recorded = {p["name"]: p for p in doc.get("perspectives", [])}
    out.append(f"<h2>{e(t['perspectives'])}</h2><table>")
    for name in PERSPECTIVES:
        p = recorded.get(name, {"status": "—", "note": ""})
        out.append(f"<tr><td>{e(name)}</td><td>{e(p['status'])}</td><td>{e(p['note'])}</td></tr>")
    out.append("</table>")
    for key in ("checked_ok", "limitations", "decisions", "next_steps"):
        items = doc.get(key, [])
        out.append(f"<h2>{e(t[key])}</h2>"
                   + ("<ul>" + "".join(f"<li>{e(i)}</li>" for i in items) + "</ul>" if items
                      else f"<p>{e(t['none'])}</p>"))
    out.append(f"</main><script>{JS}</script></body></html>")
    return "".join(out)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("findings")
    parser.add_argument("--out", required=True)
    parser.add_argument("--lang", choices=("ja", "en"))
    args = parser.parse_args(argv)
    try:
        doc = read_json(args.findings)
        validate(doc, complete=True)
    except SchemaError as exc:
        print(f"schema: {exc}", file=sys.stderr)
        return 2
    lang = args.lang or doc["meta"]["lang"]
    # Finish both renderers before creating or replacing either output.
    markdown = render_markdown(doc, lang)
    html = render_html(doc, lang)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.md").write_text(markdown, encoding="utf-8")
    (out / "dashboard.html").write_text(html, encoding="utf-8")
    print(f"wrote {out / 'dashboard.html'} and {out / 'report.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
