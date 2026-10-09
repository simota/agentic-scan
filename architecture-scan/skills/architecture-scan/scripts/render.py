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
from string import punctuation
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from findings import (EXCLUDED, PERSPECTIVES, SEVERITIES, SchemaError,  # noqa: E402
                      read_json, validate)

LABELS = {
    "en": {
        "title": "Architecture assessment", "scope": "Scope and method",
        "findings": "Findings", "rules": "Design rules", "perspectives": "Perspective coverage",
        "checked_ok": "Checked and sound", "limitations": "What could not be checked",
        "decisions": "Decisions for a human", "next_steps": "Next steps", "excluded": "Excluded",
        "all": "All", "none": "None.",
        "location": "location", "scenario": "scenario", "blast_radius": "blast radius",
        "trace": "trace", "contrast": "contrast", "impact": "what happens", "rule": "rule",
        "fix": "fix direction", "guard": "fitness function", "verdict": "recorded verdict",
        "method": "verification", "evidence": "evidence", "analysis": "analysis",
        "references": "references", "status": "status", "reason": "Reason",
        "static_note": "Static review; no code was changed or executed beyond read-only analysis.",
        "analysed_note": "Static review plus read-only tool analysis (dependency graph, history).",
        "project": "System", "scope_row": "Scope", "revision": "Revision", "date": "Date / assessor",
    },
    "ja": {
        "title": "アーキテクチャ診断", "scope": "対象と方法",
        "findings": "検出事項", "rules": "設計ルール", "perspectives": "観点のカバレッジ",
        "checked_ok": "確認して問題なかった項目", "limitations": "確認できなかったこと",
        "decisions": "人が判断すべき事項", "next_steps": "次の作業", "excluded": "除外",
        "all": "すべて", "none": "なし。",
        "location": "場所", "scenario": "シナリオ", "blast_radius": "影響範囲",
        "trace": "追跡", "contrast": "対照", "impact": "何が起きるか", "rule": "ルール",
        "fix": "修正方針", "guard": "適合性チェック", "verdict": "検証判定",
        "method": "検証の根拠", "evidence": "根拠", "analysis": "解析",
        "references": "参考", "status": "ステータス", "reason": "理由",
        "static_note": "静的レビューのみ。読み取り専用の解析以外にコードの変更や実行はしていない。",
        "analysed_note": "静的レビューに加え、読み取り専用のツール解析（依存グラフ、変更履歴）を実施。",
        "project": "システム", "scope_row": "範囲", "revision": "リビジョン", "date": "診断日 / 診断者",
    },
}
FIELDS = ("location", "scenario", "blast_radius", "trace", "contrast", "impact", "rule",
          "fix", "guard")


def counts(findings):
    active = [f for f in findings if f["validation"]["verdict"] not in EXCLUDED]
    return {s: sum(f["severity"] == s for f in active) for s in SEVERITIES}, len(findings) - len(active)


def as_text(value):
    return ", ".join(value) if isinstance(value, list) else str(value)


def review_method(doc, lang):
    """Keep the recorded scope of analysis, including runs with no findings."""
    if doc["meta"].get("method"):
        return str(doc["meta"]["method"])
    analysed = any(f["validation"]["method"] == "analysed" or "analysis" in f
                   for f in doc.get("findings", []))
    return LABELS[lang]["analysed_note" if analysed else "static_note"]


def markdown_code(value):
    """Keep a literal command or code span intact, even with backticks."""
    value = as_text(value).replace("\r\n", "\n").replace("\r", "\n")
    literal = value.translate({ord(char): f"&#{ord(char)};" for char in punctuation + " \t"})
    literal = literal.replace("\n", "<br>")
    return f"<code>{literal}</code>"


def markdown_inline(value):
    """Keep recorded text in one GFM block while preserving inline Markdown."""
    value = as_text(value).replace("\r\n", "\n").replace("\r", "\n")

    def text(part):
        part = re.sub(r"(\\+)`", lambda m: m[1][:-1] + "&#96;" if len(m[1]) % 2 else m[0],
                      escape(part, quote=False))
        return (part.replace("\\", "&#92;")
                .replace("|", "&#124;").replace("\n", "<br>"))

    parts, end = [], 0
    # An odd backslash prefix escapes the opening backtick; delimiter lengths match.
    spans = r"(?<![\\`])((?:\\\\)*)(`+)(?!`)(.+?)(?<!`)\2(?!`)"
    for match in re.finditer(spans, value, re.DOTALL):
        parts.append(text(value[end:match.start()] + match[1]))
        code = match[3].replace("\n", " ")
        if code.startswith(" ") and code.endswith(" ") and code.strip(" "):
            code = code[1:-1]  # CommonMark code spans trim one surrounding space.
        parts.append(markdown_code(code))
        end = match.end()
    parts.append(text(value[end:]))
    return "".join(parts)


def markdown_table_cell(value):
    """Keep pipes and line breaks inside a GFM cell, including in code spans."""
    return markdown_inline(value)


def markdown_reference(ref):
    title = markdown_inline(ref.get("title", ref["url"]))
    title = title.replace("[", "&#91;").replace("]", "&#93;")
    # Angle destinations allow parentheses; entities keep input from ending
    # the destination or escaping its closing delimiter.
    url = (escape(ref["url"], quote=False).replace("\\", "&#92;")
           .replace("\r", "&#13;").replace("\n", "&#10;"))
    return f"[{title}](<{url}>)"


def render_markdown(doc, lang):
    t = LABELS[lang]
    cell = markdown_table_cell
    text = markdown_inline
    meta, findings = doc["meta"], doc.get("findings", [])
    by_sev, excluded = counts(findings)
    lines = [f"# {t['title']}: {text(meta.get('project', ''))}", ""]
    lines.append(" / ".join(f"{s} {by_sev[s]}" for s in SEVERITIES)
                 + f" · {t['excluded']} {excluded} · "
                 + text(review_method(doc, lang)))
    lines += ["", f"## {t['scope']}", "", "| | |", "|---|---|",
              f"| {t['project']} | {cell(meta.get('project', ''))} |",
              f"| {t['scope_row']} | {cell(meta.get('scope', ''))} |",
              f"| {t['revision']} | {cell(meta.get('commit', 'UNKNOWN'))} |",
              f"| {t['date']} | {cell(meta.get('date', ''))} / {cell(meta.get('assessor', ''))} |", ""]
    lines += [f"## {t['findings']}", ""]
    if not findings:
        lines += [t["none"], ""]
    for f in findings:
        v = f["validation"]
        lines.append(f"### {f['id']} [{f['severity']}][{f['confidence']}] {text(f['title'])}")
        lines.append("")
        for key in FIELDS:
            if key in f:
                lines.append(f"- **{t[key]}:** {text(f[key])}")
        lines.append(f"- **{t['verdict']}:** {v['verdict']} · **{t['method']}:** {v['method']}")
        if v.get("evidence"):
            lines.append(f"- **{t['evidence']}:** {text(v['evidence'])}")
        if "analysis" in f:
            a = f["analysis"]
            lines.append(f"- **{t['analysis']}:** {text(a['result'])} "
                         f"({text(a['tool'])}: {markdown_code(a['command'])})")
        lines.append(f"- **{t['status']}:** {f.get('status', 'Open')}")
        for ref in f.get("references", []):
            lines.append(f"- **{t['references']}:** {markdown_reference(ref)}")
        lines.append("")
    if doc.get("rules"):
        lines += [f"## {t['rules']}", "", "| ID | | Source | Status |", "|---|---|---|---|"]
        for r in doc["rules"]:
            status = r["status"]
            if r.get("reason"):
                status += f"\n{t['reason']}: {r['reason']}"
            lines.append(f"| {cell(r['id'])} | {cell(r['statement'])} | {cell(r['source'])} | {cell(status)} |")
        lines.append("")
    lines += [f"## {t['perspectives']}", "", "| | Status | Note |", "|---|---|---|"]
    for p in doc.get("perspectives", []):
        lines.append(f"| {cell(p['name'])} | {cell(p['status'])} | {cell(p['note'])} |")
    lines.append("")
    for key in ("checked_ok", "limitations", "decisions", "next_steps"):
        lines += [f"## {t[key]}", ""]
        lines += [f"- {text(item)}" for item in doc.get(key, [])] or [t["none"]]
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
           f"{e(meta.get('date', ''))} · {e(meta.get('assessor', ''))}</p>",
           f"<p class='muted'>{e(review_method(doc, lang))}</p><div class='cards'>"]
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
        for ref in f.get("references", []):
            title, url = ref.get("title", ref["url"]), ref["url"]
            rows.append((t["references"], f"{title}: {url}" if title != url else url))
        out.append(f"<details data-sev='{f['severity']}'><summary><span class='{f['severity']}'>"
                   f"{f['severity']}</span> {e(f['id'])} {e(f['title'])} "
                   f"<span class='muted'>· {e(f['confidence'])} · {e(f['category'])}</span></summary><dl>"
                   + "".join(f"<dt>{e(k)}</dt><dd>{e(val)}</dd>" for k, val in rows) + "</dl></details>")
    if doc.get("rules"):
        out.append(f"<h2>{e(t['rules'])}</h2><table>")
        for r in doc["rules"]:
            status = e(r["status"])
            if r.get("reason"):
                status += f"<br>{e(t['reason'])}: {e(r['reason'])}"
            out.append(f"<tr><td>{e(r['id'])}</td><td>{e(r['statement'])}</td>"
                       f"<td>{e(r['source'])}</td><td>{status}</td></tr>")
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
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.md").write_text(render_markdown(doc, lang), encoding="utf-8")
    (out / "dashboard.html").write_text(render_html(doc, lang), encoding="utf-8")
    print(f"wrote {out / 'dashboard.html'} and {out / 'report.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
