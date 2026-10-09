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
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from findings import (EXCLUDED, PERSPECTIVES, SEVERITIES, SchemaError,  # noqa: E402
                      read_json, validate)

LABELS = {
    "en": {
        "title": "Performance assessment", "summary": "Summary", "scope": "Scope and method",
        "findings": "Findings", "budgets": "Performance budgets", "perspectives": "Perspective coverage",
        "checked_ok": "Checked and sound", "limitations": "What could not be checked",
        "decisions": "Decisions for a human", "next_steps": "Next steps", "excluded": "Excluded",
        "severity": "Severity", "count": "Count", "all": "All", "none": "None.",
        "location": "location", "workload": "workload", "scale_driver": "scale driver",
        "cost_model": "cost model", "request": "steps", "contrast": "contrast",
        "impact": "what happens", "verdict": "recorded verdict", "method": "verification",
        "evidence": "evidence", "measurement": "measurement", "fix": "fix direction",
        "regression_test": "regression test", "references": "references", "status": "status",
        "budget": "budget", "static_note": "Static review; no load was sent to any deployed environment.",
        "measured_note": "Static review plus explicitly authorized local measurements.",
        "project": "System", "revision": "Revision", "date": "Date / assessor",
    },
    "ja": {
        "title": "パフォーマンス診断", "summary": "サマリー", "scope": "対象と方法",
        "findings": "検出事項", "budgets": "性能バジェット", "perspectives": "観点のカバレッジ",
        "checked_ok": "確認して問題なかった項目", "limitations": "確認できなかったこと",
        "decisions": "人が判断すべき事項", "next_steps": "次の作業", "excluded": "除外",
        "severity": "深刻度", "count": "件数", "all": "すべて", "none": "なし。",
        "location": "場所", "workload": "ワークロード", "scale_driver": "規模の要因",
        "cost_model": "コストモデル", "request": "再現手順", "contrast": "対照",
        "impact": "何が起きるか", "verdict": "検証判定", "method": "検証の根拠",
        "evidence": "根拠", "measurement": "計測", "fix": "修正方針",
        "regression_test": "回帰テスト", "references": "参考", "status": "ステータス",
        "budget": "バジェット", "static_note": "静的レビューのみ。稼働中の環境には負荷を一切かけていない。",
        "measured_note": "静的レビューに加え、明示的に許可されたローカル計測を実施。",
        "project": "システム", "revision": "リビジョン", "date": "診断日 / 診断者",
    },
}
FIELDS = ("location", "workload", "scale_driver", "cost_model", "request", "contrast",
          "impact", "budget", "fix", "regression_test")


def counts(findings):
    active = [f for f in findings if f["validation"]["verdict"] not in EXCLUDED]
    return {s: sum(f["severity"] == s for f in active) for s in SEVERITIES}, len(findings) - len(active)


def as_text(value):
    return ", ".join(value) if isinstance(value, list) else str(value)


def render_markdown(doc, lang):
    t = LABELS[lang]
    meta, findings = doc["meta"], doc.get("findings", [])
    by_sev, excluded = counts(findings)
    measured = any(f["validation"]["method"] == "measured" for f in findings)
    lines = [f"# {t['title']}: {meta.get('project', '')}", ""]
    lines.append(" / ".join(f"{s} {by_sev[s]}" for s in SEVERITIES)
                 + f" · {t['excluded']} {excluded} · "
                 + (t["measured_note"] if measured else t["static_note"]))
    lines += ["", f"## {t['scope']}", "", "| | |", "|---|---|",
              f"| {t['project']} | {meta.get('project', '')} |",
              f"| Scope | {meta.get('scope', '')} |",
              f"| {t['revision']} | {meta.get('commit', 'UNKNOWN')} |",
              f"| {t['date']} | {meta.get('date', '')} / {meta.get('assessor', '')} |", ""]
    lines += [f"## {t['findings']}", ""]
    if not findings:
        lines += [t["none"], ""]
    for f in findings:
        v = f["validation"]
        lines.append(f"### {f['id']} [{f['severity']}][{f['confidence']}] {f['title']}")
        lines.append("")
        for key in FIELDS:
            if key in f:
                lines.append(f"- **{t[key]}:** {as_text(f[key])}")
        lines.append(f"- **{t['verdict']}:** {v['verdict']} · **{t['method']}:** {v['method']}")
        if v.get("evidence"):
            lines.append(f"- **{t['evidence']}:** {v['evidence']}")
        if "measurement" in f:
            m = f["measurement"]
            lines.append(f"- **{t['measurement']}:** {m['result']} (`{m['command']}`, {m['environment']})")
        lines.append(f"- **{t['status']}:** {f.get('status', 'Open')}")
        for ref in f.get("references", []):
            lines.append(f"- **{t['references']}:** [{ref.get('title', ref['url'])}]({ref['url']})")
        lines.append("")
    if doc.get("budgets"):
        lines += [f"## {t['budgets']}", "", "| ID | | Source | Status |", "|---|---|---|---|"]
        for b in doc["budgets"]:
            lines.append(f"| {b['id']} | {b['statement']} | {b['source']} | {b['status']} |")
        lines.append("")
    lines += [f"## {t['perspectives']}", "", "| | Status | Note |", "|---|---|---|"]
    for p in doc.get("perspectives", []):
        lines.append(f"| {p['name']} | {p['status']} | {p['note']} |")
    lines.append("")
    for key in ("checked_ok", "limitations", "decisions", "next_steps"):
        lines += [f"## {t[key]}", ""]
        lines += [f"- {item}" for item in doc.get(key, [])] or [t["none"]]
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
        if "measurement" in f:
            m = f["measurement"]
            rows.append((t["measurement"], f"{m['result']} — {m['command']} ({m['environment']})"))
        out.append(f"<details data-sev='{f['severity']}'><summary><span class='{f['severity']}'>"
                   f"{f['severity']}</span> {e(f['id'])} {e(f['title'])} "
                   f"<span class='muted'>· {e(f['confidence'])} · {e(f['category'])}</span></summary><dl>"
                   + "".join(f"<dt>{e(k)}</dt><dd>{e(val)}</dd>" for k, val in rows) + "</dl></details>")
    if doc.get("budgets"):
        out.append(f"<h2>{e(t['budgets'])}</h2><table>")
        for b in doc["budgets"]:
            out.append(f"<tr><td>{e(b['id'])}</td><td>{e(b['statement'])}</td>"
                       f"<td>{e(b['source'])}</td><td>{e(b['status'])}</td></tr>")
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
