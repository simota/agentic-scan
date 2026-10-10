#!/usr/bin/env python3
"""Render findings.json into dashboard.html and report.md.

    python3 render.py FINDINGS --out DIR [--lang ja|en]

Both outputs are derived from the one record; neither adds facts of its own.
`dashboard.html` is self-contained and works offline. `report.md` holds the
scope, counts, findings, commitments, perspective coverage, sound items,
limitations, decisions and next steps; the chat summary in `reference/report.md`
is written by the agent, not rendered.

Exit codes: 0 written, 1 an output could not be saved, 2 the record does not
match the schema (the field is named on stderr).
"""
import argparse
from html import escape
from pathlib import Path
import re
import sys
from urllib.parse import quote, urlsplit

# Importing the local helpers must not write bytecode into the skill tree.
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from findings import (PERSPECTIVES, SEVERITIES, VERDICTS, SchemaError,  # noqa: E402
                      prepare_cli, read_json, record_problems, validate)
from findings import excluded as is_excluded  # noqa: E402
from output_io import write_utf8_files  # noqa: E402

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
        "verdict_counts": "Verdict counts",
        "references": "references", "status": "status", "review_method": "Review method",
        "inferred": "inferred", "not_checked_reason": "reason",
        "static_note": "Static review; no personal data was read from any data store.",
        "analysed_note": "Static review plus read-only tool analysis (data-flow or schema scan, history); no personal data was read.",
        "project": "System", "scope_row": "Scope", "revision": "Revision", "date": "Date / assessor",
        "commitment_columns": ("ID", "Commitment", "Family", "Source", "Status"),
        "conditions": "conditions",
        "disclaimer": "Technical review of source code, not legal advice; it does not state "
                      "whether the application complies with any law.",
        "perspective": "perspective",
        "perspective_columns": ("Perspective", "Status", "Note"),
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
        "verdict_counts": "検証判定別の件数",
        "references": "参考", "status": "ステータス", "review_method": "診断方法",
        "inferred": "推定", "not_checked_reason": "未確認の理由",
        "static_note": "静的レビューのみ。データストアから個人データは一切読み取っていない。",
        "analysed_note": "静的レビューに加え、読み取り専用のツール解析（データフロー・スキーマの走査、変更履歴）を実施。個人データは読み取っていない。",
        "project": "システム", "scope_row": "範囲", "revision": "リビジョン", "date": "診断日 / 診断者",
        "commitment_columns": ("ID", "約束", "分類", "出典", "ステータス"),
        "conditions": "前提条件",
        "disclaimer": "ソースコードの技術的なレビューであり、法的見解ではない。"
                      "アプリケーションが法令に適合しているかどうかは述べていない。",
        "perspective": "観点",
        "perspective_columns": ("観点", "ステータス", "メモ"),
    },
}
FIELDS = ("location", "data", "subjects", "flow", "contrast", "impact", "conditions",
          "commitment", "fix", "guard")


def counts(findings):
    active = [f for f in findings if not is_excluded(f)]
    return {s: sum(f["severity"] == s for f in active) for s in SEVERITIES}, len(findings) - len(active)


def verdict_summary(findings):
    """Show every recorded verdict, including exclusions and zero counts."""
    return " / ".join(f"{v} {sum(f['validation']['verdict'] == v for f in findings)}"
                      for v in VERDICTS)


def as_text(value):
    return ", ".join(value) if isinstance(value, list) else str(value)


def shown(value):
    """Blank optional strings add no row or label to either report."""
    return bool(as_text(value).strip())


def finding_fields(f):
    """The perspective (with its hunt step) leads the recorded fields."""
    step = f.get("step", "")
    perspective = f"{f['category']} ({step.strip()})" if step.strip() else f["category"]
    return [("perspective", perspective)] + [(key, f[key]) for key in FIELDS
                                             if key in f and shown(f[key])]


def revision(meta):
    commit = meta.get("commit", "")
    return commit if commit.strip() else "UNKNOWN"


def perspective_rows(doc):
    """List every perspective in the reference order in both reports."""
    recorded = {p["name"]: p for p in doc.get("perspectives", [])}
    return [(name, recorded.get(name, {}).get("status", "—"), recorded.get(name, {}).get("note", ""))
            for name in PERSPECTIVES]


def reference_title(ref):
    """A blank title must not hide the link; fall back to the URL."""
    title = ref.get("title", "")
    return title if title.strip() else ref["url"]


MARKDOWN_ESCAPES = str.maketrans({c: "\\" + c for c in "\\`*_[]|~#"})


# URLs written in prose. GFM links them automatically but keeps our escape
# backslashes in the target, so they are written as explicit links instead.
URL_TOKEN = re.compile(r"(?<![\w.@/])(?:https?://|www\.)[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+")
URL_TRAILING = ".,;:!?'\"*_~"


def _literal(text):
    return escape(text, quote=False).translate(MARKDOWN_ESCAPES)


def _prose_url(url):
    """Trim trailing punctuation the way GFM does; return '' when nothing is left."""
    while url and (url[-1] in URL_TRAILING
                   or (url[-1] == ")" and url.count(")") > url.count("("))):
        url = url[:-1]
    return url if re.search(r"[/.][A-Za-z0-9]", url.split("//", 1)[-1][1:] or "") else ""


def markdown_text(value, links=True):
    """Keep prose literal inside headings, inline text and table cells.

    With `links`, URLs become explicit links whose targets keep their spelling.
    Link labels pass `links=False`, because a link cannot contain another link.
    """
    text = as_text(value).replace("\r\n", "\n").replace("\r", "\n")
    parts, pos = [], 0
    for match in URL_TOKEN.finditer(text) if links else ():
        url = _prose_url(match.group())
        if not url:
            continue
        parts.append(_literal(text[pos:match.start()]))
        # A bracketed link, not an autolink: CommonMark renderers differ on
        # decoding `&amp;` inside autolinks, but agree inside link destinations.
        target = escape(("http://" if url.startswith("www.") else "") + url, quote=False)
        parts.append(f"[{_literal(url)}](<{target}>)")
        pos = match.start() + len(url)
    parts.append(_literal(text[pos:]))
    # Add our own breaks only after escaping the supplied HTML and Markdown.
    return "".join(parts).replace("\n", "<br>")


def markdown_cell(value):
    """Keep literal text and line breaks inside one Markdown table cell."""
    return markdown_text(value)


def markdown_row(values):
    return "| " + " | ".join(markdown_cell(value) for value in values) + " |"


def markdown_item(value):
    """Keep leading whitespace and list markers from starting Markdown blocks."""
    text = markdown_text(value)
    text = re.sub(r"^([ \t]*)([-+])", r"\1\\\2", text)
    text = re.sub(r"^([ \t]*[0-9]{1,9})([.)])(?=\s|$)", r"\1\\\2", text)
    # Character references preserve spaces and tabs without making the list
    # body an indented code block. Add them after escaping supplied markup.
    return re.sub(r"^[ \t]+", lambda match: "".join(f"&#{ord(c)};" for c in match[0]), text)


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
    title = reference_title(ref)
    label = markdown_text(title, links=False)
    destination = reference_destination(url)
    if destination is None:
        return label if title == url else f"{label} — {markdown_text(url, links=False)}"
    return f"[{label}](<{escape(destination, quote=False)}>)"


def html_reference(ref):
    url = ref["url"]
    title = reference_title(ref)
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


def review_method(meta, findings, labels):
    """Prefer the recorded assessment method, including reviews with no findings."""
    method = meta.get("method", "")
    if method.strip():
        return method
    analysed = any(f["validation"]["method"] == "analysed" for f in findings)
    return labels["analysed_note"] if analysed else labels["static_note"]


def render_markdown(doc, lang):
    t = LABELS[lang]
    meta, findings = doc["meta"], doc.get("findings", [])
    by_sev, excluded = counts(findings)
    method = review_method(meta, findings, t)
    lines = [f"# {t['title']}: {markdown_text(meta.get('project', ''))}", ""]
    lines.append(" / ".join(f"{s} {by_sev[s]}" for s in SEVERITIES)
                 + f" · {t['excluded']} {excluded} · "
                 + markdown_text(method))
    lines += ["", f"**{t['verdict_counts']}:** {verdict_summary(findings)}", "", f"_{t['disclaimer']}_"]
    lines += ["", f"## {t['scope']}", "", "| | |", "|---|---|",
              markdown_row((t['project'], meta.get('project', ''))),
              markdown_row((t['scope_row'], meta.get('scope', ''))),
              markdown_row((t['revision'], revision(meta))),
              markdown_row((t['review_method'], method)),
              markdown_row((t['date'], f"{meta.get('date', '')} / {meta.get('assessor', '')}")), ""]
    lines += [f"## {t['findings']}", ""]
    if not findings:
        lines += [t["none"], ""]
    for f in findings:
        v = f["validation"]
        note = f" ({t['excluded']})" if is_excluded(f) else ""
        lines.append(f"### {f['id']} [{f['severity']}][{f['confidence']}] "
                     f"{markdown_text(f['title'])}{note}")
        lines.append("")
        for key, value in finding_fields(f):
            lines.append(f"- **{t[key]}:** {markdown_text(value)}")
        lines.append(f"- **{t['verdict']}:** {v['verdict']} · **{t['method']}:** {v['method']}")
        if shown(v.get("evidence", "")):
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
        lines += [f"## {t['commitments']}", "", markdown_row(t["commitment_columns"]), "|---|---|---|---|---|"]
        for r in doc["commitments"]:
            statement, status = commitment_text(r, t)
            cells = (r["id"], statement, r.get("family", ""), r["source"], status)
            lines.append(markdown_row(cells))
        lines.append("")
    lines += [f"## {t['perspectives']}", "", markdown_row(t["perspective_columns"]), "|---|---|---|"]
    for row in perspective_rows(doc):
        lines.append(markdown_row(row))
    lines.append("")
    for key in ("checked_ok", "limitations", "decisions", "next_steps"):
        lines += [f"## {t[key]}", ""]
        lines += [f"- {markdown_item(item)}" for item in doc.get(key, [])] or [t["none"]]
        lines.append("")
    return "\n".join(lines)


CSS = """
:root{color-scheme:light dark;--bg:#fafaf9;--fg:#1c1917;--muted:#57534e;--card:#fff;--line:#e7e5e4;
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
dt{color:var(--muted)}dd{margin:0;overflow-wrap:anywhere;white-space:pre-line}
li{white-space:pre-line}
pre{margin:4px 0 0;white-space:pre-wrap;overflow-wrap:anywhere}
table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid var(--line);padding:6px;text-align:left;vertical-align:top;overflow-wrap:anywhere}
td{white-space:pre-line}
button{background:var(--card);color:var(--fg);border:1px solid var(--line);border-radius:6px;padding:4px 10px;cursor:pointer}
button[aria-pressed="true"]{border-color:var(--fg)}
"""

JS = """
document.querySelectorAll('[data-filter]').forEach(b=>b.addEventListener('click',()=>{
const s=b.dataset.filter;document.querySelectorAll('[data-filter]').forEach(x=>x.setAttribute('aria-pressed',x===b));
let shown=0;document.querySelectorAll('details[data-sev]').forEach(d=>{d.hidden=s!=='all'&&d.dataset.sev!==s;shown+=!d.hidden});
const empty=document.querySelector('[data-empty]');if(empty)empty.hidden=shown>0;}));
"""


def html_head(columns):
    return "<thead><tr>" + "".join(f"<th>{escape(c)}</th>" for c in columns) + "</tr></thead>"


def render_html(doc, lang):
    t = LABELS[lang]
    meta, findings = doc["meta"], doc.get("findings", [])
    by_sev, excluded = counts(findings)
    method = review_method(meta, findings, t)
    e = lambda v: escape(as_text(v))  # noqa: E731
    out = [f"<!doctype html><html lang='{lang}'><head><meta charset='utf-8'>",
           "<meta name='viewport' content='width=device-width,initial-scale=1'>",
           f"<title>{e(t['title'])}: {e(meta.get('project', ''))}</title>"
           f"<style>{CSS}</style></head><body><main>",
           f"<h1>{e(t['title'])}: {e(meta.get('project', ''))}</h1>",
           "<div class='cards'>"]
    for s in SEVERITIES:
        out.append(f"<div class='card'><span class='{s}'>{s}</span><b>{by_sev[s]}</b></div>")
    out.append(f"<div class='card'><span>{e(t['excluded'])}</span><b>{excluded}</b></div></div>")
    out.append(f"<p><strong>{e(t['verdict_counts'])}:</strong> {e(verdict_summary(findings))}</p>")
    out.append(f"<p class='muted'>{e(t['disclaimer'])}</p>")
    scope_rows = [(t['project'], meta.get('project', '')),
                  (t['scope_row'], meta.get('scope', '')),
                  (t['revision'], revision(meta)),
                  (t['review_method'], method),
                  (t['date'], f"{meta.get('date', '')} / {meta.get('assessor', '')}")]
    out.append(f"<h2>{e(t['scope'])}</h2><dl>"
               + "".join(f"<dt>{e(k)}</dt><dd>{e(val)}</dd>" for k, val in scope_rows)
               + "</dl>")
    out.append(f"<h2>{e(t['findings'])}</h2><p><button data-filter='all' aria-pressed='true'>"
               f"{e(t['all'])}</button> "
               + " ".join(f"<button data-filter='{s}' aria-pressed='false'>{s}</button>" for s in SEVERITIES)
               + (f" <button data-filter='excluded' aria-pressed='false'>{e(t['excluded'])}</button>"
                  if excluded else "")
               + "</p>")
    # Shown when there are no findings, and by the filter when none match.
    out.append(f"<p data-empty{'' if not findings else ' hidden'}>{e(t['none'])}</p>")
    for f in findings:
        v = f["validation"]
        rows = [(t[k], value) for k, value in finding_fields(f)]
        rows.append((t["verdict"], f"{v['verdict']} ({v['method']})"))
        if shown(v.get("evidence", "")):
            rows.append((t["evidence"], v["evidence"]))
        analysis_html = ""
        if "analysis" in f:
            a = f["analysis"]
            analysis_html = (f"<dt>{e(t['analysis'])}</dt><dd>{e(a['result'])} — {e(a['tool'])}:"
                             f"<pre><code>{e(a['command'])}</code></pre></dd>")
        excluded_finding = is_excluded(f)
        # Excluded findings are not counted under their severity, so they are
        # filtered separately and labelled in the summary as well.
        out.append(f"<details data-sev='{'excluded' if excluded_finding else f['severity']}'>"
                   f"<summary><span class='{f['severity']}'>"
                   f"{f['severity']}</span> {e(f['id'])} {e(f['title'])} "
                   f"· {e(v['verdict'])}"
                   + (f" ({e(t['excluded'])})" if excluded_finding else "")
                   + f" <span class='muted'>· {e(f['confidence'])} · "
                   f"{e(f['category'])}</span></summary><dl>"
                   + "".join(f"<dt>{e(k)}</dt><dd>{e(val)}</dd>" for k, val in rows)
                   + analysis_html
                   + f"<dt>{e(t['status'])}</dt><dd>{e(f.get('status', 'Open'))}</dd>"
                   + "".join(f"<dt>{e(t['references'])}</dt><dd>{html_reference(ref)}</dd>"
                             for ref in f.get("references", []))
                   + "</dl></details>")
    if doc.get("commitments"):
        out.append(f"<h2>{e(t['commitments'])}</h2><table>{html_head(t['commitment_columns'])}")
        for r in doc["commitments"]:
            statement, status = commitment_text(r, t)
            cells = (r["id"], statement, r.get("family", ""), r["source"], status)
            out.append("<tr>" + "".join(f"<td>{e(cell)}</td>" for cell in cells) + "</tr>")
        out.append("</table>")
    out.append(f"<h2>{e(t['perspectives'])}</h2><table>{html_head(t['perspective_columns'])}")
    for row in perspective_rows(doc):
        out.append("<tr>" + "".join(f"<td>{e(cell)}</td>" for cell in row) + "</tr>")
    out.append("</table>")
    for key in ("checked_ok", "limitations", "decisions", "next_steps"):
        items = doc.get(key, [])
        out.append(f"<h2>{e(t[key])}</h2>"
                   + ("<ul>" + "".join(f"<li>{e(i)}</li>" for i in items) + "</ul>" if items
                      else f"<p>{e(t['none'])}</p>"))
    out.append(f"</main><script>{JS}</script></body></html>")
    return "".join(out)


def main(argv=None):
    prepare_cli()
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
    try:
        out.mkdir(parents=True, exist_ok=True)
        write_utf8_files({out / "report.md": markdown, out / "dashboard.html": html},
                         protected_paths=(args.findings,))
    except (OSError, UnicodeError) as exc:
        print(f"write failed: could not save reports ({type(exc).__name__})", file=sys.stderr)
        return 1
    print(f"wrote {out / 'dashboard.html'} and {out / 'report.md'}")
    # Rendering a draft is allowed; say now what `findings.py check` will refuse.
    for problem in record_problems(doc):
        print(f"warning: findings.py check will refuse: {problem}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
