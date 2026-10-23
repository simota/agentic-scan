#!/usr/bin/env python3
"""Render findings.json into dashboard.html and report.md.

    python3 render.py FINDINGS --out DIR [--lang ja|en]

Both outputs are derived from the one record; neither adds facts of its own.
`dashboard.html` is self-contained and works offline. `report.md` holds the
scope, counts, findings, commitments, perspective coverage, sound items,
limitations, decisions and next steps; the chat summary in `reference/report.md`
is written by the agent, not rendered.

Exit codes: 0 written, 1 an output could not be saved, 2 the record does not
match the schema (the field is named on stderr) or the command line is invalid.
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
from scan_report_kit import style as kit_style  # noqa: E402

LABELS = {
    "en": {
        "title": "Privacy assessment", "scope": "Scope and method",
        "brand": "privacy-scan", "theme": "Theme",
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
        "brand": "privacy-scan", "theme": "表示切替",
        "findings": "検出事項", "commitments": "プライバシー上の約束", "perspectives": "観点のカバレッジ",
        "checked_ok": "確認して問題なかった項目", "limitations": "確認できなかったこと",
        "decisions": "人が判断すべき事項", "next_steps": "次の作業", "excluded": "除外",
        "all": "すべて", "none": "なし。",
        "location": "場所", "data": "個人データ", "subjects": "データ主体",
        "flow": "データの流れ", "contrast": "対照", "impact": "何が起きるか", "commitment": "約束",
        "fix": "修正方針", "guard": "再発防止チェック", "verdict": "検証判定",
        "method": "検証方法", "evidence": "根拠", "analysis": "解析",
        "verdict_counts": "検証判定別の件数",
        "references": "参考", "status": "ステータス", "review_method": "診断方法",
        "inferred": "推定", "not_checked_reason": "理由",
        "static_note": "静的レビューのみ。データストアから個人データは一切読み取っていない。",
        "analysed_note": "静的レビューに加え、読み取り専用のツール解析（データフロー・スキーマの走査、変更履歴）を実施。個人データは読み取っていない。",
        "project": "システム", "scope_row": "範囲", "revision": "リビジョン", "date": "診断日 / 診断者",
        "commitment_columns": ("ID", "約束", "分類", "出典", "ステータス"),
        "conditions": "前提条件",
        # Enumerations shown in Japanese; perspective names keep the English name
        # used in `category` so findings and coverage can be matched.
        "terms": {
            "Data inventory and minimisation": "データの棚卸しと最小化",
            "Purpose and consent": "目的と同意",
            "Retention and deletion": "保持と削除",
            "Data subject rights": "データ主体の権利",
            "Third-party sharing": "第三者提供",
            "Logs, telemetry and errors": "ログ・テレメトリ・エラー",
            "Exposure to other actors": "他者への露出",
            "Storage protection": "保存時の保護",
            "Client-side tracking": "クライアント側のトラッキング",
            "Identifiers and pseudonymisation": "識別子と仮名化",
            "Non-production and derived copies": "本番以外の環境と派生コピー",
            "Location and transfers": "保存場所と移転",
            "applied": "適用", "partly applied": "一部適用", "N/A": "対象外",
            "not checked": "未確認", "holds": "守られている", "violated": "違反",
            "partly read": "一部のみ確認", "Open": "未対応", "Fixed": "修正済み",
            "Accepted": "受容",
        },
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


def finding_fields(f, labels):
    """The perspective (with its hunt step) leads the recorded fields."""
    step = f.get("step", "")
    category = perspective_name(labels, f["category"])
    perspective = f"{category} ({step.strip()})" if step.strip() else category
    return [("perspective", perspective)] + [(key, f[key]) for key in FIELDS
                                             if key in f and shown(f[key])]


def revision(meta):
    commit = meta.get("commit", "")
    return commit if commit.strip() else "UNKNOWN"


def perspective_rows(doc, labels):
    """List every perspective in the reference order in both reports."""
    recorded = {p["name"]: p for p in doc.get("perspectives", [])}
    return [(perspective_name(labels, name),
             term(labels, recorded.get(name, {}).get("status", "—")),
             recorded.get(name, {}).get("note", ""))
            for name in PERSPECTIVES]


def reference_title(ref):
    """A blank title must not hide the link; fall back to the URL."""
    title = ref.get("title", "")
    return title if title.strip() else ref["url"]


MARKDOWN_ESCAPES = str.maketrans({c: "\\" + c for c in "\\`*_[]|~#"})


# URLs written in prose. GFM links them automatically but keeps our escape
# backslashes in the target, so they are written as explicit links instead.
# GFM links a scheme in any case after anything but an ASCII letter (also
# directly after Japanese text, digits or '.'), and `www.` only at a word start.
URL_TOKEN = re.compile(r"(?:(?<![A-Za-z])(?i:https?)://|(?<![\w.@/])www\.)"
                       r"[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+")
URL_TRAILING = ".,;:!?'\"*_~"
# What GFM would still autolink in text that is not an explicit link: `ftp://`
# and the URLs `_prose_url` declines (a `www.<placeholder>`, a dotless or
# non-ASCII host, `www.` after `_`). An escaped colon or dot keeps them literal
# text, as other unsupported schemes are.
AUTOLINK_START = re.compile(r"(?<![A-Za-z])(?i:ftp|https?)(?=://)|(?<![A-Za-z0-9])www(?=\.)")


def _literal(text, in_link=False):
    text = escape(text, quote=False).translate(MARKDOWN_ESCAPES)
    # Link text is never autolinked, so it keeps its spelling.
    return text if in_link else AUTOLINK_START.sub(lambda m: m.group() + "\\", text)


def _prose_url(url):
    """Trim trailing punctuation the way GFM does; return '' when nothing is left."""
    while url and (url[-1] in URL_TRAILING
                   or (url[-1] == ")" and url.count(")") > url.count("("))):
        url = url[:-1]
    # GFM links only a host with a dot; a dotless one stays literal whatever follows.
    authority = re.split(r"[/?#]", url.split("//", 1)[-1], maxsplit=1)[0]
    host = authority.rpartition("@")[2].partition(":")[0]
    return url if re.search(r"[A-Za-z0-9]\.[A-Za-z0-9]", host) else ""


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
        before = _literal(text[pos:match.start()])
        # `!` directly before the link would make it an image.
        parts.append(before[:-1] + "\\!" if before.endswith("!") else before)
        # A bracketed link, not an autolink: CommonMark renderers differ on
        # decoding `&amp;` inside autolinks, but agree inside link destinations.
        target = escape(("http://" if url.startswith("www.") else "") + url, quote=False)
        parts.append(f"[{_literal(url, in_link=True)}](<{target}>)")
        pos = match.start() + len(url)
    parts.append(_literal(text[pos:], in_link=not links))
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
    destination = reference_destination(url)
    if destination is None:
        # Plain text, not a link label: URLs in it are linked like other prose.
        text = markdown_text(title)
        return text if title == url else f"{text} — {markdown_text(url)}"
    return f"[{markdown_text(title, links=False)}](<{escape(destination, quote=False)}>)"


def html_reference(ref):
    url = ref["url"]
    title = reference_title(ref)
    label = escape(title)
    destination = reference_destination(url)
    if destination is None:
        return label if title == url else f"{label} — {escape(url)}"
    return f'<a href="{escape(destination)}">{label}</a>'


def term(labels, value):
    """A recorded enumeration in the report language."""
    return labels.get("terms", {}).get(value, value)


def perspective_name(labels, name):
    translated = term(labels, name)
    return name if translated == name else f"{translated}（{name}）"


def commitment_text(record, labels):
    """Keep recorded qualifications visible in both commitment ledgers."""
    statement, status = record["statement"], term(labels, record["status"])
    if record.get("inferred") is True:
        statement += f" ({labels['inferred']})"
    if record.get("reason", "").strip():
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
        for key, value in finding_fields(f, t):
            lines.append(f"- **{t[key]}:** {markdown_text(value)}")
        lines.append(f"- **{t['verdict']}:** {v['verdict']} · **{t['method']}:** {v['method']}")
        if shown(v.get("evidence", "")):
            lines.append(f"- **{t['evidence']}:** {markdown_text(v['evidence'])}")
        if "analysis" in f:
            a = f["analysis"]
            lines.append(f"- **{t['analysis']}:** {markdown_text(a['result'])} "
                         f"({markdown_text(a['tool'])}: {markdown_code(a['command'])})")
        lines.append(f"- **{t['status']}:** {term(t, f.get('status', 'Open'))}")
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
    for row in perspective_rows(doc, t):
        lines.append(markdown_row(row))
    lines.append("")
    for key in ("checked_ok", "limitations", "decisions", "next_steps"):
        lines += [f"## {t[key]}", ""]
        lines += [f"- {markdown_item(item)}" for item in doc.get(key, [])] or [t["none"]]
        lines.append("")
    return "\n".join(lines)


# Rules for privacy-scan record types only, after the shared dashboard
# stylesheet (scan_report_kit/assets/dashboard.css, docs: scan-report-kit).
DASHBOARD_CSS = """
.filter-buttons{display:flex;gap:8px;flex-wrap:wrap;margin:0 0 12px}
button[aria-pressed="true"]{border-color:var(--text);background:var(--soft)}
.register{border-top:1.5px solid var(--text);border-bottom:1.5px solid var(--text)}
.register [data-empty]{color:var(--muted);padding:14px 4px;margin:0}
details[data-sev]{border-top:1px solid var(--line);padding:12px 4px 12px 16px;border-left:.6pt solid var(--line)}
details[data-sev]:first-of-type{border-top:0}
details[data-sev="High"]{border-left:2.4pt solid var(--high)}
details[data-sev="Medium"]{border-left:1.2pt solid var(--medium)}
details[data-sev="Low"]{border-left:.6pt solid var(--low)}
details[data-sev="Info"]{border-left:.6pt solid var(--info)}
details[data-sev="excluded"]{border-left:.6pt dashed var(--muted)}
details[data-sev] summary{font-family:var(--serif)}
details[data-sev] summary .badge{margin-right:8px}
details[data-sev] summary .muted{font-family:var(--sans);font-size:12px;font-weight:400}
details[data-sev] dl{display:grid;grid-template-columns:150px minmax(0,1fr);gap:8px 18px;margin:14px 0 4px}
details[data-sev] dt{font-family:var(--sans);font-size:12px;color:var(--muted)}
dd{margin:0;overflow-wrap:anywhere;white-space:pre-line}
li{white-space:pre-line}
td{white-space:pre-line}
details[data-sev] .snippet{margin:6px 0 0;white-space:pre-wrap;overflow-wrap:anywhere}
.commitments th:nth-child(1){width:9%}
.commitments th:nth-child(2){width:33%}
.commitments th:nth-child(3){width:12%}
.commitments th:nth-child(4){width:22%}
.commitments th:nth-child(5){width:24%}
.coverage-table th:nth-child(1){width:42%}
.coverage-table th:nth-child(2){width:14%}
.coverage-table th:nth-child(3){width:44%}
.lists .panel ul{white-space:normal}
@media(max-width:850px){details[data-sev] dl{grid-template-columns:minmax(0,1fr);gap:3px}details[data-sev] dd{margin-bottom:10px}}
"""
CSS = kit_style.dashboard_css() + DASHBOARD_CSS

JS = """
document.getElementById('theme').addEventListener('click',()=>{const root=document.documentElement,
dark=root.dataset.theme?root.dataset.theme==='dark':window.matchMedia('(prefers-color-scheme: dark)').matches;
root.dataset.theme=dark?'light':'dark';});
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
    byline = " · ".join(as_text(meta.get(k, "")) for k in ("date", "assessor")
                        if shown(meta.get(k, "")))
    out = [f"<!doctype html><html lang='{lang}'><head><meta charset='utf-8'>",
           "<meta name='viewport' content='width=device-width,initial-scale=1'>",
           f"<title>{e(t['title'])}: {e(meta.get('project', ''))}</title>"
           f"<style>{CSS}</style></head><body><main>",
           f"<header class='masthead'><span class='brand'>{e(t['brand'])}</span>"
           f"<div class='tools'><button id='theme' type='button'>{e(t['theme'])}</button></div></header>",
           f"<div class='hero'><div><div class='eyebrow'>{e(t['title'])}</div>"
           f"<h1>{e(meta.get('project', ''))}</h1><div class='meta'>{e(byline)}</div></div>"
           f"<div class='hero-aside'>{e(t['disclaimer'])}</div></div>",
           "<div class='cards'>"]
    for s in SEVERITIES:
        out.append(f"<div class='card'><span class='l'><span class='badge {s}'>{s}</span></span>"
                   f"<div class='n'>{by_sev[s]}</div></div>")
    out.append(f"<div class='card'><span class='l'>{e(t['excluded'])}</span>"
               f"<div class='n'>{excluded}</div></div></div>")
    out.append(f"<div class='summary-banner'><p><strong>{e(t['verdict_counts'])}:</strong> "
               f"{e(verdict_summary(findings))}</p></div>")
    scope_rows = [(t['project'], meta.get('project', '')),
                  (t['scope_row'], meta.get('scope', '')),
                  (t['revision'], revision(meta)),
                  (t['review_method'], method),
                  (t['date'], f"{meta.get('date', '')} / {meta.get('assessor', '')}")]
    out.append(f"<section class='panel'><h2>{e(t['scope'])}</h2><dl class='scope-meta'>"
               + "".join(f"<dt>{e(k)}</dt><dd>{e(val)}</dd>" for k, val in scope_rows)
               + "</dl></section>")
    out.append(f"<section id='findings'><div class='section-head'><div><h2>{e(t['findings'])}</h2>"
               f"</div></div><div class='filter-buttons'><button data-filter='all' aria-pressed='true'>"
               f"{e(t['all'])}</button> "
               + " ".join(f"<button data-filter='{s}' aria-pressed='false'>{s}</button>" for s in SEVERITIES)
               + (f" <button data-filter='excluded' aria-pressed='false'>{e(t['excluded'])}</button>"
                  if excluded else "")
               + "</div><div class='register'>")
    # Shown when there are no findings, and by the filter when none match.
    out.append(f"<p data-empty{'' if not findings else ' hidden'}>{e(t['none'])}</p>")
    for f in findings:
        v = f["validation"]
        rows = [(t[k], value) for k, value in finding_fields(f, t)]
        rows.append((t["verdict"], f"{v['verdict']} ({v['method']})"))
        if shown(v.get("evidence", "")):
            rows.append((t["evidence"], v["evidence"]))
        analysis_html = ""
        if "analysis" in f:
            a = f["analysis"]
            analysis_html = (f"<dt>{e(t['analysis'])}</dt><dd>{e(a['result'])} — {e(a['tool'])}:"
                             f"<pre class='snippet'><code>{e(a['command'])}</code></pre></dd>")
        excluded_finding = is_excluded(f)
        # Excluded findings are not counted under their severity, so they are
        # filtered separately and labelled in the summary as well.
        out.append(f"<details data-sev='{'excluded' if excluded_finding else f['severity']}'>"
                   f"<summary><span class='badge {f['severity']}'>"
                   f"{f['severity']}</span> {e(f['id'])} {e(f['title'])} "
                   f"· {e(v['verdict'])}"
                   + (f" ({e(t['excluded'])})" if excluded_finding else "")
                   + f" <span class='muted'>· {e(f['confidence'])} · "
                   f"{e(perspective_name(t, f['category']))}</span></summary><dl>"
                   + "".join(f"<dt>{e(k)}</dt><dd>{e(val)}</dd>" for k, val in rows)
                   + analysis_html
                   + f"<dt>{e(t['status'])}</dt><dd>{e(term(t, f.get('status', 'Open')))}</dd>"
                   + "".join(f"<dt>{e(t['references'])}</dt><dd>{html_reference(ref)}</dd>"
                             for ref in f.get("references", []))
                   + "</dl></details>")
    out.append("</div></section>")
    if doc.get("commitments"):
        out.append(f"<section><div class='section-head'><div><h2>{e(t['commitments'])}</h2></div></div>"
                   f"<div class='tablewrap'><table class='ledger commitments'>"
                   f"{html_head(t['commitment_columns'])}")
        for r in doc["commitments"]:
            statement, status = commitment_text(r, t)
            cells = (statement, r.get("family", ""), r["source"], status)
            out.append(f"<tr><td class='nowrap'>{e(r['id'])}</td>"
                       + "".join(f"<td>{e(cell)}</td>" for cell in cells) + "</tr>")
        out.append("</table></div></section>")
    out.append(f"<section><div class='section-head'><div><h2>{e(t['perspectives'])}</h2></div></div>"
               f"<div class='tablewrap'><table class='ledger coverage-table'>"
               f"{html_head(t['perspective_columns'])}")
    for row in perspective_rows(doc, t):
        out.append("<tr>" + "".join(f"<td>{e(cell)}</td>" for cell in row) + "</tr>")
    out.append("</table></div></section><div class='lists'>")
    for key in ("checked_ok", "limitations", "decisions", "next_steps"):
        items = doc.get(key, [])
        out.append(f"<section class='panel'><h2>{e(t[key])}</h2>"
                   + ("<ul>" + "".join(f"<li>{e(i)}</li>" for i in items) + "</ul>" if items
                      else f"<p class='muted'>{e(t['none'])}</p>")
                   + "</section>")
    out.append(f"</div><footer class='footer'>{e(t['title'])}: {e(meta.get('project', ''))}"
               f" · {e(t['revision'])} {e(revision(meta))}</footer>")
    out.append(f"</main><script>{JS}</script></body></html>")
    return "".join(out)


def main(argv=None):
    prepare_cli()
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("findings")
    parser.add_argument("--out", required=True)
    parser.add_argument("--lang", choices=("ja", "en"))
    args = parser.parse_args(argv)
    if not args.out.strip():
        # A blank --out (an unset shell variable) would write into the working
        # directory, which may be the audited repository.
        parser.error("--out must name the output directory")
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
