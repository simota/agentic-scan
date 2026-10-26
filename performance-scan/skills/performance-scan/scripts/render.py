#!/usr/bin/env python3
"""Render findings.json into dashboard.html and report.md.

    python3 render.py FINDINGS --out DIR [--lang ja|en]

Both outputs are derived from the one record; neither adds facts of its own.
`dashboard.html` is self-contained and works offline. `report.md` follows the
findings-report shape in `reference/report.md`.

Exit codes: 0 written, 1 an output could not be encoded or saved, 2 an input
could not be read or decoded, or does not match the schema, or a command-line
usage error (reasons on stderr).
"""
import argparse
from html import escape
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile
import unicodedata
from urllib.parse import quote, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
from findings import (EXCLUDED, PERSPECTIVES, SEVERITIES, VERDICTS, SchemaError,  # noqa: E402
                      escape_unencodable_console, file_mode, read_json, resolve_path,
                      validate)
from scan_report_kit import style as kit_style  # noqa: E402

LABELS = {
    "en": {
        "title": "Performance assessment", "scope": "Scope and method",
        "findings": "Findings", "budgets": "Performance budgets", "perspectives": "Perspective coverage",
        "checked_ok": "Checked and sound", "limitations": "What could not be checked",
        "decisions": "Decisions for a human", "next_steps": "Next steps", "excluded": "Excluded",
        "severity": "Severity", "all": "All", "none": "None.",
        "location": "location", "workload": "workload", "scale_driver": "scale driver",
        "cost_model": "cost model", "request": "steps", "contrast": "contrast",
        "impact": "what happens", "verdict": "recorded verdict", "method": "verification",
        "evidence": "evidence", "measurement": "measurement", "fix": "fix direction",
        "command": "command", "environment": "environment",
        "regression_test": "regression test", "references": "references", "status": "status",
        "budget": "budget", "static_note": "Static review; no load was sent to any deployed environment.",
        "measured_note": "Static review plus explicitly authorized local measurements.",
        "project": "System", "revision": "Revision", "date": "Date / assessor",
        "source": "Source", "family": "Family", "inferred": "Inferred", "reason": "Reason (partly read or not checked)",
        "inferred_yes": "Yes — confirm with owner", "inferred_no": "No",
        "verdict_counts": "Verification counts",
        "incomplete_high": "High with incomplete verification",
        "scope_row": "Scope", "perspective": "perspective", "status_col": "Status", "note": "Note",
        "method_row": "Method", "confidence": "Confidence", "verdict_col": "Verdict",
        "title_col": "Title", "location_col": "Location", "findings_col": "Cited by", "budget_col": "Budget",
        "item_col": "Item", "value_col": "Value", "perspective_col": "Perspective", "lang": "en",
        "excluded_findings": "Excluded findings", "brand": "PERFORMANCE REVIEW",
        "theme": "Toggle theme", "copy_llm": "Copy for LLM", "copied": "Copied",
        "copy_failed": "Copy failed",
        "findings_note": "Open a finding for its cost model, evidence and fix direction. "
                         "Copy for LLM copies that finding as Markdown.",
        "jump_findings": "Jump to findings", "contents": "Contents", "nav_summary": "Summary",
        "nav_lists": "Checks, limits and next steps", "shortcuts": "Keyboard",
        "key_move": "Next / previous finding", "key_toggle": "Show or hide details",
    },
    "ja": {
        "title": "パフォーマンス診断", "scope": "対象と方法",
        "findings": "検出事項", "budgets": "性能バジェット", "perspectives": "観点のカバレッジ",
        "checked_ok": "確認して問題なかった項目", "limitations": "確認できなかったこと",
        "decisions": "人が判断すべき事項", "next_steps": "次の作業", "excluded": "除外",
        "severity": "深刻度", "all": "すべて", "none": "なし。",
        "location": "場所", "workload": "ワークロード", "scale_driver": "規模の要因",
        "cost_model": "コストモデル", "request": "再現手順", "contrast": "対照",
        "impact": "何が起きるか", "verdict": "検証判定", "method": "検証方法",
        "evidence": "根拠", "measurement": "計測", "fix": "修正方針",
        "command": "コマンド", "environment": "実行環境",
        "regression_test": "回帰テスト", "references": "参考", "status": "ステータス",
        "budget": "バジェット", "static_note": "静的レビューのみ。稼働中の環境には負荷を一切かけていない。",
        "measured_note": "静的レビューに加え、明示的に許可されたローカル計測を実施。",
        "project": "システム", "revision": "リビジョン", "date": "診断日 / 診断者",
        "source": "出典", "family": "分類", "inferred": "推定", "reason": "未確認・一部確認の理由",
        "inferred_yes": "推定・要確認", "inferred_no": "いいえ",
        "verdict_counts": "検証判定別の件数", "incomplete_high": "検証未完了の High",
        "scope_row": "範囲", "perspective": "観点", "status_col": "状態", "note": "メモ",
        "method_row": "方法", "confidence": "確度", "verdict_col": "検証判定",
        "title_col": "タイトル", "location_col": "場所", "findings_col": "引用する検出事項", "budget_col": "バジェット",
        "item_col": "項目", "value_col": "値", "perspective_col": "観点", "lang": "ja",
        "excluded_findings": "除外した検出事項", "brand": "PERFORMANCE REVIEW",
        "theme": "配色を切り替え", "copy_llm": "LLM用にコピー", "copied": "コピーしました",
        "copy_failed": "コピーできませんでした",
        "findings_note": "検出事項を開くとコストモデル・根拠・修正方針を確認できます。"
                         "「LLM用にコピー」でその検出事項を Markdown としてコピーします。",
        "jump_findings": "検出事項へ移動", "contents": "目次", "nav_summary": "概要",
        "nav_lists": "確認結果・制約・次の作業", "shortcuts": "キー操作",
        "key_move": "次・前の検出事項", "key_toggle": "詳細の表示・非表示",
    },
}
# Display names for fixed values. Severity, confidence and verdict names stay as
# written: the templates and the chat summary use them verbatim in both languages.
VALUE_LABELS = {
    "ja": {"static": "静的", "measured": "計測", "holds": "維持", "violated": "違反",
           "partly read": "一部のみ確認", "not checked": "未確認", "applied": "適用",
           "N/A": "対象外", "Open": "未対応", "Fixed": "修正済み", "Accepted": "許容"},
}


def shown(value, lang):
    return VALUE_LABELS.get(lang, {}).get(value, value)


FIELDS = ("location", "workload", "scale_driver", "cost_model", "request", "contrast",
          "impact", "budget", "fix", "regression_test")
LIST_SECTIONS = ("checked_ok", "limitations", "decisions", "next_steps")


def is_excluded(finding):
    return finding["validation"]["verdict"] in EXCLUDED


def finding_group(finding):
    """Use the same groups for summary counts and dashboard filters."""
    return "excluded" if is_excluded(finding) else finding["severity"]


def counts(findings):
    groups = [finding_group(f) for f in findings]
    return {s: groups.count(s) for s in SEVERITIES}, groups.count("excluded")


def verification_summary(findings, labels):
    """Use the same included findings as the severity totals, without upgrading verdicts."""
    by_verdict = {v: 0 for v in VERDICTS if v not in EXCLUDED}
    incomplete_high = 0
    for finding in findings:
        if is_excluded(finding):
            continue
        verdict = finding["validation"]["verdict"]
        by_verdict[verdict] += 1
        if finding["severity"] == "High" and verdict != "Valid":
            incomplete_high += 1
    return (labels["verdict_counts"] + ": "
            + " / ".join(f"{verdict} {count}" for verdict, count in by_verdict.items()),
            f"{labels['incomplete_high']} {incomplete_high}")


def review_note(findings, labels):
    # A finding can retain static verification while recording a local measurement.
    measured = any("measurement" in f for f in findings)
    return labels["measured_note"] if measured else labels["static_note"]


def as_text(value):
    return ", ".join(value) if isinstance(value, list) else str(value)


# C0/C1 controls (except tab and newline) and bidi controls can reorder or hide
# text (Trojan Source) or drive a terminal that prints report.md; show them as
# visible escapes instead.
UNSAFE_CHARS = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f"
                          "\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]")


def text_lines(value):
    text = as_text(value).replace("\r\n", "\n").replace("\r", "\n")
    return UNSAFE_CHARS.sub(lambda m: f"\\u{ord(m.group()):04x}", text).split("\n")


def markdown_text(value):
    """Keep record strings literal and keep newlines inside their current block."""
    def inline(line):
        line = escape(line, quote=False)
        line = re.sub(r"([\\`*_\[\]#!~$])", r"\\\1", line)
        # A list value has no static label before it: "- - text", "- 1. text"
        # and "-     text" would otherwise create nested blocks.
        line = re.sub(r"^([ \t]*)([-+])", r"\1\\\2", line)
        line = re.sub(r"^([ \t]*[0-9]{1,9})([.)])(?=[ \t]|$)", r"\1\\\2", line)
        # GFM also recognises bare URLs and email addresses. Only references[]
        # should create links; character references retain their visible text.
        # cmark-gfm decodes entities before matching emails, so an empty
        # comment splits the text node around "@" instead.
        line = line.replace("://", "&#58;//").replace("@", "@<!-- -->")
        # GitHub turns ":name:" into an emoji; split the first colon off the same way.
        # Escaping ran first, so a shortcode may already contain "\_".
        line = re.sub(r":(?=(?:\\.|[A-Za-z0-9_+-])+:)", ":<!-- -->", line)
        line = re.sub(r"www\.", lambda match: match.group()[:-1] + "&#46;", line,
                      flags=re.IGNORECASE)
        return re.sub(r"^[ \t]+", lambda match: "".join(
            "&#32;" if char == " " else "&#9;" for char in match.group()), line)

    return "<br>".join(inline(line) for line in text_lines(value))


def markdown_cell(value):
    # An entity cannot become a GFM column separator, including after a backslash.
    return markdown_text(value).replace("|", "&#124;")


def markdown_code(value):
    """Use a delimiter absent from each command line; code spans consume no data."""
    def span(line):
        if not line:
            return ""
        fence = "`" * (max((len(run) for run in re.findall(r"`+", line)), default=0) + 1)
        # CommonMark removes one surrounding space only when both are present
        # and the span is not entirely spaces. Padding also separates backticks.
        pad = " " if (line.startswith("`") or line.endswith("`") or
                      (line.startswith(" ") and line.endswith(" ") and line.strip(" "))) else ""
        return f"{fence}{pad}{line}{pad}{fence}"

    # A newline inside a code span is normalised to a space by CommonMark.
    return "<br>".join(span(line) for line in text_lines(value))


def link_destination(url):
    """Return a URL safe to link, before escaping for Markdown or HTML.

    Absolute http(s) URLs with a host, mailto: links and relative paths (e.g. a
    document beside the report) qualify. A protocol-relative URL does not: opened
    from file://, //host resolves to a network share (an SMB fetch on Windows).
    """
    # urlsplit drops tabs and newlines, so a padded absolute URL would pass the
    # check and then be quoted as "%20https://...": check and quote one string.
    # A relative path keeps its characters, since a file name may hold them.
    cleaned = re.sub(r"[\t\n\r]", "", url).strip()
    try:
        if urlsplit(cleaned).scheme:
            url = cleaned
        parts = urlsplit(url)
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    relative = not scheme and not parts.netloc and not url.lstrip().startswith(("//", "\\"))
    if not ((scheme in ("http", "https") and parts.netloc) or scheme == "mailto" or relative):
        return None
    return quote(url, safe="/:?#[]@!$&'+,;=%")


def markdown_link(title, url):
    label = markdown_text(title)
    destination = link_destination(url)
    if destination is None:
        return f"{label} ({markdown_text(url)})"
    # Keep URL syntax separate from Markdown syntax and from HTML entities.
    return f"[{label}](<{escape(destination, quote=False)}>)"


def html_text(value):
    return escape("\n".join(text_lines(value)))


def html_link(title, url):
    label = html_text(title)
    destination = link_destination(url)
    if destination is None:
        return f"{label} ({html_text(url)})"
    return f"<a href='{escape(destination)}'>{label}</a>"


def reference_title(ref):
    """Fall back to the URL so an empty or invisible title (only spaces, format
    or control characters such as U+200B) never yields an invisible link."""
    title = ref.get("title", "")
    visible = any(unicodedata.category(ch)[0] not in "CZ" for ch in title)
    return title if visible else ref["url"]


def budget_cells(budget, labels, findings):
    inferred = budget.get("inferred")
    inference = (labels["inferred_yes"] if inferred is True else
                 labels["inferred_no"] if inferred is False else "—")
    # Link each ledger entry to the included findings that cite it.
    # A finding cites its own budget in `budget` and any other it violates in `impact`.
    mention = re.compile(rf"(?<![A-Za-z0-9_-]){re.escape(budget['id'])}(?![A-Za-z0-9_-])")
    cited = ", ".join(f["id"] for f in findings if not is_excluded(f) and (
        f.get("budget") == budget["id"] or mention.search(f["impact"])))
    return (budget["id"], budget.get("family", "").strip() or "—", budget["statement"], budget["source"], shown(budget["status"], labels["lang"]),
            inference, budget.get("reason", "") if budget["status"] in ("partly read", "not checked")
            else "",
            cited or "—")


def budget_headers(labels):
    return ("ID", labels["family"], labels["budget_col"], labels["source"], labels["status_col"], labels["inferred"],
            labels["reason"], labels["findings_col"])


def perspective_rows(doc, lang):
    """One row per known perspective, recorded or not, in the reference order."""
    recorded = {p["name"]: p for p in doc.get("perspectives", [])}
    rows = []
    for name in PERSPECTIVES:
        p = recorded.get(name, {"status": "—", "note": ""})
        rows.append((name, shown(p["status"], lang), p["note"]))
    return rows


def first_location(finding):
    location = finding["location"]
    if not isinstance(location, list):
        return location
    return location[0] + (f" (+{len(location) - 1})" if len(location) > 1 else "")


def markdown_finding(f, t):
    """One finding's block; an excluded finding shows its verdict instead of a grade."""
    v = f["validation"]
    excluded = is_excluded(f)
    grade = f"[{v['verdict']}]" if excluded else f"[{f['severity']}][{f['confidence']}]"
    lines = [f"### {f['id']} {grade} {markdown_text(f['title'])}", ""]
    step = f" ({markdown_text(f['step'])})" if f.get("step", "").strip() else ""
    lines.append(f"- **{t['perspective']}:** {f['category']}{step}")
    for key in FIELDS:
        if key == "location":
            # Code spans keep paths copyable (no snake\_case escapes) and inert.
            locations = f[key] if isinstance(f[key], list) else [f[key]]
            lines.append(f"- **{t[key]}:** " + ", ".join(markdown_code(loc) for loc in locations))
        elif str(f.get(key, "")).strip():  # optional contrast/budget may be blank
            lines.append(f"- **{t[key]}:** {markdown_text(f[key])}")
    lines.append(f"- **{t['verdict']}:** {v['verdict']} · **{t['method']}:** {shown(v['method'], t['lang'])}")
    if v.get("evidence", "").strip():
        lines.append(f"- **{t['evidence']}:** {markdown_text(v['evidence'])}")
    if "measurement" in f:
        m = f["measurement"]
        lines.append(f"- **{t['measurement']}:** {markdown_text(m['result'])} "
                     f"({markdown_code(m['command'])}, {markdown_text(m['environment'])})")
    if not excluded:
        lines.append(f"- **{t['status']}:** {shown(f.get('status', 'Open'), t['lang'])}")
    for ref in f.get("references", []):
        lines.append(f"- **{t['references']}:** "
                     f"{markdown_link(reference_title(ref), ref['url'])}")
    return lines + [""]


def markdown_table(headers, rows):
    """GFM table lines; headers and cells are already Markdown."""
    return (["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
            + ["| " + " | ".join(row) + " |" for row in rows])


def render_markdown(doc, lang):
    t = LABELS[lang]
    meta, findings = doc["meta"], doc.get("findings", [])
    by_sev, excluded = counts(findings)
    verdicts, incomplete_high = verification_summary(findings, t)
    lines = [f"# {t['title']}: {markdown_text(meta.get('project', ''))}", ""]
    lines.append(" / ".join(f"{s} {by_sev[s]}" for s in SEVERITIES)
                 + f" · {t['excluded']} {excluded} · "
                 + review_note(findings, t))
    lines += ["", f"{verdicts} · **{incomplete_high}**"]
    scope = [(t["project"], markdown_cell(meta.get("project", ""))),
             (t["scope_row"], markdown_cell(meta.get("scope", ""))),
             (t["revision"], markdown_cell(meta.get("commit", "").strip() or "UNKNOWN"))]
    if meta.get("method", "").strip():
        scope.append((t["method_row"], markdown_cell(meta["method"])))
    scope.append((t["date"], f"{markdown_cell(meta.get('date', ''))} / "
                             f"{markdown_cell(meta.get('assessor', ''))}"))
    lines += ["", f"## {t['scope']}", ""]
    lines += markdown_table((t["item_col"], t["value_col"]), scope)
    lines += ["", f"## {t['findings']}", ""]
    if findings:
        headers = ("ID", t["severity"], t["confidence"], t["verdict_col"], t["title_col"],
                   t["location_col"])
        lines += markdown_table(headers, [
            [markdown_cell(cell) for cell in (f["id"], f["severity"], f["confidence"],
                                              f["validation"]["verdict"], f["title"],
                                              first_location(f))]
            for f in findings])
        lines.append("")
    else:
        lines += [t["none"], ""]
    included = [f for f in findings if not is_excluded(f)]
    dropped = [f for f in findings if is_excluded(f)]
    for f in included:
        lines += markdown_finding(f, t)
    if dropped:
        lines += [f"## {t['excluded_findings']}", ""]
        for f in dropped:
            lines += markdown_finding(f, t)
    if doc.get("budgets"):
        lines += [f"## {t['budgets']}", ""]
        lines += markdown_table(budget_headers(t), [
            [markdown_cell(cell) for cell in budget_cells(b, t, findings)]
            for b in doc["budgets"]])
        lines.append("")
    lines += [f"## {t['perspectives']}", ""]
    lines += markdown_table((t["perspective_col"], t["status_col"], t["note"]),
                            [[markdown_cell(cell) for cell in row]
                             for row in perspective_rows(doc, lang)])
    lines.append("")
    for key in LIST_SECTIONS:
        lines += [f"## {t[key]}", ""]
        lines += [f"- {markdown_text(item)}" for item in doc.get(key, [])] or [t["none"]]
        lines.append("")
    return "\n".join(lines)


# The shared *-scan dashboard style (scan-report-kit, vendored in
# scan_report_kit/) comes first, with the page opted into its application shell
# (app bar, contents sidebar with severity facets, pinned filter bar); these
# rules cover only what performance-scan renders differently: <details>
# findings, severity filter buttons, h2 section rules, summary card spacing and
# plain data tables.
CSS = """
h2{margin:36px 0 12px;padding-top:14px;border-top:1.5px solid var(--text)}
.lists h2{font-size:19px}
dt,.meta,.hero-aside,.section-note{font-family:var(--sans)}
.meta{font-size:13px;margin:0}
.hero-aside{margin:0;color:var(--muted)}
.summary-banner{margin:0 0 16px}
.cards{margin:20px 0}
.card .l.High{color:var(--high)}.card .l.Medium{color:var(--medium)}.card .l.Low{color:var(--low)}.card .l.Info{color:var(--info)}
.badge{margin-right:6px}
.section-note{margin:0 0 10px}
.filters{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 12px}
button{font-size:13px;padding:6px 12px}
button[aria-pressed="true"]{border-color:var(--text);background:var(--soft)}
details{border-top:1px solid var(--line);padding:12px 0}
details:last-of-type{border-bottom:1px solid var(--line)}
details[data-sev="High"]{border-top:2px solid var(--high)}details[data-sev="Medium"]{border-top:2px solid var(--medium)}
summary .small{font-weight:400;font-size:13px;margin-left:0}
.detail-actions{justify-content:flex-end;margin:10px 0 0}
details dl{display:grid;grid-template-columns:160px minmax(0,1fr);gap:8px 18px;margin:12px 0 4px;padding:14px 18px;background:var(--tint)}
dt{font-size:12px;color:var(--muted)}dd{margin:0}
/* Record text keeps its line breaks and wraps anywhere. Lists are scoped to .lists:
   a bare li would also reach the contents links, which the kit keeps on one line. */
h1,summary,p,dd,.lists li{overflow-wrap:anywhere}
h1,summary,p,dd,td,.lists li{white-space:pre-wrap}
pre{margin:0;white-space:pre-wrap;overflow-wrap:anywhere;border-left:1px solid var(--text);padding:2px 0 2px 10px}
code{line-height:1.6}
td,th{padding:10px}
tr:last-child td{border-bottom:0}
.lists{gap:0 28px;margin-top:0}
.lists ul{margin:0;padding-left:20px}
@media (max-width:850px){details dl{grid-template-columns:minmax(0,1fr);gap:2px}dd{margin-bottom:10px}}
@media (max-width:480px){.card{padding:12px 2px 6px}}
@media print{.filters,.detail-actions{display:none}details{break-inside:avoid}}
/* Application shell: findings are <details>, not the kit's register table, so the
   filter bar and the focused finding get the shell's pinning and focus marks here. */
.app-shell #budgets:focus{outline:0}
.app-shell .nav-title{padding-top:0;border-top:0}
.app-shell .filters-panel .filters{margin:0}
.app-shell details[data-sev]:focus-within>summary{background:var(--tint);box-shadow:inset 2px 0 0 var(--text)}
@media print{.app-shell details[data-sev]:focus-within>summary{background:none;box-shadow:none}}
"""
CSS = kit_style.dashboard_css() + CSS

JS = """
const filters=[...document.querySelectorAll('[data-filter]')],facets=[...document.querySelectorAll('.facet')];
function filter(s){filters.forEach(x=>x.setAttribute('aria-pressed',x.dataset.filter===s));
facets.forEach(x=>x.setAttribute('aria-pressed',x.dataset.sev===s));
document.querySelectorAll('details[data-sev]').forEach(d=>{d.hidden=s!=='all'&&d.dataset.sev!==s});}
filters.forEach(b=>b.addEventListener('click',()=>filter(b.dataset.filter)));
// Sidebar facets: a press filters the findings by severity, a second press clears it.
facets.forEach(b=>b.addEventListener('click',()=>{filter(b.getAttribute('aria-pressed')==='true'?'all':b.dataset.sev);
document.getElementById('findings').scrollIntoView();}));
// Keyboard: j/k step through the visible findings; Enter on the focused title opens it.
document.addEventListener('keydown',e=>{if(e.altKey||e.ctrlKey||e.metaKey||e.isComposing||(e.key!=='j'&&e.key!=='k'))return;
const t=e.target;if(t&&t.closest&&t.closest('input,select,textarea'))return;
const shown=[...document.querySelectorAll('details[data-sev]:not([hidden])>summary')];if(!shown.length)return;
const current=document.activeElement&&document.activeElement.closest('details[data-sev]'),
at=shown.findIndex(s=>s.parentNode===current),next=at<0?0:Math.min(shown.length-1,Math.max(0,at+(e.key==='j'?1:-1)));
e.preventDefault();shown[next].focus();shown[next].scrollIntoView({block:'nearest'});});
// Mark the section in view in the sidebar contents.
const navLinks=[...document.querySelectorAll('#nav a[href^="#"]')];if(window.IntersectionObserver){const visible=new Map(),
spy=new IntersectionObserver(entries=>{entries.forEach(en=>visible.set(en.target.id,en.isIntersecting));
const first=navLinks.find(a=>visible.get(a.getAttribute('href').slice(1)));
navLinks.forEach(a=>{if(a===first)a.setAttribute('aria-current','location');else a.removeAttribute('aria-current');});},
{rootMargin:'-35% 0px -60% 0px'});navLinks.forEach(a=>{const s=document.getElementById(a.getAttribute('href').slice(1));if(s)spy.observe(s);});}
document.getElementById('theme').addEventListener('click',()=>{const r=document.documentElement,
dark=r.dataset.theme?r.dataset.theme==='dark':matchMedia('(prefers-color-scheme: dark)').matches;
r.dataset.theme=dark?'light':'dark';});
// file:// pages or a denied Clipboard API fall back to a selection copy.
function copyFallback(text){const prev=document.activeElement,t=document.createElement('textarea');
t.value=text;t.setAttribute('readonly','');t.style.cssText='position:fixed;top:0;left:-9999px';
document.body.appendChild(t);t.select();let ok=false;try{ok=document.execCommand('copy');}catch(e){}
t.remove();if(prev&&prev.focus)prev.focus({preventScroll:true});
return ok?Promise.resolve():Promise.reject(new Error('copy'));}
function copyText(text){return navigator.clipboard&&window.isSecureContext
?navigator.clipboard.writeText(text).catch(()=>copyFallback(text)):copyFallback(text);}
document.querySelectorAll('[data-llm]').forEach(b=>{const label=b.textContent;let timer;
b.addEventListener('click',()=>{const done=s=>{b.textContent=s;clearTimeout(timer);
timer=setTimeout(()=>{b.textContent=label;},2000);};
copyText(b.dataset.llm).then(()=>done(b.dataset.copied),()=>done(b.dataset.failed));});});
"""


def html_table(headers, rows, id_column=False):
    """id_column: the first column holds IDs (B-01), which never wrap at the hyphen."""
    e = html_text
    first = "<td class='nowrap'>" if id_column else "<td>"
    return ("<div class='tablewrap'><table><thead><tr>"
            + "".join(f"<th scope='col'>{e(header)}</th>" for header in headers)
            + "</tr></thead><tbody>"
            + "".join("<tr>" + "".join(f"{first if i == 0 else '<td>'}{e(cell)}</td>" for i, cell in enumerate(row))
                      + "</tr>" for row in rows)
            + "</tbody></table></div>")


def llm_line(value):
    """One line of plain text: an LLM prompt is not rendered, so nothing is escaped."""
    return " ".join(line.strip() for line in text_lines(value) if line.strip())


def llm_block(label, value):
    """A fence longer than any backtick run keeps record text from closing it."""
    text = "\n".join(text_lines(value))
    fence = "`" * max(3, max((len(run) for run in re.findall(r"`+", text)), default=0) + 1)
    return ["", f"### {label}", "", f"{fence}text", text, fence]


def llm_finding(f, t, meta):
    """Plain Markdown for pasting one finding into an LLM: short facts as bullets,
    recorded prose fenced so it reads as data rather than instructions."""
    v, lang = f["validation"], t["lang"]
    step = f" ({llm_line(f['step'])})" if f.get("step", "").strip() else ""
    out = [f"## {llm_line(f['id'])} · {llm_line(f['title'])}", "",
           f"- {t['project']}: {llm_line(meta.get('project', ''))}",
           f"- {t['revision']}: {llm_line(meta.get('commit', '').strip() or 'UNKNOWN')}",
           f"- {t['severity']}: {f['severity']} · {t['confidence']}: {f['confidence']}",
           f"- {t['perspective']}: {f['category']}{step}"]
    locations = f["location"] if isinstance(f["location"], list) else [f["location"]]
    if len(locations) == 1:
        out.append(f"- {t['location']}: {llm_line(locations[0])}")
    else:
        out += [f"- {t['location']}:"] + [f"  - {llm_line(loc)}" for loc in locations]
    verdict = f"{v['verdict']} ({shown(v['method'], lang)})"
    out.append(f"- {t['verdict']}: {verdict}" + (f" · {t['excluded']}" if is_excluded(f) else ""))
    if not is_excluded(f):
        out.append(f"- {t['status']}: {shown(f.get('status', 'Open'), lang)}")
    if str(f.get("budget", "")).strip():
        out.append(f"- {t['budget']}: {llm_line(f['budget'])}")
    for key in FIELDS:
        if key not in ("location", "budget") and str(f.get(key, "")).strip():
            out += llm_block(t[key], f[key])
    if v.get("evidence", "").strip():
        out += llm_block(t["evidence"], v["evidence"])
    if "measurement" in f:
        m = f["measurement"]
        out += (llm_block(t["measurement"], m["result"]) + llm_block(t["environment"], m["environment"])
                + llm_block(t["command"], m["command"]))
    if f.get("references"):
        out += ["", f"### {t['references']}", ""]
        out += [f"- {llm_line(reference_title(ref))}: {llm_line(ref['url'])}" for ref in f["references"]]
    return "\n".join(out) + "\n"


def html_finding(f, t, meta):
    """One finding's <details>; an excluded finding shows its verdict instead of a status."""
    e, lang = html_text, t["lang"]
    v = f["validation"]
    group = finding_group(f)
    excluded = is_excluded(f)
    exclusion = (f" <span class='small'>· {e(t['excluded'])}: {e(v['verdict'])}</span>"
                 if excluded else "")
    step = f" ({e(f['step'])})" if f.get("step", "").strip() else ""
    # One location per line: a path may itself contain ", ".
    rows = [(t[k], "\n".join(f[k]) if k == "location" and isinstance(f[k], list) else f[k])
            for k in FIELDS if str(f.get(k, "")).strip()]
    rows.append((t["verdict"], f"{v['verdict']} ({shown(v['method'], lang)})"))
    if v.get("evidence", "").strip():
        rows.append((t["evidence"], v["evidence"]))
    if not excluded:
        rows.append((t["status"], shown(f.get("status", "Open"), lang)))
    if "measurement" in f:
        m = f["measurement"]
        rows += [(t["measurement"], m["result"]), (t["environment"], m["environment"])]
    out = [f"<details data-sev='{group}'><summary><span class='badge {f['severity']}'>"
           f"{f['severity']}</span> {e(f['id'])} {e(f['title'])} "
           f"<span class='small'>· {e(f['confidence'])} · {e(f['category'])}{step}</span>"
           f"{exclusion}</summary>"
           f"<div class='detail-actions'><button type='button' class='copy-finding' "
           f"data-llm='{escape(llm_finding(f, t, meta))}' data-copied='{e(t['copied'])}' "
           f"data-failed='{e(t['copy_failed'])}'>{e(t['copy_llm'])}</button></div><dl>"]
    out += [f"<dt>{e(k)}</dt><dd>{e(val)}</dd>" for k, val in rows]
    if "measurement" in f:
        out.append(f"<dt>{e(t['command'])}</dt><dd><pre><code>"
                   f"{e(f['measurement']['command'])}</code></pre></dd>")
    for ref in f.get("references", []):
        out.append(f"<dt>{e(t['references'])}</dt><dd>"
                   f"{html_link(reference_title(ref), ref['url'])}</dd>")
    out.append("</dl></details>")
    return "".join(out)


def render_html(doc, lang):
    t = LABELS[lang]
    meta, findings = doc["meta"], doc.get("findings", [])
    by_sev, excluded = counts(findings)
    verdicts, incomplete_high = verification_summary(findings, t)
    e = html_text
    nav = [("overview", t["nav_summary"]), ("findings", t["findings"])]
    nav += [("budgets", t["budgets"])] if doc.get("budgets") else []
    nav += [("coverage", t["perspectives"]), ("lists", t["nav_lists"])]
    # The record's text is the bulk of the page, so it sets the document language.
    out = [f"<!doctype html><html lang='{meta['lang']}' class='app-shell'><head><meta charset='utf-8'>",
           "<meta name='viewport' content='width=device-width,initial-scale=1'>",
           f"<title>{e(t['title'])}</title><style>{CSS}</style></head><body>",
           f"<a class='skip' href='#findings'>{e(t['jump_findings'])}</a>",
           f"<header class='appbar'><div class='appbar-in'><span class='brand'><span>{e(t['brand'])}</span>"
           f"<span class='appbar-project'>{e(meta.get('project', ''))}</span></span>"
           f"<div class='tools'><button type='button' id='theme'>{e(t['theme'])}</button></div></div></header>",
           f"<div class='shell'><nav class='sidebar' id='nav' aria-label='{e(t['contents'])}'>"
           f"<h2 class='nav-title'>{e(t['contents'])}</h2><ol class='nav-links'>"
           + "".join(f"<li><a href='#{i}'>{e(label)}</a></li>" for i, label in nav) + "</ol>",
           f"<div class='facets'><h2 class='nav-title'>{e(t['severity'])}</h2>"
           + "".join(f"<button type='button' class='facet' data-sev='{s}' aria-pressed='false'>"
                     f"<span class='facet-name {s}'>{s}</span><span class='facet-n'>{by_sev[s]}</span></button>"
                     for s in SEVERITIES) + "</div>",
           f"<dl class='keys'><dt class='nav-title'>{e(t['shortcuts'])}</dt>"
           f"<dd><kbd>j</kbd> <kbd>k</kbd> {e(t['key_move'])}</dd>"
           f"<dd><kbd>Enter</kbd> {e(t['key_toggle'])}</dd></dl></nav>",
           "<main><section id='overview' tabindex='-1' aria-labelledby='h'>",
           f"<div class='hero'><div><div class='eyebrow'>{e(t['title'])}</div>"
           f"<h1 id='h'>{e(meta.get('project', ''))}</h1>",
           f"<p class='meta'>{e(meta.get('scope', ''))} · {e(meta.get('commit', '').strip() or 'UNKNOWN')} · "
           + (f"{e(meta['method'])} · " if meta.get("method", "").strip() else "")
           + f"{e(meta.get('date', ''))} · {e(meta.get('assessor', ''))}</p></div>"
           f"<p class='hero-aside'>{e(review_note(findings, t))}</p></div>",
           f"<p class='summary-banner'><strong>{e(incomplete_high)}</strong>{e(verdicts)}</p>",
           "<div class='cards'>"]
    for s in SEVERITIES:
        out.append(f"<div class='card'><span class='l {s}'>{s}</span><b class='n'>{by_sev[s]}</b></div>")
    out.append(f"<div class='card'><span class='l'>{e(t['excluded'])}</span><b class='n'>{excluded}</b></div></div>"
               "</section>")
    out.append(f"<section id='findings' tabindex='-1'><h2>{e(t['findings'])}</h2>"
               f"<p class='section-note'>{e(t['findings_note'])}</p>"
               f"<div class='filters-panel'><div class='filters'><button type='button' data-filter='all' "
               f"aria-pressed='true'>{e(t['all'])}</button>"
               + "".join(f"<button type='button' data-filter='{s}' aria-pressed='false'>{s}</button>"
                         for s in SEVERITIES)
               + f"<button type='button' data-filter='excluded' aria-pressed='false'>{e(t['excluded'])}</button>"
               + "</div></div>")
    if not findings:
        out.append(f"<p>{e(t['none'])}</p>")
    out += [html_finding(f, t, meta) for f in findings]
    out.append("</section>")
    if doc.get("budgets"):
        out.append(f"<section id='budgets' tabindex='-1'><h2>{e(t['budgets'])}</h2>"
                   + html_table(budget_headers(t),
                                [budget_cells(b, t, findings) for b in doc["budgets"]], id_column=True)
                   + "</section>")
    out.append(f"<section id='coverage' tabindex='-1'><h2>{e(t['perspectives'])}</h2>"
               + html_table((t["perspective_col"], t["status_col"], t["note"]),
                            perspective_rows(doc, lang)) + "</section>")
    out.append("<div class='lists' id='lists' tabindex='-1'>")
    for key in LIST_SECTIONS:
        items = doc.get(key, [])
        out.append(f"<section><h2>{e(t[key])}</h2>"
                   + ("<ul>" + "".join(f"<li>{e(i)}</li>" for i in items) + "</ul>" if items
                      else f"<p class='muted'>{e(t['none'])}</p>") + "</section>")
    out.append(f"</div></main></div><script>{JS}</script></body></html>")
    return "".join(out)


def write_outputs(outputs):
    """Stage every output before replacing any, restoring old files on failure."""
    destinations = [(resolve_path(path), content) for path, content in outputs]
    if len({path for path, _ in destinations}) != len(destinations):
        raise OSError("report and dashboard must have different destinations")
    temporary_dirs, prepared, attempted = [], [], []
    retained = set()
    try:
        for target, content in destinations:
            mode = file_mode(target)
            if mode is not None and not stat.S_ISREG(mode):
                raise OSError(f"{target}: output must be a regular file")
            directory = Path(tempfile.mkdtemp(dir=target.parent,
                                              prefix=f".{target.name}."))
            temporary_dirs.append(directory)
            staged = directory / "new"
            staged.write_bytes(content)
            staged.chmod(stat.S_IMODE(mode) if mode is not None else 0o600)
            backup = None
            if mode is not None:
                backup = directory / "previous"
                # Finish recovery copies too before publishing either output.
                shutil.copy2(target, backup)
            prepared.append((target, staged, backup))
        try:
            for target, staged, backup in prepared:
                # An interrupt can arrive after the rename has succeeded.
                attempted.append((target, staged, backup))
                os.replace(staged, target)
        except BaseException as exc:
            # Also restore after an interrupt between the two replacements.
            failures = []
            for target, staged, backup in reversed(attempted):
                try:
                    # A surviving staged file means the rename did not happen.
                    if staged.exists():
                        continue
                    if backup is None:
                        target.unlink(missing_ok=True)
                    else:
                        os.replace(backup, target)
                except OSError as restore_error:
                    detail = f"{target}: {restore_error}"
                    if backup is not None:
                        retained.add(backup.parent)
                        detail += f"; previous output retained at {backup}"
                    failures.append(detail)
            if failures:
                raise OSError(f"{exc}; could not restore outputs: {'; '.join(failures)}") from exc
            raise
    finally:
        unwinding = sys.exc_info()[0] is not None
        failures = []
        for directory in temporary_dirs:
            if directory in retained:
                continue
            try:
                shutil.rmtree(directory)
            except OSError as exc:
                failures.append(f"{directory}: {exc}")
        if failures:
            message = "could not remove temporary outputs: " + "; ".join(failures)
            if not unwinding:
                raise OSError(message)
            print(f"render: {message}", file=sys.stderr)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("findings")
    parser.add_argument("--out", required=True)
    parser.add_argument("--lang", choices=("ja", "en"))
    args = parser.parse_args(argv)
    escape_unencodable_console()
    if not args.out.strip():
        parser.error("--out must name a directory")  # Path("") would be the cwd
    try:
        doc = read_json(args.findings)  # Its errors already name the file.
        try:
            validate(doc, complete=True)
        except SchemaError as exc:
            raise SchemaError(f"{args.findings}: {exc}") from exc
    except SchemaError as exc:
        print(f"schema: {exc}", file=sys.stderr)
        return 2
    lang = args.lang or doc["meta"]["lang"]
    if lang != doc["meta"]["lang"]:
        print(f"render: note: labels in {lang}, but the record's text is in "
              f"{doc['meta']['lang']}", file=sys.stderr)
    out = Path(args.out)
    try:
        outputs = [(out / "report.md", render_markdown(doc, lang).encode("utf-8")),
                   (out / "dashboard.html", render_html(doc, lang).encode("utf-8"))]
        source = resolve_path(args.findings)
        if any(resolve_path(path) == source for path, _ in outputs):
            raise OSError("an output destination must not replace findings.json")
        out.mkdir(parents=True, exist_ok=True)
        write_outputs(outputs)
    except (OSError, UnicodeError) as exc:
        print(f"render: {exc}", file=sys.stderr)
        return 1
    print(f"wrote {out / 'dashboard.html'} and {out / 'report.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
