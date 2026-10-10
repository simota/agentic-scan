#!/usr/bin/env python3
"""Render findings.json into dashboard.html and report.md.

    python3 render.py FINDINGS --out DIR [--lang ja|en]

Both outputs are derived from the one record; neither adds facts of its own.
`dashboard.html` is self-contained and works offline. `report.md` follows the
findings-report shape in `reference/report.md`.

Exit codes: 0 written, 1 an output could not be written (render again before
`findings.py check`), 2 the record cannot be read or does not match the schema
(the file or field is named on stderr), or the command line is wrong.
"""
import argparse
import base64
import hashlib
from html import escape
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.dont_write_bytecode = True  # leave no __pycache__ beside the skill
from findings import (EXCLUDED, PERSPECTIVES, SEVERITIES, VERDICTS, SchemaError,  # noqa: E402
                      _atomic_write_all, as_locations, read_json, safe_output, validate)

URL_SCHEME = re.compile(r"https?://", re.IGNORECASE)
SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:")


def is_web_url(url):
    return (bool(URL_SCHEME.match(url)) and not re.search(r"[\x00-\x20\x7f]", url)
            and not BIDI_CONTROLS.search(url))


def is_safe_link(url):
    """A web URL or a scheme-less relative path; never javascript:, data: and the like.

    Browsers drop tabs, newlines and leading control characters from a URL, so
    any control character could hide a scheme: such a URL is never a link.
    """
    # A bidi control would reorder the destination wherever it is shown or
    # copied, though its label makes it visible: such a URL is never a link.
    if re.search(r"[\x00-\x1f\x7f]", url) or BIDI_CONTROLS.search(url):
        return False
    stripped = url.lstrip(" ")
    if len(stripped) > 1 and set(stripped[:2]) <= {"/", "\\"}:
        return False  # protocol-relative or UNC: another host, not a relative path
    return is_web_url(url) or not SCHEME.match(stripped)


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
        "verdicts": "Verdict counts",
        "method": "verification", "evidence": "evidence", "analysis": "analysis",
        "references": "references", "status": "status", "reason": "Reason",
        "category": "perspective", "id": "ID", "statement": "Rule", "source": "Source",
        "rule_status": "Status", "perspective": "Perspective", "note": "Note",
        "not_recorded": "not recorded", "inferred": "inferred, to confirm",
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
        "verdicts": "検証判定別件数",
        "method": "検証方法", "evidence": "根拠", "analysis": "解析",
        "references": "参考", "status": "ステータス", "reason": "理由",
        "category": "観点", "id": "ID", "statement": "ルール", "source": "出典",
        "rule_status": "状態", "perspective": "観点", "note": "メモ",
        "not_recorded": "未記録", "inferred": "推定・要確認",
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


def verdict_counts(findings):
    return {v: sum(f["validation"]["verdict"] == v for f in findings) for v in VERDICTS}


# Bidirectional controls (U+202A-202E, U+2066-2069) reorder the text after them,
# so a recorded value could display reversed or hide its own end (Trojan Source).
# They are shown as visible code points instead.
BIDI_CONTROLS = re.compile("[\u202a-\u202e\u2066-\u2069]")


def as_text(value):
    text = ", ".join(value) if isinstance(value, list) else str(value)
    return BIDI_CONTROLS.sub(lambda m: f"[U+{ord(m[0]):04X}]", text)


def review_method(doc, lang):
    """Keep the recorded scope of analysis, including runs with no findings."""
    if doc["meta"].get("method", "").strip():
        return doc["meta"]["method"]
    analysed = any(f["validation"]["method"] == "analysed" or "analysis" in f
                   for f in doc.get("findings", []))
    return LABELS[lang]["analysed_note" if analysed else "static_note"]


# Inside `<code>` GFM still parses inline syntax, so these are encoded; the rest
# of a path or command (`/`, `.`, `:`, `-`) stays readable in the raw file.
CODE_LITERAL = {ord(char): f"&#{ord(char)};" for char in "\\`*_~[]<&|!$\t"}


def markdown_code(value):
    """Keep a literal command or code span intact, even with backticks."""
    value = as_text(value).replace("\r\n", "\n").replace("\r", "\n")
    literal = disarm_autolinks(value.translate(CODE_LITERAL))
    # Runs of spaces and edge spaces would collapse or be trimmed.
    literal = re.sub(r"^ +| {2,}| +$", lambda m: "&#32;" * len(m[0]), literal)
    literal = literal.replace("\n", "<br>")
    return f"<code>{literal}</code>"


# Backslashes are literal (paths such as `docs\\adr`), so the punctuation after
# one loses its escape and is encoded instead; `&<>` are already entities.
AFTER_BACKSLASH = re.compile(r"(?<=\\)[!-%'-/:;=>?@^_{-~]")
# What GFM turns into a link without brackets: a scheme's colon, `www.`, and
# the `@` of an e-mail address. Encoding the last character disarms each.
# No `\b`: GFM also links a scheme or `www.` right after a word character
# (`_https://x`, `参照https://x`).
AUTOLINK = re.compile(r"(?i)(?:https?|ftp|mailto|xmpp):|www\.")


# An `@` after anything but a blank, opening punctuation or a tag's `>`. A `;`
# is not safe: it usually ends an entity this renderer wrote (`a&#95;@x.com`),
# which cmark-gfm decodes back into the local part before it autolinks.
EMAIL_AT = re.compile(r"(?<=[^\s(\[{'\"`,:>])@")


def disarm_autolinks(text):
    """Encode one character of each autolink trigger.

    cmark-gfm finds e-mail addresses after entities are decoded, so an `@` with
    a local part before it (`bob@example.com`) also gets an empty comment,
    which no autolinker reads through. An `@` that starts a word (`@scope/pkg`,
    `@decorator`) has no local part, cannot be an address, and stays readable.
    """
    text = AUTOLINK.sub(lambda m: m[0][:-1] + f"&#{ord(m[0][-1])};", text)
    return EMAIL_AT.sub("&#64;<!-- -->", text)
# Outside code spans these stay literal: a backslash, a stray backtick, the
# brackets of a link or image (whose target could be any scheme), a cell pipe.
LITERAL = {ord("\\"): "&#92;", ord("`"): "&#96;", ord("["): "&#91;", ord("]"): "&#93;",
           ord("|"): "&#124;", ord("$"): "&#36;"}  # `$` opens math on GitHub and in pandoc


def markdown_inline(value):
    """Keep recorded text in one GFM block, keeping emphasis and code spans.

    Links and images are shown as literal text, and backslashes as written, so
    no recorded text turns into a link or loses a delimiter it escaped.
    """
    value = as_text(value).replace("\r\n", "\n").replace("\r", "\n")

    def text(part):
        part = re.sub(r"(\\+)`", lambda m: m[1][:-1] + "&#96;" if len(m[1]) % 2 else m[0],
                      # `>` stays readable (`a -> b`): without `<` it opens
                      # no tag, and block_safe stops it quoting a list item.
                      escape(part, quote=False).replace("&gt;", ">"))
        part = AFTER_BACKSLASH.sub(lambda m: f"&#{ord(m[0])};", part)
        return disarm_autolinks(part.translate(LITERAL)).replace("\n", "<br>")

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


# Leading whitespace (indented code) and the markers that open a block when
# they start a line: a heading, a list bullet (`*` or `+` before a blank), a
# rule (three of `*` or `_`), a setext line, a fence, a link definition or task
# box, an ordered item. A leading `-` is always encoded: with the item's own
# `- ` bullet, even `--` makes a rule. `*em*` or `~~struck~~` at the start is inline, not
# a block, so it is left alone.
BLOCK_START = re.compile(
    r"([ \t]*)(#|=|>|\[|-|[*+_](?=[ \t]|$)|([*_])(?=(?:[ \t]*\3){2,}[ \t]*$)|~~~|```"
    r"|[0-9]{1,9}[.)])?")


def block_safe(rendered):
    """Keep recorded text from opening a Markdown block where it starts a line."""
    match = BLOCK_START.match(rendered)
    indent, marker = match[1], match[2] or ""
    if marker[:1].isdigit():
        # `12.` stops being an ordered item once its delimiter is encoded.
        marker = marker[:-1] + f"&#{ord(marker[-1])};"
    elif marker:
        marker = f"&#{ord(marker[0])};" + marker[1:]
    return "".join(f"&#{ord(char)};" for char in indent) + marker + rendered[match.end():]


def heading_text(value):
    """Inline text that cannot lose a trailing `#` to a closing sequence."""
    # The heading drops trailing blanks, which would expose the `#` again.
    rendered = markdown_inline(value).rstrip(" \t")
    return rendered[:-1] + "&#35;" if rendered.endswith("#") else rendered


def markdown_table_cell(value):
    """Keep pipes and line breaks inside a GFM cell, including in code spans."""
    return markdown_inline(value)


def revision(meta):
    commit = meta.get("commit", "")
    return commit if commit.strip() else "UNKNOWN"


def category(f):
    return f"{f['category']} ({f['step']})" if "step" in f else f["category"]


def perspective_rows(doc, lang):
    """Every perspective in reference order, so both outputs show the same gaps."""
    recorded = {p["name"]: p for p in doc.get("perspectives", [])}
    missing = {"status": "—", "note": LABELS[lang]["not_recorded"]}
    return [(name, recorded.get(name, missing)) for name in PERSPECTIVES]


def rule_id(rule):
    """The ledger ID with its family (reference/rules.md §2), e.g. `R-01 · OWN`."""
    return f"{rule['id']} · {rule['family']}" if rule.get("family") else rule["id"]


def rule_statement(rule, lang):
    """An inferred rule is a question for the requester (reference/rules.md §1)."""
    if rule.get("inferred") is True:
        return f"{rule['statement']} ({LABELS[lang]['inferred']})"
    return rule["statement"]


def filled(record, key):
    """A recorded value worth a row: present and not blank."""
    return key in record and bool(as_text(record[key]).strip())


def markdown_reference(ref):
    if not is_safe_link(ref["url"]):
        # Web URLs and relative paths become links; any other scheme stays literal.
        title = ref.get("title")
        code = markdown_code(ref["url"])
        return f"{markdown_inline(title)}: {code}" if title and title != ref["url"] else code
    title = markdown_inline(ref.get("title") or ref["url"])
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
    by_verdict = verdict_counts(findings)
    lines = [f"# {t['title']}: {heading_text(meta.get('project', ''))}", ""]
    lines.append(" / ".join(f"{s} {by_sev[s]}" for s in SEVERITIES)
                 + f" · {t['excluded']} {excluded} · "
                 + text(review_method(doc, lang)))
    lines += ["", f"{t['verdicts']}: "
              + " / ".join(f"{v} {by_verdict[v]}" for v in VERDICTS)]
    lines += ["", f"## {t['scope']}", "", "| | |", "|---|---|",
              f"| {t['project']} | {cell(meta.get('project', ''))} |",
              f"| {t['scope_row']} | {cell(meta.get('scope', ''))} |",
              f"| {t['revision']} | {cell(revision(meta))} |",
              f"| {t['date']} | {cell(meta.get('date', ''))} / {cell(meta.get('assessor', ''))} |", ""]
    lines += [f"## {t['findings']}", ""]
    if not findings:
        lines += [t["none"], ""]
    for f in findings:
        v = f["validation"]
        lines.append(f"### {f['id']} [{f['severity']}][{f['confidence']}][{v['verdict']}] "
                     f"{heading_text(f['title'])}")
        lines.append("")
        lines.append(f"- **{t['category']}:** {text(category(f))}")
        for key in FIELDS:
            if filled(f, key):
                value = f[key]
                if key == "location":
                    paths = as_locations(value)
                    formatted = ", ".join(markdown_code(path) for path in paths)
                else:
                    formatted = text(value)
                lines.append(f"- **{t[key]}:** {formatted}")
        lines.append(f"- **{t['verdict']}:** {v['verdict']} · **{t['method']}:** {v['method']}")
        if filled(v, "evidence"):
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
        lines += [f"## {t['rules']}", "",
                  f"| {t['id']} | {t['statement']} | {t['source']} | {t['rule_status']} |",
                  "|---|---|---|---|"]
        for r in doc["rules"]:
            status = r["status"]
            if filled(r, "reason"):
                status += f"\n{t['reason']}: {r['reason']}"
            lines.append(f"| {cell(rule_id(r))} | {cell(rule_statement(r, lang))} | "
                         f"{cell(r['source'])} | {cell(status)} |")
        lines.append("")
    lines += [f"## {t['perspectives']}", "",
              f"| {t['perspective']} | {t['rule_status']} | {t['note']} |", "|---|---|---|"]
    for name, p in perspective_rows(doc, lang):
        lines.append(f"| {cell(name)} | {cell(p['status'])} | {cell(p['note'])} |")
    lines.append("")
    for key in ("checked_ok", "limitations", "decisions", "next_steps"):
        lines += [f"## {t[key]}", ""]
        lines += [f"- {block_safe(text(item))}" for item in doc.get(key, [])] or [t["none"]]
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
h1,summary{overflow-wrap:anywhere}h1{font-size:1.5rem;margin:0 0 4px}h2{font-size:1.1rem;margin:28px 0 8px}
.muted{color:var(--muted)}.cards{display:flex;flex-wrap:wrap;gap:8px;margin:16px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 14px;min-width:96px}
.card b{display:block;font-size:1.4rem}
.High{color:var(--high)}.Medium{color:var(--medium)}.Low{color:var(--low)}.Info{color:var(--info)}
details{background:var(--card);border:1px solid var(--line);border-radius:8px;margin:8px 0;padding:8px 12px}
summary{cursor:pointer;font-weight:600}dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 12px}
dt{color:var(--muted)}dd{margin:0;overflow-wrap:anywhere}
table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid var(--line);padding:6px;text-align:left;vertical-align:top;overflow-wrap:anywhere}
th{color:var(--muted);font-weight:600}a{color:inherit}
.rules td:first-child,.rules td:last-child,.coverage td:nth-child(2){overflow-wrap:normal}
details.excluded summary{text-decoration:line-through}
.coverage td:first-child,th{overflow-wrap:normal}
@media print{[data-filter]{display:none}}
button{background:var(--card);color:var(--fg);border:1px solid var(--line);border-radius:6px;padding:4px 10px;cursor:pointer}
button[aria-pressed="true"]{border-color:var(--fg)}
"""

JS = """
const show=s=>{let n=0;document.querySelectorAll('details[data-sev]').forEach(d=>{
d.hidden=s!=='all'&&d.dataset.sev!==s;if(!d.hidden)n++});
const m=document.querySelector('[data-empty]');if(m)m.hidden=n>0;};
document.querySelectorAll('[data-filter]').forEach(b=>b.addEventListener('click',()=>{
document.querySelectorAll('[data-filter]').forEach(x=>x.setAttribute('aria-pressed',x===b));
show(b.dataset.filter);}));
let shut=[];addEventListener('beforeprint',()=>{shut=[];
document.querySelectorAll('details[data-sev]').forEach(d=>{if(!d.open)shut.push(d);d.hidden=false;d.open=true});
const m=document.querySelector('[data-empty]');if(m)m.hidden=true;});
addEventListener('afterprint',()=>{shut.forEach(d=>{d.open=false});
show(document.querySelector('[aria-pressed="true"]').dataset.filter);});
"""


def html_text(value):
    """Keep recorded line breaks visible without interpreting recorded HTML."""
    value = as_text(value).replace("\r\n", "\n").replace("\r", "\n")
    return escape(value).replace("\n", "<br>")


def csp_hash(source):
    return "'sha256-" + base64.b64encode(hashlib.sha256(source.encode("utf-8")).digest()).decode() + "'"


# Nothing is fetched: only the inline style and script below may run.
CSP = (f"default-src 'none'; style-src {csp_hash(CSS)}; script-src {csp_hash(JS)}; "
       "base-uri 'none'; form-action 'none'")


def html_reference(ref):
    """Link only web URLs; any other scheme stays visible as text."""
    title, url = ref.get("title") or ref["url"], ref["url"]
    label = html_text(f"{title}: {url}" if title != url else url)
    if is_web_url(url):
        return f"<a href='{escape(url)}' rel='noopener noreferrer'>{label}</a>"
    return label


def render_html(doc, lang):
    t = LABELS[lang]
    meta, findings = doc["meta"], doc.get("findings", [])
    by_sev, excluded = counts(findings)
    by_verdict = verdict_counts(findings)
    e = html_text
    out = [f"<!doctype html><html lang='{lang}'><head><meta charset='utf-8'>",
           f"<meta http-equiv='Content-Security-Policy' content=\"{CSP}\">",
           "<meta name='viewport' content='width=device-width,initial-scale=1'>",
           f"<title>{escape(t['title'])}: {escape(' '.join(as_text(meta.get('project', '')).split()))}</title>"
           f"<style>{CSS}</style></head><body><main>",
           f"<h1>{e(t['title'])}: {e(meta.get('project', ''))}</h1>",
           f"<p class='muted'>{e(meta.get('scope', ''))} · {e(revision(meta))} · "
           f"{e(meta.get('date', ''))} · {e(meta.get('assessor', ''))}</p>",
           f"<p class='muted'>{e(review_method(doc, lang))}</p><div class='cards'>"]
    for s in SEVERITIES:
        out.append(f"<div class='card'><span class='{s}'>{s}</span><b>{by_sev[s]}</b></div>")
    out.append(f"<div class='card'><span>{e(t['excluded'])}</span><b>{excluded}</b></div></div>")
    out.append(f"<p>{e(t['verdicts'])}: "
               + " / ".join(f"{v} {by_verdict[v]}" for v in VERDICTS) + "</p>")
    out.append(f"<h2>{e(t['findings'])}</h2><p><button data-filter='all' aria-pressed='true'>"
               f"{e(t['all'])}</button> "
               + " ".join(f"<button data-filter='{s}' aria-pressed='false'>{s}</button>" for s in SEVERITIES)
               + f" <button data-filter='excluded' aria-pressed='false'>{e(t['excluded'])}</button></p>")
    if not findings:
        out.append(f"<p>{e(t['none'])}</p>")
    else:
        # Shown by the filter when it leaves no finding visible.
        out.append(f"<p data-empty hidden>{e(t['none'])}</p>")
    for f in findings:
        v = f["validation"]
        rows = [(t["category"], e(category(f)))]
        rows += [(t[k], e(f[k])) for k in FIELDS if filled(f, k)]
        rows.append((t["verdict"], e(f"{v['verdict']} ({v['method']})")))
        if filled(v, "evidence"):
            rows.append((t["evidence"], e(v["evidence"])))
        rows.append((t["status"], e(f.get("status", "Open"))))
        if "analysis" in f:
            a = f["analysis"]
            rows.append((t["analysis"], e(f"{a['result']} — {a['tool']}: {a['command']}")))
        for ref in f.get("references", []):
            rows.append((t["references"], html_reference(ref)))
        # Excluded findings are not in the severity counts, so not in their filters.
        group = "excluded' class='excluded" if v["verdict"] in EXCLUDED else f["severity"]
        out.append(f"<details data-sev='{group}'><summary>"
                   f"<span class='{f['severity']}'>"
                   f"{f['severity']}</span> {e(f['id'])} {e(f['title'])} "
                   f"<span class='muted'>· {e(f['confidence'])} · {e(v['verdict'])} · "
                   f"{e(f['category'])}</span></summary><dl>"
                   + "".join(f"<dt>{e(k)}</dt><dd>{val}</dd>" for k, val in rows) + "</dl></details>")
    if doc.get("rules"):
        out.append(f"<h2>{e(t['rules'])}</h2><table class='rules'><thead><tr><th>{e(t['id'])}</th>"
                   f"<th>{e(t['statement'])}</th><th>{e(t['source'])}</th>"
                   f"<th>{e(t['rule_status'])}</th></tr></thead><tbody>")
        for r in doc["rules"]:
            status = e(r["status"])
            if filled(r, "reason"):
                status += f"<br>{e(t['reason'])}: {e(r['reason'])}"
            out.append(f"<tr><td>{e(rule_id(r))}</td>"
                       f"<td>{e(rule_statement(r, lang))}</td><td>{e(r['source'])}</td>"
                       f"<td>{status}</td></tr>")
        out.append("</tbody></table>")
    out.append(f"<h2>{e(t['perspectives'])}</h2><table class='coverage'><thead><tr><th>{e(t['perspective'])}</th>"
               f"<th>{e(t['rule_status'])}</th><th>{e(t['note'])}</th></tr></thead><tbody>")
    for name, p in perspective_rows(doc, lang):
        out.append(f"<tr><td>{e(name)}</td><td>{e(p['status'])}</td><td>{e(p['note'])}</td></tr>")
    out.append("</tbody></table>")
    for key in ("checked_ok", "limitations", "decisions", "next_steps"):
        items = doc.get(key, [])
        out.append(f"<h2>{e(t[key])}</h2>"
                   + ("<ul>" + "".join(f"<li>{e(i)}</li>" for i in items) + "</ul>" if items
                      else f"<p>{e(t['none'])}</p>"))
    out.append(f"</main><script>{JS}</script></body></html>")
    return "".join(out)


def rendered_outputs(doc, lang):
    """The exact bytes render.py writes for doc, keyed by output name."""
    return {"report.md": render_markdown(doc, lang).encode("utf-8"),
            "dashboard.html": render_html(doc, lang).encode("utf-8")}


def main(argv=None):
    safe_output()
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
    try:
        out.mkdir(parents=True, exist_ok=True)
        # Both outputs are staged before either replaces the previous file.
        _atomic_write_all({out / name: data for name, data in rendered_outputs(doc, lang).items()})
    except (OSError, RuntimeError) as exc:
        print(f"write failed: {exc}", file=sys.stderr)
        return 1
    print(f"wrote {out / 'dashboard.html'} and {out / 'report.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
