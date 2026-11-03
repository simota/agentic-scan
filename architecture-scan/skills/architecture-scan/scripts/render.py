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
import json
from html import escape
from itertools import accumulate
from operator import add, sub
from pathlib import Path
import re
import sys
import unicodedata

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.dont_write_bytecode = True  # leave no __pycache__ beside the skill
from findings import (CONFIDENCES, DIAGRAMS, EXCLUDED, PERSPECTIVES, RULE_LIST, SEVERITIES,  # noqa: E402
                      STATUSES, VERDICTS, SchemaError, _atomic_write_all, as_locations, read_json,
                      safe_output, validate, visible)
from scan_report_kit import style as kit_style  # noqa: E402

URL_SCHEME = re.compile(r"https?://", re.IGNORECASE)
SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:")


def is_web_url(url):
    return (bool(URL_SCHEME.match(url)) and not re.search(r"[\x00-\x20\x7f-\x9f]", url)
            and not BIDI_CONTROLS.search(url))


def is_safe_link(url):
    """A web URL or a scheme-less relative path; never javascript:, data: and the like.

    Browsers drop tabs, newlines and leading control characters from a URL, so
    any control character could hide a scheme: such a URL is never a link.
    """
    # A bidi control would reorder the destination wherever it is shown or
    # copied, though its label makes it visible: such a URL is never a link.
    if re.search(r"[\x00-\x1f\x7f-\x9f]", url) or BIDI_CONTROLS.search(url):
        return False
    # A link destination unescapes a backslash before ASCII punctuation, even
    # one written as `&#92;`: `ftp\://x` would link `ftp://x`, `a\#b` `a#b`.
    if re.search(r"\\[!-/:-@\[-`{-~]", url):
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
        "baseline": "baseline",
        "static_note": "Static review; no code was changed or executed beyond read-only analysis.",
        "analysed_note": "Static review plus read-only tool analysis (dependency graph, history).",
        "project": "System", "scope_row": "Scope", "revision": "Revision", "date": "Date / assessor",
        "architecture": "Architecture: before and after",
        "before": "Before: the assessed revision",
        "after": "After: with the recorded fix directions applied",
        "not_drawn": "Not recorded.",
        "legend_before": "Red: an edge a finding cites. Dashed: removed in the after diagram.",
        "legend_after": "Bold blue: added by the fix.",
        "shapes_md": "Cylinder: a data store; hexagon: an external system.",
        "shapes_svg": "Rounded, shaded box: a data store; dashed border: an external system. "
                      "A module keeps its place in both diagrams.",
        "changes": "Changes from before to after", "no_changes": "The after diagram adds or "
        "removes no module or edge.",
        "removed_node": "Removed module", "added_node": "Added module",
        "removed_edge": "Removed edge", "added_edge": "Added edge",
        "edges_text": "Modules and edges as text",
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
        "not_recorded": "未記録", "inferred": "推定・要確認", "baseline": "ベースライン",
        "static_note": "静的レビューのみ。読み取り専用の解析以外にコードの変更や実行はしていない。",
        "analysed_note": "静的レビューに加え、読み取り専用のツール解析（依存グラフ、変更履歴）を実施。",
        "project": "システム", "scope_row": "範囲", "revision": "リビジョン", "date": "診断日 / 診断者",
        "architecture": "アーキテクチャ: 修正前と修正後",
        "before": "修正前: 診断時点のリビジョン",
        "after": "修正後: 記録した修正方針を適用した姿",
        "not_drawn": "未記録。",
        "legend_before": "赤: 検出事項が指摘する依存。破線: 修正後の図で取り除かれる依存。",
        "legend_after": "太い青: 修正で加わる依存。",
        "shapes_md": "円柱: データストア。六角形: 外部システム。",
        "shapes_svg": "角が丸く色の付いた箱: データストア。破線の枠: 外部システム。"
                      "同じモジュールは両方の図で同じ位置に置く。",
        "changes": "修正前から修正後への変更", "no_changes": "修正後の図で増減するモジュールや依存はない。",
        "removed_node": "取り除くモジュール", "added_node": "加えるモジュール",
        "removed_edge": "取り除く依存", "added_edge": "加える依存",
        "edges_text": "モジュールと依存の一覧（テキスト）",
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
    if visible(as_text(doc["meta"].get("method", ""))):
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


# An `@` is disarmed unless what precedes it cannot end an e-mail local part
# in any renderer: a blank, an opening bracket or quote, `,` or `:` (as in
# `@scope/pkg`, `(@Version`), or punctuation outside ASCII (`。@Transactional`,
# `（@Version`). Everything else is disarmed: letters and digits in any script
# (pandoc reads them all), a combining mark (pandoc composes it into the letter
# before), the `;` that ends an entity this renderer wrote (`a&#95;@x.com`,
# decoded back into the local part before cmark-gfm autolinks), and the rest of
# ASCII punctuation, which other autolinkers accept (`a=@x.com`).
EMAIL_AT = re.compile(r"(?<=(.))@", re.DOTALL)
NOT_LOCAL_PART = set(" \t\r\n([{'\"`,:")


def _disarm_at(match):
    before = match[1]
    if before in NOT_LOCAL_PART or before.isspace() or (
            ord(before) > 127 and unicodedata.category(before)[0] in "PSZ"):
        return "@"
    return "&#64;<!-- -->"


def disarm_autolinks(text):
    """Encode one character of each autolink trigger.

    cmark-gfm finds e-mail addresses after entities are decoded, so an `@` with
    a local part before it (`bob@example.com`) also gets an empty comment,
    which no autolinker reads through. An `@` that starts a word (`@scope/pkg`,
    `@decorator`) has no local part, cannot be an address, and stays readable.
    """
    text = AUTOLINK.sub(lambda m: m[0][:-1] + f"&#{ord(m[0][-1])};", text)
    return EMAIL_AT.sub(_disarm_at, text)
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
    return commit if visible(as_text(commit)) else "UNKNOWN"


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


# `baseline` or `baseline; shared/db.py:12 …`, not a file such as `baselines/x.md`.
BASELINE_SOURCE = re.compile(r"\s*baseline(?![\w./-])", re.IGNORECASE)


def rule_statement(rule, lang):
    """An inferred rule is a question for the requester (reference/rules.md §1).

    A baseline entry is inferred too, but states a general family rule, not
    this codebase's intent, so it is labelled as such and asks nothing.
    """
    if BASELINE_SOURCE.match(rule["source"]):
        return f"{rule['statement']} ({LABELS[lang]['baseline']})"
    if rule.get("inferred") is True:
        return f"{rule['statement']} ({LABELS[lang]['inferred']})"
    return rule["statement"]


def filled(record, key):
    """A recorded value worth a row: present and not blank."""
    return key in record and visible(as_text(record[key]))


def reference_title(ref):
    """The recorded title, or None when it shows nothing (the URL stands in)."""
    title = ref.get("title")
    return title if title and visible(as_text(title)) else None


def markdown_reference(ref):
    if not is_safe_link(ref["url"]):
        # Web URLs and relative paths become links; any other scheme stays literal.
        title = reference_title(ref)
        code = markdown_code(ref["url"])
        return f"{markdown_inline(title)}: {code}" if title and title != ref["url"] else code
    title = markdown_inline(reference_title(ref) or ref["url"])
    title = title.replace("[", "&#91;").replace("]", "&#93;")
    # Angle destinations allow parentheses; entities keep input from ending
    # the destination or escaping its closing delimiter.
    url = (escape(ref["url"], quote=False).replace("\\", "&#92;")
           .replace("\r", "&#13;").replace("\n", "&#10;"))
    return f"[{title}](<{url}>)"


def diagram_changes(arch):
    """What the after diagram removes and adds, by node ID and by (from, to) edge."""
    before, after = arch.get("before"), arch.get("after")
    if before is None or after is None:
        return {"removed_nodes": set(), "added_nodes": set(),
                "removed_edges": set(), "added_edges": set()}
    nodes = [{n["id"] for n in d["nodes"]} for d in (before, after)]
    edges = [{(e["from"], e["to"]) for e in d.get("edges", [])} for d in (before, after)]
    return {"removed_nodes": nodes[0] - nodes[1], "added_nodes": nodes[1] - nodes[0],
            "removed_edges": edges[0] - edges[1], "added_edges": edges[1] - edges[0]}


def edge_state(edge, side, changes):
    """The classes an edge is drawn with: violation, removed (before) or added (after)."""
    pair = (edge["from"], edge["to"])
    states = ["violation"] if "finding" in edge else []
    if side == "before" and pair in changes["removed_edges"]:
        states.append("removed")
    if side == "after" and pair in changes["added_edges"]:
        states.append("added")
    return states


def node_state(node, side, changes):
    if side == "before" and node["id"] in changes["removed_nodes"]:
        return "removed"
    if side == "after" and node["id"] in changes["added_nodes"]:
        return "added"
    return ""


def edge_caption(edge):
    """The label and the findings an edge cites, as one line: `writes · A-001`."""
    parts = [edge["label"]] if "label" in edge else []
    if "finding" in edge:
        parts.append(", ".join(x for x in RULE_LIST.split(edge["finding"]) if x))
    return " · ".join(" ".join(as_text(p).split()) for p in parts)


def diagram_change_items(arch, lang):
    """Each change as (kind label, text) in diagram order, for both outputs."""
    t, changes = LABELS[lang], diagram_changes(arch)
    if "before" not in arch or "after" not in arch:
        return []
    labels = {n["id"]: n["label"] for side in DIAGRAMS for n in arch[side]["nodes"]}
    items = []
    for side, node_key, edge_key in (("before", "removed_nodes", "removed_edges"),
                                     ("after", "added_nodes", "added_edges")):
        kind = "removed" if side == "before" else "added"
        items += [(t[f"{kind}_node"], n["label"]) for n in arch[side]["nodes"]
                  if n["id"] in changes[node_key]]
        for e in arch[side].get("edges", []):
            if (e["from"], e["to"]) in changes[edge_key]:
                caption = edge_caption(e)
                items.append((t[f"{kind}_edge"], f"{labels[e['from']]} → {labels[e['to']]}"
                              + (f" ({caption})" if caption else "")))
    return items


# Mermaid reads `#code;` as a character, so these cannot end a quoted label,
# open a markdown string or HTML, split a statement or close the fence.
MERMAID_ESCAPE = {ord(c): f"#{ord(c)};" for c in '#"<>&`|;'}
MERMAID_SHAPES = {"module": ('["', '"]'), "store": ('[("', '")]'), "external": ('{{"', '"}}')}
MERMAID_EDGE_STYLE = {"violation": "stroke:#c0392b,stroke-width:2.5px",
                      "added": "stroke:#1f6fb2,stroke-width:3px",
                      "removed": "stroke-dasharray:6 4"}
MERMAID_NODE_STYLE = {"added": "stroke:#1f6fb2,stroke-width:3px",
                      "removed": "stroke-dasharray:5 3,color:#888"}


def mermaid_text(value):
    return " ".join(as_text(value).split()).translate(MERMAID_ESCAPE)


def mermaid(diagram, side, changes):
    """One diagram as a Mermaid flowchart; node IDs are generated, labels quoted."""
    ids = {n["id"]: f"n{i}" for i, n in enumerate(diagram["nodes"], 1)}
    lines = ["```mermaid", "flowchart LR"]
    for n in diagram["nodes"]:
        opening, closing = MERMAID_SHAPES[n.get("kind", "module")]
        lines.append(f"  {ids[n['id']]}{opening}{mermaid_text(n['label'])}{closing}")
    styles = []
    for i, e in enumerate(diagram.get("edges", [])):
        caption = edge_caption(e)
        label = f'|"{mermaid_text(caption)}"|' if caption else ""
        lines.append(f"  {ids[e['from']]} -->{label} {ids[e['to']]}")
        style = ",".join(MERMAID_EDGE_STYLE[state] for state in edge_state(e, side, changes))
        if style:
            styles.append(f"  linkStyle {i} {style}")
    lines += styles
    for state in ("added", "removed"):
        marked = [ids[n["id"]] for n in diagram["nodes"] if node_state(n, side, changes) == state]
        if marked:
            lines += [f"  classDef {state} {MERMAID_NODE_STYLE[state]}",
                      f"  class {','.join(marked)} {state}"]
    return lines + ["```"]


def markdown_architecture(doc, lang):
    t, text = LABELS[lang], markdown_inline
    arch = doc.get("architecture", {})
    changes = diagram_changes(arch)
    lines = [f"## {t['architecture']}", ""]
    for side in DIAGRAMS:
        lines += [f"### {t[side]}", ""]
        if side not in arch:
            lines += [t["not_drawn"], ""]
            continue
        if filled(arch[side], "note"):
            lines += [block_safe(text(arch[side]["note"])), ""]
        lines += mermaid(arch[side], side, changes) + [
            "", f"{t[f'legend_{side}']} {t['shapes_md']}", ""]
    if "before" in arch and "after" in arch:
        lines += [f"### {t['changes']}", ""]
        items = diagram_change_items(arch, lang)
        lines += [f"- {kind}: {text(value)}" for kind, value in items] or [t["no_changes"]]
        lines.append("")
    return lines


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
    if not any(by_sev.values()):
        # As on the dashboard: zero findings is not evidence of a sound design.
        lines += [text(DASH[lang]["no_findings"]), ""]
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
    lines += markdown_architecture(doc, lang)
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


# The dashboard follows security-scan's layout and visual language: the kit's
# application shell (app bar, contents sidebar with severity facets), summary,
# counts, a priority queue, coverage, overview charts and a filterable register.
# Unlike security-scan it is rendered here, not by its script, so it reads in
# full without JavaScript and runs under a hash-only CSP.
DASH = {
    "en": {
        "eyebrow": "ARCHITECTURE REVIEW",
        "report_note": "Static review · read-only · offline dashboard",
        "report_note_method": "Architecture review · offline dashboard",
        "report_link": "Markdown report", "theme": "Toggle color theme",
        "jump_findings": "Jump to findings",
        "risk_summary": "{n} open High / Medium findings need attention.",
        "risk_summary_one": "1 open High / Medium finding needs attention.",
        "open_summary": "{n} open findings are recorded; none are High or Medium.",
        "open_summary_one": "1 open finding is recorded; it is not High or Medium.",
        "no_open": "No open findings are recorded. This does not establish that the design is sound.",
        "no_findings": "No included findings are recorded. Review the scope and limitations before "
                       "drawing conclusions.",
        "unverified_line": "{n} included findings are not yet Valid (Likely, Unlikely or Unverified).",
        "unverified_line_one": "1 included finding is not yet Valid (Likely, Unlikely or Unverified).",
        "none_unverified_line": "Every included finding has a definitive verdict.",
        "open_hm": "Open High/Medium", "open_count": "Open findings",
        "needs_validation": "Open, needs validation", "closed_count": "Fix recorded / accepted",
        "included": "Included findings", "all_records": "All records",
        "counts_note": "Report-wide totals include Open, Fixed and Accepted. Excluded findings do not "
                       "contribute to these totals.",
        "priority": "Start here",
        "priority_note": "Open findings, ordered by severity, then readiness to fix. Confirm the "
                         "scenario before changing code.",
        "view_all": "View all findings",
        "fix_now": "Plan the fix", "verify_first": "Verify first",
        "fix_now_note": "Valid and Confirmed. Use the recorded fix direction and add the fitness "
                        "function so the rule stays enforced.",
        "verify_first_note": "Confirm the scenario, the blast radius and the rule it breaks; record "
                             "evidence before deciding on a fix.",
        "missing_fix": "Fix direction not recorded. Define it after reviewing the evidence.",
        "more_high": "{n} more open High findings are listed in the findings register.",
        "more_high_one": "1 more open High finding is listed in the findings register.",
        "queue_more": "Showing {shown} of {total} open findings.",
        "coverage_heading": "Scope, coverage and limitations",
        "coverage_note": "Coverage is recorded per perspective below. A perspective marked not "
                         "checked, or not recorded, was not reviewed. Zero findings is not a "
                         "guarantee of a sound design.",
        "limitations_count": "Recorded limitations",
        "limitations_empty": "No limitations were recorded. This is not evidence of complete coverage.",
        "perspective_count": "Perspectives applied: {applied} of {total}",
        "rules_note": "The design rules each finding is judged against, with what was checked.",
        "overview": "Results overview",
        "count_basis": "Severity is the cost if the scenario happens; confidence is how certain the "
                       "path is. The verdict records whether the finding applies.",
        "by_sev": "By severity", "by_conf": "By confidence", "by_cat": "By perspective",
        "by_status": "By status", "by_verdict": "By verdict",
        "excluded_note": "Excluded findings are retained with their justification. They are not "
                         "counted in included totals.",
        "findings_register": "Findings register",
        "findings_note": "Open a finding for its scenario, trace, evidence and fix direction. Totals "
                         "above remain report-wide while filtering.",
        "record_set": "Records", "included_set": "Included (excludes ruled-out findings)",
        "excluded_set": "Excluded only", "severity": "Severity", "confidence": "Confidence",
        "category": "Perspective", "status": "Status", "verdict": "Verdict", "sort": "Order",
        "priority_sort": "Open first, then severity", "severity_sort": "Severity",
        "search": "Search", "reset": "Clear filters", "title_col": "Title",
        "showing": "Showing {shown} of {total} records in this view",
        "no_matches": "No findings match these filters. Clear filters to see more.",
        "copy_llm": "Copy for LLM", "copied": "Copied", "copy_failed": "Copy failed",
        "permalink": "Link to finding", "expand": "Show details", "collapse": "Hide details",
        "method_row": "Method",
        "contents": "Contents", "nav_summary": "Summary", "nav_coverage": "Scope and coverage",
        "nav_architecture": "Architecture",
        "nav_lists": "Next steps and checks", "shortcuts": "Keyboard", "key_search": "Search",
        "key_move": "Next / previous finding", "key_toggle": "Show or hide details",
        "footer": "Rendered from findings.json; every value is shown as recorded. Inspect this "
                  "dashboard before sharing.",
    },
    "ja": {
        "eyebrow": "ARCHITECTURE REVIEW",
        "report_note": "静的レビュー · 読み取り専用 · オフラインダッシュボード",
        "report_note_method": "アーキテクチャレビュー · オフラインダッシュボード",
        "report_link": "Markdown レポート", "theme": "配色を切り替え",
        "jump_findings": "検出事項一覧へ移動",
        "risk_summary": "未対応の High / Medium が {n} 件あります。",
        "open_summary": "未対応の検出事項は {n} 件です。High / Medium は含まれていません。",
        "no_open": "未対応の検出事項は記録されていません。設計の健全性を保証するものではありません。",
        "no_findings": "集計対象の検出事項はありません。対象範囲と制約を確認してから判断してください。",
        "unverified_line": "集計対象のうち {n} 件は判定が確定していません（Likely・Unlikely・Unverified）。",
        "none_unverified_line": "集計対象の検出事項はすべて判定が確定しています。",
        "open_hm": "未対応の高・中", "open_count": "未対応の検出事項",
        "needs_validation": "未対応・要検証", "closed_count": "修正の申告 / 受容",
        "included": "集計対象の検出事項", "all_records": "すべての記録",
        "counts_note": "全体集計には Open・Fixed・Accepted を含みます。除外した検出事項は含みません。",
        "priority": "まず取り組むこと",
        "priority_note": "未対応の検出事項を重大度順、同じ重大度では修正判断の準備ができた順に表示します。"
                         "シナリオを確認してから修正してください。",
        "view_all": "検出事項一覧を見る",
        "fix_now": "修正を計画", "verify_first": "先に検証する",
        "fix_now_note": "Valid・Confirmed です。記録された修正方針で直し、ルールが守られ続けるよう"
                        "適合性チェックを追加してください。",
        "verify_first_note": "シナリオ・影響範囲・違反するルールを確認し、根拠を記録してから修正要否を"
                             "判断してください。",
        "missing_fix": "修正方針が未記録です。根拠を確認し、修正内容を具体化してください。",
        "more_high": "未対応の High がほかに {n} 件あります（検出事項一覧に記載）。",
        "queue_more": "未対応 {total} 件のうち {shown} 件を表示しています。",
        "coverage_heading": "対象範囲・確認状況・制約",
        "coverage_note": "観点ごとの確認状況を下に示します。not checked や未記録の観点は確認していません。"
                         "検出事項がゼロでも設計の健全性の保証にはなりません。",
        "limitations_count": "記録された制約",
        "limitations_empty": "制約事項が記録されていません。すべて確認済みであることを示すものではありません。",
        "perspective_count": "適用した観点: {total} 件中 {applied} 件",
        "rules_note": "各検出事項の判断基準とした設計ルールと、その確認結果です。",
        "overview": "結果概要",
        "count_basis": "重大度はシナリオが起きた場合の損害、確度は経路の確かさ、検証判定はこの対象に"
                       "検出事項が成立するかを表します。",
        "by_sev": "重大度別", "by_conf": "確度別", "by_cat": "観点別",
        "by_status": "対応状況別", "by_verdict": "検証判定別",
        "excluded_note": "除外した検出事項も、その根拠とともに保持します。集計対象の件数には含めません。",
        "findings_register": "検出事項一覧",
        "findings_note": "検出事項を開くとシナリオ・追跡・根拠・修正方針を確認できます。絞り込んでも上部の"
                         "全体集計は変わりません。",
        "record_set": "表示対象", "included_set": "集計対象（誤検知・対象外を除く）",
        "excluded_set": "除外した検出事項のみ", "severity": "重大度", "confidence": "確度",
        "category": "観点", "status": "状況", "verdict": "検証判定", "sort": "表示順",
        "priority_sort": "未対応を先に、重大度順", "severity_sort": "重大度順",
        "search": "検索", "reset": "絞り込みを解除", "title_col": "件名",
        "showing": "この表示対象 {total} 件中 {shown} 件を表示",
        "no_matches": "条件に一致する検出事項はありません。絞り込みを解除すると、ほかの検出事項を確認できます。",
        "copy_llm": "LLM用にコピー", "copied": "コピーしました", "copy_failed": "コピーできませんでした",
        "permalink": "この検出事項へのリンク", "expand": "詳細を開く", "collapse": "詳細を閉じる",
        "method_row": "方法",
        "contents": "目次", "nav_summary": "概要", "nav_coverage": "対象範囲と確認状況",
        "nav_architecture": "アーキテクチャ",
        "nav_lists": "次の作業と確認済み事項", "shortcuts": "キー操作", "key_search": "検索",
        "key_move": "次・前の検出事項", "key_toggle": "詳細の表示・非表示",
        "footer": "findings.json から生成しています。値はすべて記録どおりに表示しています。共有前に内容を"
                  "確認してください。",
    },
}

# Rules for architecture-scan record types only, after the shared dashboard
# stylesheet (scan_report_kit/assets/dashboard.css, docs: scan-report-kit).
DASHBOARD_CSS = """
.action-label,.reg-head,.reg-meta,.detail dt,.small,.toggle-label{font-family:var(--sans)}
.action-label{font-size:12px;font-weight:700;color:var(--accent)}
.card .n .pair{display:inline-block;white-space:nowrap;margin-right:18px}
.card .n .u{font-family:var(--sans);font-size:11px;letter-spacing:.06em;color:var(--muted);margin-left:6px}
.coverage h2 .small{font-size:13px;font-weight:400;color:var(--muted);margin-left:10px}
#decisions ul{margin:6px 0;padding-left:20px}
.bar .fill{display:block;width:0}
.bar .fill.High{background:var(--high)}
.bar .fill.Medium{background:var(--medium)}
.bar .fill.Low{background:var(--low)}
.bar .fill.Info{background:var(--info)}
.register{border-top:1.5px solid var(--text);border-bottom:1.5px solid var(--text);margin-top:12px}
.reg-head,.finding>details>summary{display:grid;grid-template-columns:9% 9% 14% 9% 10% minmax(0,1fr) 18%;gap:12px;padding:12px}
.reg-head{font-size:11px;font-weight:700;letter-spacing:.06em;border-bottom:1px solid var(--text)}
.finding{border-bottom:1px solid var(--line)}
.finding:last-child{border-bottom:0}
.finding>details>summary{list-style:none;cursor:pointer;font-weight:400}
.finding>details>summary::-webkit-details-marker{display:none}
.finding>details>summary:hover{background:var(--tint)}
.reg-title{font-weight:700;min-width:0}
.reg-meta{font-size:13px}
.toggle-label{display:block;font-size:11px;font-weight:400;color:var(--accent);margin-top:4px}
.finding .open-label,.finding details[open] .closed-label{display:none}
.finding details[open] .open-label{display:inline}
details.excluded .reg-title>span:first-child{text-decoration:line-through}
.detail{background:var(--tint);padding:18px 24px}
.detail dl{display:grid;grid-template-columns:150px minmax(0,1fr);gap:8px 18px;margin:12px 0}
.detail dt{font-size:12px;color:var(--muted)}
.detail dd{margin:0;overflow-wrap:anywhere;white-space:pre-wrap}
.action-guidance{margin-top:12px}
.action-guidance strong{font-family:var(--sans);font-size:13px}
.empty{padding:20px 12px;margin:0}
@media(max-width:850px){.reg-head{display:none}.finding>details>summary{grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;padding:14px}.finding>details>summary>span:before{content:attr(data-label);display:block;color:var(--muted);font-size:10px;font-family:var(--sans)}.reg-title{grid-column:1/-1;grid-row:1}.reg-cat{grid-column:span 2}.detail{padding:16px}.detail dl{grid-template-columns:minmax(0,1fr);gap:3px}.detail dd{margin-bottom:10px}}
@media(max-width:480px){.detail-actions{flex-direction:column;align-items:flex-start}}
/* Rules ledger and perspective coverage: a long path or note breaks anywhere rather than
   widen the table past its status column; below the register's breakpoint each row
   stacks, its ID or perspective beside its status, each value under its column label. */
table.rules td,table.coverage-table td{overflow-wrap:anywhere}
@media(max-width:850px){table.rules,table.rules>tbody,table.coverage-table,table.coverage-table>tbody{display:block}table.rules>thead,table.coverage-table>thead{position:absolute;width:1px;height:1px;overflow:hidden;clip-path:inset(50%);white-space:nowrap}table.rules>tbody>tr,table.coverage-table>tbody>tr{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px;padding:14px 12px;border-bottom:1px solid var(--line)}table.rules>tbody>tr:last-child,table.coverage-table>tbody>tr:last-child{border-bottom:0}table.rules>tbody>tr>td,table.coverage-table>tbody>tr>td{border:0;padding:0}table.rules>tbody>tr>td:before,table.coverage-table>tbody>tr>td:before{content:attr(data-label);display:block;color:var(--muted);font-size:10px;font-family:var(--sans);margin-bottom:3px}table.rules>tbody>tr>td:nth-child(2),table.rules>tbody>tr>td:nth-child(3),table.coverage-table>tbody>tr>td:nth-child(3){grid-column:1/-1}table.rules>tbody>tr>td:nth-child(4){grid-column:2;grid-row:1}table.rules>tbody>tr>td.nowrap{white-space:normal}}
/* Application shell: the register is a list of details, not the kit's table, so
   its head row and focused finding get the shell's pinning and focus marks here. */
.app-shell #decisions-section:focus,.app-shell #rules-section:focus{outline:0}
.app-shell .filters{grid-template-columns:minmax(0,2fr) repeat(3,minmax(0,1fr))}
.app-shell .finding:focus-within>details>summary{background:var(--tint);box-shadow:inset 2px 0 0 var(--text)}
@media(max-width:1099px){.app-shell .filters{grid-template-columns:repeat(3,minmax(0,1fr))}}
@media(max-width:850px){.app-shell .filters{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(min-width:1100px){.app-shell .reg-head{position:sticky;z-index:4;top:calc(var(--appbar-h) + var(--filters-h,0px));background:var(--bg)}}
@media print{.app-shell .reg-head{position:static}.app-shell .finding:focus-within>details>summary{background:none;box-shadow:none}}
/* Before/after architecture: a wide diagram scrolls inside its frame, never the page. */
.arch-figure{margin:18px 0 0}
.arch-figure figcaption p{margin:4px 0}
.arch-scroll{overflow-x:auto;border:1px solid var(--line);background:var(--bg);margin-top:8px}
.arch-scroll:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.arch-svg{display:block;font-family:var(--sans);font-size:12px}
.arch-svg .node rect{fill:var(--panel);stroke:var(--text);stroke-width:1.2}
.arch-svg .node text{fill:var(--text)}
.arch-svg .node.store rect{fill:var(--soft)}
.arch-svg .node.external rect{stroke-dasharray:4 3}
.arch-svg .node.added rect{stroke:var(--accent);stroke-width:3}
.arch-svg .node.removed rect{stroke:var(--muted);stroke-dasharray:6 4}
.arch-svg .node.removed text{fill:var(--muted)}
.arch-svg .edge path{fill:none;stroke:var(--muted);stroke-width:1.4}
.arch-svg .edge.violation path{stroke:var(--high);stroke-width:2.6}
.arch-svg .edge.added path{stroke:var(--accent);stroke-width:3}
.arch-svg .edge.removed path{stroke-dasharray:7 5}
.arch-svg .arrow path{fill:var(--muted)}
.arch-svg .arrow.violation path{fill:var(--high)}
.arch-svg .arrow.added path{fill:var(--accent)}
.arch-svg .elabel{fill:var(--text);font-size:11px;paint-order:stroke;stroke:var(--bg);stroke-width:4px;stroke-linejoin:round}
.arch-svg .elabel.violation{fill:var(--high)}
.arch-text{margin-top:8px;font-family:var(--sans);font-size:13px}
.arch-text li,.arch-changes li{overflow-wrap:anywhere}
@media print{.arch-scroll{overflow:visible;border:0}.arch-svg{max-width:100%;height:auto}.arch-figure{break-inside:avoid}.filters-panel,.copy-finding,.toggle-label{display:none!important}.priority-item{break-inside:avoid}.finding{display:block!important}}
"""
CSS = kit_style.dashboard_css() + DASHBOARD_CSS

JS = """
(function(){
'use strict';
var root=document.documentElement,L=JSON.parse(document.getElementById('labels').textContent);
var COPY=JSON.parse(document.getElementById('copy-data').textContent);
function byId(id){return document.getElementById(id);}
function fmt(text,values){return text.replace(/\\{(\\w+)\\}/g,function(_,k){return values[k];});}
document.querySelectorAll('[data-js]').forEach(function(e){e.hidden=false;});
byId('theme').onclick=function(){var dark=root.dataset.theme?root.dataset.theme==='dark':window.matchMedia('(prefers-color-scheme: dark)').matches;root.dataset.theme=dark?'light':'dark';};
document.querySelectorAll('.bar .fill').forEach(function(f){f.style.width=f.dataset.w+'%';});
// With no findings the register is a note only: no search box, no filters.
var list=byId('f-q')?byId('register-list'):null,items=list?Array.prototype.slice.call(list.querySelectorAll('.finding')):[];
var m=document.querySelector('[data-empty]'),q=byId('f-q'),searchCache=new Map();
function v(id){return byId(id).value;}
// Search the recorded values only, not the dashboard's own labels and buttons.
function text(d){if(!searchCache.has(d))searchCache.set(d,Array.prototype.map.call(d.querySelectorAll('summary>span:not(.reg-title),.reg-title>span:not(.toggle-label),.reg-title>code,.detail dd'),function(n){return n.textContent;}).join(' ').toLowerCase());return searchCache.get(d);}
function show(){if(!list)return;var scope=v('f-scope'),term=q.value.trim().toLowerCase(),key=v('f-sort')==='severity'?'s':'p',pool=0,n=0;
items.slice().sort(function(a,b){return a.dataset[key]-b.dataset[key];}).forEach(function(d){list.appendChild(d);
var x=d.dataset.x==='1',inPool=scope==='all'||(scope==='excluded')===x;if(inPool)pool++;
d.hidden=!(inPool&&(!v('f-sev')||d.dataset.sev===v('f-sev'))&&(!v('f-conf')||d.dataset.conf===v('f-conf'))&&(!v('f-cat')||d.dataset.cat===v('f-cat'))&&(!v('f-status')||d.dataset.status===v('f-status'))&&(!v('f-verdict')||d.dataset.verdict===v('f-verdict'))&&(!term||text(d).indexOf(term)>=0));if(!d.hidden)n++;});
byId('result-count').textContent=fmt(L.showing,{shown:n,total:pool});if(m)m.hidden=n>0;
facets.forEach(function(b){b.setAttribute('aria-pressed',String(scope==='included'&&v('f-sev')===b.dataset.sev));});}
function reset(){['f-sev','f-conf','f-cat','f-status','f-verdict'].forEach(function(id){byId(id).value='';});byId('f-scope').value='included';byId('f-sort').value='priority';q.value='';}
if(list){document.querySelectorAll('.filters select').forEach(function(s){s.onchange=function(){if(s.id==='f-verdict'&&s.dataset.excluded.split(' ').indexOf(s.value)>=0)byId('f-scope').value='all';show();};});
var timer=null;q.oninput=function(){clearTimeout(timer);timer=setTimeout(show,items.length>300?150:0);};
byId('reset').onclick=function(){reset();show();};}
// Sidebar facets: a press filters the register by severity, a second press clears it.
// It clears an excluded verdict, which no included finding carries.
var facets=Array.prototype.slice.call(document.querySelectorAll('.facet'));
facets.forEach(function(b){b.onclick=function(){var on=b.getAttribute('aria-pressed')==='true',vs=byId('f-verdict');byId('f-scope').value='included';
if(vs&&vs.dataset.excluded.split(' ').indexOf(vs.value)>=0)vs.value='';byId('f-sev').value=on?'':b.dataset.sev;show();byId('findings').scrollIntoView();};});
if(list)show();
function openHash(){var id;try{id=decodeURIComponent(location.hash.slice(1));}catch(err){return;}var d=byId(id);if(!d||!d.classList.contains('finding'))return;if(d.hidden){reset();if(d.dataset.x==='1')byId('f-scope').value='all';show();}d.querySelector('details').open=true;d.scrollIntoView({block:'start'});d.querySelector('summary').focus({preventScroll:true});}
window.addEventListener('hashchange',openHash);if(location.hash)openHash();
document.addEventListener('click',function(e){var a=e.target.closest('a[href^="#finding-"]');if(a&&a.getAttribute('href')===location.hash){e.preventDefault();openHash();}});
// A denied or unavailable Clipboard API falls back to the selection copy.
function copyFallback(value){return new Promise(function(resolve,reject){var prev=document.activeElement,t=document.createElement('textarea');t.value=value;t.readOnly=true;t.style.position='fixed';t.style.top='0';t.style.left='-9999px';document.body.appendChild(t);t.select();var ok=false;try{ok=document.execCommand('copy');}catch(err){}t.remove();if(prev&&prev.focus)prev.focus({preventScroll:true});if(ok)resolve();else reject(new Error('copy'));});}
function copyText(value){if(navigator.clipboard&&window.isSecureContext)return navigator.clipboard.writeText(value).catch(function(){return copyFallback(value);});return copyFallback(value);}
document.querySelectorAll('.copy-finding').forEach(function(b){var t;b.onclick=function(){var done=function(label){b.textContent=label;clearTimeout(t);t=setTimeout(function(){b.textContent=L.copy_llm;},2000);};copyText(COPY[b.dataset.copy]).then(function(){done(L.copied);},function(){done(L.copy_failed);});};});
// Keyboard: "/" searches, j/k step through the visible findings (Enter on the focused title toggles it), Escape clears the search.
document.addEventListener('keydown',function(e){if(!q||e.altKey||e.ctrlKey||e.metaKey||e.isComposing)return;var t=e.target;if(t&&t.closest&&t.closest('input,select,textarea')){if(e.key==='Escape'&&t===q&&q.value){q.value='';show();}return;}
if(e.key==='/'){e.preventDefault();q.focus();}else if(e.key==='j'||e.key==='k'){var shown=Array.prototype.slice.call(list.querySelectorAll('.finding:not([hidden])>details>summary')),current=document.activeElement&&document.activeElement.closest('.finding');if(!shown.length)return;var at=shown.findIndex(function(s){return s.closest('.finding')===current;}),next=at<0?0:Math.min(shown.length-1,Math.max(0,at+(e.key==='j'?1:-1)));e.preventDefault();shown[next].focus();shown[next].scrollIntoView({block:'nearest'});}});
// The register's head row pins below the filter bar, whose height depends on the language and viewport.
var panel=document.querySelector('.filters-panel');if(panel&&window.ResizeObserver)new window.ResizeObserver(function(entries){byId('findings').style.setProperty('--filters-h',entries[0].target.offsetHeight+'px');}).observe(panel);
// Mark the section in view in the sidebar contents.
var navLinks=Array.prototype.slice.call(byId('nav').querySelectorAll('a[href^="#"]'));if(window.IntersectionObserver){var visible=new Map(),spy=new window.IntersectionObserver(function(entries){entries.forEach(function(en){visible.set(en.target.id,en.isIntersecting);});var first=navLinks.find(function(a){return visible.get(a.getAttribute('href').slice(1));});navLinks.forEach(function(a){if(a===first)a.setAttribute('aria-current','location');else a.removeAttribute('aria-current');});},{rootMargin:'-35% 0px -60% 0px'});navLinks.forEach(function(a){var s=byId(a.getAttribute('href').slice(1));if(s)spy.observe(s);});}
// Printing shows and opens every finding, then restores the filtered view.
var shut=[];addEventListener('beforeprint',function(){shut=[];items.forEach(function(f){var d=f.querySelector('details');if(!d.open)shut.push(d);f.hidden=false;d.open=true;});if(m)m.hidden=true;});
addEventListener('afterprint',function(){shut.forEach(function(d){d.open=false;});if(list)show();});
})();
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
    title, url = reference_title(ref) or ref["url"], ref["url"]
    label = html_text(f"{title}: {url}" if title != url else url)
    if is_web_url(url):
        return f"<a href='{escape(url)}' rel='noopener noreferrer'>{label}</a>"
    return label


def plural(d, key, n, **values):
    text = d[key + "_one"] if n == 1 and key + "_one" in d else d[key]
    return text.format(n=n, **values)


def is_excluded(f):
    return f["validation"]["verdict"] in EXCLUDED


def action(f):
    """Fix now only what is Open, Valid and Confirmed; anything else is verified first."""
    return ("fix_now" if f["validation"]["verdict"] == "Valid" and f["confidence"] == "Confirmed"
            else "verify_first")


def anchor(f):
    return f"finding-{f['id'].lower()}"


def json_data(value):
    # A `<` would let recorded text end the data block or open a comment.
    return json.dumps(value, ensure_ascii=False).replace("<", "\\u003c")


def fenced(value):
    value = as_text(value).replace("\r\n", "\n").replace("\r", "\n")
    fence = "`" * max(3, max((len(run) for run in re.findall(r"`+", value)), default=0) + 1)
    return f"{fence}text\n{value}\n{fence}"


def finding_markdown(f, lang):
    """One finding as plain Markdown for pasting into a model, every value literal."""
    t = LABELS[lang]

    def one(value):
        return re.sub(r"\s*[\r\n]+\s*", " ", as_text(value))

    v = f["validation"]
    out = [f"## {one(f['id'])} · {one(f['title'])}", ""]
    for label, value in (("severity", f["severity"]), ("confidence", f["confidence"]),
                         ("verdict", f"{v['verdict']} ({v['method']})"),
                         ("status", f.get("status", "Open")), ("category", category(f)),
                         ("location", ", ".join(as_locations(f["location"])))):
        out.append(f"- {DASH[lang].get(label, t.get(label))}: {one(value)}")
    if filled(f, "rule"):
        out.append(f"- {t['rule']}: {one(f['rule'])}")
    blocks = [(t[k], f[k]) for k in FIELDS if k not in ("location", "rule") and filled(f, k)]
    if filled(v, "evidence"):
        blocks.append((t["evidence"], v["evidence"]))
    if "analysis" in f:
        a = f["analysis"]
        blocks.append((t["analysis"], f"{a['result']}\n{a['tool']}: {a['command']}"))
    for label, value in blocks:
        out += ["", f"### {label}", "", fenced(value)]
    refs = f.get("references", [])
    if refs:
        out += ["", f"### {t['references']}", ""]
        out += [f"- {one(r['title']) + ' — ' if reference_title(r) not in (None, r['url']) else ''}"
                f"{one(r['url'])}" for r in refs]
    return "\n".join(out) + "\n"


def bars(order, counter, colored=False):
    top = max([counter.get(k, 0) for k in order] + [1])
    return "".join(
        f"<div class='bar'><span class='t'>{html_text(k)}</span><span class='track'>"
        f"<span class='fill{' ' + k if colored else ''}' data-w='{counter.get(k, 0) * 100 // top}'>"
        f"</span></span><span class='v'>{counter.get(k, 0)}</span></div>" for k in order)


def tally(findings, key):
    out = {}
    for f in findings:
        out[key(f)] = out.get(key(f), 0) + 1
    return out


def options(values, first=None):
    head = f"<option value=''>{html_text(first)}</option>" if first else ""
    return head + "".join(f"<option value='{escape(as_text(value))}'>{html_text(label)}</option>"
                          for value, label in values)


def bullet_list(items, empty):
    if not items:
        return f"<p class='muted'>{html_text(empty)}</p>"
    return "<ul>" + "".join(f"<li>{html_text(i)}</li>" for i in items) + "</ul>"


# Diagram geometry, in SVG user units (CSS pixels at natural size).
# A gap between columns holds an edge label of about 24 narrow characters.
NODE_W, NODE_H, GAP_X, GAP_Y, PAD = 184, 44, 168, 28, 24
# Room right of the last column for an edge between two nodes of one column.
LOOP = 48
# Width of a narrow character in an edge label, and the label's line height.
LABEL_UNIT, LABEL_H = 6.4, 14
LABEL_UNITS = 24


def arch_layout(arch):
    """Place every node of either diagram once, so a module sits still between them.

    Columns follow the longest path along the edges of both diagrams (an edge
    closing a cycle is left out of the ranking). An edge spanning several
    columns passes through a free slot in each column between, so it never runs
    under a node it does not touch; an edge against the columns is routed from
    its target and drawn with the arrow at its start. Within a column, nodes
    and slots are ordered by the mean row of their neighbours in the column
    before, then in the column after, a few times over; then each one moves to
    the place in its column with the fewest crossings (on a tie, away from where
    it stood, to leave a plateau), and the order with the fewest crossings seen
    is kept. Returns the node positions, each edge's route and the canvas size.
    """
    order, edges = [], []
    for side in DIAGRAMS:
        if side in arch:
            order += [n["id"] for n in arch[side]["nodes"] if n["id"] not in order]
            edges += [(e["from"], e["to"]) for e in arch[side].get("edges", [])
                      if (e["from"], e["to"]) not in edges]
    out = {node: [] for node in order}
    for a, b in edges:
        out[a].append(b)
    # Depth-first, in record order: an edge to a node still on the path closes a cycle.
    state, kept = {}, []
    for root in order:
        if root in state:
            continue
        state[root], stack = 1, [(root, iter(out[root]))]
        while stack:
            node, children = stack[-1]
            child = next(children, None)
            if child is None:
                state[node] = 2
                stack.pop()
            elif child not in state:
                kept.append((node, child))
                state[child] = 1
                stack.append((child, iter(out[child])))
            elif state[child] == 2:
                kept.append((node, child))
    rank = {node: 0 for node in order}
    incoming = {node: 0 for node in order}
    for _, b in kept:
        incoming[b] += 1
    ready = [node for node in order if not incoming[node]]
    while ready:
        node = ready.pop(0)
        for a, b in kept:
            if a == node:
                rank[b] = max(rank[b], rank[a] + 1)
                incoming[b] -= 1
                if not incoming[b]:
                    ready.append(b)
    columns = [[] for _ in range(max(rank.values()) + 1)]
    for node in order:
        columns[rank[node]].append(node)
    # Each edge as a chain left to right: its first node, a slot per column
    # between, its last node. A slot is a tuple, so it never equals a node ID.
    chains = {}
    for a, b in edges:
        left, right = (a, b) if rank[a] <= rank[b] else (b, a)
        slots = [("slot", a, b, c) for c in range(rank[left] + 1, rank[right])]
        for slot in slots:
            columns[slot[3]].append(slot)
        chains[(a, b)] = [left, *slots, right]
    neighbours = {node: set() for column in columns for node in column}
    for chain in chains.values():
        for x, y in zip(chain, chain[1:]):
            neighbours[x].add(y)
            neighbours[y].add(x)

    def reorder(c, beside):
        row = {node: i for i, node in enumerate(columns[beside])}

        def key(at, node):
            near = [row[x] for x in neighbours[node] if x in row]
            return (sum(near) / len(near) if near else at, at)
        columns[c] = [node for _, node in sorted(
            ((key(at, node), i), node) for i, (at, node) in enumerate(enumerate(columns[c])))]

    for _ in range(4):
        for c in range(1, len(columns)):
            reorder(c, c - 1)
        for c in range(len(columns) - 2, -1, -1):
            reorder(c, c + 1)
    def gap_crossings(c):
        """Crossings between columns c and c + 1: inversions, counted with a Fenwick tree."""
        here = {node: i for i, node in enumerate(columns[c])}
        there = {node: i for i, node in enumerate(columns[c + 1])}
        pairs = sorted((here[x], there[y]) for x in columns[c] for y in neighbours[x] if y in there)
        tree, count = [0] * (len(there) + 1), 0
        for seen, (_, j) in enumerate(pairs):
            i, below = j + 1, 0
            while i:
                below, i = below + tree[i], i - (i & -i)
            count += seen - below  # earlier pairs ending below j cross this one
            i = j + 1
            while i <= len(there):
                tree[i], i = tree[i] + 1, i + (i & -i)
        return count

    def total():
        return sum(gap_crossings(c) for c in range(len(columns) - 1))

    def sift(c):
        """Move each node of column c to its place with the fewest crossings."""
        column = columns[c]
        sides = [{node: i for i, node in enumerate(columns[o])}
                 for o in (c - 1, c + 1) if 0 <= o < len(columns)]
        # The neighbouring columns do not move while column c is sifted, so the
        # crossings of every pair are counted once, by node index, before the moves:
        # pairs[u][v] counts the pairs of rows (a, b), one side at a time, with a
        # of u, b of v and a > b, i.e. the crossings when u stands above v.
        nodes = list(column)
        rows = [[sorted(row[x] for x in neighbours[node] if x in row) for row in sides]
                for node in nodes]

        def greater(node_rows):
            """For each row k of each side in turn: how many of the node's rows there exceed k."""
            counts = []
            for node_side, row in zip(node_rows, sides):
                start = 0  # sorted, so the count drops by one at each of the node's rows
                for passed, r in enumerate(node_side):
                    counts += [len(node_side) - passed] * (r - start)
                    start = r
                counts += [0] * (len(row) - start)
            return counts

        # by_row[k][u] is greater(rows[u])[k]; below[v][u] == pairs[u][v] sums it
        # over the rows k of v, in the same numbering.
        by_row, below = list(zip(*map(greater, rows))), []
        for node_rows in rows:
            column_sum, offset = [0] * len(nodes), 0
            for node_side, row in zip(node_rows, sides):
                for r in node_side:
                    column_sum = list(map(add, column_sum, by_row[offset + r]))
                offset += len(row)
            below.append(column_sum)
        pairs = [list(row) for row in zip(*below)]
        order = list(range(len(nodes)))
        for node in range(len(nodes)):
            stood = order.index(node)
            others = order[:stood] + order[stood + 1:]
            above = pairs[node]
            # costs[i]: crossings with node placed at i among the others; moving
            # it past x swaps which of the two stands above.
            costs = list(accumulate(
                map(sub, map(below[node].__getitem__, others), map(above.__getitem__, others)),
                initial=sum(above) - above[node]))
            fewest = min(costs)
            at = costs.index(fewest)
            if at == stood:
                # On a tie, move away from where it stood, to leave a plateau.
                at = next((i for i in range(stood + 1, len(costs)) if costs[i] == fewest), at)
            others.insert(at, node)
            order = others
        column[:] = [nodes[i] for i in order]

    best, fewest_total = [list(column) for column in columns], total()
    for _ in range(6):
        if not fewest_total:
            break
        for c in range(len(columns)):
            sift(c)
        crossings = total()
        if crossings < fewest_total:
            best, fewest_total = [list(column) for column in columns], crossings
    columns = best
    tallest = max(len(column) for column in columns)
    positions = {}
    for c, column in enumerate(columns):
        offset = (tallest - len(column)) * (NODE_H + GAP_Y) / 2
        for r, node in enumerate(column):
            positions[node] = (PAD + c * (NODE_W + GAP_X), PAD + offset + r * (NODE_H + GAP_Y))
    routes = {}
    for (a, b), chain in chains.items():
        # Two edges joining the same pair both ways run a little apart.
        shift = (7 if chain[0] == b else -7) if (b, a) in chains else 0
        if rank[a] == rank[b]:
            routes[(a, b)] = ("loop", positions[a], positions[b], shift)
            continue
        points = []
        for i, node in enumerate(chain):
            x, y = positions[node]
            y += NODE_H / 2 + shift
            if i:
                points.append((x, y))
            if i < len(chain) - 1:
                points.append((x + NODE_W, y))
        routes[(a, b)] = ("chain", points, chain[0] == b, shift)
    width = PAD * 2 + len(columns) * NODE_W + (len(columns) - 1) * GAP_X + LOOP
    height = PAD * 2 + tallest * NODE_H + (tallest - 1) * GAP_Y
    return positions, routes, width, height


def text_units(value):
    """value's width in narrow characters: a wide (CJK) character counts two."""
    return sum(2 if unicodedata.east_asian_width(char) in "WF" else 1 for char in value)


def fit(value, units):
    """value collapsed to one line and cut to about `units` narrow characters."""
    value = " ".join(as_text(value).split())
    used = 0
    for i, char in enumerate(value):
        used += text_units(char)
        if used > units:
            return value[:i - 1] + "…" if i else "…"
    return value


def fit_caption(edge):
    """An edge's label as lines that fit its gap: the text may be cut, a finding ID never.

    The label and the IDs share one line when they fit, the text cut first;
    otherwise the text takes a line of its own and the IDs as many lines as
    they need.
    """
    caption = edge_caption(edge)
    if "finding" not in edge or text_units(caption) <= LABEL_UNITS:
        return [fit(caption, LABEL_UNITS)]
    lines = [""]
    for fid in (x for x in RULE_LIST.split(edge["finding"]) if x):
        joined = f"{lines[-1]}, {fid}" if lines[-1] else fid
        if text_units(joined) <= LABEL_UNITS:
            lines[-1] = joined
        else:
            lines.append(fid)
    if "label" not in edge:
        return lines
    room = LABEL_UNITS - text_units(lines[0]) - 3
    if len(lines) == 1 and room >= 4:
        return [f"{fit(edge['label'], room)} · {lines[0]}"]
    return [fit(edge["label"], LABEL_UNITS), *lines]


def svg_route(route):
    """A route as SVG path data, and the cubic segments a label may sit on."""
    kind, *rest = route
    if kind == "loop":
        # Same column: out of the right side and back in, bulging right.
        (x1, y1), (x2, y2), shift = rest
        p0, p3 = (x1 + NODE_W, y1 + NODE_H / 2 + shift), (x2 + NODE_W, y2 + NODE_H / 2 + shift)
        p1, p2 = (p0[0] + LOOP, p0[1]), (p3[0] + LOOP, p3[1])
        data = "M{:g},{:g} C{:g},{:g} {:g},{:g} {:g},{:g}".format(*p0, *p1, *p2, *p3)
        return data, [(p0, p1, p2, p3)], False
    points, reverse, _ = rest
    data, segments = ["M{:g},{:g}".format(*points[0])], []
    for i in range(0, len(points) - 1, 2):
        p0, p3 = points[i], points[i + 1]
        dx = (p3[0] - p0[0]) / 2
        segment = (p0, (p0[0] + dx, p0[1]), (p3[0] - dx, p3[1]), p3)
        segments.append(segment)
        data.append("C{:g},{:g} {:g},{:g} {:g},{:g}".format(*segment[1], *segment[2], *p3))
        if i + 2 < len(points):
            data.append("L{:g},{:g}".format(*points[i + 2]))  # across a column's free slot
    return " ".join(data), segments, reverse


def bezier(points, t):
    return tuple(sum(c * p[i] for c, p in zip(
        ((1 - t) ** 3, 3 * t * (1 - t) ** 2, 3 * t * t * (1 - t), t ** 3), points)) for i in (0, 1))


def label_spot(segments, width, taken, height=LABEL_H):
    """Where a label of `width` and `height` goes: the middle of a gap, unless a box is there.

    `taken` holds the boxes (x, y, w, h, weight) of the nodes and of the labels
    placed so far; the spot with the least weighted overlap wins, the middle
    first. A node weighs more than a label: a label over a box hides its name.
    """
    def overlap(spot):
        x, y = spot[0] - width / 2, spot[1] - height
        # Only boxes that overlap add to the sum: every term is at least 0, so
        # leaving out the zeros keeps the sum, in the same order, unchanged.
        return sum(weight * across * down for bx, by, bw, bh, weight in taken
                   if (across := min(x + width, bx + bw) - max(x, bx)) > 0
                   and (down := min(y + height, by + bh) - max(y, by)) > 0)

    spots = [bezier(segment, t) for t in (0.5, 0.35, 0.65, 0.2, 0.8, 0.1, 0.9)
             for segment in segments]
    # As min(spots, key=overlap): the first of equal spots wins, and no spot
    # can beat one that overlaps nothing, so the search stops there.
    spot, least = None, None
    for candidate in spots:
        cost = overlap(candidate)
        if least is None or cost < least:
            spot, least = candidate, cost
            if not cost:
                break
    taken.append((spot[0] - width / 2, spot[1] - height, width, height, 1))
    return spot


def svg_text(value):
    return escape(" ".join(as_text(value).split()))


def svg_diagram(diagram, side, changes, layout, title):
    positions, routes, width, height = layout
    out = [f"<svg class='arch-svg' role='img' aria-labelledby='{side}-arch-title' "
           f"width='{width:g}' height='{height:g}' viewBox='0 0 {width:g} {height:g}' "
           f"xmlns='http://www.w3.org/2000/svg'><title id='{side}-arch-title'>{escape(title)}</title><defs>"]
    for state in ("plain", "violation", "added"):
        out.append(f"<marker id='{side}-arrow-{state}' class='arrow {state}' viewBox='0 0 10 10' "
                   "refX='10' refY='5' markerWidth='10' markerHeight='10' markerUnits='userSpaceOnUse' "
                   "orient='auto-start-reverse'>"
                   "<path d='M0,0 L10,5 L0,10 z'/></marker>")
    out.append("</defs>")
    taken = [(*positions[n["id"]], NODE_W, NODE_H, 10) for n in diagram["nodes"]]
    labels = []
    for e in diagram.get("edges", []):
        states = edge_state(e, side, changes)
        path, segments, reverse = svg_route(routes[(e["from"], e["to"])])
        arrow = next((s for s in ("violation", "added") if s in states), "plain")
        caption = edge_caption(e)
        end = "start" if reverse else "end"
        out.append(f"<g class='edge {' '.join(states)}'><title>{svg_text(caption)}</title>"
                   f"<path d='{path}' marker-{end}='url(#{side}-arrow-{arrow})'/></g>")
        if caption:
            lines = fit_caption(e)
            mx, my = label_spot(segments, max(map(text_units, lines)) * LABEL_UNIT, taken,
                                LABEL_H * len(lines))
            # The lines stack upward, the last one where a one-line label sits.
            top = my - 4 - LABEL_H * (len(lines) - 1)
            spans = "".join(f"<tspan x='{mx:g}' dy='{LABEL_H if i else 0}'>{svg_text(line)}</tspan>"
                            for i, line in enumerate(lines))
            labels.append(f"<text class='elabel {' '.join(states)}' x='{mx:g}' y='{top:g}' "
                          f"text-anchor='middle'>{spans}</text>")
    for n in diagram["nodes"]:
        x, y = positions[n["id"]]
        cls = f"node {n.get('kind', 'module')} {node_state(n, side, changes)}".strip()
        radius = 16 if n.get("kind") == "store" else 4
        out.append(f"<g class='{cls}'><title>{svg_text(n['label'])}</title>"
                   f"<rect x='{x:g}' y='{y:g}' width='{NODE_W}' height='{NODE_H}' rx='{radius}'/>"
                   f"<text x='{x + NODE_W / 2:g}' y='{y + NODE_H / 2 + 4:g}' text-anchor='middle'>"
                   f"{svg_text(fit(n['label'], 24))}</text></g>")
    # Labels last, so no node box covers them.
    return "".join(out + labels) + "</svg>"


def html_architecture(doc, lang):
    t = LABELS[lang]
    e = html_text
    arch = doc.get("architecture", {})
    changes = diagram_changes(arch)
    layout = arch_layout(arch) if arch else None
    out = [f"<section class='panel arch' id='architecture' tabindex='-1'><h2>{e(t['architecture'])}</h2>"]
    for side in DIAGRAMS:
        out.append(f"<figure class='arch-figure'><figcaption><h3>{e(t[side])}</h3>")
        if side not in arch:
            out.append(f"<p class='muted'>{e(t['not_drawn'])}</p></figcaption></figure>")
            continue
        diagram = arch[side]
        if filled(diagram, "note"):
            out.append(f"<p>{e(diagram['note'])}</p>")
        out.append(f"<p class='section-note'>{e(t[f'legend_{side}'])} {e(t['shapes_svg'])}</p></figcaption>"
                   # Focusable, so a keyboard can scroll a diagram wider than the screen.
                   f"<div class='arch-scroll' tabindex='0' role='region' aria-label='{escape(t[side])}'>"
                   f"{svg_diagram(diagram, side, changes, layout, t[side])}</div>")
        labels = {n["id"]: n["label"] for n in diagram["nodes"]}
        rows = [f"<li>{e(n['label'])}</li>" for n in diagram["nodes"]]
        rows += [f"<li>{e(labels[x['from']])} → {e(labels[x['to']])}"
                 + (f" ({e(x['label'])})" if "label" in x else "")
                 + (f" · {e(x['finding'])}" if "finding" in x else "") + "</li>"
                 for x in diagram.get("edges", [])]
        out.append(f"<details class='arch-text'><summary>{e(t['edges_text'])}</summary>"
                   f"<ul>{''.join(rows)}</ul></details></figure>")
    if "before" in arch and "after" in arch:
        items = diagram_change_items(arch, lang)
        out.append(f"<h3>{e(t['changes'])}</h3>")
        out.append("<ul class='arch-changes'>" + "".join(
            f"<li><strong>{e(kind)}:</strong> {e(value)}</li>" for kind, value in items) + "</ul>"
            if items else f"<p class='muted'>{e(t['no_changes'])}</p>")
    out.append("</section>")
    return "".join(out)


def render_html(doc, lang):
    t, d = LABELS[lang], DASH[lang]
    e = html_text
    meta, findings = doc["meta"], doc.get("findings", [])
    by_sev, excluded = counts(findings)
    included = [f for f in findings if not is_excluded(f)]
    status = {f["id"]: f.get("status", "Open") for f in findings}
    open_ = [f for f in included if status[f["id"]] == "Open"]
    open_hm = sum(f["severity"] in ("High", "Medium") for f in open_)
    rank = {s: i for i, s in enumerate(SEVERITIES)}
    queue = sorted(open_, key=lambda f: (rank[f["severity"]], action(f) != "fix_now", f["id"]))
    fix_now = sum(action(f) == "fix_now" for f in open_)
    pending = sum(f["validation"]["verdict"] != "Valid" for f in included)

    nav = [("overview", d["nav_summary"]), ("priority-section", d["priority"]),
           ("decisions-section", t["decisions"]), ("coverage", d["nav_coverage"])]
    nav += [("rules-section", t["rules"])] if doc.get("rules") else []
    nav += [("findings", d["findings_register"]), ("architecture", d["nav_architecture"]),
            ("lists", d["nav_lists"])]
    sidebar = [f"<nav class='sidebar' id='nav' aria-label='{escape(d['contents'])}'>"
               f"<h2 class='nav-title'>{e(d['contents'])}</h2><ol class='nav-links'>"
               + "".join(f"<li><a href=\"#{i}\">{e(label)}</a></li>" for i, label in nav) + "</ol>"]
    if findings:
        # Facets and keys act on the register through the script, so they appear with it.
        sidebar.append(f"<div class='facets' data-js hidden><h2 class='nav-title'>{e(d['severity'])}</h2>"
                       + "".join(f"<button type='button' class='facet' data-sev='{s}' aria-controls='register-list' "
                                 f"aria-pressed='false'><span class='facet-name {s}'>{s}</span>"
                                 f"<span class='facet-n'>{by_sev[s]}</span></button>" for s in SEVERITIES)
                       + f"</div><dl class='keys' data-js hidden><dt class='nav-title'>{e(d['shortcuts'])}</dt>"
                       f"<dd><kbd>/</kbd> {e(d['key_search'])}</dd><dd><kbd>j</kbd> <kbd>k</kbd> {e(d['key_move'])}</dd>"
                       f"<dd><kbd>Enter</kbd> {e(d['key_toggle'])}</dd></dl>")
    sidebar.append("</nav>")
    # A recorded method (e.g. a GUARD step) supersedes the read-only note.
    note = "report_note_method" if visible(as_text(meta.get("method", ""))) else "report_note"

    out = [f"<!doctype html><html lang='{lang}' class='app-shell'><head><meta charset='utf-8'>",
           f"<meta http-equiv='Content-Security-Policy' content=\"{CSP}\">",
           "<meta name='viewport' content='width=device-width,initial-scale=1'>",
           f"<title>{escape(t['title'])}: {escape(' '.join(as_text(meta.get('project', '')).split()))}</title>"
           f"<style>{CSS}</style></head><body>",
           f"<a class='skip' href=\"#findings\">{e(d['jump_findings'])}</a>",
           f"<header class='appbar'><div class='appbar-in'><span class='brand'><span>{e(d['eyebrow'])}</span>"
           f"<span class='appbar-project'>{e(meta.get('project', ''))}</span></span><div class='tools'>"
           f"<a class='button' href=\"report.md\">{e(d['report_link'])}</a>"
           f"<button type='button' id='theme' data-js hidden>{e(d['theme'])}</button></div></div></header>",
           "<div class='shell'>", *sidebar,
           "<main><section id='overview' tabindex='-1' aria-labelledby='h'>",
           f"<div class='hero'><div><div class='eyebrow'>{e(t['title'])}</div>"
           f"<h1 id='h'>{e(meta.get('project', ''))}</h1>"
           f"<div class='meta'>{e(meta.get('scope', ''))} · {e(revision(meta))} · "
           f"{e(meta.get('date', ''))} · {e(meta.get('assessor', ''))}</div></div>"
           f"<div class='hero-aside'>{e(d[note])}</div></div>"]

    if not included:
        headline = d["no_findings"]
    elif open_hm:
        headline = plural(d, "risk_summary", open_hm)
    elif open_:
        headline = plural(d, "open_summary", len(open_))
    else:
        headline = d["no_open"]
    detail = plural(d, "unverified_line", pending) if pending else d["none_unverified_line"]
    out.append(f"<div class='summary-banner'><strong>{e(headline)}</strong>"
               f"<p>{e(detail if included else review_method(doc, lang))}</p></div>")

    closed = "".join(f"<span class='pair'>{sum(status[f['id']] == s for f in included)}"
                     f"<span class='u'>{s}</span></span>" for s in ("Fixed", "Accepted"))
    cards = [(d["open_hm"], open_hm, "urgent", f"{d['open_count']}: {len(open_)}"),
             (d["needs_validation"], len(open_) - fix_now, "review", f"{d['fix_now']}: {fix_now}"),
             (d["closed_count"], closed, "", f"{d['included']}: {len(included)}"),
             (t["excluded"], excluded, "", f"{d['all_records']}: {len(findings)}")]
    out.append("<div class='cards'>" + "".join(
        f"<div class='card {cls}'><span class='l'>{e(label)}</span><div class='n'>{n}</div>"
        f"<div class='sub'>{e(sub)}</div></div>" for label, n, cls, sub in cards) + "</div>")
    out.append(f"<p class='report-note'>{e(d['counts_note'])}</p></section>")

    # The priority queue: every open High, at least four items, at most twelve.
    highs = sum(f["severity"] == "High" for f in queue)
    top = queue[:max(4, min(highs, 12))]
    out.append(f"<section id='priority-section' tabindex='-1' aria-labelledby='priority-heading'>"
               f"<div class='section-head'><div>"
               f"<h2 id='priority-heading'>{e(d['priority'])}</h2><p>{e(d['priority_note'])}</p></div>"
               f"<a href=\"#findings\">{e(d['view_all'])}</a></div>")
    if any(action(f) == "verify_first" for f in top):
        out.append(f"<p class='section-note'><span class='action-label'>{e(d['verify_first'])}</span> "
                   f"{e(d['verify_first_note'])}</p>")
    if top:
        out.append("<div class='priority-list'>")
        for f in top:
            a = action(f)
            item = [f"<article class='panel priority-item sev-{f['severity']}'><div class='priority-top'>"
                    f"<span class='badge {f['severity']}'>{f['severity']}</span>"
                    f"<span class='action-label'>{e(d[a])}</span></div>"
                    f"<h3><a href=\"#{anchor(f)}\">{e(f['id'])} · {e(f['title'])}</a></h3>"
                    f"<div class='verdict'>{e(f['confidence'])} · {e(f['validation']['verdict'])} · "
                    f"{e(category(f))}</div>",
                    "".join(f"<code class='location'>{e(p)}</code>" for p in as_locations(f["location"])),
                    f"<p>{e(f['impact'])}</p>" if filled(f, "impact") else ""]
            if a == "fix_now":
                item.append(f"<p class='action'>{e(f['fix']) if filled(f, 'fix') else e(d['missing_fix'])}</p>")
            out.append("".join(item) + "</article>")
        out.append("</div>")
    else:
        out.append(f"<p class='panel muted'>{e(d['no_open'] if included else d['no_findings'])}</p>")
    hidden_high = highs - sum(f["severity"] == "High" for f in top)
    if hidden_high > 0:
        out.append(f"<p class='section-note'>{e(plural(d, 'more_high', hidden_high))}</p>")
    if len(top) < len(queue):
        out.append(f"<p class='section-note'>{e(d['queue_more'].format(shown=len(top), total=len(queue)))}</p>")
    out.append("</section>")

    out.append(f"<section class='panel' id='decisions-section' tabindex='-1'><h2>{e(t['decisions'])}</h2>"
               f"<div id='decisions'>"
               f"{bullet_list(doc.get('decisions', []), t['none'])}</div></section>")

    rows = perspective_rows(doc, lang)
    applied = sum(p["status"] == "applied" for _, p in rows)
    limitations = doc.get("limitations", [])
    out.append(f"<section class='panel coverage' id='coverage' tabindex='-1'><h2>{e(d['coverage_heading'])}<span class='small'>"
               f"{e(d['limitations_count'])}: {len(limitations)}</span></h2>"
               f"<p>{e(d['coverage_note'])}</p><dl class='scope-meta'>"
               f"<dt>{e(t['scope_row'])}</dt><dd>{e(meta.get('scope', ''))}</dd>"
               f"<dt>{e(d['method_row'])}</dt><dd>{e(review_method(doc, lang))}</dd>"
               f"<dt>{e(t['revision'])}</dt><dd>{e(revision(meta))}</dd></dl>"
               f"<h3>{e(t['limitations'])}</h3>{bullet_list(limitations, d['limitations_empty'])}"
               f"<h3>{e(t['perspectives'])}</h3><p class='section-note'>"
               f"{e(d['perspective_count'].format(applied=applied, total=len(rows)))}</p>"
               f"<div class='tablewrap'><table class='coverage-table'><thead><tr><th>{e(t['perspective'])}</th>"
               f"<th>{e(t['rule_status'])}</th><th>{e(t['note'])}</th></tr></thead><tbody>")
    for name, p in rows:
        out.append(f"<tr><td data-label='{escape(t['perspective'])}'>{e(name)}</td>"
                   f"<td data-label='{escape(t['rule_status'])}'>{e(p['status'])}</td>"
                   f"<td data-label='{escape(t['note'])}'>{e(p['note'])}</td></tr>")
    out.append("</tbody></table></div></section>")

    if doc.get("rules"):
        out.append(f"<section class='panel' id='rules-section' tabindex='-1'><h2>{e(t['rules'])}</h2><p class='section-note'>"
                   f"{e(d['rules_note'])}</p><div class='tablewrap'><table class='rules'><thead><tr>"
                   f"<th>{e(t['id'])}</th><th>{e(t['statement'])}</th><th>{e(t['source'])}</th>"
                   f"<th>{e(t['rule_status'])}</th></tr></thead><tbody>")
        for r in doc["rules"]:
            rule_state = e(r["status"])
            if filled(r, "reason"):
                rule_state += f"<br>{e(t['reason'])}: {e(r['reason'])}"
            out.append(f"<tr><td class='nowrap' data-label='{escape(t['id'])}'>{e(rule_id(r))}</td>"
                       f"<td data-label='{escape(t['statement'])}'>{e(rule_statement(r, lang))}</td>"
                       f"<td data-label='{escape(t['source'])}'>{e(r['source'])}</td>"
                       f"<td data-label='{escape(t['rule_status'])}'>{rule_state}</td></tr>")
        out.append("</tbody></table></div></section>")

    cats = sorted(tally(included, lambda f: f["category"]).items(), key=lambda kv: (-kv[1], kv[0]))
    out.append(f"<section class='panel'><h2>{e(d['overview'])}</h2><p class='section-note'>"
               f"{e(d['count_basis'])}</p><div class='grid'>"
               f"<div><h3>{e(d['by_sev'])}</h3>{bars(SEVERITIES, by_sev, colored=True)}</div>"
               f"<div><h3>{e(d['by_conf'])}</h3>{bars(CONFIDENCES, tally(included, lambda f: f['confidence']))}</div>"
               f"<div><h3>{e(d['by_cat'])}</h3>{bars([k for k, _ in cats], dict(cats))}</div>"
               f"<div><h3>{e(d['by_status'])}</h3>{bars(STATUSES, tally(included, lambda f: status[f['id']]))}</div>"
               f"<div><h3>{e(d['by_verdict'])}</h3>{bars(VERDICTS, verdict_counts(findings))}"
               f"<p class='section-note'>{e(d['excluded_note'])}</p></div></div></section>")

    out.append(f"<section id='findings' tabindex='-1' aria-labelledby='findings-heading'><div class='section-head'><div>"
               f"<h2 id='findings-heading'>{e(d['findings_register'])}</h2><p>{e(d['findings_note'])}</p>"
               f"</div></div>")
    if findings:
        excluded_values = " ".join(EXCLUDED)
        all_cats = sorted({f["category"] for f in findings})
        out.append(
            "<div class='panel filters-panel' data-js hidden><div class='filters'>"
            f"<label><span>{e(d['record_set'])}</span><select id='f-scope'>"
            + options([("included", d["included_set"]), ("excluded", d["excluded_set"]),
                       ("all", d["all_records"])]) + "</select></label>"
            f"<label><span>{e(d['severity'])}</span><select id='f-sev'>"
            + options([(s, s) for s in SEVERITIES], t["all"]) + "</select></label>"
            f"<label><span>{e(d['confidence'])}</span><select id='f-conf'>"
            + options([(c, c) for c in CONFIDENCES], t["all"]) + "</select></label>"
            f"<label><span>{e(d['category'])}</span><select id='f-cat'>"
            + options([(c, c) for c in all_cats], t["all"]) + "</select></label>"
            f"<label><span>{e(d['status'])}</span><select id='f-status'>"
            + options([(s, s) for s in STATUSES], t["all"]) + "</select></label>"
            f"<label><span>{e(d['verdict'])}</span><select id='f-verdict' data-excluded='{excluded_values}'>"
            + options([(v, v) for v in VERDICTS], t["all"]) + "</select></label>"
            f"<label><span>{e(d['sort'])}</span><select id='f-sort'>"
            + options([("priority", d["priority_sort"]), ("severity", d["severity_sort"])]) + "</select></label>"
            f"<label class='search'><span>{e(d['search'])}</span><input id='f-q' type='search' "
            f"placeholder='{escape(d['search'])}'></label></div><div class='filter-bottom'>"
            "<p class='result-count' id='result-count' role='status' aria-live='polite'></p>"
            f"<button type='button' id='reset'>{e(d['reset'])}</button></div></div>")
    heads = ("ID", d["severity"], d["confidence"], d["status"], d["verdict"], d["title_col"], d["category"])
    out.append("<div class='register'><div class='reg-head' aria-hidden='true'>"
               + "".join(f"<span>{e(h)}</span>" for h in heads) + "</div><div id='register-list'>")
    if not findings:
        out.append(f"<p class='empty'>{e(t['none'])}</p>")
    else:
        # Shown by the filter when it leaves no finding visible.
        out.append(f"<p class='empty' data-empty hidden>{e(d['no_matches'])}</p>")

    # Excluded findings come last in either order, as in their IDs: a ruled-out
    # High is nothing to act on before an open Medium.
    def priority(f):
        return (is_excluded(f), status[f["id"]] != "Open", rank[f["severity"]],
                action(f) != "fix_now", f["id"])

    p_order = {f["id"]: i for i, f in enumerate(sorted(findings, key=priority))}
    s_order = {f["id"]: i for i, f in enumerate(sorted(
        findings, key=lambda f: (is_excluded(f), rank[f["severity"]], f["id"])))}
    copy = {}
    for f in findings:
        v = f["validation"]
        x = is_excluded(f)
        copy[f["id"]] = finding_markdown(f, lang)
        fields = [(t["category"], e(category(f)))]
        fields += [(t[k], e(f[k])) for k in FIELDS if filled(f, k)]
        fields.append((t["verdict"], e(f"{v['verdict']} ({v['method']})")))
        if filled(v, "evidence"):
            fields.append((t["evidence"], e(v["evidence"])))
        fields.append((t["status"], e(status[f["id"]])))
        if "analysis" in f:
            a = f["analysis"]
            fields.append((t["analysis"], e(f"{a['result']} — {a['tool']}: {a['command']}")))
        if f.get("references"):
            # Every reference keeps its own row label.
            fields += [(t["references"], html_reference(ref)) for ref in f["references"]]
        guidance = ""
        if status[f["id"]] == "Open" and not x:
            a = action(f)
            guidance = (f"<div class='action-guidance'><strong>{e(d[a])}</strong>"
                        f"<p>{e(d[a + '_note'])}</p></div>")
        elif x:
            guidance = f"<p class='muted'>{e(d['excluded_note'])}</p>"
        # Excluded findings are not in the severity counts, so not in their filters.
        group = "excluded' class='excluded" if x else f["severity"]
        attrs = {"sev": f["severity"], "conf": f["confidence"], "cat": f["category"],
                 "status": status[f["id"]], "verdict": v["verdict"], "x": "1" if x else "0",
                 "p": p_order[f["id"]], "s": s_order[f["id"]]}
        data = "".join(f" data-{k}='{escape(as_text(val))}'" for k, val in attrs.items())
        locations = "".join(f"<code class='location'>{e(p)}</code>" for p in as_locations(f["location"]))
        out.append(
            f"<div class='finding' id='{anchor(f)}'{data}><details data-sev='{group}'><summary>"
            f"<span data-label='ID'>{e(f['id'])}</span>"
            f"<span data-label='{escape(d['severity'])}'><span class='badge {f['severity']}'>{f['severity']}</span></span>"
            f"<span class='reg-meta' data-label='{escape(d['confidence'])}'>{e(f['confidence'])}</span>"
            f"<span class='reg-meta' data-label='{escape(d['status'])}'>{e(status[f['id']])}</span>"
            f"<span class='reg-meta' data-label='{escape(d['verdict'])}'>{e(v['verdict'])}</span>"
            f"<span class='reg-title'><span>{e(f['title'])}</span>{locations}"
            f"<span class='toggle-label' aria-hidden='true'><span class='closed-label'>{e(d['expand'])}</span>"
            f"<span class='open-label'>{e(d['collapse'])}</span></span></span>"
            f"<span class='reg-meta reg-cat' data-label='{escape(d['category'])}'>{e(f['category'])}</span>"
            f"</summary><div class='detail'><div class='detail-actions'><strong>{e(f['id'])} · {e(f['title'])}</strong>"
            f"<span class='detail-links'><button type='button' class='copy-finding' data-js hidden "
            f"data-copy='{escape(f['id'])}' aria-live='polite'>{e(d['copy_llm'])}</button>"
            f"<a href=\"#{anchor(f)}\">{e(d['permalink'])}</a></span></div>{guidance}<dl>"
            + "".join(f"<dt>{e(k)}</dt><dd>{val}</dd>" for k, val in fields) + "</dl></div></details></div>")
    out.append("</div></div></section>")
    # After the register: the after diagram is where the fix directions lead.
    out.append(html_architecture(doc, lang))

    out.append("<div class='lists' id='lists' tabindex='-1'>" + "".join(
        f"<section class='panel'><h2>{e(t[k])}</h2>{bullet_list(doc.get(k, []), t['none'])}</section>"
        for k in ("next_steps", "checked_ok")) + "</div>")
    out.append(f"<footer class='footer'>{e(d['footer'])}</footer></main></div>")
    labels = {k: d[k] for k in ("showing", "copy_llm", "copied", "copy_failed")}
    out.append(f"<script type='application/json' id='labels'>{json_data(labels)}</script>"
               f"<script type='application/json' id='copy-data'>{json_data(copy)}</script>"
               f"<script>{JS}</script></body></html>")
    return "".join(out)


def rendered_outputs(doc, lang):
    """The exact bytes render.py writes for doc, keyed by output name."""
    return {"report.md": render_markdown(doc, lang).encode("utf-8"),
            "dashboard.html": render_html(doc, lang).encode("utf-8")}


def main(argv=None):
    safe_output()
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
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
