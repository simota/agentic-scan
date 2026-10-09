#!/usr/bin/env python3
"""Render findings.json into dashboard.html and report.md.

    python3 render.py FINDINGS --out DIR [--lang ja|en]

Both outputs are derived from the one record; neither adds facts of its own.
`dashboard.html` is self-contained and works offline. `report.md` follows the
findings-report shape in `reference/report.md`.

Exit codes: 0 written, 1 an output could not be encoded or saved, 2 an input
could not be read or decoded, or does not match the schema (reasons on stderr).
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
from urllib.parse import quote, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
from findings import (EXCLUDED, PERSPECTIVES, SEVERITIES, VERDICTS, SchemaError,  # noqa: E402
                      read_json, resolve_path, validate)

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
        "command": "command", "environment": "environment",
        "regression_test": "regression test", "references": "references", "status": "status",
        "budget": "budget", "static_note": "Static review; no load was sent to any deployed environment.",
        "measured_note": "Static review plus explicitly authorized local measurements.",
        "project": "System", "revision": "Revision", "date": "Date / assessor",
        "source": "Source", "inferred": "Inferred", "reason": "Reason not checked",
        "inferred_yes": "Yes — confirm with owner", "inferred_no": "No",
        "verdict_counts": "Verification counts",
        "incomplete_high": "High with incomplete verification",
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
        "command": "コマンド", "environment": "実行環境",
        "regression_test": "回帰テスト", "references": "参考", "status": "ステータス",
        "budget": "バジェット", "static_note": "静的レビューのみ。稼働中の環境には負荷を一切かけていない。",
        "measured_note": "静的レビューに加え、明示的に許可されたローカル計測を実施。",
        "project": "システム", "revision": "リビジョン", "date": "診断日 / 診断者",
        "source": "出典", "inferred": "推定", "reason": "未確認の理由",
        "inferred_yes": "推定・要確認", "inferred_no": "いいえ",
        "verdict_counts": "検証判定別の件数", "incomplete_high": "検証未完了の High",
    },
}
FIELDS = ("location", "workload", "scale_driver", "cost_model", "request", "contrast",
          "impact", "budget", "fix", "regression_test")


def finding_group(finding):
    """Use the same groups for summary counts and dashboard filters."""
    return "excluded" if finding["validation"]["verdict"] in EXCLUDED else finding["severity"]


def counts(findings):
    groups = [finding_group(f) for f in findings]
    return {s: groups.count(s) for s in SEVERITIES}, groups.count("excluded")


def verification_summary(findings, labels):
    """Use the same included findings as the severity totals, without upgrading verdicts."""
    by_verdict = {v: 0 for v in VERDICTS if v not in EXCLUDED}
    incomplete_high = 0
    for finding in findings:
        verdict = finding["validation"]["verdict"]
        if verdict in EXCLUDED:
            continue
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


def text_lines(value):
    return as_text(value).replace("\r\n", "\n").replace("\r", "\n").split("\n")


def markdown_text(value):
    """Keep record strings literal and keep newlines inside their current block."""
    def inline(line):
        line = escape(line, quote=False)
        line = re.sub(r"([\\`*_\[\]#!~])", r"\\\1", line)
        # A list value has no static label before it: "- - text", "- 1. text"
        # and "-     text" would otherwise create nested blocks.
        line = re.sub(r"^([ \t]*)([-+])", r"\1\\\2", line)
        line = re.sub(r"^([ \t]*[0-9]{1,9})([.)])(?=[ \t]|$)", r"\1\\\2", line)
        # GFM also recognises bare URLs and email addresses. Only references[]
        # should create links; character references retain their visible text.
        line = line.replace("://", "&#58;//").replace("@", "&#64;")
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
    """Return a URL safe to link, before escaping for Markdown or HTML."""
    try:
        scheme = urlsplit(url).scheme.lower()
    except ValueError:
        return None
    if scheme not in ("", "http", "https", "mailto"):
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


def budget_cells(budget, labels):
    inferred = budget.get("inferred")
    inference = (labels["inferred_yes"] if inferred is True else
                 labels["inferred_no"] if inferred is False else "—")
    return (budget["id"], budget["statement"], budget["source"], budget["status"],
            inference, budget.get("reason", ""))


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
    lines += ["", f"## {t['scope']}", "", "| | |", "|---|---|",
              f"| {t['project']} | {markdown_cell(meta.get('project', ''))} |",
              f"| Scope | {markdown_cell(meta.get('scope', ''))} |",
              f"| {t['revision']} | {markdown_cell(meta.get('commit', 'UNKNOWN'))} |",
              f"| {t['date']} | {markdown_cell(meta.get('date', ''))} / "
              f"{markdown_cell(meta.get('assessor', ''))} |", ""]
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
        if "measurement" in f:
            m = f["measurement"]
            lines.append(f"- **{t['measurement']}:** {markdown_text(m['result'])} "
                         f"({markdown_code(m['command'])}, {markdown_text(m['environment'])})")
        lines.append(f"- **{t['status']}:** {f.get('status', 'Open')}")
        for ref in f.get("references", []):
            lines.append(f"- **{t['references']}:** "
                         f"{markdown_link(ref.get('title', ref['url']), ref['url'])}")
        lines.append("")
    if doc.get("budgets"):
        headers = ("ID", t["budget"], t["source"], t["status"], t["inferred"], t["reason"])
        lines += [f"## {t['budgets']}", "", "| " + " | ".join(headers) + " |",
                  "|---|---|---|---|---|---|"]
        for b in doc["budgets"]:
            lines.append("| " + " | ".join(markdown_cell(cell) for cell in budget_cells(b, t)) + " |")
        lines.append("")
    lines += [f"## {t['perspectives']}", "", "| | Status | Note |", "|---|---|---|"]
    for p in doc.get("perspectives", []):
        lines.append("| " + " | ".join(markdown_cell(p[key]) for key in ("name", "status", "note")) + " |")
    lines.append("")
    for key in ("checked_ok", "limitations", "decisions", "next_steps"):
        lines += [f"## {t[key]}", ""]
        lines += [f"- {markdown_text(item)}" for item in doc.get(key, [])] or [t["none"]]
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
a{color:var(--low)}
details{background:var(--card);border:1px solid var(--line);border-radius:8px;margin:8px 0;padding:8px 12px}
summary{cursor:pointer;font-weight:600}dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 12px}
dt{color:var(--muted)}dd{margin:0;overflow-wrap:anywhere}
h1,summary,p,dd,td,li{white-space:pre-wrap}
pre{margin:0;white-space:pre-wrap;overflow-wrap:anywhere}
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
    verdicts, incomplete_high = verification_summary(findings, t)
    e = html_text
    out = [f"<!doctype html><html lang='{lang}'><head><meta charset='utf-8'>",
           "<meta name='viewport' content='width=device-width,initial-scale=1'>",
           f"<title>{e(t['title'])}</title><style>{CSS}</style></head><body><main>",
           f"<h1>{e(t['title'])}: {e(meta.get('project', ''))}</h1>",
           f"<p class='muted'>{e(meta.get('scope', ''))} · {e(meta.get('commit', 'UNKNOWN'))} · "
           f"{e(meta.get('date', ''))} · {e(meta.get('assessor', ''))}</p><div class='cards'>"]
    for s in SEVERITIES:
        out.append(f"<div class='card'><span class='{s}'>{s}</span><b>{by_sev[s]}</b></div>")
    out.append(f"<div class='card'><span>{e(t['excluded'])}</span><b>{excluded}</b></div></div>")
    out.append(f"<p>{e(verdicts)} · <strong>{e(incomplete_high)}</strong></p>"
               f"<p class='muted'>{e(review_note(findings, t))}</p>")
    out.append(f"<h2>{e(t['findings'])}</h2><p><button data-filter='all' aria-pressed='true'>"
               f"{e(t['all'])}</button> "
               + " ".join(f"<button data-filter='{s}' aria-pressed='false'>{s}</button>" for s in SEVERITIES)
               + f" <button data-filter='excluded' aria-pressed='false'>{e(t['excluded'])}</button>"
               + "</p>")
    if not findings:
        out.append(f"<p>{e(t['none'])}</p>")
    for f in findings:
        v = f["validation"]
        group = finding_group(f)
        exclusion = (f" <span class='muted'>· {e(t['excluded'])}: {e(v['verdict'])}</span>"
                     if group == "excluded" else "")
        rows = [(t[k], f[k]) for k in FIELDS if k in f]
        rows += [(t["verdict"], f"{v['verdict']} ({v['method']})"), (t["evidence"], v.get("evidence", "")),
                 (t["status"], f.get("status", "Open"))]
        if "measurement" in f:
            m = f["measurement"]
            rows += [(t["measurement"], m["result"]), (t["environment"], m["environment"])]
        out.append(f"<details data-sev='{group}'><summary><span class='{f['severity']}'>"
                   f"{f['severity']}</span> {e(f['id'])} {e(f['title'])} "
                   f"<span class='muted'>· {e(f['confidence'])} · {e(f['category'])}</span>{exclusion}</summary><dl>"
                   + "".join(f"<dt>{e(k)}</dt><dd>{e(val)}</dd>" for k, val in rows))
        if "measurement" in f:
            out.append(f"<dt>{e(t['command'])}</dt><dd><pre><code>"
                       f"{e(f['measurement']['command'])}</code></pre></dd>")
        for ref in f.get("references", []):
            out.append(f"<dt>{e(t['references'])}</dt><dd>"
                       f"{html_link(ref.get('title', ref['url']), ref['url'])}</dd>")
        out.append("</dl></details>")
    if doc.get("budgets"):
        headers = ("ID", t["budget"], t["source"], t["status"], t["inferred"], t["reason"])
        out.append(f"<h2>{e(t['budgets'])}</h2><table><thead><tr>"
                   + "".join(f"<th scope='col'>{e(header)}</th>" for header in headers)
                   + "</tr></thead><tbody>")
        for b in doc["budgets"]:
            out.append("<tr>" + "".join(f"<td>{e(cell)}</td>" for cell in budget_cells(b, t)) + "</tr>")
        out.append("</tbody></table>")
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


def write_outputs(outputs):
    """Stage every output before replacing any, restoring old files on failure."""
    destinations = [(resolve_path(path), content) for path, content in outputs]
    if len({path for path, _ in destinations}) != len(destinations):
        raise OSError("report and dashboard must have different destinations")
    temporary_dirs, prepared, attempted = [], [], []
    retained = set()
    try:
        for target, content in destinations:
            try:
                mode = target.stat().st_mode
            except FileNotFoundError:
                mode = None
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
    try:
        doc = read_json(args.findings)
        validate(doc, complete=True)
    except SchemaError as exc:
        print(f"schema: {exc}", file=sys.stderr)
        return 2
    lang = args.lang or doc["meta"]["lang"]
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
