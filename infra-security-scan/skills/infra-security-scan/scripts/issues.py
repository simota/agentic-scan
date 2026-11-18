#!/usr/bin/env python3
"""Draft one issue per finding from templates/issue.<lang>.md.

    python3 issues.py FINDINGS --out DIR [--lang ja|en] [--ids ID ...]
                      [--min-severity High|Medium|Low|Info] [--mask]

Writes DIR/<ID>.md for each counted finding (excluded findings need no change,
and an I-* covered by a review finding is filed through that finding) and
DIR/index.md listing every draft with where it may be filed. DIR is scratch:
never the output directory (its file set is fixed) nor the assessed
repository. Drafts are for a human to review and file; nothing is sent.

The template is the source of truth: each `{{field}}` takes the same field of
the finding (`{{meta.*}}` of the record), a line holding `{{list[].field}}` is
repeated per item, a table row whose fields are all empty is dropped, and a
comment naming one field becomes that field's line when the finding has it.
Unfixed High and Medium drafts open with a banner: private tracker only.

`--mask` replaces 12-digit account IDs and IPv4 addresses (0.0.0.0 kept) with
placeholders, for a tracker whose readers should not see them; other
identifying names (buckets, projects) still need a reading before filing.

Exit codes: 0 written, 1 refused (an ID that cannot be drafted, a bad DIR),
2 unreadable input, schema error or unwritable DIR.
"""
import argparse
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))  # also under python -I
import render  # noqa: E402
from common import SEV_RANK, SEVERITIES, has_symlink_parent  # noqa: E402
from redaction import CREDENTIAL  # noqa: E402
from scan_report_kit.output import write_output  # noqa: E402

TEMPLATES = Path(__file__).resolve().parents[1] / "templates"
PLACEHOLDER = re.compile(r"\{\{\s*([A-Za-z_][\w.]*(?:\[\])?(?:\.[\w]+)?)\s*\}\}")
COMMENT = re.compile(r"<!--(.*?)-->", re.DOTALL)
ACCOUNT_ID = re.compile(r"(?<![\w.-])[0-9]{12}(?![\w-])")
IPV4 = re.compile(r"(?<![\w.])(?!0\.0\.0\.0(?![\d]))(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\w.])")
DISPLAYED = ("severity", "confidence", "category", "validation.verdict")
LABELS = {
    "en": {"private": "> **Private tracker only.** An unfixed {0} finding: never file it in a public issue; "
                      "use a private tracker or a security advisory.",
           "any": "> Check the masking before filing: account IDs, project IDs, bucket names and addresses "
                  "should match the readers of the tracker.",
           "index": "Issue drafts", "where": "File in", "private_where": "private tracker only",
           "any_where": "any tracker, after the masking check",
           "draft": "Draft", "masked": "Masked: 12-digit account IDs as <account-id>, IPv4 addresses as <ip>."},
    "ja": {"private": "> **非公開トラッカー専用。** 未修正の {0} の検出事項です。公開 issue には登録せず、"
                      "非公開トラッカーか Security Advisory を使ってください。",
           "any": "> 登録前に、アカウント ID・プロジェクト ID・バケット名・アドレスの伏せ方を閲覧範囲に合わせて確認してください。",
           "index": "issue 下書き", "where": "登録先", "private_where": "非公開トラッカーのみ",
           "any_where": "伏せ字を確認したうえで任意のトラッカー",
           "draft": "下書き", "masked": "伏せ字: 12 桁のアカウント ID を <account-id>、IPv4 アドレスを <ip> にしています。"},
}


class Refused(Exception):
    pass


def lookup(finding, meta, name):
    """The value a placeholder names, or None; `meta.*` reads the record's meta."""
    source, parts = (meta, name.split(".")[1:]) if name.startswith("meta.") else (finding, name.split("."))
    value = source
    for part in parts:
        value = value.get(part) if isinstance(value, dict) else None
    return value


def text_of(value, finding, name, lang, code=False):
    if value is None or value == "" or value == []:
        return ""
    if name in DISPLAYED:
        value = render.shown(value, lang)
    if name == "meta.inputs" and isinstance(value, list):
        value = [f"{i.get('kind')}: {i.get('path')}" for i in value if isinstance(i, dict)]
    if isinstance(value, list):
        return ("`, `" if code else ", ").join(str(x) for x in value)
    return str(value)


def fill_line(line, finding, meta, lang, item=None):
    """(filled line, how many placeholders, how many were empty)."""
    total = empty = 0
    table = line.lstrip().startswith("|")

    def sub(m):
        nonlocal total, empty
        name = m.group(1)
        total += 1
        if "[]" in name:
            base, _, field = name.partition("[].")
            value = item.get(field) if isinstance(item, dict) else None
        else:
            value = lookup(finding, meta, name)
        before = line[:m.start()]
        text = text_of(value, finding, name, lang, code=before.endswith("`"))
        if not text:
            empty += 1
            return "—"
        if table:
            text = text.replace("|", "\\|").replace("\n", "<br>")
        return text
    return PLACEHOLDER.sub(sub, line), total, empty


def fill(template, finding, meta, lang, L):
    """The template with this finding's fields; see the module docstring for the rules."""
    head, body = "", template
    m = re.match(r"\s*<!--.*?-->\s*\n", template, re.DOTALL)
    if m:  # The filing checklist stays, invisible once filed, for whoever files it.
        head, body = m.group(), template[m.end():]

    def comment(m):
        names = PLACEHOLDER.findall(m.group(1))
        if len(names) != 1:
            return m.group()  # guidance for the filer
        value = text_of(lookup(finding, meta, names[0]), finding, names[0], lang)
        label = render.LABELS[lang].get(names[0].split(".")[-1], names[0])
        return f"**{label}:** {value}" if value else ""
    body = COMMENT.sub(comment, body)
    out = []
    for line in body.split("\n"):
        names = PLACEHOLDER.findall(line)
        if not names:
            out.append(line)
            continue
        if any("[]" in n for n in names):
            base = names[0].partition("[]")[0]
            items = lookup(finding, meta, base)
            for item in items if isinstance(items, list) else []:
                out.append(fill_line(line, finding, meta, lang, item)[0])
            continue
        filled, total, empty = fill_line(line, finding, meta, lang)
        only_fields = not PLACEHOLDER.sub("", line).strip(" `")
        if empty == total and not only_fields:
            continue  # an optional row or labelled line with nothing to say
        out.append(filled)
    text = head + "\n".join(out)
    text = re.sub(r"\n{3,}", "\n\n", text)
    # Drop a section heading left with nothing under it (a finding with no references).
    text = re.sub(r"\n## [^\n]*\n+(?=## |\Z)", "\n", text)
    return text


def banner(finding, L, lang):
    private = finding.get("severity") in ("High", "Medium")
    note = L["private"].format(render.shown(finding.get("severity"), lang)) if private else L["any"]
    return private, note


def mask(text):
    return IPV4.sub("<ip>", ACCOUNT_ID.sub("<account-id>", text))


def select(data, ids=None, min_severity="Info"):
    findings = {f["id"]: f for f in data.get("findings", []) if isinstance(f, dict)}
    covered = render.covered_by(data)
    if ids:
        missing = [i for i in ids if i not in findings]
        if missing:
            raise Refused(f"no such finding: {', '.join(missing)}")
        excluded = [i for i in ids if render.is_excluded(findings[i])]
        if excluded:
            raise Refused(f"{', '.join(excluded)}: excluded after triage (FalsePositive / NotApplicable); "
                          "an excluded finding needs no issue")
        merged = [f"{i} (covered by {', '.join(covered[i])})" for i in ids if i in covered]
        if merged:
            raise Refused(f"{', '.join(merged)}: file the covering review finding instead")
        chosen = [findings[i] for i in ids]
    else:
        chosen = [f for f in findings.values() if not render.is_excluded(f) and f["id"] not in covered]
    limit = SEV_RANK[min_severity]
    return render.ordered([f for f in chosen if SEV_RANK.get(f.get("severity"), 9) <= limit])


def drafts(data, lang, ids=None, min_severity="Info", masked=False):
    """{file name: text} for the drafts and index.md."""
    template = (TEMPLATES / f"issue.{lang}.md").read_text(encoding="utf-8")
    L = LABELS[lang]
    meta = data.get("meta", {})
    out, rows = {}, []
    for f in select(data, ids, min_severity):
        private, note = banner(f, L, lang)
        text = note + "\n\n" + fill(template, f, meta, lang, L).lstrip()
        text = CREDENTIAL.sub("[redacted]", text)  # gated at merge; never repeat one here either
        if masked:
            text = mask(text)
        name = f"{f['id']}.md"
        out[name] = text.rstrip() + "\n"
        rows.append(f"| [{f['id']}]({name}) | {render.shown(f.get('severity'), lang)} | "
                    f"{str(render.shown(f.get('title', ''), lang)).replace('|', chr(92) + '|')} | "
                    f"{L['private_where'] if private else L['any_where']} |")
    index = [f"# {L['index']} — {meta.get('project', '')}", "",
             f"| ID | {render.LABELS[lang]['severity']} | {render.LABELS[lang]['title']} | {L['where']} |",
             "|---|---|---|---|", *rows]
    if masked:
        index += ["", L["masked"]]
    text = CREDENTIAL.sub("[redacted]", "\n".join(index) + "\n")
    out["index.md"] = mask(text) if masked else text
    return out


def out_problem(out, findings_path):
    out = Path(out)
    if out.is_symlink() or has_symlink_parent(out):
        return f"{out} is a symlink or has a symlinked parent directory"
    record_dir = Path(findings_path).resolve().parent
    if out.resolve() == record_dir:
        return (f"{out} holds findings.json; the output directory's file set is fixed — "
                "write drafts to scratch")
    if out.exists() and not out.is_dir():
        return f"{out} is not a directory"
    return None


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("findings")
    p.add_argument("--out", required=True, help="scratch directory for the drafts")
    p.add_argument("--lang", choices=sorted(LABELS), default="en")
    p.add_argument("--ids", nargs="+", metavar="ID", help="draft only these findings")
    p.add_argument("--min-severity", choices=SEVERITIES, default="Info", metavar="SEVERITY")
    p.add_argument("--mask", action="store_true", help="mask 12-digit account IDs and IPv4 addresses")
    a = p.parse_args(argv)
    try:
        data = render.load_record(a.findings)
        render.validate(data, partial=True)
    except render.SchemaError as e:
        for problem in e.problems:
            print(f"schema: {problem}", file=sys.stderr)
        return 2
    problem = out_problem(a.out, a.findings)
    if problem:
        print(f"refused: {problem}", file=sys.stderr)
        return 1
    try:
        texts = drafts(data, a.lang, a.ids, a.min_severity, a.mask)
    except Refused as e:
        print(f"refused: {e}", file=sys.stderr)
        return 1
    out = Path(a.out)
    try:
        out.mkdir(parents=True, exist_ok=True)
        for name, text in texts.items():
            target = out / name
            if target.is_symlink() or (target.exists() and not target.is_file()):
                print(f"refused: {target} is a symlink or not a regular file", file=sys.stderr)
                return 1
            write_output(target, text)
    except OSError as e:
        print(f"cannot write {out}: {e.strerror or e}", file=sys.stderr)
        return 2
    print(f"wrote {len(texts) - 1} draft(s) and index.md to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
