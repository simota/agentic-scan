#!/usr/bin/env python3
"""Draft issues and an owner report from findings.json, filled from the templates.

    python3 drafts.py FINDINGS --out DIR [--lang ja|en] [--only A-001,A-003]

Writes one `DIR/<id>.md` per finding to file, from `templates/issue.<lang>.md`,
and `DIR/owner-report.md` from `templates/report.<lang>.md`, every `{{field}}`
copied from the record the way the templates' own notes say: optional lines
left empty are dropped, a section left empty is dropped with its heading, the
trace keeps one numbered step per line, each cited rule carries its statement
and source, and a missing commit reads `UNKNOWN` as in report.md.

Never drafted as an issue: an excluded finding (`FalsePositive`,
`NotApplicable`) and a finding whose status is `Fixed` or `Accepted`; the owner
report still counts them, as its template says. Recorded text is made safe for
Markdown exactly as in report.md, so it cannot open a block, form a link or end
a table cell. What only a person can write stays a comment for them to fill:
an issue's open questions, the report's one-line conclusion, the issue URLs and
a GUARD note. Filing or sending stays with the requester.

Exit codes: 0 written, 1 a draft could not be written or `--only` names no
draftable finding, 2 the record cannot be read or does not match the schema,
or the command line is wrong.
"""
import argparse
from functools import lru_cache
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.dont_write_bytecode = True  # leave no __pycache__ beside the skill
from findings import (EXCLUDED, FINDING_ID, SEVERITIES, SchemaError,  # noqa: E402
                      atomic_write_all, as_locations, cited_rules, read_json, safe_output,
                      template_counts, validate)
from render import (DIAGRAMS, LABELS, block_safe, diagram_change_items, diagram_changes,  # noqa: E402
                    filled, markdown_code, markdown_inline, markdown_reference, mermaid,
                    revision, review_method, rule_statement)

TEMPLATES = Path(__file__).resolve().parent.parent / "templates"
CLOSED = ("Fixed", "Accepted")
PLACEHOLDER = re.compile(r"\{\{([A-Za-z_.\[\]]+)\}\}")
COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
# `1. step 2. step`: a step number after a blank (or at the start), then a blank.
STEP = re.compile(r"(?:(?<=\s)|^)([1-9][0-9]{0,2})\.[ \t]+")
SEP = {"en": ", ", "ja": "、"}
WORDS = {
    "en": {"source": "source", "unknown_rule": "not in the rules ledger",
           "none": "None.",
           "after_note": "<!-- Say in one line what the after diagram changes. -->",
           "not_drawn": "Not recorded."},
    "ja": {"source": "出典", "unknown_rule": "ルール台帳にない",
           "none": "なし。",
           "after_note": "<!-- 修正後の図で何が変わるかを 1 行で書く。 -->",
           "not_drawn": "未記録。"},
}


def inline(value):
    """Recorded text as one safe Markdown line, as report.md writes it."""
    return markdown_inline(value)


def sections(text):
    """The template as (heading, body lines), the part before the first `## ` first."""
    parts, heading, body = [], None, []
    for line in text.split("\n"):
        if line.startswith("## "):
            parts.append((heading, body))
            heading, body = line, []
        else:
            body.append(line)
    parts.append((heading, body))
    return parts


def join_sections(parts):
    lines = []
    for heading, body in parts:
        if heading is not None:
            lines.append(heading)
        lines += body
    text = "\n".join(lines)
    text = re.sub(r"\n{3,}", "\n\n", text).strip("\n")
    return text + "\n"


def strip_comments(lines):
    """The lines with every HTML comment removed; a line left blank by it goes too."""
    text = "\n".join(lines)
    out = []
    for line in COMMENT.sub("\x00", text).split("\n"):
        if "\x00" in line:
            line = line.replace("\x00", "").rstrip()
            if not line.strip():
                continue
        out.append(line)
    return out


def substantive(lines):
    """Whether a section body still says anything once fill notes are gone."""
    return any(line.strip() and line.strip() not in ("-", "1.") for line in strip_comments(lines))


def trace_steps(trace):
    """The trace's numbered steps, one per item; one item when it is not numbered."""
    text = str(trace).replace("\r\n", "\n").replace("\r", "\n").strip()
    lines = [line.strip() for line in text.split("\n") if line.strip()]
    if len(lines) > 1:
        return [STEP.sub("", line, count=1) if STEP.match(line) else line for line in lines]
    marks, expected = [], 1
    for match in STEP.finditer(text):
        if int(match[1]) == expected:
            marks.append(match)
            expected += 1
    if not marks or marks[0].start() != 0:
        return [text]
    if len(marks) == 1:
        return [text[marks[0].end():].strip() or text]
    steps = []
    for i, match in enumerate(marks):
        end = marks[i + 1].start() if i + 1 < len(marks) else len(text)
        steps.append(text[match.end():end].strip())
    return [step for step in steps if step]


def trace_lines(trace):
    steps = trace_steps(trace)
    if len(steps) == 1:
        return [block_safe(inline(steps[0]))]
    return [f"{i}. {block_safe(inline(step))}" for i, step in enumerate(steps, 1)]


def rule_text(f, rules, lang):
    """Each cited rule with its statement and source, as the template asks."""
    w, parts = WORDS[lang], []
    for rid in cited_rules(f):
        rule = rules.get(rid)
        if rule is None:
            parts.append(f"{inline(rid)} ({w['unknown_rule']})")
            continue
        parts.append(f"{inline(rid)}: {inline(rule_statement(rule, lang))} "
                     f"({w['source']}: {inline(rule['source'])})")
    return "; ".join(parts) if parts else None


def finding_values(f, doc, lang):
    """Each issue placeholder as rendered Markdown, or None when the field is empty."""
    v, meta = f["validation"], doc["meta"]
    rules = {r["id"]: r for r in doc.get("rules", [])}
    values = {
        "id": inline(f["id"]), "severity": f["severity"], "title": inline(f["title"]),
        "confidence": f["confidence"], "validation.verdict": v["verdict"],
        "validation.method": v["method"], "category": inline(f["category"]),
        "step": inline(f["step"]) if filled(f, "step") else None,
        "location": SEP[lang].join(markdown_code(loc) for loc in as_locations(f["location"])),
        "meta.commit": inline(revision(meta)), "meta.date": inline(meta["date"]),
        "meta.assessor": inline(meta["assessor"]),
        "rule": rule_text(f, rules, lang) if filled(f, "rule") else None,
        "validation.evidence": inline(v["evidence"]) if filled(v, "evidence") else None,
    }
    for key in ("impact", "scenario", "blast_radius", "fix", "guard", "contrast"):
        values[key] = inline(f[key]) if filled(f, key) else None
    return values


def substitute(line, values):
    """The line with its placeholders filled; None when a needed value is empty."""
    for name in PLACEHOLDER.findall(line):
        if values.get(name) is None:
            # `({{step}})` without a step drops its parentheses, not the row.
            stripped = re.sub(r"\s*[(（]\{\{" + re.escape(name) + r"\}\}[)）]", "", line)
            if stripped == line:
                return None
            line = stripped
    return PLACEHOLDER.sub(lambda m: values[m[1]], line)


@lru_cache(maxsize=8)
def template_sections(template):
    """The template's sections without its leading note, parsed once per template.

    Read-only tuples, so every draft filled from the cached parse sees the same text.
    """
    return tuple((heading, tuple(body))
                 for heading, body in sections(COMMENT.sub("", template, count=1).lstrip("\n")))


def issue_draft(f, doc, lang, template, cache=None):
    # The owner report, filled first, leaves its findings' values in cache;
    # each is taken out here, so the cache shrinks as the drafts grow.
    values = cache.pop(f["id"], None) if cache is not None else None
    if values is None:
        values = finding_values(f, doc, lang)
    parts = template_sections(template)
    out = []
    for heading, body in parts:
        fills = any(PLACEHOLDER.search(line) for line in body) or (
            heading is not None and PLACEHOLDER.search(heading))
        if not fills:
            out.append((heading, body))  # a section for a person: kept as written
            continue
        lines = []
        for line in body:
            if "{{analysis." in line:
                if "analysis" in f:
                    a = f["analysis"]
                    lines.append(f"{inline(a['tool'])} {markdown_code(a['command'])} → "
                                 f"{inline(a['result'])}")
                continue
            if "{{references[]." in line:
                lines += [f"- {markdown_reference(ref)}" for ref in f.get("references", [])]
                continue
            if "{{trace}}" in line:
                lines += trace_lines(f["trace"])
                continue
            if "{{confidence}}" in line:
                # The hint is for the drafter: the condition goes under Open questions.
                line = re.sub(r"(\{\{confidence\}\})\s*[(（][^|]*[)）]", r"\1", line)
            filled_line = substitute(line, values)
            if filled_line is not None:
                lines.append(filled_line)
        lines = strip_comments(lines)
        if heading is not None and not substantive(lines):
            continue
        out.append((heading, lines))
    return join_sections(out)


def report_finding_block(block, f, doc, lang, cache=None, stripped=None):
    values = finding_values(f, doc, lang)
    if cache is not None:
        cache[f["id"]] = values  # for its issue draft
    lines = []
    for line in strip_comments(block) if stripped is None else stripped:
        filled_line = substitute(line, values)
        if filled_line is not None:
            lines.append(filled_line)
    return lines


def architecture_section(body, doc, lang):
    """§4: the Mermaid blocks and change list report.md shows, under the template's headings."""
    arch, t, w = doc.get("architecture", {}), LABELS[lang], WORDS[lang]
    changes = diagram_changes(arch)
    heads = [line for line in body if line.startswith("### ")]
    lines = [""]
    for side, head in zip((*DIAGRAMS, "changes"), heads):
        lines += [head, ""]
        if side == "changes":
            items = diagram_change_items(arch, lang) if "before" in arch and "after" in arch else []
            lines += [f"- {kind}: {inline(value)}" for kind, value in items] or [t["no_changes"]]
            lines += ["", w["after_note"], ""]
            continue
        if side not in arch:
            lines += [w["not_drawn"], ""]
            continue
        if filled(arch[side], "note"):
            lines += [block_safe(inline(arch[side]["note"])), ""]
        lines += mermaid(arch[side], side, changes) + [
            "", f"{t[f'legend_{side}']} {t['shapes_md']}", ""]
    return lines


def rules_section(doc, lang):
    t = LABELS[lang]
    lines = []
    for r in doc.get("rules", []):
        status = r["status"]
        if filled(r, "reason"):
            status += f" — {t['reason']}: {inline(r['reason'])}"
        lines.append(f"- **{inline(r['id'])}** {inline(rule_statement(r, lang))} "
                     f"({WORDS[lang]['source']}: {inline(r['source'])}) — {status}")
    return lines


def list_section(doc, key, lang, numbered=False):
    items = doc.get(key, [])
    if not items:
        return [WORDS[lang]["none"]]
    if numbered:
        return [f"{i}. {block_safe(inline(item))}" for i, item in enumerate(items, 1)]
    return [f"- {block_safe(inline(item))}" for item in items]


REPORT_LISTS = {"5": None, "6": "checked_ok", "7": "limitations", "8": "decisions",
                "9": "next_steps"}


def owner_report(doc, lang, template, cache=None):
    meta = doc["meta"]
    values = {f"meta.{k}": inline(meta[k]) for k in ("project", "scope", "date", "assessor")}
    values["meta.commit"] = inline(revision(meta))
    values["meta.method"] = inline(review_method(doc, lang))
    values.update({k: str(v) for k, v in template_counts(doc).items()})
    active = [f for f in doc.get("findings", [])
              if f["validation"]["verdict"] not in EXCLUDED and f["severity"] in SEVERITIES[:2]]
    out = []
    for heading, body in template_sections(template):
        body = list(body)
        number = re.match(r"## ([0-9]+)\.", heading or "")
        number = number[1] if number else None
        if heading is not None and heading.startswith("## ") and number is None:
            out.append((heading, body))  # attachments: kept as written
            continue
        if number == "1":
            # The conclusion is for a person; the counts are filled in.
            out.append((heading, [x for x in (substitute(line, values) for line in body)
                                  if x is not None]))
        elif number == "2":
            lines = []
            for line in body:
                if COMMENT.fullmatch(line.strip()):
                    lines.append(line)  # the GUARD note is the requester's to write
                    continue
                line = COMMENT.sub("", line).rstrip()
                filled_line = substitute(line, values)
                if filled_line is not None:
                    lines.append(filled_line)
            out.append((heading, lines))
        elif number == "3":
            start = next(i for i, line in enumerate(body) if line.startswith("### "))
            intro, block = body[:start], body[start:]
            lines = strip_comments(intro)
            stripped = strip_comments(block)  # the same template block for every finding
            for f in active:
                lines += report_finding_block(block, f, doc, lang, cache, stripped) + [""]
            if not active:
                lines += [WORDS[lang]["none"], ""]
            out.append((heading, lines))
        elif number == "4":
            out.append((heading, architecture_section(body, doc, lang)))
        elif number in REPORT_LISTS:
            key = REPORT_LISTS[number]
            items = (rules_section(doc, lang) or [WORDS[lang]["none"]]) if key is None \
                else list_section(doc, key, lang, numbered=number == "9")
            out.append((heading, [""] + items + [""]))
        else:
            lines = [x for x in (substitute(line, values) for line in body) if x is not None]
            out.append((heading, lines))
    return join_sections(out)


def draftable(f):
    return f["validation"]["verdict"] not in EXCLUDED and f.get("status", "Open") not in CLOSED


def drafts(doc, lang, only=None):
    """The draft files for doc as {name: text}, and the IDs left out with the reason."""
    issue = (TEMPLATES / f"issue.{lang}.md").read_text(encoding="utf-8")
    report = (TEMPLATES / f"report.{lang}.md").read_text(encoding="utf-8")
    files, skipped = {}, []
    # A High or Medium finding is filled for the owner report and for its issue:
    # the report goes first and hands its values on to the issue drafts.
    cache = {}
    owner = owner_report(doc, lang, report, cache)
    for f in doc.get("findings", []):
        if only is not None and f["id"] not in only:
            continue
        if not draftable(f):
            reason = f["validation"]["verdict"] if f["validation"]["verdict"] in EXCLUDED \
                else f.get("status")
            skipped.append((f["id"], reason))
            continue
        files[f"{f['id']}.md"] = issue_draft(f, doc, lang, issue, cache)
    cache.clear()  # values of findings not drafted (closed, or not in --only)
    files["owner-report.md"] = owner
    return files, skipped


def main(argv=None):
    safe_output()
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("findings")
    parser.add_argument("--out", required=True, help="directory for the drafts (scratch)")
    parser.add_argument("--lang", choices=("ja", "en"))
    parser.add_argument("--only", metavar="IDS",
                        help="draft issues only for these finding IDs (A-001,A-003)")
    args = parser.parse_args(argv)
    only = None
    if args.only is not None:
        only = {x for x in re.split(r"[\s,]+", args.only) if x}
        bad = sorted(x for x in only if not FINDING_ID.fullmatch(x))
        if bad or not only:
            parser.error(f"--only takes finding IDs such as A-001, not {', '.join(bad) or 'nothing'}")
    try:
        doc = read_json(args.findings)
        validate(doc, complete=True)
    except SchemaError as exc:
        print(f"schema: {exc}", file=sys.stderr)
        return 2
    lang = args.lang or doc["meta"]["lang"]
    files, skipped = drafts(doc, lang, only)
    if only is not None:
        missing = sorted(only - {f["id"] for f in doc.get("findings", [])})
        for fid in missing:
            print(f"refused: {fid} is not a recorded finding", file=sys.stderr)
        if missing or len(files) == 1:
            if not missing:
                print("refused: --only names no finding that can be filed", file=sys.stderr)
            for fid, reason in skipped:
                print(f"skipped {fid}: {reason}", file=sys.stderr)
            return 1
    out = Path(args.out)
    try:
        out.mkdir(parents=True, exist_ok=True)
        atomic_write_all({out / name: text.encode("utf-8") for name, text in files.items()})
    except (OSError, RuntimeError) as exc:
        print(f"write failed: {exc}", file=sys.stderr)
        return 1
    current = set(files)
    for fid, reason in skipped:
        print(f"skipped {fid}: {reason} (not filed)")
    for name in sorted(files):
        print(f"wrote {out / name}")
    for f in doc.get("findings", []):
        if f"{f['id']}.md" in files and (f["validation"]["verdict"] != "Valid"
                                          or f["confidence"] == "Environment-dependent"):
            print(f"todo {f['id']}: {f['validation']['verdict']} / {f['confidence']} - write what "
                  "is still open under its open questions before filing")
    stale = sorted(p.name for p in out.glob("A-[0-9][0-9][0-9].md")
                   if p.name not in current and (only is None))
    for name in stale:
        print(f"note: {out / name} is from an earlier run (no such draftable finding now); "
              "delete it before filing", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
