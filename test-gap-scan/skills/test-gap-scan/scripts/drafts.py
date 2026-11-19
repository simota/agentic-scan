#!/usr/bin/env python3
"""Fill the issue and plan templates from findings.json.

    python3 drafts.py FINDINGS --out DIR [--lang ja|en] [--id F-001]...

Writes `DIR/issue-F-NNN.md` for each selected finding (by default every
finding that is not excluded, `Fixed` or `Accepted`) from
`templates/issue.<lang>.md`, and `DIR/plan.md` from `templates/plan.<lang>.md`.
Every value is copied from the record, so drafts never disagree with the
dashboard; what the record cannot say (the decisions a batch waits on) stays
as `<to fill in>` for a person.

Template rules, as each template's header comment states them: comments are
dropped; a line whose optional value is blank is dropped, and a section left
empty is dropped with its heading and with the Done-when items that name it;
` ({{step}})` is dropped without a step; `depends_on` and `convention` read
"none" when absent; an empty `coverage.tests` reads "—" as in report.md; a
blank `meta.commit` is written UNKNOWN as in report.md.
The plan repeats its batch block per `plan[]` entry and its finding block per
ID in the batch, never an excluded finding; Deferred lists the open Low and
Info findings no batch holds. Values are escaped for Markdown as in report.md.

DIR must not be the run's output directory itself: use scratch, or
`<out>/drafts` and then `findings.py check <out> --allow drafts`. The record
must be renumbered first, so draft IDs match the dashboard. Filing and sending
stay with the requester.

Exit status: 0 written, 1 a draft could not be saved, 2 the record or a
template was refused.
"""
import argparse
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.dont_write_bytecode = True  # leave no __pycache__ beside the skill
from findings import (EXCLUDED, FINDING_KEYS, SchemaError, _atomic_write_all, as_locations,  # noqa: E402
                      nonempty, read_json, renumber, run, safe_output, shown_line, validate,
                      visible)
from markdown_safe import as_text, block_safe, markdown_code, markdown_inline  # noqa: E402
from perspective_labels import perspective_name  # noqa: E402

TEMPLATES = Path(__file__).resolve().parent.parent / "templates"
COMMENT = re.compile(r"<!--.*?-->[ \t]*\n?", re.S)
PLACEHOLDER = re.compile(r"{{([^{}]+)}}")
RUN_OUTPUTS = ("findings.json", "dashboard.html", "report.md")
CLOSED = ("Fixed", "Accepted")
LIST_FIELDS = ("asserts", "steps")
CODE_FIELDS = ("location", "coverage.tests")
NONE_FIELDS = ("depends_on", "convention")

WORDS = {"en": {"none": "none", "fill": "<to fill in>", "sep": ", "},
         "ja": {"none": "なし", "fill": "<要記入>", "sep": "、"}}


class Fill:
    """Resolves one template's placeholders for one record, batch and finding."""

    def __init__(self, doc, lang, finding=None, batch=None):
        self.doc, self.lang, self.f, self.batch = doc, lang, finding, batch

    def raw(self, name):
        meta, f = self.doc["meta"], self.f
        if name.startswith("meta."):
            value = meta.get(name[5:], "")
            return value if name != "meta.commit" or visible(value) else "UNKNOWN"
        if name.startswith("plan[]."):
            return self.batch.get(name[7:], "")
        if f is None:
            raise SchemaError(f"template placeholder {{{{{name}}}}} needs a finding")
        if name.startswith(("validation.", "coverage.")):
            group, key = name.split(".", 1)
            return f.get(group, {}).get(key, "")
        if name == "location":
            return as_locations(f["location"])
        if name == "category":
            return perspective_name(f.get(name, ""), self.lang)
        return f.get(name, "")

    def block(self, name):
        """A placeholder alone on its line: a paragraph, or one bullet per list item."""
        value = self.raw(name)
        if name in LIST_FIELDS:
            return [f"- {block_safe(markdown_inline(item))}" for item in value if visible(as_text(item))]
        return [block_safe(markdown_inline(value))] if visible(as_text(value)) else []

    def inline(self, name):
        """A placeholder inside a line, or None when the optional value is blank."""
        value = self.raw(name)
        if name == "depends_on":
            return WORDS[self.lang]["sep"].join(markdown_code(v) for v in value) or WORDS[self.lang]["none"]
        if name in CODE_FIELDS and "." in name and name.split(".", 1)[0] in self.f and not value:
            return "—"
        if name in NONE_FIELDS and not visible(as_text(value)):
            return WORDS[self.lang]["none"]
        if not visible(as_text(value)):
            return None
        if name in CODE_FIELDS:
            return WORDS[self.lang]["sep"].join(markdown_code(v) for v in value)
        return markdown_inline(value)

    def line(self, line):
        """The filled lines for one template line: none drops it."""
        if self.f is not None and not visible(self.f.get("step", "")):
            line = line.replace(" ({{step}})", "").replace("（{{step}}）", "")
        alone = PLACEHOLDER.fullmatch(line.strip())
        if alone:
            return self.block(alone[1])
        blank = False

        def value(match):
            nonlocal blank
            text = self.inline(match[1])
            blank = blank or text is None
            return text or ""

        line = PLACEHOLDER.sub(value, line)
        return [] if blank else [line]

    def lines(self, template_lines):
        return [out for line in template_lines
                for out in (self.line(line) if "{{" in line else [line])]


def tidy(lines):
    """Drop headings whose section is now empty, the Done-when items naming them,
    an empty bullet left for a person, and runs of blank lines."""
    kept, dropped = [], []
    for i, line in enumerate(lines):
        if line.startswith("## "):
            rest = next((x for x in lines[i + 1:] if x.strip()), None)
            if rest is None or rest.startswith(("## ", "# ")):
                dropped.append(re.sub(r"[（(].*", "", line[3:]).strip())
                continue
        kept.append(line)
    out = []
    for line in kept:
        if line.startswith("- [ ] ") and any(title and title in line for title in dropped):
            continue
        if not line.strip() and (not out or not out[-1].strip()):
            continue
        out.append(line)
    while out and not out[-1].strip():
        out.pop()
    return "\n".join(out) + "\n"


def template(name, lang):
    return COMMENT.sub("", (TEMPLATES / f"{name}.{lang}.md").read_text(encoding="utf-8")).split("\n")


def excluded(f):
    return f["validation"]["verdict"] in EXCLUDED


def issue(doc, f, lang):
    return tidy(Fill(doc, lang, f).lines(template("issue", lang)))


def section(lines, start_prefix):
    start = next(i for i, x in enumerate(lines) if x.startswith(start_prefix))
    end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("## ")), len(lines))
    return start, end


def plan(doc, lang):
    """The plan: batch block per plan[] entry, finding block per ID, Deferred filled."""
    lines = template("plan", lang)
    words = WORDS[lang]
    b_start, b_end = section(lines, next(x for x in lines if "{{plan[].batch}}" in x))
    f_start = next(i for i in range(b_start, b_end) if lines[i].startswith("### {{id}}"))
    head, batch_head, finding_block = lines[:b_start], lines[b_start:f_start], lines[f_start:b_end]
    tail = lines[b_end:]
    findings = {f["id"]: f for f in doc.get("findings", [])}
    shared = Fill(doc, lang)
    out = [x if x.strip() != "-" else f"- {words['fill']}" for x in shared.lines(head)]
    for batch in doc.get("plan", []):
        out += Fill(doc, lang, batch=batch).lines(batch_head)
        for fid in batch["findings"]:
            if not excluded(findings[fid]):
                out += Fill(doc, lang, findings[fid], batch).lines(finding_block)
    planned = {fid for batch in doc.get("plan", []) for fid in batch["findings"]}
    deferred = [f"- {block_safe(markdown_inline(f['id'] + ': ' + f['title']))}"
                for f in doc.get("findings", [])
                if f["severity"] in ("Low", "Info") and f["id"] not in planned
                and not excluded(f) and f.get("status", "Open") not in CLOSED]
    for line in shared.lines(tail):
        if line.strip() == "-":
            out += deferred or [f"- {words['none']}"]
        else:
            out.append(line)
    return tidy(out)


def selected(doc, ids):
    findings = doc.get("findings", [])
    if not ids:
        return [f for f in findings if not excluded(f) and f.get("status", "Open") not in CLOSED]
    known = {f["id"]: f for f in findings}
    missing = [i for i in ids if i not in known]
    if missing:
        raise SchemaError(f"--id names findings that are not in the record: {', '.join(missing)}")
    refused = [i for i in ids if excluded(known[i])]
    if refused:
        raise SchemaError(f"excluded findings are never filed: {', '.join(refused)}")
    return [known[i] for i in dict.fromkeys(ids)]


def is_run_output(out, record):
    if out.resolve() == Path(record).resolve().parent:
        return True
    return any((out / name).exists() for name in RUN_OUTPUTS)


def unknown_placeholders(lang):
    """Placeholders a template names that drafts.py cannot fill: a template bug."""
    names = set()
    for name in ("issue", "plan"):
        names |= set(PLACEHOLDER.findall("\n".join(template(name, lang))))
    return sorted(n for n in names
                  if not (n.startswith(("meta.", "plan[]."))
                          or n.split(".", 1)[0] in ("validation", "coverage")
                          or n in FINDING_KEYS))


def main(argv=None):
    safe_output()
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("findings", type=nonempty)
    parser.add_argument("--out", required=True, type=nonempty,
                        help="a directory outside the run's output directory, or <out>/drafts")
    parser.add_argument("--lang", choices=("ja", "en"))
    parser.add_argument("--id", action="append", default=[], dest="ids", metavar="F-NNN",
                        help="draft an issue for this finding only (repeatable)")
    args = parser.parse_args(argv)
    out = Path(args.out)
    try:
        doc = read_json(args.findings)
        validate(doc, complete=True)
        if [f["id"] for f in renumber(doc)[0].get("findings", [])] != [f["id"] for f in doc.get("findings", [])]:
            raise SchemaError("IDs are not final; run findings.py renumber first, so draft IDs "
                              "match the dashboard")
        if is_run_output(out, args.findings):
            raise SchemaError("--out is the run's output directory (or holds its files); write "
                              "drafts to scratch or to <out>/drafts")
        lang = args.lang or doc["meta"]["lang"]
        unknown = unknown_placeholders(lang)
        if unknown:
            raise SchemaError(f"templates name placeholders drafts.py cannot fill: {', '.join(unknown)}")
        chosen = selected(doc, args.ids)
        drafts = {out / f"issue-{f['id']}.md": issue(doc, f, lang).encode("utf-8") for f in chosen}
        drafts[out / "plan.md"] = plan(doc, lang).encode("utf-8")
    except SchemaError as exc:
        print(f"refused: {shown_line(exc)}", file=sys.stderr)
        return 2
    try:
        if out.is_symlink():
            raise OSError(f"{out} is a symlink; write drafts to a plain, new directory")
        out.mkdir(parents=True, exist_ok=True)
        _atomic_write_all(drafts)
    except OSError as exc:
        print(f"write failed: {shown_line(exc)}", file=sys.stderr)
        return 1
    print(f"wrote {len(chosen)} issue draft(s) and plan.md to {out}; "
          f"fill each {WORDS[lang]['fill']} before handing them on")
    return 0


if __name__ == "__main__":
    sys.exit(run(main))
