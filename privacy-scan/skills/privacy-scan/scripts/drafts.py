#!/usr/bin/env python3
"""Fill the issue and owner-report templates from findings.json.

    python3 drafts.py FINDINGS --out DIR [--lang ja|en] [--id PV-001]...

Writes `DIR/issue-PV-NNN.md` for each selected finding (by default every
reported finding whose status is not `Fixed`) from `templates/issue.<lang>.md`,
and `DIR/owner-report.md` from `templates/report.<lang>.md`. Every value is
copied from the record, so drafts never disagree with the dashboard; what the
record cannot say (the summary, issue URLs, decisions on data already sent)
stays as `<to fill in>` for a person.

Template rules (also in each template's header comment): comments are dropped;
a line whose optional value is blank is dropped, and a section left empty is
dropped with its heading; a line with a `{{name[]}}` placeholder repeats once per
entry; ` — {{step}}` is dropped without a step; a blank `meta.commit` is written
UNKNOWN and a blank `meta.method` as report.md's review-method line. Values are
escaped for Markdown as in report.md.

An unfixed High (status `Open` or `Accepted`) starts with a line saying it
belongs in a private tracker. Filing and sending stay with the requester.

DIR must not be the run's output directory (the run contract allows exactly
three files there): use scratch or another new directory. The record must be
renumbered first, so issue IDs match the dashboard.

Exit codes: 0 written, 1 the record was refused or a draft could not be saved,
2 the command line is invalid.
"""
import argparse
from functools import lru_cache
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from findings import (COMMITMENT_REF, PV_REFERENCE, SchemaError, commitment_citations,  # noqa: E402
                      counts, excluded, locations, order_key, prepare_cli, read_json, validate)
from output_io import write_utf8_files  # noqa: E402
import render  # noqa: E402

TEMPLATES = Path(__file__).resolve().parent.parent / "templates"
COMMENT = re.compile(r"<!--.*?-->[ \t]*\n?", re.S)
PLACEHOLDER = re.compile(r"{{([^{}]+)}}")
# One pass over the template line: a value written in is never read as a placeholder.
FIELD = re.compile(r"`{{(?P<code>[^{}]+)}}`|{{(?P<text>[^{}]+)}}")
# A placeholder that starts a paragraph or a list item's text.
ITEM_START = re.compile(r"^(?:[-*+] |[0-9]+\. )?{{")
# A `{{name[]}}` placeholder: the line repeats once per entry.
LOOP = re.compile(r"{{([a-z_]+)\[\]")
RUN_OUTPUTS = ("findings.json", "dashboard.html", "report.md")

LABELS = {
    "en": {"private": "> **Private tracker only:** this High finding is not fixed (status Open or "
                      "Accepted). File it in a private tracker, not a public issue.",
           "source": "source", "cited_by": "cited by"},
    "ja": {"private": "> **非公開のトラッカーのみ:** 未修正（status: Open または Accepted）の High。"
                      "公開 issue ではなく非公開のトラッカーに登録する。",
           "source": "根拠", "cited_by": "該当"},
}


class Draft:
    """Resolves the placeholders of one template for one record (and one finding)."""

    def __init__(self, doc, lang, finding=None):
        self.doc, self.lang, self.f = doc, lang, finding
        self.t = render.LABELS[lang]
        self.ledger = {r["id"]: r for r in doc.get("commitments", [])}

    def cited(self):
        return [self.ledger[c] for c in dict.fromkeys(COMMITMENT_REF.findall(self.f.get("commitment", "")))
                if c in self.ledger]

    def scalar(self, name):
        """The text of a placeholder, or '' when the optional value is blank."""
        meta, f = self.doc["meta"], self.f
        if name.startswith("meta."):
            key = name[5:]
            if key == "commit":
                return render.revision(meta)
            if key == "method":
                return render.review_method(meta, self.doc.get("findings", []), self.t)
            return meta.get(key, "")
        if name.startswith("n_"):
            return str(counts(self.doc)[name])
        if name.startswith("validation."):
            return f["validation"].get(name[11:], "")
        if name == "commitments[id].statement":
            return "; ".join(r["statement"] + (f" ({self.t['inferred']})" if r.get("inferred") else "")
                             for r in self.cited())
        if name == "commitments[id].source":
            return "; ".join(r["source"] for r in self.cited())
        if name in ("location", "id", "severity", "confidence", "category", "step", "title", "data",
                    "subjects", "flow", "contrast", "impact", "commitment", "fix", "guard",
                    "conditions"):
            value = f.get(name, "")
            return render.as_text(value) if shown_text(value) else ""
        raise SchemaError(f"template placeholder {{{{{name}}}}} is not known to drafts.py")

    def items(self, name):
        """The entries a `{{name[]}}` line repeats for."""
        doc, t = self.doc, self.t
        if name in ("checked_ok", "limitations", "decisions", "next_steps"):
            return [render.markdown_item(v) for v in doc.get(name, [])]
        if name == "references":
            return [render.markdown_reference(ref) for ref in self.f.get("references", [])]
        if name == "commitments":
            citing = commitment_citations(doc)
            rows = []
            for r in doc.get("commitments", []):
                statement, status = render.commitment_text(r, t)
                family = f"{r['family']}; " if r.get("family", "").strip() else ""
                ids = citing.get(r["id"], [])
                rows.append(render.markdown_text(
                    f"{r['id']}: {statement} ({family}{LABELS[self.lang]['source']}: {r['source']}) "
                    f"— {status}" + (f" — {LABELS[self.lang]['cited_by']}: {', '.join(ids)}" if ids else "")))
            return rows
        if name == "recipients":
            return [render.markdown_text(f"{recipient}: " + ", ".join(elements.split("\n")))
                    for recipient, elements in render.recipient_rows(doc, t)]
        if name == "open_questions":
            rows = [self.f["conditions"]] if shown_text(self.f.get("conditions", "")) else []
            # The lines that name this finding, matched as renumber matches references.
            rows += [v for key in ("decisions", "limitations") for v in doc.get(key, [])
                     if any(m.group() == self.f["id"] for m in PV_REFERENCE.finditer(v))]
            return [render.markdown_item(v) for v in rows]
        raise SchemaError(f"template placeholder {{{{{name}[]}}}} is not known to drafts.py")

    def line(self, line):
        """Fill one template line; return the filled lines (none drops it)."""
        if self.f is not None and not self.f.get("step", "").strip():
            line = line.replace(" — {{step}}", "")
        if "{{commitments[id]." in line and self.f is not None and not self.cited():
            line = line.split(" — {{commitments[id].", 1)[0]
        loop = LOOP.search(line)
        if loop:
            name = loop.group(1)
            if name == "references":
                return [f"- {item}" for item in self.items(name)]
            return [PLACEHOLDER.sub(lambda m, item=item: item, line) for item in self.items(name)]
        blank = False
        # Text that opens a paragraph or list item is escaped so it starts no block.
        opening = line.index("{{") if ITEM_START.match(line) else -1

        def value(match):
            nonlocal blank
            if match.group("code"):
                name = match.group("code")
                values = locations(self.f) if name == "location" else [self.scalar(name)]
                blank = blank or not any(v.strip() for v in values)
                return ", ".join(render.markdown_code(v) for v in values)
            text = self.scalar(match.group("text"))
            blank = blank or not text.strip()
            return render.markdown_item(text) if match.start() == opening else render.markdown_text(text)

        line = FIELD.sub(value, line)
        return [] if blank else [line]


def shown_text(value):
    return render.shown(value)


def fill(template, draft):
    """The template with comments dropped, placeholders filled and empty sections removed."""
    text = COMMENT.sub("", template)
    lines = []
    for line in text.split("\n"):
        lines.extend(draft.line(line) if "{{" in line else [line])
    return tidy(lines)


def tidy(lines):
    """Drop headings whose section is now empty, and runs of blank lines."""
    out = []
    for i, line in enumerate(lines):
        if line.startswith("## "):
            rest = next((x for x in lines[i + 1:] if x.strip()), None)
            if rest is None or rest.startswith(("## ", "---")):
                continue
        if not line.strip() and (not out or not out[-1].strip()):
            continue
        out.append(line)
    while out and not out[-1].strip():
        out.pop()
    return "\n".join(out) + "\n"


@lru_cache(maxsize=None)
def _template(name, lang):
    """A template's text, read once per run: an issue draft is filled per finding.
    Only the shipped templates are read, so the cache holds at most four."""
    return (TEMPLATES / f"{name}.{lang}.md").read_text(encoding="utf-8")


def issue(doc, f, lang):
    template = _template("issue", lang)
    text = fill(template, Draft(doc, lang, f))
    if f["severity"] == "High" and not excluded(f) and f.get("status", "Open") != "Fixed":
        text = LABELS[lang]["private"] + "\n\n" + text
    return text


def owner_report(doc, lang):
    """The report template, with its per-finding block repeated for every reported High and Medium."""
    template = COMMENT.sub("", _template("report", lang))
    lines = template.split("\n")
    start = next(i for i, x in enumerate(lines) if x.startswith("### {{id}}"))
    end = next(i for i in range(start + 1, len(lines)) if lines[i].startswith("## "))
    block = lines[start:end]
    shared = Draft(doc, lang)
    filled = [y for x in lines[:start] for y in (shared.line(x) if "{{" in x else [x])]
    chosen = [f for f in doc.get("findings", [])
              if not excluded(f) and f["severity"] in ("High", "Medium")]
    for f in chosen:
        draft = Draft(doc, lang, f)
        filled += [y for x in block for y in (draft.line(x) if "{{" in x else [x])]
    if not chosen:
        filled += [render.LABELS[lang]["none"], ""]
    filled += [y for x in lines[end:] for y in (shared.line(x) if "{{" in x else [x])]
    return tidy(filled)


def selected(doc, ids):
    findings = doc.get("findings", [])
    if not ids:
        return [f for f in findings if not excluded(f) and f.get("status", "Open") != "Fixed"]
    known = {f["id"]: f for f in findings}
    missing = [i for i in ids if i not in known]
    if missing:
        raise SchemaError(f"--id names findings that are not in the record: {', '.join(missing)}")
    return [known[i] for i in dict.fromkeys(ids)]


def _final_ids(doc):
    findings = doc.get("findings", [])
    keys = [order_key(f) for f in findings]
    return ([f["id"] for f in findings] == [f"PV-{i:03d}" for i in range(1, len(findings) + 1)]
            and keys == sorted(keys))


def _is_run_output(out, record):
    """Whether `out` is the directory of the record or already holds run outputs."""
    try:
        if out.resolve() == Path(record).resolve().parent:
            return True
        return any((out / name).exists() for name in RUN_OUTPUTS)
    except OSError:
        return True


def main(argv=None):
    prepare_cli()
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("findings")
    parser.add_argument("--out", required=True, help="a directory outside the run's output directory")
    parser.add_argument("--lang", choices=("ja", "en"))
    parser.add_argument("--id", action="append", default=[], dest="ids",
                        help="draft an issue for this finding only (repeatable)")
    args = parser.parse_args(argv)
    if not args.out.strip():
        parser.error("--out must name the drafts directory")
    out = Path(args.out)
    try:
        doc = read_json(args.findings)
        validate(doc, complete=True)
        if not _final_ids(doc):
            raise SchemaError("IDs are not final; run scripts/findings.py renumber first, so issue "
                              "IDs match the dashboard")
        if _is_run_output(out, args.findings):
            raise SchemaError("--out is the run's output directory (or holds its files); the run "
                              "contract allows exactly findings.json, dashboard.html and report.md "
                              "there, so write drafts to scratch or another new directory")
        lang = args.lang or doc["meta"]["lang"]
        chosen = selected(doc, args.ids)
        drafts = {out / f"issue-{f['id']}.md": issue(doc, f, lang) for f in chosen}
        drafts[out / "owner-report.md"] = owner_report(doc, lang)
    except SchemaError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 1
    try:
        out.mkdir(parents=True, exist_ok=True)
        write_utf8_files(drafts, protected_paths=(args.findings,))
    except (OSError, UnicodeError) as exc:
        print(f"write failed: could not save drafts ({type(exc).__name__})", file=sys.stderr)
        return 1
    private = [f["id"] for f in chosen if f["severity"] == "High" and f.get("status", "Open") != "Fixed"
               and not excluded(f)]
    print(f"wrote {len(chosen)} issue draft(s) and owner-report.md to {out}")
    if private:
        print(f"private tracker only (unfixed High): {', '.join(private)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
