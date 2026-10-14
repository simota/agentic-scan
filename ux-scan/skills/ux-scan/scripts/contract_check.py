#!/usr/bin/env python3
"""Check a ux-scan output directory against the run contract (SKILL.md).

    python3 contract_check.py OUT [--no-pdf] [--allow NAME]...

Passes when OUT holds exactly findings.json, flows.json, inventory.json,
dashboard.html, report.html and report.pdf (no PDF with --no-pdf, which then
requires the "report.pdf not produced" limitation); the record and flows are
valid; every perspective family is recorded in perspectives; no finding is
left Unverified; and both complete pages match the current findings, flows and PDF.
An allowed en or ja directory is a second-language render: it must hold exactly
both pages (and its report.pdf unless --no-pdf) in that language, rendered from
the same findings and flows.
Exit status: 0 ok, 1 contract not met (each problem on stderr), 2 bad arguments.
"""

import argparse
import re
import shlex
import sys
from html.parser import HTMLParser
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from findings import FAMILIES, RecordError, canonical_digest, check_findings, check_flows, flow_ids, loads_json  # noqa: E402
from render import (FLOWS_STAMP, PAGE_KIND_STAMP, PAGE_STAMP, PDF_STAMP, RENDER_STAMP, STAMP,  # noqa: E402
                    page_stamp, pdf_stamp, read_regular, source_stamp)

REQUIRED = ("findings.json", "flows.json", "inventory.json", "dashboard.html", "report.html")
NO_PDF = "report.pdf not produced"
LANGUAGES = ("en", "ja")
# "N/A" in its common spellings, in English and Japanese.
NOT_APPLICABLE = re.compile(r"(?i)^(?:N\s*[/／]?\s*A|not\s+applicable|該当なし|対象外|適用外)(?![\w/／])")


class PageMetadata(HTMLParser):
    """Read actual head metadata, ignoring stamp-like prose, comments and JSON."""

    def __init__(self, page):
        super().__init__()
        self.in_head = False
        self.stamps = {}
        self.languages = []
        self.feed(page)
        self.close()

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "html":
            self.languages.append(attrs.get("lang"))
        elif tag == "head":
            self.in_head = True
        elif tag == "meta" and self.in_head:
            self.stamps.setdefault(attrs.get("name"), []).append(attrs.get("content"))

    def handle_endtag(self, tag):
        if tag == "head":
            self.in_head = False


def rendered_lang(out):
    """The language the existing pages were rendered in, so a re-render keeps it."""
    for name in ("report.html", "dashboard.html"):
        try:
            languages = PageMetadata(read_regular(out / name).decode("utf-8")).languages
        except (OSError, ValueError):
            continue
        if len(languages) == 1 and languages[0] in ("en", "ja"):
            return languages[0]
    return "<ja|en>"


def problems(out, no_pdf=False, allow=()):
    out = Path(out)
    try:
        found = {p.name for p in out.iterdir()}
    except OSError as e:
        yield f"{out}: cannot read output directory: {e.strerror or e}"
        return
    expected = set(REQUIRED) | ({"report.pdf"} if not no_pdf else set())
    rerender = (f"render.py {shlex.quote(str(out / 'findings.json'))} --out {shlex.quote(str(out))}"
                f" --lang {rendered_lang(out)} --repo <repo>"
                + (" --no-pdf" if no_pdf else ""))
    for name in sorted(expected - found):
        hint = {"findings.json": "merge fragments with findings.py merge",
                "flows.json": "write the flows with findings.py flows",
                "inventory.json": f"run inventory.py <repo> --flows {out}/flows.json --out {out}/inventory.json",
                "report.pdf": "render where Chrome works, or follow the no-PDF path in SKILL.md"}.get(
                    name, f"run {rerender}")
        yield f"{name}: missing; {hint}"
    forbidden = {"report.pdf"} if no_pdf else set()
    for name in sorted(found - expected - set(allow) - forbidden):
        yield (f"{name}: not part of the contract "
               f"(contract_check.py --allow {shlex.quote(name)} if it was asked for)")
    if no_pdf and "report.pdf" in found:
        yield "report.pdf: must be absent with --no-pdf"
    sources = {}
    for name in sorted(found & expected):
        try:
            sources[name] = read_regular(out / name)
        except (OSError, ValueError) as e:
            yield f"{name}: {e}"

    flows = flows_digest = None
    if "flows.json" in sources:
        try:
            flows = check_flows(loads_json(sources["flows.json"].decode("utf-8"), "flows.json"))
            flows_digest = canonical_digest(flows)
            shared = sum(fl["priority"] == "shared" for fl in flows["flows"])
            if shared != 1:
                yield (f"flows.json: {shared} shared flows; record exactly one shared unit (app shell, navigation, "
                       "global styles and shared components), added with findings.py flows")
        except (ValueError, RecordError) as e:
            flows = None
            yield f"flows.json: {e}"
    data = None
    if "findings.json" in sources:
        try:
            data = check_findings(loads_json(sources["findings.json"].decode("utf-8"), "findings.json"),
                                  flow_ids(flows) if flows else None)
        except (ValueError, RecordError) as e:
            yield f"record: {e}"
    if data is not None:
        recorded = set()
        for perspective in data.get("perspectives", []):
            name, result = perspective["name"], perspective.get("result", "").strip()
            family = re.match(r"^(%s)(?=\W|$)" % "|".join(FAMILIES), name.strip())
            if not family:
                yield f"perspectives: {name!r} must start with a family token such as 'AX Accessibility'"
                continue
            if not result:
                yield f"perspectives: {name!r} needs a non-empty result (applied, N/A with a reason, or not checked)"
                continue
            recorded.add(family[1])
            na = NOT_APPLICABLE.match(result)
            # Punctuation alone, in either script, is not a reason.
            if (na and not re.sub(r"[\W_]", "", result[na.end():])
                    and not perspective.get("note", "").strip()):
                yield f"perspectives: {name!r} is N/A without a reason in result or note"
        missing = [f for f in FAMILIES if f not in recorded]
        if missing:
            yield (f"perspectives: no entry for {', '.join(missing)}; record each family as applied, "
                   "N/A with the reason, or not checked")
        unverified = [f["id"] for f in data["findings"] if f["validation"]["verdict"] == "Unverified"]
        if unverified:
            yield f"findings: {', '.join(unverified)} still Unverified; settle the verdict in VERIFY"
        limited = any(line.startswith(NO_PDF) for line in data.get("limitations", []))
        explained = any(line.startswith(NO_PDF + ":") and line[len(NO_PDF) + 1:].strip()
                        for line in data.get("limitations", []))
        if no_pdf and not explained:
            yield f"limitations: --no-pdf needs the line '{NO_PDF}: <reason>'"
        if not no_pdf and limited:
            yield (f"limitations: says '{NO_PDF}' but report.pdf is expected; on the no-PDF path run "
                   "contract_check.py with --no-pdf, otherwise render the PDF and remove that line")
    if "inventory.json" in sources:
        try:
            inventory = loads_json(sources["inventory.json"].decode("utf-8"), "inventory.json")
            if not isinstance(inventory, dict):
                yield "inventory.json: expected an object"
            elif inventory.get("tool") != "inventory.py":
                yield "inventory.json: not written by inventory.py"
            elif flows is not None and inventory.get("flows_sha256") != flows_digest:
                yield ("inventory.json: stale or missing flows_sha256; rerun inventory.py <repo> "
                       f"--flows {shlex.quote(str(out / 'flows.json'))} "
                       f"--out {shlex.quote(str(out / 'inventory.json'))}")
        except (ValueError, RecordError) as e:
            yield f"inventory.json: not valid JSON: {e}"

    expected_stamps = {STAMP: source_stamp(sources["findings.json"])} if "findings.json" in sources else {}
    if flows is not None:
        expected_stamps[FLOWS_STAMP] = flows_digest
    if "report.pdf" in sources:
        try:
            expected_stamps[PDF_STAMP] = pdf_stamp(sources["report.pdf"])
        except ValueError as e:
            yield f"report.pdf: {e}; run {rerender}"
    yield from page_problems(sources, expected_stamps, no_pdf, rerender)
    if "findings.json" not in sources:
        return
    # A requested second language must exist; it is not merely tolerated.
    for name in sorted(set(allow) & set(LANGUAGES)):
        yield from translation_problems(out, name, expected_stamps, no_pdf)


def translation_problems(out, lang, parent_stamps, no_pdf):
    """A second-language render in OUT/<lang> must come from the current record and flows."""
    directory = out / lang
    rerender = (f"render.py {shlex.quote(str(out / 'findings.json'))} --out {shlex.quote(str(directory))}"
                f" --lang {lang} --repo <repo>" + (" --no-pdf" if no_pdf else ""))
    try:
        if not directory.is_dir() or directory.is_symlink():
            yield f"{lang}: expected a directory holding the {lang} render; run {rerender}"
            return
        found = {p.name for p in directory.iterdir()}
    except OSError as e:
        yield f"{lang}: cannot read directory: {e.strerror or e}"
        return
    if rendered_lang(out) == lang:
        yield f"{lang}: the main pages are already in {lang}; a second-language render needs the other language"
        return
    expected = {"dashboard.html", "report.html"} | (set() if no_pdf else {"report.pdf"})
    for name in sorted(expected - found):
        yield f"{lang}/{name}: missing; run {rerender}"
    for name in sorted(found - expected):
        yield f"{lang}/{name}: not part of a second-language render"
    sources = {}
    for name in sorted(found & expected):
        try:
            sources[name] = read_regular(directory / name)
        except (OSError, ValueError) as e:
            yield f"{lang}/{name}: {e}"
    stamps = {k: v for k, v in parent_stamps.items() if k != PDF_STAMP}
    if "report.pdf" in sources:
        try:
            stamps[PDF_STAMP] = pdf_stamp(sources["report.pdf"])
        except ValueError as e:
            yield f"{lang}/report.pdf: {e}; run {rerender}"
    yield from page_problems(sources, stamps, no_pdf, rerender, prefix=f"{lang}/", lang=lang)


def page_problems(sources, expected_stamps, no_pdf, rerender, prefix="", lang=None):
    """Both pages are complete, current, of one render and (when given) in lang."""
    pages = {}
    for name in ("dashboard.html", "report.html"):
        if name not in sources:
            continue
        try:
            page = pages[name] = PageMetadata(sources[name].decode("utf-8"))
        except ValueError as e:
            yield f"{prefix}{name}: not valid UTF-8 HTML: {e}"
            continue
        try:
            digest = page_stamp(sources[name])
        except ValueError as e:
            yield f"{prefix}{name}: invalid page fingerprint: {e}; run {rerender}"
        else:
            if page.stamps.get(PAGE_STAMP) != [digest]:
                yield f"{prefix}{name}: altered or incomplete HTML (page fingerprint mismatch); run {rerender}"
        if page.stamps.get(PAGE_KIND_STAMP) != [name]:
            yield f"{prefix}{name}: wrong or missing page kind (expected {name}); run {rerender}"
        for stamp, digest in expected_stamps.items():
            if page.stamps.get(stamp) != [digest]:
                yield f"{prefix}{name}: stale {stamp}; re-render after the last input or PDF change ({rerender})"
        identity = page.stamps.get(RENDER_STAMP, [])
        if len(identity) != 1 or not re.fullmatch(r"sha256:[0-9a-f]{64}", identity[0] or ""):
            yield f"{prefix}{name}: stale or missing render identity; run {rerender}"
        if len(page.languages) != 1 or page.languages[0] not in LANGUAGES or lang not in (None, page.languages[0]):
            yield f"{prefix}{name}: missing or invalid report language; run {rerender}"
        if no_pdf and PDF_STAMP in page.stamps:
            yield f"{prefix}{name}: stale PDF metadata with --no-pdf; run {rerender}"
    if len(pages) == 2:
        dashboard, document = pages["dashboard.html"], pages["report.html"]
        if (dashboard.stamps.get(RENDER_STAMP) != document.stamps.get(RENDER_STAMP)
                or dashboard.languages != document.languages):
            yield f"{prefix}pages: different render versions; run {rerender}"


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("out")
    p.add_argument("--no-pdf", action="store_true")
    p.add_argument("--allow", action="append", default=[])
    a = p.parse_args(argv)
    if not Path(a.out).is_dir():
        print(f"contract_check.py: {a.out} is not a directory", file=sys.stderr)
        return 2
    found = list(problems(a.out, a.no_pdf, a.allow))
    for problem in found:
        print(f"contract_check.py: {problem}", file=sys.stderr)
    if found:
        return 1
    print(f"contract ok: {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
