#!/usr/bin/env python3
"""Check a ux-scan output directory against the run contract (SKILL.md).

    python3 contract_check.py OUT [--no-pdf] [--allow NAME]...

Passes when OUT holds exactly findings.json, flows.json, inventory.json,
dashboard.html, report.html and report.pdf (no PDF with --no-pdf, which then
requires the "report.pdf not produced" limitation); the record and flows are
valid; every perspective family is recorded in perspectives; no finding is
left Unverified; and both complete pages match the current findings, flows and PDF.
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
from render import (FLOWS_STAMP, OUTPUT_LOCK, PAGE_KIND_STAMP, PAGE_STAMP, PDF_STAMP, RENDER_STAMP, STAMP,  # noqa: E402
                    page_stamp, pdf_stamp, read_regular, source_stamp)

REQUIRED = ("findings.json", "flows.json", "inventory.json", "dashboard.html", "report.html")
NO_PDF = "report.pdf not produced"


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
    if OUTPUT_LOCK in found:
        yield (f"{out}: output directory is locked; finish the active render before checking. "
               "If a previous run was interrupted, verify that no renderer uses this directory, "
               f"then remove the empty lock with 'rmdir {shlex.quote(str(out.absolute() / OUTPUT_LOCK))}' and rerender")
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
            na = re.match(r"(?i)^N/A(?=$|[\s:—–-])", result)
            if na and not result[na.end():].strip(" \t\r\n:—–-") and not perspective.get("note", "").strip():
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
            yield f"limitations: says '{NO_PDF}' but report.pdf is expected; remove that line"
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
    pages = {}
    for name in ("dashboard.html", "report.html"):
        if name not in sources:
            continue
        try:
            page = pages[name] = PageMetadata(sources[name].decode("utf-8"))
        except ValueError as e:
            yield f"{name}: not valid UTF-8 HTML: {e}"
            continue
        try:
            digest = page_stamp(sources[name])
        except ValueError as e:
            yield f"{name}: invalid page fingerprint: {e}; run {rerender}"
        else:
            if page.stamps.get(PAGE_STAMP) != [digest]:
                yield f"{name}: altered or incomplete HTML (page fingerprint mismatch); run {rerender}"
        if page.stamps.get(PAGE_KIND_STAMP) != [name]:
            yield f"{name}: wrong or missing page kind (expected {name}); run {rerender}"
        for stamp, digest in expected_stamps.items():
            if page.stamps.get(stamp) != [digest]:
                yield f"{name}: stale {stamp}; re-render after the last input or PDF change ({rerender})"
        identity = page.stamps.get(RENDER_STAMP, [])
        if len(identity) != 1 or not re.fullmatch(r"sha256:[0-9a-f]{64}", identity[0] or ""):
            yield f"{name}: stale or missing render identity; run {rerender}"
        if len(page.languages) != 1 or page.languages[0] not in ("en", "ja"):
            yield f"{name}: missing or invalid report language; run {rerender}"
        if no_pdf and PDF_STAMP in page.stamps:
            yield f"{name}: stale PDF metadata with --no-pdf; run {rerender}"
    if len(pages) == 2:
        dashboard, document = pages["dashboard.html"], pages["report.html"]
        if (dashboard.stamps.get(RENDER_STAMP) != document.stamps.get(RENDER_STAMP)
                or dashboard.languages != document.languages):
            yield f"pages: different render versions; run {rerender}"
    # The renderer can acquire its lock after the initial directory listing,
    # even after all the old, complete files have already been read. Do not
    # approve that snapshot while a new publication is still in progress.
    try:
        (out / OUTPUT_LOCK).lstat()
    except FileNotFoundError:
        pass
    except OSError as e:
        yield f"{out}: cannot recheck output lock: {e.strerror or e}"
    else:
        yield (f"{out}: a render started during the contract check; wait for it to finish, "
               "then run contract_check.py again")


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
