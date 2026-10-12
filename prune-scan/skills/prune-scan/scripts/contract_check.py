#!/usr/bin/env python3
"""Check a prune-scan output directory against the run contract (SKILL.md).

    python3 contract_check.py OUT [--no-pdf] [--allow NAME]...

Passes when OUT holds exactly findings.json, units.json, inventory.json,
dashboard.html, report.html and report.pdf (no PDF with --no-pdf, which then
requires the "report.pdf not produced" limitation); the record and units are
valid; every perspective family is recorded in perspectives; no finding is
left Unverified; every open Purpose-dependent finding is named in decisions;
and both pages carry the SHA-256 of the current findings.json and units.json.
Exit status: 0 ok, 1 contract not met (each problem on stderr), 2 bad arguments.
"""

import argparse
import hashlib
import os
import re
import stat
import sys
from html import unescape
from html.parser import HTMLParser
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from findings import (EXCLUDED, FAMILIES, FINDING_REF, RecordError, check_findings,  # noqa: E402
                      check_units, parse_json)
from render import NOFOLLOW_DIR_FD, STAMP, UNITS_STAMP, open_artifact, pdf_complete  # noqa: E402
from safe_paths import open_directory  # noqa: E402

REQUIRED = ("findings.json", "units.json", "inventory.json", "dashboard.html", "report.html")
NO_PDF = "report.pdf not produced"


def read_json_source(path, *, directory=None):
    """Contract records must stay regular artifacts, even if replaced after inspection."""
    with open_artifact(path, directory=directory) as handle:
        return handle.read()


def artifact_version(info):
    """Identify the file and its content-changing metadata, excluding read atime."""
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def artifact_digest(handle):
    """Hash one newly opened artifact in bounded chunks, rejecting size changes."""
    remaining = os.fstat(handle.fileno()).st_size
    digest = hashlib.sha256()
    while remaining:
        chunk = handle.read(min(remaining, 1024 * 1024))
        if not chunk:
            raise OSError("artifact shortened while being read")
        digest.update(chunk)
        remaining -= len(chunk)
    if handle.read(1):
        raise OSError("artifact grew while being read")
    return digest.digest()


def artifact_changes(out, regular, hashes, found, expected, allow, *, directory=None):
    """Recheck the actual bytes validated, then their current names and versions."""
    changed = set()
    for name, digest in hashes.items():
        try:
            with open_artifact(out / name, directory=directory) as handle:
                before = artifact_version(os.fstat(handle.fileno()))
                if (before != artifact_version(regular[name]) or artifact_digest(handle) != digest
                        or artifact_version(os.fstat(handle.fileno())) != before):
                    changed.add(name)
        except OSError:
            changed.add(name)
    # A later read can race with a previously rechecked artifact. Check every
    # pathname again after all hashes, using the pinned directory when available.
    for name, before in regular.items():
        try:
            current = ((out / name).lstat() if directory is None
                       else os.stat(name, dir_fd=directory, follow_symlinks=False))
            if artifact_version(current) != artifact_version(before):
                changed.add(name)
        except OSError:
            changed.add(name)
    try:
        current = set(os.listdir(directory)) if directory is not None else {p.name for p in out.iterdir()}
        changed.update((found ^ current) - (set(allow) - expected))
    except OSError as error:
        yield f"{out}: cannot recheck artifact set: {error.strerror or error}"
    for name in sorted(changed):
        yield f"{name}: changed during validation; run the check again"


class PageMetadata(HTMLParser):
    """Read real head stamps and the complete envelope of a generated page.

    Hashes in comments or script text are not metadata. A matching input hash
    alone also cannot prove that writing the rest of the page completed.
    """

    VOID_TAGS = frozenset(("area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta",
                           "param", "source", "track", "wbr"))
    HEAD_TAGS = frozenset(("base", "link", "meta", "title", "style", "script", "template"))
    HTML_WHITESPACE = " \t\n\r\f"
    NUMERIC_REFERENCES = re.compile(r"&#(?:[xX][0-9a-fA-F]+|[0-9]+);?")
    SCRIPT_OPEN = re.compile(r"<script(?=[\t\n\f\r />])", re.IGNORECASE | re.ASCII)

    def __init__(self, page):
        # Keep references observable: html.unescape silently drops some control
        # references (for example &#11;) which browsers treat as non-whitespace.
        super().__init__(convert_charrefs=False)
        page = page.removeprefix("\ufeff")  # A leading UTF-8 BOM is an encoding signature.
        self.source_lines = page.split("\n")
        self.envelope = []
        self.in_head = False
        self.in_body = False
        self.head_children = []
        self.script_tail = None
        self.script_comment = False
        self.stamps = {}
        self.lang = None
        self.invalid = False
        try:
            self.feed(page)
            self.close()
        except (AssertionError, ValueError):
            # Some Python versions reject malformed marked sections or numeric
            # character references while parsing otherwise readable text.
            self.invalid = True

    def handle_starttag(self, tag, attrs):
        if tag == "script":
            self.script_tail = ""
            self.script_comment = False
        if tag in ("html", "head", "body"):
            self.envelope.append(tag)
        if tag == "head":
            self.in_head = True
        elif tag == "body":
            self.in_body = True
        elif tag != "html" and not (self.in_head or self.in_body):
            self.invalid = True
        duplicate_attrs = len({key for key, _ in attrs}) != len(attrs)
        attrs = dict(attrs)
        if tag == "html":
            self.lang = attrs.get("lang")
        if self.in_head and tag != "head":
            if not self.head_children and tag not in self.HEAD_TAGS:
                # Body content implicitly closes a browser's head. This checker
                # requires the explicit envelope emitted by the renderer.
                self.invalid = True
            if tag == "meta" and not self.head_children and attrs.get("name") in (STAMP, UNITS_STAMP):
                # Attribute values are decoded even with convert_charrefs=False.
                # Reject references that HTMLParser drops but browsers preserve.
                if any(not unescape(match.group()) for match in self.NUMERIC_REFERENCES.finditer(
                        self.get_starttag_text())):
                    self.invalid = True
                self.stamps.setdefault(attrs["name"], []).append(None if duplicate_attrs else attrs.get("content"))
            if tag not in self.VOID_TAGS:
                self.head_children.append(tag)

    def handle_startendtag(self, tag, attrs):
        # Browsers ignore the closing slash on non-void HTML elements, while
        # HTMLParser's default invents an end tag and can expose inert stamps.
        if tag not in self.VOID_TAGS:
            self.invalid = True
            return
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        if tag == "script":
            self.script_tail = None
            self.script_comment = False
        if tag in ("html", "head", "body"):
            self.envelope.append("/" + tag)
        if tag == "head":
            if self.head_children:
                self.invalid = True
            self.in_head = False
        elif tag == "body":
            self.in_body = False
        elif not self.in_body and not self.head_children and tag == "br":
            self.invalid = True
        elif self.in_head and self.head_children and self.head_children[-1] == tag:
            self.head_children.pop()

    def handle_data(self, data):
        if self.script_tail is not None:
            # HTMLParser lacks browser script double-escaping. Reject scripts
            # that may enter it, including body scripts and split callbacks,
            # while retaining harmless comments and text such as <scripture>.
            script_data = self.script_tail + data
            escaped = 0 if self.script_comment else script_data.find("<!--")
            if escaped >= 0:
                start = 0 if self.script_comment else escaped + 4
                self.script_comment = True
            else:
                start = len(script_data)
            if self.SCRIPT_OPEN.search(script_data, start):
                self.invalid = True
            self.script_tail = script_data[-7:]
        if (not self.in_body and not (self.in_head and self.head_children)
                and data.strip(self.HTML_WHITESPACE)):
            # Only HTML's five ASCII whitespace characters keep the head open;
            # they are also the only text around the explicit document envelope.
            # str.isspace()/strip() would incorrectly allow body text such as NBSP.
            self.invalid = True

    def handle_entityref(self, name):
        line, column = self.getpos()
        # Preserve whether the source has a semicolon: &Tab; is whitespace, but
        # &Tab without a semicolon remains text in the browser.
        end = column + len(name) + 1
        semicolon = self.source_lines[line - 1][end:end + 1] == ";"
        self.handle_data(unescape("&" + name + (";" if semicolon else "")))

    def handle_charref(self, name):
        try:
            number = int(name[1:], 16) if name[:1].lower() == "x" else int(name)
        except (ValueError, OverflowError):
            number = -1
        # C1 replacement rules do not change whether a reference is HTML
        # whitespace, so a code point check is sufficient for this contract.
        self.handle_data(chr(number) if number in (9, 10, 12, 13, 32) else "\ufffd")

    @property
    def complete(self):
        return (not self.invalid and not self.head_children
                and self.envelope == ["html", "head", "/head", "body", "/body", "/html"])


def rendered_lang(out, *, directory=None):
    """The language the existing pages were rendered in, so a re-render keeps it."""
    for name in ("report.html", "dashboard.html"):
        try:
            path = out / name
            with open_artifact(path, directory=directory) as handle:
                lang = PageMetadata(handle.read().decode("utf-8", errors="replace")).lang
        except OSError:
            continue
        if lang in ("ja", "en"):
            return lang
    return "<ja|en>"


def problems(out, no_pdf=False, allow=()):
    directory = None
    try:
        # Keep the caller's lexical path as well as the resolved path used for
        # traversal: retargeting an intentional alias must invalidate success.
        requested = Path(out).absolute()
        # Capture identity before resolving intentional aliases: a normal
        # directory substitution is just as significant as a planted symlink.
        selected_info = requested.stat()
        selected = requested.resolve(strict=True)
        if NOFOLLOW_DIR_FD:
            directory = open_directory(selected, expected_stat=selected_info)
        elif not os.path.samestat(selected_info, selected.stat()):
            raise OSError("directory changed before validation")
    except (OSError, RuntimeError) as e:
        yield f"{out}: cannot inspect directory: {getattr(e, 'strerror', None) or e}"
        return
    try:
        yield from directory_problems(selected, no_pdf, allow, directory=directory)
        try:
            expected = os.fstat(directory) if directory is not None else selected_info
            if directory is not None:
                current = open_directory(selected)
                try:
                    unchanged = os.path.samestat(expected, os.fstat(current))
                finally:
                    os.close(current)
            else:
                unchanged = os.path.samestat(expected, selected.stat())
            unchanged = unchanged and os.path.samestat(expected, requested.stat())
        except (OSError, RuntimeError):
            unchanged = False
        if not unchanged:
            yield f"{out}: directory changed during validation; run the check again"
    finally:
        if directory is not None:
            os.close(directory)


def directory_problems(out, no_pdf=False, allow=(), *, directory=None):
    """Inspect and read the artifact set through the same directory descriptor."""
    try:
        found = (set(os.listdir(directory)) if directory is not None
                 else {p.name for p in out.iterdir()} if out.is_dir() else set())
    except OSError as e:
        yield f"{out}: cannot inspect directory: {e.strerror or e}"
        return
    expected = set(REQUIRED) | ({"report.pdf"} if not no_pdf else set())
    rerender = (f"render.py {out}/findings.json --out {out} --lang {rendered_lang(out, directory=directory)} --repo <repo>"
                + (" --no-pdf" if no_pdf else ""))
    for name in sorted(expected - found):
        hint = {"findings.json": "merge fragments with findings.py merge",
                "units.json": "write the purpose, entry points, consumers and units with findings.py units",
                "inventory.json": f"run inventory.py <repo> --units {out}/units.json --out {out}/inventory.json",
                "report.pdf": "render where Chrome works, or follow the no-PDF path in SKILL.md"}.get(
                    name, f"run {rerender}")
        yield f"{name}: missing; {hint}"
    for name in sorted(found - expected - set(allow)):
        yield f"{name}: not part of the contract (contract_check.py --allow {name} if it was asked for)"
    regular = {}
    hashes = {}
    for name in sorted(found & expected):
        path = out / name
        try:
            info = path.lstat() if directory is None else os.stat(name, dir_fd=directory, follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode):
                yield f"{name}: must be a regular file"
            else:
                regular[name] = info
        except OSError as e:
            yield f"{name}: cannot inspect file: {e.strerror or e}"
    if "findings.json" not in regular:
        return
    try:
        source = read_json_source(out / "findings.json", directory=directory)
        hashes["findings.json"] = hashlib.sha256(source).digest()
        units = None
        units_source = None
        if "units.json" in regular:
            units_source = read_json_source(out / "units.json", directory=directory)
            hashes["units.json"] = hashlib.sha256(units_source).digest()
            units = check_units(parse_json(units_source, "units.json"))
        data = check_findings(parse_json(source, "findings.json"), units)
    except (OSError, ValueError, RecordError) as e:
        yield f"record: {e}"
        return
    recorded = {p["name"][:2] for p in data.get("perspectives", [])}
    missing = [f for f in FAMILIES if f not in recorded]
    if missing:
        yield (f"perspectives: no entry for {', '.join(missing)}; record each family as applied, "
               "N/A with the reason, or not checked")
    unfinished = [p["name"] for p in data.get("perspectives", []) if not p.get("result", "").strip()]
    if unfinished:
        yield (f"perspectives: no result for {', '.join(unfinished)}; record applied, "
               "N/A with the reason, or not checked")
    unverified = [f["id"] for f in data["findings"] if f["validation"]["verdict"] == "Unverified"]
    if unverified:
        yield f"findings: {', '.join(unverified)} still Unverified; settle the verdict in VERIFY"
    decisions = set(FINDING_REF.findall("\n".join(data.get("decisions", []))))
    undecided = [f["id"] for f in data["findings"] if f["confidence"] == "Purpose-dependent" and f["status"] == "Open"
                 and f["validation"]["verdict"] not in EXCLUDED and f["id"] not in decisions]
    if undecided:
        yield (f"decisions: {', '.join(undecided)} rest on an inferred purpose; name each in a decisions line "
               "so a human makes the keep or remove call")
    if "inventory.json" in regular:
        try:
            inventory_source = read_json_source(out / "inventory.json", directory=directory)
            hashes["inventory.json"] = hashlib.sha256(inventory_source).digest()
            inventory = parse_json(inventory_source, "inventory.json")
            if not isinstance(inventory, dict) or inventory.get("tool") != "inventory.py":
                yield "inventory.json: not written by inventory.py"
        except (ValueError, RecordError) as e:
            yield f"inventory.json: not valid JSON: {e}"
        except OSError as e:
            yield f"inventory.json: cannot read file: {e.strerror or e}"
    digests = {STAMP: "sha256:" + hashlib.sha256(source).hexdigest()}
    if units_source is not None:
        digests[UNITS_STAMP] = "sha256:" + hashlib.sha256(units_source).hexdigest()
    for name in ("dashboard.html", "report.html"):
        if name not in regular:
            continue
        try:
            with open_artifact(out / name, directory=directory) as handle:
                page_source = handle.read()
            hashes[name] = hashlib.sha256(page_source).digest()
            page = page_source.decode("utf-8")
        except (OSError, UnicodeError) as e:
            yield f"{name}: cannot read file: {e}"
            continue
        metadata = PageMetadata(page)
        if not metadata.complete:
            yield f"{name}: invalid or incomplete HTML; re-render the page ({rerender})"
            continue
        for stamp, digest in digests.items():
            if metadata.stamps.get(stamp) != [digest]:
                yield f"{name}: stale; re-render after the last findings or units change ({rerender})"
                break
    if "report.pdf" in regular:
        try:
            with open_artifact(out / "report.pdf", directory=directory) as handle:
                hashes["report.pdf"] = artifact_digest(handle)
        except OSError as error:
            yield f"report.pdf: cannot read file: {error.strerror or error}"
        if not pdf_complete(out / "report.pdf", directory=directory):
            yield "report.pdf: empty, invalid or incomplete; re-render the PDF"
    pdf_limitations = [line for line in data.get("limitations", []) if line.startswith(NO_PDF)]
    limited = any(re.match(re.escape(NO_PDF) + r":\s*\S", line) for line in pdf_limitations)
    if no_pdf and not limited:
        yield f"limitations: --no-pdf needs the line '{NO_PDF}: <reason>'"
    if not no_pdf and pdf_limitations:
        yield f"limitations: says '{NO_PDF}' but report.pdf is expected; remove that line"
    yield from artifact_changes(out, regular, hashes, found, expected, allow, directory=directory)


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
