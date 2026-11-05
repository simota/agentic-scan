#!/usr/bin/env python3
"""Check a prune-scan output directory against the run contract (SKILL.md).

    python3 contract_check.py OUT [--no-pdf] [--allow NAME]...

Passes when OUT holds exactly findings.json, units.json, inventory.json,
dashboard.html, report.html and report.pdf (no PDF with --no-pdf, which then
requires the "report.pdf not produced" limitation); the record and units are
valid; every perspective family is recorded in perspectives; no finding is
left Unverified; every open Purpose-dependent finding is named in decisions;
and both pages carry the SHA-256 of the current findings.json and units.json.
An --allow NAME directory holding rendered pages (a second language) must show
the current record too.
Exit status: 0 ok, 1 contract not met (each problem on stderr), 2 bad arguments.
"""

import argparse
import hashlib
import os
import re
import stat
import sys
from contextlib import ExitStack
from html import unescape
from html.parser import HTMLParser
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from findings import (EXCLUDED, FAMILIES, RecordError, check_findings, check_units,  # noqa: E402
                      finding_references, parse_json)
from render import (STAMP, UNITS_STAMP, open_artifact,  # noqa: E402
                    pdf_complete as stored_pdf_complete, pdf_envelope_complete)
from safe_output import tolerant_stdout  # noqa: E402
from safe_paths import NOFOLLOW_DIR_FD, open_directory  # noqa: E402

REQUIRED = ("findings.json", "units.json", "inventory.json", "dashboard.html", "report.html")
NO_PDF = "report.pdf not produced"
NOT_APPLICABLE = re.compile(r"\s*N/?A\b[\s:;,.()\-\u2013\u2014]*(.*)\Z", re.I | re.S)
# A reason holds a word: punctuation alone (N/A：, N/A。, N/A ->) is none.
REASON = re.compile(r"[^\W_]")


def read_json_source(path, *, directory=None, snapshots=None):
    """Contract records must stay regular artifacts, even if replaced after inspection."""
    if snapshots is not None:
        return snapshots.read(path)
    with open_artifact(path, directory=directory) as handle:
        return handle.read()


def pdf_complete(path, *, directory=None, snapshots=None):
    """Check the exact PDF bytes captured for this contract, when supplied."""
    if snapshots is not None:
        return snapshots.read(path, pdf=True)
    return stored_pdf_complete(path, directory=directory)


def artifact_version(info):
    """Identify the file and its content-changing metadata, excluding read atime."""
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def fingerprint(handle, size):
    """Hash a bounded read and retain the PDF envelope from those same bytes."""
    digest = hashlib.sha256()
    header, tail = b"", b""
    remaining = size + 1
    while remaining:
        chunk = handle.read(min(65536, remaining))
        if not chunk:
            break
        digest.update(chunk)
        header = (header + chunk[:8])[:8]
        tail = (tail + chunk)[-1024:]
        remaining -= len(chunk)
    return digest.digest(), header, tail, size + 1 - remaining


class ArtifactSnapshots:
    """Bind inspected bytes to open files and recheck them before success.

    Holding descriptors prevents inode reuse while checking. This detects
    observed changes; it does not lock publishers or create an atomic set.
    """

    def __init__(self, stack, directory):
        self.stack = stack
        self.directory = directory
        self.files = {}
        self.regular = {}
        self.names = None

    def read(self, path, *, pdf=False):
        handle = self.stack.enter_context(open_artifact(path, directory=self.directory))
        before = os.fstat(handle.fileno())
        if artifact_version(before) != artifact_version(self.regular[path.name]):
            raise OSError(f"{path.name}: changed during validation; run the check again")
        if pdf:
            digest, header, tail, size = fingerprint(handle, before.st_size)
            value = pdf_envelope_complete(header, tail)
        else:
            value = handle.read(before.st_size + 1)
            digest, size = hashlib.sha256(value).digest(), len(value)
        if size != before.st_size or artifact_version(before) != artifact_version(os.fstat(handle.fileno())):
            raise OSError(f"{path.name}: changed during validation; run the check again")
        self.files[path.name] = handle, before, digest
        return value

    def problems(self, out, allow):
        changed = set()
        for name, (_, expected, digest) in self.files.items():
            try:
                with open_artifact(out / name, directory=self.directory) as handle:
                    before = os.fstat(handle.fileno())
                    unchanged = artifact_version(expected) == artifact_version(before)
                    if unchanged:
                        current, _, _, size = fingerprint(handle, before.st_size)
                        unchanged = (current == digest and size == before.st_size
                                     and artifact_version(before) == artifact_version(os.fstat(handle.fileno())))
            except (OSError, RuntimeError):
                unchanged = False
            if not unchanged:
                changed.add(name)
        # A later read can race with a previously rechecked artifact. Check
        # every pathname again after all hashes, through the selected directory.
        for name, before in self.regular.items():
            try:
                current = ((out / name).lstat() if self.directory is None else
                           os.stat(name, dir_fd=self.directory, follow_symlinks=False))
                if artifact_version(current) != artifact_version(before):
                    changed.add(name)
            except OSError:
                changed.add(name)
        if self.names is not None:
            try:
                current = (set(os.listdir(self.directory)) if self.directory is not None
                           else {path.name for path in out.iterdir()})
                changed.update((current ^ self.names) - allow)
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
    # Older supported Python releases only recognize script/style as text.
    # Keep other text elements opaque too, using scripting-enabled noscript,
    # so their contents cannot supply the document's closing tags.
    CDATA_CONTENT_ELEMENTS = HTMLParser.CDATA_CONTENT_ELEMENTS + (
        "title", "textarea", "xmp", "iframe", "noembed", "noframes", "noscript")
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
        self.template_depth = 0
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
        if tag == "template":
            self.template_depth += 1
        if tag == "plaintext":
            # Plaintext never returns to markup, so the explicit envelope
            # required by this contract cannot close after it starts.
            self.invalid = True
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
        if tag == "template" and self.template_depth:
            self.template_depth -= 1
        elif tag in ("html", "head", "body") and self.template_depth:
            # Template children still produce parser callbacks, but their
            # document end tags are inert. Closing the template later cannot
            # turn those tags into the document's explicit closing envelope.
            self.invalid = True
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
        return (not self.invalid and not self.head_children and not self.template_depth
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
        with ExitStack() as stack:
            snapshots = ArtifactSnapshots(stack, directory)
            yield from directory_problems(selected, no_pdf, allow, directory=directory, snapshots=snapshots)
            expected_names = set(REQUIRED) | ({"report.pdf"} if not no_pdf else set())
            yield from snapshots.problems(selected, set(allow) - expected_names)
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


def directory_problems(out, no_pdf=False, allow=(), *, directory=None, snapshots):
    """Inspect and read the artifact set through the same directory descriptor."""
    try:
        found = (set(os.listdir(directory)) if directory is not None
                 else {p.name for p in out.iterdir()} if out.is_dir() else set())
    except OSError as e:
        yield f"{out}: cannot inspect directory: {e.strerror or e}"
        return
    snapshots.names = found
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
    regular = snapshots.regular
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
        source = read_json_source(out / "findings.json", directory=directory, snapshots=snapshots)
        units = None
        units_source = None
        if "units.json" in regular:
            units_source = read_json_source(out / "units.json", directory=directory, snapshots=snapshots)
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
    # "N/A with the reason": the reason may follow in result (N/A: no database) or sit in note.
    unexplained = [p["name"] for p in data.get("perspectives", [])
                   if (na := NOT_APPLICABLE.match(p.get("result", ""))) and not REASON.search(na.group(1))
                   and not REASON.search(p.get("note", ""))]
    if unexplained:
        yield (f"perspectives: {', '.join(unexplained)} N/A without a reason; give it in the result "
               "(N/A: <reason>) or in note")
    unverified = [f["id"] for f in data["findings"] if f["validation"]["verdict"] == "Unverified"]
    if unverified:
        yield f"findings: {', '.join(unverified)} still Unverified; settle the verdict in VERIFY"
    # A path such as docs/P-021.md is a source, not a finding, as renumber reads it.
    decisions = finding_references(data, "\n".join(data.get("decisions", [])))
    undecided = [f["id"] for f in data["findings"] if f["confidence"] == "Purpose-dependent" and f["status"] == "Open"
                 and f["validation"]["verdict"] not in EXCLUDED and f["id"] not in decisions]
    if undecided:
        yield (f"decisions: {', '.join(undecided)} rest on an inferred purpose; name each in a decisions line "
               "so a human makes the keep or remove call")
    if "inventory.json" in regular:
        try:
            inventory = parse_json(read_json_source(out / "inventory.json", directory=directory,
                                                     snapshots=snapshots), "inventory.json")
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
            page = snapshots.read(out / name).decode("utf-8")
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
    yield from allowed_page_problems(out, sorted(set(allow) & found), digests, directory=directory)
    if "report.pdf" in regular:
        try:
            complete = pdf_complete(out / "report.pdf", directory=directory, snapshots=snapshots)
        except OSError:
            complete = False
        if not complete:
            yield "report.pdf: empty, invalid or incomplete; re-render the PDF"
    pdf_limitations = [line for line in data.get("limitations", []) if line.startswith(NO_PDF)]
    limited = any((m := re.match(re.escape(NO_PDF) + r":(.*)\Z", line, re.S)) and REASON.search(m.group(1))
                  for line in pdf_limitations)
    if no_pdf and not limited:
        yield f"limitations: --no-pdf needs the line '{NO_PDF}: <reason>'"
    if not no_pdf and pdf_limitations:
        yield f"limitations: says '{NO_PDF}' but report.pdf is expected; remove that line"


def allowed_page_problems(out, names, digests, *, directory=None):
    """An allowed directory holding rendered pages (a second language) must show the current record.

    Its pages are not part of the contract, so a directory without pages is
    not a problem; once it holds one page it needs both, each complete and
    carrying the same stamps.
    """
    for name in names:
        try:
            info = (os.stat(name, dir_fd=directory, follow_symlinks=False) if directory is not None
                    else (out / name).lstat())
            if stat.S_ISLNK(info.st_mode):
                target_is_dir = (stat.S_ISDIR(os.stat(name, dir_fd=directory).st_mode) if directory is not None
                                 else (out / name).is_dir())
                if target_is_dir:
                    yield (f"{name}: a symbolic link to a directory; its pages cannot be checked in place, "
                           f"so render the second language into {out / name} itself")
                continue
        except OSError:
            continue
        try:
            if directory is not None:
                fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            elif (out / name).is_dir() and not (out / name).is_symlink():
                fd = None
            else:
                continue
        except OSError:
            continue  # Not a directory: an allowed extra file is outside these checks.
        try:
            missing, rerender = [], None
            for page in ("dashboard.html", "report.html"):
                path = out / name / page
                try:
                    with open_artifact(path, directory=fd) as handle:
                        text = handle.read().decode("utf-8")
                except FileNotFoundError:
                    missing.append(page)
                    continue
                except (OSError, UnicodeError) as e:
                    yield f"{name}/{page}: cannot read file: {e}"
                    continue
                metadata = PageMetadata(text)
                lang = metadata.lang if metadata.lang in ("ja", "en") else "<ja|en>"
                rerender = f"render.py {out}/findings.json --out {out / name} --lang {lang} --repo <repo>"
                if not metadata.complete:
                    yield f"{name}/{page}: invalid or incomplete HTML; re-render the page ({rerender})"
                elif any(metadata.stamps.get(stamp) != [digest] for stamp, digest in digests.items()):
                    yield f"{name}/{page}: stale; re-render after the last findings or units change ({rerender})"
            if len(missing) == 1:
                rerender = rerender or f"render.py {out}/findings.json --out {out / name} --lang <ja|en> --repo <repo>"
                yield f"{name}/{missing[0]}: missing beside its other page; re-render the second language ({rerender})"
        finally:
            if fd is not None:
                os.close(fd)


def allowed_name(value):
    """--allow names one entry of OUT; a trailing slash from tab completion is accepted."""
    name = value.rstrip("/")
    if not name or "/" in name or name in (".", ".."):
        raise argparse.ArgumentTypeError(f"expected a name inside OUT, got {value!r}")
    return name


def main(argv=None):
    tolerant_stdout()
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("out", help="output directory holding the contracted files")
    p.add_argument("--no-pdf", action="store_true",
                   help="accept a run without report.pdf when a limitation records why")
    p.add_argument("--allow", action="append", default=[], type=allowed_name, metavar="NAME",
                   help="tolerate one extra file name in the output directory (repeatable)")
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
