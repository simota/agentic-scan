"""Definitions shared by the scripts, kept in one place so they cannot drift."""
import json
import os
from pathlib import Path
import re
import stat
import tempfile

SEVERITIES = ("High", "Medium", "Low", "Info")
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
# The record's lists of plain strings, and every list a new record starts with.
STRING_LISTS = ("checked_ok", "decisions", "limitations", "next_steps")
RECORD_LISTS = ("attack_paths", "findings", "perspectives", *STRING_LISTS)

# terraform.tfstate, .tfstate.backup and the timestamped backups that
# `terraform state` subcommands write (terraform.tfstate.1700000000.backup).
STATE_FILE = re.compile(r"\.tfstate(\.[^/]*)?$")
STATE_OR_VARS = re.compile(STATE_FILE.pattern + r"|\.tfvars(\.json)?$")

# A record ID in prose or a Markdown label, not inside a word, filename or
# resource address (aws_security_group.I-900 names a resource, not I-900).
# ASCII classes: Japanese text often joins an ID directly (F-009は). "#F-123"
# is another tracker's key. URLs are skipped by span (url_spans), including
# their queries and fragments, so every tool reads references the same way.
ID_BEFORE = r"(?<![A-Za-z0-9_#.-])"
ID_AFTER = r"(?![A-Za-z0-9_-]|\.[A-Za-z0-9])"
BASELINE_REFERENCE = re.compile(ID_BEFORE + r"I-[0-9]{3,}" + ID_AFTER)
F_REFERENCE = re.compile(ID_BEFORE + r"F-[0-9]{3,}" + ID_AFTER)
RECORD_REFERENCE = re.compile(ID_BEFORE + r"(?:F-[0-9]{3,}|AP-[0-9]{2,}|I-[0-9]{3,})" + ID_AFTER)
# A URL ends at the first non-ASCII character: Japanese prose often joins the
# next word directly (https://example.com/runbookを参照し、F-005を…).
URL = re.compile(r"\b[A-Za-z][A-Za-z0-9+.-]*://[^\s<>`\"'\u0080-\U0010ffff]+")
# The limitation iac_scan.py writes when a rescan drops a verdict names the
# baseline IDs of that scan on purpose; every other line follows a rescan.
CARRY_NOTE = re.compile(r"I-[0-9]{3,} \(was I-[0-9]{3,}\): .* Recheck this baseline finding\.", re.DOTALL)
# Next to "/", an ID is a reference only beside another ID ("F-002/F-005");
# otherwise it is a path component (docs/F-001/main.tf).
_ID_END = re.compile(r"(?:F-[0-9]{3,}|AP-[0-9]{2,}|I-[0-9]{3,})\Z")
_ID_START = re.compile(r"(?:F-[0-9]{3,}|AP-[0-9]{2,}|I-[0-9]{3,})")

YAML_DOCUMENT_MARK = re.compile(r"(?:---|\.\.\.)(?:\s+#.*)?\s*")


def url_spans(text):
    """(start, end) of each URL, ending before a Markdown link's closing parenthesis."""
    cursor = 0
    while match := URL.search(text, cursor):
        depth, end = 0, match.end()
        for offset, char in enumerate(match.group()):
            if char == "(":
                depth += 1
            elif char == ")":
                if depth == 0:
                    end = match.start() + offset
                    break
                depth -= 1
        yield match.start(), end
        cursor = end


def _is_reference(text, match, spans):
    start, end = match.span()
    if any(s <= start < e for s, e in spans):
        return False
    if start and text[start - 1] == "/" and not _ID_END.search(text, 0, start - 1):
        return False
    return not (text[end:end + 1] == "/" and not _ID_START.match(text, end + 1))


def find_references(pattern, text):
    """Matches of pattern outside URLs and file paths."""
    spans = list(url_spans(text))
    return [m for m in pattern.finditer(text) if _is_reference(text, m, spans)]


def sub_references(pattern, text, replace):
    """pattern.sub outside URLs and file paths, in one pass (I-001 -> I-002 and
    I-002 -> I-003 do not chain)."""
    spans = list(url_spans(text))
    return pattern.sub(lambda m: replace(m) if _is_reference(text, m, spans) else m.group(), text)


def shape_problems(data):
    """The structure every tool relies on before it reads a record at all."""
    if not isinstance(data, dict):
        return ["record: must be a JSON object"]
    problems = []
    for key in ("meta", "inventory"):
        if key in data and not isinstance(data[key], dict):
            problems.append(f"{key}: must be an object")
    for key in RECORD_LISTS:
        if key in data and not isinstance(data[key], list):
            problems.append(f"{key}: must be a list")
        elif key in ("findings", "attack_paths", "perspectives"):
            for n, item in enumerate(data.get(key, [])):
                if not isinstance(item, dict):
                    problems.append(f"{key}[{n}]: must be an object")
                elif key != "perspectives" and not isinstance(item.get("id"), str):
                    problems.append(f"{key}[{n}]: id must be a string")
    return problems


def unique_object(pairs):
    """object_pairs_hook refusing duplicate keys, which JSON would silently drop.

    Object keys can themselves be credentials: the error never names the key.
    """
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


MAX_JSON_DEPTH = 32  # a record nests about six levels; the tools copy and walk it recursively


def json_depth(value):
    """Nesting depth of parsed JSON, without recursion."""
    deepest, stack = 0, [(value, 1)]
    while stack:
        item, level = stack.pop()
        if isinstance(item, (dict, list)):
            deepest = max(deepest, level)
            stack.extend((x, level + 1) for x in (item.values() if isinstance(item, dict) else item))
    return deepest


def has_symlink_parent(path):
    """True when any existing parent directory of path (relative or anchored to cwd) is a symlink."""
    raw_path = Path(path)
    abs_path = Path(os.path.abspath(str(raw_path)))
    temp_parents = set(Path(tempfile.gettempdir()).parents) | {Path("/tmp"), Path("/var"), Path("/etc")}
    candidates = (*raw_path.parents, abs_path.parent, *abs_path.parent.parents)
    return any(p.is_symlink() for p in candidates if p not in temp_parents and os.path.lexists(p))


def split_yaml_documents(lines):
    """[(line number, text)] per document, split on --- and ... markers.

    YAML permits a BOM at each document start, not only at the file start.
    """
    docs, current = [], []
    for n, line in enumerate(lines, 1):
        if not current:
            line = line.removeprefix("﻿")
        if YAML_DOCUMENT_MARK.fullmatch(line):
            docs.append(current)
            current = []
        else:
            current.append((n, line))
    docs.append(current)
    return docs


def write_json_atomic(path, data, *, mkdir=False):
    """Replace path with JSON in one rename, keeping the file's mode."""
    write_text_atomic(path, json.dumps(data, ensure_ascii=False, indent=2) + "\n", mkdir=mkdir)


def write_text_atomic(path, text, *, mkdir=False):
    """Replace path with UTF-8 text in one rename, keeping the file's mode.

    A new file gets the umask default rather than mkstemp's 0600. A symlink is
    refused rather than replaced or written through. Text that cannot be
    encoded (a lone surrogate) raises OSError before anything is touched.
    """
    path = Path(path)
    try:
        data = text.encode("utf-8")
    except UnicodeEncodeError:
        raise OSError(f"{path}: text contains a lone surrogate and cannot be written as UTF-8") from None
    if path.is_symlink():
        raise OSError(f"{path} is a symlink; refusing to replace it")
    if os.path.lexists(path) and not path.is_file():
        raise OSError(f"{path} is not a regular file; refusing to replace it")
    if has_symlink_parent(path):
        raise OSError(f"{path}: parent directory is a symlink; refusing to write through it")
    if mkdir:
        path.parent.mkdir(parents=True, exist_ok=True)
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except FileNotFoundError:
        umask = os.umask(0)
        os.umask(umask)
        mode = 0o666 & ~umask
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        os.chmod(tmp, mode)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
