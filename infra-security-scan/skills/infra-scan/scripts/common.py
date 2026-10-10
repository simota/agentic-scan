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

# A baseline ID in prose or a Markdown label, not inside a word or filename.
# URL ranges are protected separately, including their queries and fragments.
BASELINE_REFERENCE = re.compile(r"(?<![A-Za-z0-9_./-])I-[0-9]{3,}(?![A-Za-z0-9_/-]|\.[A-Za-z0-9])")

YAML_DOCUMENT_MARK = re.compile(r"(?:---|\.\.\.)(?:\s+#.*)?\s*")


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
