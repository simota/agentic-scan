#!/usr/bin/env python3
"""Merge finding fragments into findings.json without writing ad-hoc scripts.

    python3 findings.py merge FINDINGS FRAGMENT [FRAGMENT ...]

A fragment is a JSON file written with the host's file-write tool (never a
shell heredoc or a generated script). Its top-level keys:

- `meta` is merged key by key (`commit` and `dirty` come only from
  inventory.py --into)
- `prompts`, `findings` and `eval_runs` records are matched by `id`: a known
  record is updated key by key (so a later fragment can add just `validation`
  to F-003), a new one appended
- a `perspectives` entry replaces the recorded entry with the same `name`
- `checked_ok`, `decisions`, `limitations` and `next_steps` are appended
  without duplicates; `remove` (e.g. {"limitations": ["exact text"]}) first
  deletes exact entries from those lists, and an entry not recorded is refused

A fragment adds at most five new findings, so a refused write loses at most
that batch. `L-*` findings belong to inventory.py: a fragment may only add
`validation` to an existing `L-*` ID.

Finding text describes the weakness, not an attack: literal instruction-override
strings and credential-shaped values in report prose are refused.

FINDINGS is created when absent and replaced atomically, only if no other
writer changed it meanwhile. The merged report must pass render.py's schema.

Exit codes: 0 merged, 1 a fragment was refused (reason on stderr), 2 unreadable
input or schema error.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import render  # noqa: E402

OBJECTS = ("meta",)
RECORDS = ("prompts", "findings", "eval_runs")
LISTS = ("perspectives", "checked_ok", "decisions", "limitations", "next_steps")
REMOVABLE = LISTS[1:]
SCANNER_META = {"commit", "dirty"}
LINT_REVIEW = {"id", "validation"}
MAX_NEW_FINDINGS = 5
# Working override strings, not descriptions of them. Prose names the weakness
# and the variable; a payload that would work against a model never belongs in the report.
PAYLOAD = re.compile(
    r"\b(?:ignore|disregard|forget)\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|preceding|earlier)\s+"
    r"(?:instructions|prompts?|rules|messages)\b|"
    r"\byou\s+are\s+now\s+(?:DAN|in\s+developer\s+mode|jailbroken|unrestricted)\b|"
    r"\b(?:developer|god|jailbreak)\s+mode\s+(?:enabled|activated|on)\b|"
    r"(?:以前|前|上記|これまで)の(?:指示|命令|ルール|プロンプト)を(?:すべて|全て)?(?:無視|忘れ)",
    re.IGNORECASE,
)


def read_regular(path):
    """Read a regular file, never a FIFO, device or symlink."""
    path = Path(path)
    if not stat.S_ISREG(os.lstat(str(path)).st_mode):
        raise OSError(f"{path}: not a regular file")
    return path.read_bytes()


def read_json(path, raw=None):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key {key!r}")
            result[key] = value
        return result
    try:
        raw = read_regular(path) if raw is None else raw
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
    except (OSError, UnicodeError, ValueError) as e:
        raise render.SchemaError(f"{path}: {e}") from None
    if render.json_depth(value) > render.MAX_JSON_DEPTH:
        raise render.SchemaError(f"{path}: JSON nesting deeper than {render.MAX_JSON_DEPTH} levels")
    return value


def strings(value, path):
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from strings(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from strings(item, f"{path}[{index}]")


def fragment_problems(fragment, name, base):
    if not isinstance(fragment, dict):
        return [f"{name}: a fragment must be a JSON object"]
    unsupported = fragment.keys() - {*OBJECTS, *RECORDS, *LISTS, "remove"}
    if unsupported:
        return [f"{name}: unsupported keys {sorted(unsupported)}"]
    problems = []
    for key in OBJECTS:
        if key in fragment and not isinstance(fragment[key], dict):
            problems.append(f"{name}: {key} must be an object")
    for key in (*RECORDS, *LISTS):
        if key in fragment and not isinstance(fragment[key], list):
            problems.append(f"{name}: {key} must be a list")
    remove = fragment.get("remove", {})
    if not isinstance(remove, dict) or remove.keys() - set(REMOVABLE) or any(
            not isinstance(v, list) or not all(isinstance(x, str) for x in v) for v in remove.values()):
        problems.append(f"{name}: remove must map {', '.join(REMOVABLE)} to lists of exact entries")
    if problems:
        return problems
    if SCANNER_META & fragment.get("meta", {}).keys():
        problems.append(f"{name}: meta.commit and meta.dirty come from inventory.py --into")
    known = {f.get("id") for f in base.get("findings", []) if isinstance(f, dict)}
    new = 0
    for key in RECORDS:
        seen = set()
        for record in fragment.get(key, []):
            ident = record.get("id") if isinstance(record, dict) else None
            if not isinstance(ident, str) or not ident.strip():
                problems.append(f"{name}: {key} records need a nonblank id")
                continue
            if ident in seen:
                problems.append(f"{name}: duplicate {key} id {ident}")
            seen.add(ident)
            if key != "findings":
                continue
            if ident.startswith("L-"):
                if ident not in known:
                    problems.append(f"{name}: {ident}: L-* findings are created only by inventory.py --into")
                elif record.keys() - LINT_REVIEW:
                    problems.append(f"{name}: {ident}: L-* scanner fields {sorted(record.keys() - LINT_REVIEW)} "
                                    "come only from inventory.py; merge only validation")
            elif ident not in known:
                new += 1
                if {"source", "rule", "previous_validation"} & record.keys():
                    problems.append(f"{name}: {ident}: source, rule and previous_validation belong to inventory.py")
    if new > MAX_NEW_FINDINGS:
        problems.append(f"{name}: {new} new findings in one fragment; write at most {MAX_NEW_FINDINGS} "
                        "per fragment and merge each batch before writing the next")
    for where, value in strings({k: v for k, v in fragment.items() if k != "remove"}, name):
        if PAYLOAD.search(value):
            problems.append(f"{where} contains a literal instruction-override string; describe the weakness "
                            "and name the variable instead")
        if render.SECRET_RE.search(value):
            problems.append(f"{where} contains a credential-shaped value; give its location and kind only")
    return problems


def upsert(items, updates):
    by_id = {r.get("id"): r for r in items if isinstance(r, dict)}
    for r in updates:
        if r.get("id") in by_id:
            by_id[r["id"]].update(r)
        else:
            items.append(r)
            by_id[r["id"]] = r


def merge(base, fragment):
    for key, entries in fragment.get("remove", {}).items():
        base[key] = [item for item in base.get(key, []) if item not in entries]
    for key in OBJECTS:
        if key in fragment:
            base.setdefault(key, {}).update(fragment[key])
    for key in RECORDS:
        if key in fragment:
            upsert(base.setdefault(key, []), fragment[key])
    for key in LISTS:
        items = base.setdefault(key, [])
        for item in fragment.get(key, []):
            if key == "perspectives" and isinstance(item, dict):
                same = [i for i, old in enumerate(items) if isinstance(old, dict) and old.get("name") == item.get("name")]
                if same:
                    items[same[0]] = item
                    for i in reversed(same[1:]):
                        del items[i]
                    continue
            if item not in items:
                items.append(item)
    base.setdefault("schema_version", 1)
    base.setdefault("findings", [])
    return base


class MergeConflict(Exception):
    pass


def write_report(path, data, original):
    """Replace path atomically unless another writer changed it since it was read."""
    path = Path(path)
    lock = path.with_name(path.name + ".lock")
    try:
        fd = os.open(str(lock), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise MergeConflict(f"{lock}: a writer lock exists; check the other writer before removing a stale lock")
    os.close(fd)
    temp = None
    try:
        current = path.read_bytes() if path.exists() else None
        if path.is_symlink() or current != original:
            raise MergeConflict(f"{path}: file changed concurrently; no update written")
        fd, temp = tempfile.mkstemp(prefix="." + path.name + ".", dir=str(path.parent))
        with os.fdopen(fd, "wb") as stream:
            stream.write((json.dumps(data, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temp, 0o644)
        os.replace(temp, path)
        temp = None
    finally:
        if temp is not None and os.path.exists(temp):
            os.unlink(temp)
        lock.unlink(missing_ok=True)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("merge", help="merge fragments into FINDINGS")
    m.add_argument("findings", type=Path)
    m.add_argument("fragments", nargs="+", type=Path)
    a = p.parse_args(argv)
    try:
        original = read_regular(a.findings) if os.path.lexists(a.findings) else None
        base = read_json(a.findings, original) if original is not None else {}
        if not isinstance(base, dict):
            raise render.SchemaError(f"{a.findings}: report must be an object")
        fragments = [(str(path), read_json(path)) for path in a.fragments]
    except (render.SchemaError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    refused = []
    for name, fragment in fragments:
        refused += fragment_problems(fragment, name, base)
    if refused:
        print("\n".join(refused), file=sys.stderr)
        return 1
    for name, fragment in fragments:
        missing = [f"{name}: remove.{key}: {entry!r} is not recorded"
                   for key, entries in fragment.get("remove", {}).items()
                   for entry in entries if entry not in base.get(key, [])]
        if missing:
            print("\n".join(missing), file=sys.stderr)
            return 1
        base = merge(base, fragment)
    try:
        render.validate_data(copy.deepcopy(base))
        write_report(a.findings, base, original)
    except render.SchemaError as e:
        print(f"error: merged report does not match the schema: {e}", file=sys.stderr)
        return 2
    except (MergeConflict, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    print(f"merged {len(fragments)} fragment(s) into {a.findings}: {len(base['findings'])} finding(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
