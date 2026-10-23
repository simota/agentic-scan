#!/usr/bin/env python3
"""Merge finding fragments into findings.json without writing ad-hoc scripts.

    python3 findings.py merge FINDINGS FRAGMENT [FRAGMENT ...]
    python3 findings.py renumber FINDINGS

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

`renumber` gives the F-* findings the order the run contract asks for, once
severities are final: F-001.. by severity, then path and line, with
FalsePositive / NotApplicable findings after the rest. Every F-* reference in
the record (ids, eval_runs, prose, reference titles) follows the new numbers;
quoted `proposal` text, reference URLs, locations, an F-NNN that is part of a
path or file name, `meta`, the prompt records and the scanner fields of `L-*` findings are
left as written.

FINDINGS is created when absent and replaced atomically, only if no other
writer changed it meanwhile. The merged report must pass render.py's schema.

Exit codes: 0 merged or renumbered, 1 a fragment was refused (reason on
stderr), 2 unreadable input or schema error.
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
    try:
        raw = read_regular(path) if raw is None else raw
    except OSError as e:
        raise render.SchemaError(f"{path}: {e}") from None
    return render.parse_json(raw, path)


def strings(value, path):
    """Every string in value, object keys included: a key is written to findings.json like any value."""
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield f"{path} (key)", key
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
            else:
                new += ident not in known
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


# ASCII boundaries: \b would count the kana in "F-001とF-002" as part of the word and skip both ids.
CODE_REF = re.compile(r"(?<![A-Za-z0-9_])F-[0-9]{3,}(?![A-Za-z0-9_])")
# Quoted prompt text, link targets and locations are not references to findings, even when they contain
# an F-NNN (a feature id naming a directory, say). Neither are meta, the prompt records and the scanner
# fields of L-* findings; an L-* finding's own review may cite findings.
VERBATIM = {"proposal", "url", "location"}
UNTOUCHED = {"meta", "prompts"}
LINT_REVIEWED = {"validation", "previous_validation"}


def order_key(f):
    """The run contract's F-* order: severity, then path and line (the old id breaks ties)."""
    m = render.LOC_RE.match(f["location"])
    path, line = (m["path"], int(m["start"])) if m else (f["location"], 0)
    return render.SEVERITIES.index(f["severity"]), path, line, render.id_key(f["id"])


def renumber_map(findings):
    """Old F-* id -> new id: order_key; excluded findings last, in their old order."""
    code = [f for f in findings if f["id"].startswith("F-")]
    active = sorted((f for f in code if f["validation"]["verdict"] not in render.EXCLUDED), key=order_key)
    excluded = sorted((f for f in code if f["validation"]["verdict"] in render.EXCLUDED), key=lambda f: render.id_key(f["id"]))
    return {f["id"]: f"F-{n:03d}" for n, f in enumerate(active + excluded, 1)}


LIST_OF_REFS = re.compile(r"F-[0-9]{3,}(?:/F-[0-9]{3,})+")


def in_path(text, start, end):
    """Whether the F-NNN at text[start:end] belongs to a path or file name, not to the prose around it.

    A word holding a slash or backslash is a path (prompts/F-002/a.md, a URL) unless it is only finding
    ids joined by slashes (F-001/F-002/F-003); F-002.md and F-002-system.md are file names.
    """
    if re.match(r"[.-][A-Za-z0-9_]", text[end:]) and not re.match(r"-F-[0-9]{3,}(?![A-Za-z0-9_])", text[end:]):
        return True
    # A path is a run of ASCII characters: Japanese prose has no spaces, so "answer.pyの12行目でF-001" must
    # stop at the kana rather than make the whole sentence one word.
    first, last = start, end
    while first > 0 and text[first - 1].isascii() and not text[first - 1].isspace() \
            and text[first - 1] not in "([{<\"'`":
        first -= 1
    while last < len(text) and text[last].isascii() and not text[last].isspace() and text[last] not in ")]}>\"'`":
        last += 1
    word = text[first:last].rstrip(".,;:!?")
    return ("/" in word or "\\" in word) and not LIST_OF_REFS.fullmatch(word)


def renumber(data, mapping):
    """Rewrite every F-* reference in data's strings at once, then order the F-* records by id."""
    def ref(m):
        return m.group(0) if in_path(m.string, m.start(), m.end()) else mapping.get(m.group(0), m.group(0))

    def rewrite(value):
        if isinstance(value, str):
            return CODE_REF.sub(ref, value)
        if isinstance(value, dict):
            return {k: v if k in VERBATIM else rewrite(v) for k, v in value.items()}
        if isinstance(value, list):
            return [rewrite(v) for v in value]
        return value
    findings = [rewrite(f) if f["id"].startswith("F-") else
                {k: rewrite(v) if k in LINT_REVIEWED else v for k, v in f.items()} for f in data["findings"]]
    data = {k: v if k in UNTOUCHED else rewrite(v) for k, v in data.items() if k != "findings"}
    data["findings"] = findings
    code = sorted((f for f in data["findings"] if f["id"].startswith("F-")), key=lambda f: render.id_key(f["id"]))
    data["findings"] = code + [f for f in data["findings"] if not f["id"].startswith("F-")]
    return data


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
        # Keep an existing file's permissions; a new one is private, like the rendered outputs.
        mode = stat.S_IMODE(os.stat(str(path)).st_mode) if current is not None else 0o600
        fd, temp = tempfile.mkstemp(prefix="." + path.name + ".", dir=str(path.parent))
        with os.fdopen(fd, "wb") as stream:
            stream.write((json.dumps(data, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temp, mode)
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
    r = sub.add_parser("renumber", help="number F-* findings in severity order, then path and line")
    r.add_argument("findings", type=Path)
    a = p.parse_args(argv)
    if a.cmd == "renumber":
        return main_renumber(a.findings)
    try:
        original = read_regular(a.findings) if os.path.lexists(a.findings) else None
        base = read_json(a.findings, original) if original is not None else {}
        if original is not None:
            try:
                render.validate_data(base)
            except render.SchemaError as e:
                raise render.SchemaError(f"{a.findings}: {e}") from None
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


def main_renumber(path):
    try:
        original = read_regular(path)
        data = render.validate_data(read_json(path, original))
        mapping = renumber_map(data.get("findings", []))
        if all(old == new for old, new in mapping.items()):
            print(f"{path}: F-* findings already in order")
            return 0
        data = renumber(data, mapping)
        render.validate_data(copy.deepcopy(data))
        write_report(path, data, original)
    except (render.SchemaError, MergeConflict, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    moved = ", ".join(f"{old}->{new}" for old, new in sorted(mapping.items()) if old != new)
    print(f"renumbered {path}: {moved}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
