#!/usr/bin/env python3
"""Resolve the change a diff-scoped review covers, and place locations against it.

    diffscope.py scope <repo> [--base REF] [--head REF | --worktree]
                       [--path PATHSPEC]... --out <scratch>/diff.json
    diffscope.py locate <diff.json> <path[:line]>... [--near N] [--json]

`scope` diffs the merge base of BASE and HEAD against HEAD (what a pull request
shows), or against the working tree with --worktree (staged, unstaged and
untracked files). Without --base it uses origin/HEAD, then main, then master.
It writes every changed file with its status and the changed line ranges on the
new side, and prints the `meta.scope` line for the record.

`locate` says, for each location, whether it is on a changed line (`changed`),
in a changed file but not on a changed line (`file`), in a deleted file
(`deleted`) or outside the diff (`outside`).

Read-only: runs only git commands that read the repository. Exit 0 on success,
2 on a usage or git error.
"""
import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

VERSION = 1
HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
STATUS = {"A": "added", "M": "modified", "D": "deleted", "R": "renamed",
          "C": "copied", "T": "typechange"}


class DiffError(Exception):
    pass


def git(repo, *args):
    proc = subprocess.run(["git", "-C", str(repo), "-c", "core.quotePath=false", *args],
                          capture_output=True)
    if proc.returncode != 0:
        detail = proc.stderr.decode("utf-8", "replace").strip()
        raise DiffError(f"git {' '.join(args)} failed: {detail}")
    return proc.stdout.decode("utf-8", "replace")


def ref_exists(repo, ref):
    proc = subprocess.run(["git", "-C", str(repo), "rev-parse", "--verify", "--quiet",
                           f"{ref}^{{commit}}"], capture_output=True)
    return proc.returncode == 0


def default_base(repo):
    proc = subprocess.run(["git", "-C", str(repo), "symbolic-ref", "--quiet", "--short",
                           "refs/remotes/origin/HEAD"], capture_output=True)
    candidates = [proc.stdout.decode().strip()] if proc.returncode == 0 else []
    for ref in candidates + ["main", "master"]:
        if ref and ref_exists(repo, ref):
            return ref
    raise DiffError("no base found (origin/HEAD, main, master): pass --base <ref>")


def name_status(repo, revs, pathspecs):
    out = git(repo, "diff", "--no-ext-diff", "--name-status", "-z", "-M", *revs, "--", *pathspecs)
    parts = out.split("\0")
    entries, i = [], 0
    while i < len(parts) and parts[i]:
        code = parts[i][0]
        if code in "RC":
            entries.append((code, parts[i + 2], parts[i + 1]))
            i += 3
        else:
            entries.append((code, parts[i + 1], None))
            i += 2
    return entries


def hunks(repo, revs, path, old_path):
    paths = [old_path, path] if old_path else [path]
    out = git(repo, "diff", "--no-ext-diff", "--no-color", "--unified=0", "-M", *revs, "--", *paths)
    changed, removed_at, added, removed, binary = [], [], 0, 0, False
    for line in out.splitlines():
        if line.startswith("Binary files "):
            binary = True
        match = HUNK.match(line)
        if not match:
            continue
        old_count = int(match.group(2)) if match.group(2) is not None else 1
        start = int(match.group(3))
        count = int(match.group(4)) if match.group(4) is not None else 1
        removed += old_count
        added += count
        if count:
            changed.append([start, start + count - 1])
        else:
            removed_at.append(start)
    return changed, removed_at, added, removed, binary


def untracked(repo, pathspecs):
    out = git(repo, "ls-files", "--others", "--exclude-standard", "-z", "--", *pathspecs)
    return [p for p in out.split("\0") if p]


def line_count(path):
    try:
        data = path.read_bytes()
    except OSError:
        return 0, False
    if b"\0" in data[:8000]:
        return 0, True
    return data.count(b"\n") + (0 if not data or data.endswith(b"\n") else 1), False


def scope(repo, base=None, head=None, worktree=False, pathspecs=()):
    repo = Path(repo)
    git(repo, "rev-parse", "--git-dir")
    base = base or default_base(repo)
    if not ref_exists(repo, base):
        raise DiffError(f"base {base!r} is not a commit in this repository")
    head_ref = head or "HEAD"
    if not ref_exists(repo, head_ref):
        raise DiffError(f"head {head_ref!r} is not a commit in this repository")
    merge_base = git(repo, "merge-base", base, head_ref).strip()
    head_commit = git(repo, "rev-parse", head_ref).strip()
    revs = [merge_base] if worktree else [merge_base, head_commit]
    files = []
    for code, path, old_path in name_status(repo, revs, list(pathspecs)):
        changed, removed_at, added, removed, binary = hunks(repo, revs, path, old_path)
        files.append({"path": path, "status": STATUS.get(code, code), "old_path": old_path,
                      "binary": binary, "changed": changed, "removed_at": removed_at,
                      "added_lines": added, "removed_lines": removed})
    if worktree:
        known = {f["path"] for f in files}
        for path in untracked(repo, list(pathspecs)):
            if path in known:
                continue
            count, binary = line_count(repo / path)
            files.append({"path": path, "status": "untracked", "old_path": None, "binary": binary,
                          "changed": [[1, count]] if count else [], "removed_at": [],
                          "added_lines": count, "removed_lines": 0})
    files.sort(key=lambda f: f["path"])
    totals = {"files": len(files), "added_lines": sum(f["added_lines"] for f in files),
              "removed_lines": sum(f["removed_lines"] for f in files)}
    head_label = "working tree" if worktree else head_ref
    line = (f"Diff {base}...{head_label} (merge base {merge_base[:12]}"
            + ("" if worktree else f", head {head_commit[:12]}") + f"): {totals['files']} files, "
            f"+{totals['added_lines']}/-{totals['removed_lines']} lines")
    if pathspecs:
        line += f", limited to {', '.join(pathspecs)}"
    return {"tool": "diffscope", "version": VERSION, "base": base, "head": head_label,
            "merge_base": merge_base, "head_commit": None if worktree else head_commit,
            "worktree": worktree, "pathspecs": list(pathspecs), "files": files,
            "totals": totals, "scope": line}


def split_location(text):
    match = re.match(r"^(.*?):(\d+)(?:[-:]\d+)?$", text)
    return (match.group(1), int(match.group(2))) if match else (text, None)


def locate(diff, location, near=0):
    path, line = split_location(location)
    by_path = {f["path"]: f for f in diff["files"]}
    entry = by_path.get(path)
    if entry is None:
        return "outside"
    if entry["status"] == "deleted":
        return "deleted"
    if line is None:
        return "file"
    for start, end in entry["changed"]:
        if start - near <= line <= end + near:
            return "changed"
    for point in entry["removed_at"]:
        if point - near <= line <= point + near + 1:
            return "changed"
    return "file"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    s = sub.add_parser("scope", help="write the changed files and line ranges")
    s.add_argument("repo")
    s.add_argument("--base", help="base branch or commit (default: origin/HEAD, main, master)")
    group = s.add_mutually_exclusive_group()
    group.add_argument("--head", help="head commit (default: HEAD)")
    group.add_argument("--worktree", action="store_true", help="diff against the working tree, untracked files included")
    s.add_argument("--path", action="append", default=[], help="git pathspec to limit the diff (repeatable)")
    s.add_argument("--out", required=True, help="where to write the JSON")
    l = sub.add_parser("locate", help="place locations against a written diff")
    l.add_argument("diff")
    l.add_argument("locations", nargs="+", metavar="path[:line]")
    l.add_argument("--near", type=int, default=0, help="lines of slack around a changed range")
    l.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "scope":
            result = scope(args.repo, args.base, args.head, args.worktree, args.path)
            Path(args.out).write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n",
                                      encoding="utf-8")
            print(result["scope"])
            if not result["files"]:
                print("no changes: nothing to review in diff mode")
            for f in result["files"]:
                print(f"  {f['status']:<10} {f['path']}  +{f['added_lines']}/-{f['removed_lines']}")
        else:
            diff = json.loads(Path(args.diff).read_text(encoding="utf-8"))
            if diff.get("tool") != "diffscope":
                raise DiffError(f"{args.diff} was not written by diffscope.py scope")
            verdicts = {loc: locate(diff, loc, args.near) for loc in args.locations}
            if args.json:
                print(json.dumps(verdicts, ensure_ascii=False, indent=2))
            else:
                for loc, verdict in verdicts.items():
                    print(f"{verdict}\t{loc}")
    except (DiffError, OSError, ValueError) as exc:
        print(f"diffscope: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
