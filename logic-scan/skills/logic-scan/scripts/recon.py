#!/usr/bin/env python3
"""Read a repository's history for RECON: window, hotspots and escaped defects.

    python3 recon.py REPO --out recon-git.json [--since YYYY-MM-DD | --months N]
        [--today YYYY-MM-DD] [--exclude GLOB]... [--source-root PATH]...
        [--fix-pattern REGEX]

Runs only `git rev-parse`, `git rev-list` and `git log`, without external diff
drivers or textconv; nothing in REPO is executed or written. The JSON written to --out holds:

- `head`, `shallow`, `first_commit`: whether the history is usable. A shallow
  clone's first commit is where the clone was cut, not where history starts
- `window`: from --since, or --months back from --today (default 12), to
  --today. When the first commit is later, the whole history is used and
  `whole_history` is true. `value` is what `meta.window` records
- `commits`, `merges`: counts in the window
- `test_file_rule`: the one definition of a test file, used both to leave test
  files out of the hotspots and to decide whether a fix touched a test
- `hotspots`: commits per source file in the window, most first, leaving out
  test files, lock files and --exclude globs, and limited to --source-root
  directories when given. `top_decile` marks the top tenth of those files by
  commits, ties at the cut included
- `fixes`: non-merge commits in the window whose message matches
  --fix-pattern, with the files each changed and `touched_tests`.
  `matched_in` is `body` when only the message body matched: read those
  before citing them
- `warnings`: what makes history evidence weaker (shallow clone, a window
  wider than the history, a history of one commit)

Which fixes are product defects, and which critical flow each belongs to,
stay the reviewer's reading. Exit status: 0 written, 2 invalid arguments or a
git failure.
"""

import argparse
from calendar import monthrange
from datetime import date
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys

FIX_PATTERN = r"(^|[^[:alnum:]])((hot|bug)?fix(e[sd]|ing)?|bugs?)([^[:alnum:]]|$)"

TEST_DIRS = ("test", "tests", "__tests__", "__mocks__", "spec", "e2e", "Tests")
TEST_DIR_SUFFIXES = (".Tests",)
TEST_NAMES = ("*_test.*", "*.test.*", "*.spec.*", "*.test-d.*", "*.cy.*", "*_spec.rb",
              "test_*.py", "conftest.py", "*Test.java", "*Test.kt", "*Tests.swift")
LOCK_NAMES = ("*.lock", "package-lock.json", "pnpm-lock.yaml", "go.sum")

RECORD = "\x1e"
FIELD = "\x1f"


class ReconError(Exception):
    pass


def glob_regex(pattern):
    """A path glob as a regex: `*` and `?` stay inside one segment, `**` spans any."""
    out, i = [], 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("".join(out) + r"\Z")


TEST_NAME_RES = tuple(glob_regex(p) for p in TEST_NAMES)
LOCK_NAME_RES = tuple(glob_regex(p) for p in LOCK_NAMES)


def is_test_file(path):
    *dirs, name = path.split("/")
    if any(d in TEST_DIRS or d.endswith(TEST_DIR_SUFFIXES) for d in dirs):
        return True
    return any(r.match(name) for r in TEST_NAME_RES)


def is_lock_file(path):
    name = path.rsplit("/", 1)[-1]
    return any(r.match(name) for r in LOCK_NAME_RES)


def excluded(path, exclude_res):
    """A glob excludes the path itself or any directory above it."""
    parts = path.split("/")
    prefixes = ["/".join(parts[:n]) for n in range(1, len(parts) + 1)]
    return any(r.match(p) for r in exclude_res for p in prefixes)


def under(path, roots):
    return not roots or any(path == r or path.startswith(r + "/") for r in roots)


def python_pattern(pattern):
    """The git ERE as a Python regex, for telling a subject match from a body match."""
    return re.compile(pattern.replace("[:alnum:]", "0-9A-Za-z"), re.IGNORECASE)


def git(repo, *args):
    env = {**os.environ, "GIT_OPTIONAL_LOCKS": "0", "GIT_PAGER": "cat", "LC_ALL": "C"}
    cmd = ["git", "-C", str(repo), "-c", "core.fsmonitor=false", "-c", "core.quotePath=false",
           *args]
    proc = subprocess.run(cmd, capture_output=True, env=env)
    if proc.returncode:
        message = proc.stderr.decode("utf-8", "replace").strip()
        raise ReconError(f"git {args[0]} failed: {message}")
    return proc.stdout.decode("utf-8", "replace")


def months_before(day, months):
    year, month = divmod(day.year * 12 + day.month - 1 - months, 12)
    month += 1
    return date(year, month, min(day.day, monthrange(year, month)[1]))


def log_records(repo, since, *args):
    """Commits in the window as (hash, date, subject, files), newest first."""
    out = git(repo, "log", f"--since={since}T00:00", "--no-ext-diff", "--no-textconv",
              f"--format={RECORD}%h{FIELD}%cs{FIELD}%s", "--name-only", *args)
    records = []
    for chunk in out.split(RECORD)[1:]:
        header, _, names = chunk.partition("\n")
        commit, day, subject = header.split(FIELD, 2)
        files = [n for n in names.split("\n") if n]
        records.append((commit, day, subject, files))
    return records


def recon(repo, today, since=None, months=12, exclude=(), source_roots=(),
          fix_pattern=FIX_PATTERN):
    if git(repo, "rev-parse", "--is-inside-work-tree").strip() != "true":
        raise ReconError(f"{repo} is not a git working tree")
    warnings = []
    head = git(repo, "rev-parse", "--short", "HEAD").strip()
    shallow = git(repo, "rev-parse", "--is-shallow-repository").strip() == "true"
    if shallow:
        warnings.append("shallow clone: the first commit is where the clone was cut, so history "
                        "before it is missing and a wider window cannot help")
    first_hash, first_day = git(repo, "log", "--reverse", "--format=%h %cs").split("\n", 1)[0].split()
    total = int(git(repo, "rev-list", "--count", "HEAD").strip())
    if total == 1:
        warnings.append("the history is a single commit: escaped-defect and churn evidence is absent")

    start = since or months_before(today, months)
    whole_history = date.fromisoformat(first_day) > start
    if whole_history:
        start = date.fromisoformat(first_day)
        warnings.append(f"the repository is younger than the window: the whole history from "
                        f"{first_hash} ({first_day}) is used")
    since_arg = start.isoformat()

    commits = int(git(repo, "rev-list", "--count", f"--since={since_arg}T00:00", "HEAD").strip())
    merges = int(git(repo, "rev-list", "--count", "--merges", f"--since={since_arg}T00:00",
                     "HEAD").strip())

    exclude_res = [glob_regex(g.rstrip("/")) for g in exclude]
    roots = [r.strip("/") for r in source_roots]
    churn = {}
    for _, _, _, files in log_records(repo, since_arg):
        for path in set(files):
            if is_test_file(path) or is_lock_file(path) or excluded(path, exclude_res):
                continue
            if under(path, roots):
                churn[path] = churn.get(path, 0) + 1
    ranked = sorted(churn.items(), key=lambda kv: (-kv[1], kv[0]))
    cutoff = ranked[math.ceil(len(ranked) / 10) - 1][1] if ranked else None
    hotspots = [{"path": path, "commits": n, "rank": i, "top_decile": n >= cutoff}
                for i, (path, n) in enumerate(ranked, 1)]

    subject_re = python_pattern(fix_pattern)
    fixes = [{"hash": commit, "date": day, "subject": subject, "files": files,
              "touched_tests": any(is_test_file(f) for f in files),
              "matched_in": "subject" if subject_re.search(subject) else "body"}
             for commit, day, subject, files in log_records(
                 repo, since_arg, "-i", "-E", f"--grep={fix_pattern}", "--no-merges")]

    return {
        "head": head,
        "shallow": shallow,
        "first_commit": {"hash": first_hash, "date": first_day},
        "window": {"start": since_arg, "end": today.isoformat(),
                   "value": f"{since_arg}..{today.isoformat()}", "whole_history": whole_history},
        "commits": commits,
        "merges": merges,
        "test_file_rule": {"dirs": list(TEST_DIRS), "dir_suffixes": list(TEST_DIR_SUFFIXES),
                           "names": list(TEST_NAMES)},
        "lock_files": list(LOCK_NAMES),
        "exclude": list(exclude),
        "source_roots": roots,
        "fix_pattern": fix_pattern,
        "source_files": len(ranked),
        "decile_cutoff": cutoff,
        "hotspots": hotspots,
        "fixes": fixes,
        "warnings": warnings,
    }


def iso_date(value):
    try:
        return date.fromisoformat(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{value!r} is not YYYY-MM-DD") from None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("repo", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    window = parser.add_mutually_exclusive_group()
    window.add_argument("--since", type=iso_date, metavar="YYYY-MM-DD")
    window.add_argument("--months", type=int, default=12)
    parser.add_argument("--today", type=iso_date, default=date.today(), metavar="YYYY-MM-DD")
    parser.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                        help="a generated or vendored directory or file glob (`**/dist`, `vendor`)")
    parser.add_argument("--source-root", action="append", default=[], metavar="PATH",
                        help="limit hotspots to these directories (the review units' sources)")
    parser.add_argument("--fix-pattern", default=FIX_PATTERN, metavar="REGEX")
    args = parser.parse_args(argv)
    if args.months < 1:
        parser.error("--months must be at least 1")
    try:
        result = recon(args.repo, args.today, args.since, args.months, args.exclude,
                       args.source_root, args.fix_pattern)
    except ReconError as exc:
        print(f"recon: {exc}", file=sys.stderr)
        return 2
    args.out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    top = sum(h["top_decile"] for h in result["hotspots"])
    untested = sum(not f["touched_tests"] for f in result["fixes"])
    print(f"window {result['window']['value']}: {result['commits']} commits, "
          f"{result['source_files']} source files ({top} in the top decile), "
          f"{len(result['fixes'])} fix commits ({untested} touched no test)")
    for warning in result["warnings"]:
        print(f"warning: {warning}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
