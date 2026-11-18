# Recon — the risk map

**Read when:** RECON, before any unit is reviewed. **Reader:** the agent
running the skill, cold. **Decision it supports:** which units to review
first, which gaps can carry exposure, and how directly a test could reach
each behaviour.

Recon answers four questions for every unit: *what must not break* (critical
flows), *where defects already escaped* (fix commits that touched no test),
*what the tests check today* (the test map), and *what actually runs* (the
runner and CI). Record each in scratch; the findings cite them.

All commands here are read-only. Name each tool before running it. Never
install anything into the audited repository, never run the application or
its tests.

## 1. Stack and units

- Languages, build system, package or module layout, workspace members
- Test frameworks and runners per language, and their configuration files
  (`pytest.ini`, `pyproject.toml`, `jest.config.*`, `vitest.config.*`,
  `go test` build tags, `build.gradle` test tasks)
- Generated and vendored directories (out of scope; list them for
  `limitations`)
- Review units: one per top-level module or package with its tests, plus the
  cross-cutting unit (shared fixtures, test helpers, test configuration, CI)

## 2. Critical flows and history window

List the critical flows the requester named, and add any the code makes
obvious (money movement, authentication and permissions, data deletion,
anything with an audit log). For each, its entry points at `path:line`
(routes, handlers, jobs, CLI commands) and the modules it passes through:

| Flow | Entry points | Modules | Named by |
|---|---|---|---|

Fix the history window once (default 12 months, or the whole history if
shorter) and record it in `meta.window` (`2025-10-15..2026-10-15`); the issue
and plan templates read it from there. One read-only script reads the history
for §2 to §4; name it before running it. It runs only `git rev-parse`,
`git rev-list` and `git log`, never the repository's own code:

```
python3 <skill>/scripts/recon.py <checkout> --out <scratch>/recon-git.json \
  [--exclude '**/dist']... [--source-root src]... [--since <window start>]
```

`--exclude` takes one glob per generated or vendored directory (`**/dist`
also finds `packages/*/dist` in a monorepo); `--source-root` limits the
hotspots to the review units' source roots, so CI, build configuration, docs
and assets never fill the top decile. The JSON stays in scratch: the output
directory holds only what `check` allows.

Read `warnings` and `window` first. `shallow` true means the clone holds less
history than it shows, and its first commit is only where the clone was cut:
widening the window cannot help, so treat it as missing history (`SKILL.md`,
*Decide first*). `whole_history` true means the repository is younger than
the window, and `window.value` already starts at its first commit. Copy
`window.value` into `meta.window` with a fragment. A history that is a single
import commit, squashed per release, or migrated without authorship makes
every escaped-defect claim `Environment-dependent` or `Suspected`; say so in
the chat's first line.

## 3. Hotspots

**Test files.** The script holds one definition of a test file
(`test_file_rule` in its output) and uses it both to leave tests out of the
hotspots and to decide whether a fix touched a test (§4), so a file is never a
hotspot in one and a test in the other: a file under a directory named `test`,
`tests`, `__tests__`, `__mocks__`, `spec`, `e2e` or `Tests`, or ending in
`.Tests` (a C# test project); or a file named `*_test.*`, `*.test.*`,
`*.spec.*`, `*.test-d.*`, `*.cy.*`, `*_spec.rb`, `test_*.py`, `conftest.py`,
`*Test.java`, `*Test.kt` or `*Tests.swift`. `*` stays inside one path segment,
so `test_utils/` is not a test. When the suite's layout differs, name the
misread files in `limitations` and read them by hand. Lock files (`*.lock`,
`package-lock.json`, `pnpm-lock.yaml`, `go.sum`) are never hotspots.

`hotspots` lists every source file changed in the window, most commits first.
The severity table's Medium row uses `top_decile`: the top tenth of those
files by commits, ties at the cut included (`decile_cutoff`). Record:

| File | Commits in window | Critical flow? | Rank | Top decile? |
|---|---|---|---|---|


Function-level churn, when a hotspot file is large (`<window start>` is
`window.start` with a time of day, `2025-10-15T00:00`: a bare date counts from
the current time of day, so it would drop that day's earlier commits):
`n=$(git log --since=<window start> -s -L :<function>:<file> --format=%h) && printf '%s\n' "$n" | grep -c .`
(`-s` drops the diff, which would otherwise be counted line by line; git 2.22
or later honours it with `-L`). A `fatal: ... no match` prints no count: the
function was not measured, which is not zero commits. `:<function>` finds a
definition only where git knows the language or the line starts with a
letter, and takes the first such line naming it, so it misses indented
methods (JavaScript, TypeScript, Ruby without a diff driver) and can land on
an `import { name }` line, a Python docstring line or a longer name that
contains it (`merge` finds `_merge_records`). Anchor a top-level definition
with its own keyword instead (`-L ':^def <function>(:<file>'` in Python,
`-L ':^func <function>(:<file>'` in Go). For an indented one, give the range:
`-L <start>,<end>:<file>` (Python, which has no closing brace) or
`-L '/^<indent><function>(/,/^<indent>}/:<file>'`, where `<indent>` is the
definition's own indentation, so the range ends at its closing brace and not
at a nested block's.

## 4. Escaped defects

- **Fix commits** (`fixes`): non-merge commits whose message marks a fix,
  as whole words, so `prefix`, `debug` and `fixture` do not count. Pass
  `--fix-pattern` to follow the repository's convention (conventional
  commits, issue labels). `matched_in: body` means only the message body
  matched: read each fix (`git show -s <hash>`) before citing it, and leave
  out fixes to docs, typos, CI or tests, which are not product defects
- **Fixes that left no test**: a fix with `touched_tests: false` changed no
  test file by the definition in §3: an escaped defect with no regression test
  (`reference/perspectives.md`, RP1). Read the fix before citing it; a fix
  whose test lives in another repository or was added in the next commit is
  not one (check the next commits that touch the same `files`)
- **Escaped defects per flow**: map each such fix to the critical flow and
  the file it changed; these hashes are the High evidence

## 5. The test map and the runner

**Test map** — for each critical-flow branch and hotspot behaviour, which
tests reach it and what they check:

| Behaviour (`path:line`) | Tests (`path:line`) | Level (unit / integration / contract / e2e) | Doubles used | What is asserted | Gaps |
|---|---|---|---|---|---|

Find tests by import, by name convention and by fixture use; tests in the
same package (Go, and Java's same-package tests) import nothing, so match them
by test name and by the entry point they drive. A test that only constructs
the unit, asserts a status code, or snapshots output unrelated to the
behaviour reaches it without checking it: record it under *What is asserted*
as such. An existing coverage report file in the repository may be read;
never run the suite to produce one.

**Runner and CI** — what actually runs:

- The test command per suite (`Makefile`, package scripts, `tox.ini`), the
  discovery patterns and the directories they cover
- Markers, tags or filters that exclude tests (`-m "not slow"`, build tags,
  `testPathIgnorePatterns`)
- The CI jobs that run each suite, whether a failure fails the job
  (`continue-on-error`, allowed failures, a discarded exit status), and
  whether the job is required where the repository documents it
- Rerun and retry settings (`--reruns`, `retries`, `flaky` markers)
- Skipped and quarantined tests with their stated reasons (`skip`, `xfail`,
  `@Ignore`, `t.Skip`, `.only`)

## 6. Recurring test idioms

For each recurring concern, how most of the suite does it, with the count:
fixtures and setup, test doubles, the clock and randomness, test data
(factories, builders, fixture files), assertion style, isolation (database
reset, temp directories), the runner and its markers. This is the input to
the test idiom ledger (`reference/conventions.md`).

## 7. Output of recon

In scratch: the critical-flow table, the unit list in critical-flow then
hotspot order, the hotspot table, the fix commits that changed no test, the
test map, the runner and CI notes, the idiom counts. End by deriving the
test idiom ledger.
