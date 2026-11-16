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
and plan templates read it from there. The commands below take its start as
`<window start>` with a time of day, `2025-10-15T00:00`: a bare date counts
from the current time of day, so it would drop that day's earlier commits.
Check that the history is usable:

```
git rev-parse --short HEAD
git rev-parse --is-shallow-repository
git log --reverse --format='%h %cs' | head -1
git log --since=<window start> --oneline | wc -l
git log --since=<window start> --merges --oneline | wc -l
```

A shallow clone (`true`) holds less history than it shows, and its first
commit is only where the clone was cut: widening the window cannot help, so
treat it as missing history (`SKILL.md`, *Decide first*). In a full clone, a
first commit later than the window start means the repository is younger than
the window: use the whole history, from that commit, and record it in
`meta.window`. A history that is a single import commit, squashed per release,
or migrated without authorship makes every escaped-defect claim
`Environment-dependent` or `Suspected`; say so in the chat's first line.

## 3. Hotspots

**Test files.** The hotspot command below and the escaped-defect command in
§4 share one default definition of a test file, so a file is never a hotspot
in one and a test in the other:

- a file under a directory named `test`, `tests`, `__tests__`, `__mocks__`,
  `spec` or `e2e`, or ending in `.Tests` (a C# test project such as
  `Shop.Tests/`); Java and Kotlin tests sit under `src/test/`, so `test`
  covers them
- a file named `*_test.*` (Go keeps `_test.go` beside the code it tests),
  `*.test.*`, `*.spec.*`, `*.test-d.*`, `*.cy.*`, `*_spec.rb`, `test_*.py` or
  `conftest.py`

Change both commands together when the suite's layout differs.

Churn per source file in the window, excluding generated, vendored and lock
files, and test files (they are read in the test map, §5):

```
git log --since=<window start> --format= --name-only -- . \
  ':(exclude,glob)<generated>/**' ':(exclude,glob)**/*.lock' \
  ':(exclude,glob)**/package-lock.json' ':(exclude,glob)**/pnpm-lock.yaml' \
  ':(exclude,glob)**/go.sum' \
  ':(exclude,glob)**/test/**' ':(exclude,glob)**/tests/**' \
  ':(exclude,glob)**/__tests__/**' ':(exclude,glob)**/__mocks__/**' \
  ':(exclude,glob)**/spec/**' ':(exclude,glob)**/e2e/**' \
  ':(exclude,glob)**/*.Tests/**' \
  ':(exclude,glob)**/*_test.*' ':(exclude,glob)**/*.test.*' \
  ':(exclude,glob)**/*.spec.*' ':(exclude,glob)**/*.test-d.*' \
  ':(exclude,glob)**/*.cy.*' ':(exclude,glob)**/*_spec.rb' \
  ':(exclude,glob)**/test_*.py' ':(exclude,glob)**/conftest.py' \
  | sort | uniq -c | sort -rn | head -50
```

`<generated>` is a glob for each generated or vendored directory, one
pathspec each (`**/dist`, `vendor`), and the pathspec is dropped when there is
none (an empty one makes git stop with `'/**' is outside repository`); a plain `':!dist'` misses
`packages/*/dist` in a monorepo. `*.lock` covers `yarn.lock`, `Cargo.lock`,
`poetry.lock`, `Gemfile.lock`, `composer.lock` and `uv.lock`. `glob` keeps
`*` inside one path segment, so `test_utils/` is not mistaken for a test.

The severity table's Medium row uses hotspots: the top decile of churn
(commits in the window), taken over the source files of the review units: CI,
build configuration, docs and assets are not units, even when they churn
most. To size it, run the command with `-- .` replaced by
`-- <source roots>` and `| head -50` by `| wc -l`, then take the top tenth of
that many files by commits. Record:

| File | Commits in window | Critical flow? | Rank | Top decile? |
|---|---|---|---|---|

Function-level churn, when a hotspot file is large:
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

- **Fix commits**: commits whose message or linked issue marks a fix
  (`git log --since=<window start> -i -E --grep='(^|[^[:alnum:]])((hot|bug)?fix(e[sd]|ing)?|bugs?)([^[:alnum:]]|$)' --no-merges --format='%h %s'`,
  whole words, so `prefix`, `debug` and `fixture` do not count, and no merge
  commit, whose subject names a `fix/` branch rather than a fix,
  adjusted to the repository's convention — conventional commits, issue
  labels). `--grep` searches the whole message, so a commit can match on its
  body while `%s` shows only the subject: read each one (`git show -s
  <hash>`) before citing it, and leave out fixes to docs, typos, CI or tests,
  which are not product defects
- **Fixes that left no test**: for each fix commit, whether its diff touched a
  test file, by the default definition in §3 (the same directories and names
  as the hotspot command's exclusions):

  ```
  git log --since=<window start> -i -E --grep='(^|[^[:alnum:]])((hot|bug)?fix(e[sd]|ing)?|bugs?)([^[:alnum:]]|$)' --no-merges --format=%h \
    | while read -r h; do git show --name-only --format= "$h" | grep -qE '(^|/)(tests?|__tests__|__mocks__|spec|e2e|[^/]+\.Tests)/|_test\.[^/]*$|\.(test|spec|test-d|cy)\.[^/]*$|_spec\.rb$|(^|/)(test_[^/]*\.py|conftest\.py)$' || git log -1 --format='%h %s' "$h"; done
  ```

  Each line printed is a fix that changed no test: an escaped defect with no
  regression test (`reference/perspectives.md`, RP1). Read the fix before
  citing it; a fix whose test lives in another repository or was added in the
  next commit is not one (check the next commits that touch the same files)
- **Escaped defects per flow**: map each printed fix to the critical flow and
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
