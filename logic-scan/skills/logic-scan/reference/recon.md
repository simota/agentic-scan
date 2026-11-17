# Recon — the logic map

**Read when:** RECON, before any unit is reviewed. **Reader:** the agent
running the skill, cold. **Decision it supports:** which units to review
first, which defects can carry exposure, and where each expected result is
stated.

Recon answers four questions for every unit: *what must be right* (core flows,
the rules they obey and every place that implements each rule), *where the
right answer is stated* (the oracles), *what changes the result outside the
code* (time zone, locale, flags, configuration), and *where results already
went wrong* (fix commits on rule code). Record each in scratch; the findings
cite them.

All commands here are read-only. Name each tool before running it. Never run
the application, its tests or its scripts, and never install anything into the
audited repository.

## 1. Stack and units

- Languages, frameworks and the libraries that decide results: money and
  decimal types, date and time libraries, i18n and formatting libraries,
  state machine libraries, validation libraries
- Where business logic lives: services, domain models, use cases, jobs,
  frontend code that computes prices or eligibility, SQL that computes
  results (views, report queries, stored procedures in the repository)
- Generated and vendored directories (out of scope; list them for
  `limitations`)
- Review units: one per top-level module or package on a core flow, plus the
  cross-cutting unit (shared helpers for money, time, text, validation and
  formatting; constants and configuration the rules read)

## 2. Core flows, rules and history window

List the core flows the requester named, and add any the code makes obvious
(checkout, pricing, tax, invoicing, payouts, entitlements and quotas,
inventory, subscriptions and renewals, deadlines, anything billed, audited or
sent to a customer). For each flow, write the rules it must obey as
statements ("tax is per line, rounded down", "a subscription renews on its
billing day in the customer's zone", "a cancelled order is never shipped").

For each rule, find **every place that implements it** by working backward
from the rule: the function named for it, every literal of its parameters
(`grep` the rate, the limit, the status name), every query that filters or
aggregates on it, frontend code that recomputes it, jobs, admin tools and
imports that set the values it reads. This is the rule-backward pass; a rule
is only as right as its least careful copy.

| Flow | Rule | Site (`path:line`) | Role (computes, checks, sets, displays) | Shared helper? |
|---|---|---|---|---|

Fix the history window once (default 12 months, or the whole history if
shorter) and record it in `meta.window` (`2025-10-15..2026-10-15`); the issue
and plan templates read it from there. One read-only script reads the history
for §2, §5 and §6; name it before running it. It runs only `git rev-parse`,
`git rev-list` and `git log`, never the repository's own code:

```
python3 <skill>/scripts/recon.py <checkout> --out <scratch>/recon-git.json \
  [--exclude '**/dist']... [--source-root src]... [--since <window start>]
```

`--exclude` takes one glob per generated or vendored directory (`**/dist`
also finds `packages/*/dist` in a monorepo); `--source-root` limits the churn
rows to the source roots. The JSON stays in scratch: the output directory
holds only what `check` allows.

Read `warnings` and `window` first. `shallow` true means the clone holds less
history than it shows, and its first commit is only where the clone was cut:
widening the window cannot help, so treat it as missing history (`SKILL.md`,
*Decide first*). `whole_history` true means the repository is younger than
the window, and `window.value` already starts at its first commit. Copy
`window.value` into `meta.window` with a fragment. A history that is a single
import commit, squashed per release, or migrated without authorship makes
every fix-commit claim `Suspected`; say so in the chat's first line.

## 3. Oracles — where the right answer is stated

A counterexample needs an expected result someone other than the reviewer
stated. List each source with what it covers, strongest first:

- **Specifications and domain documents** in the repository: product specs,
  pricing and tax notes, ADRs, API documentation with example values
- **Tests that assert a rule**: the cases they cover and, as important, the
  boundary values they do not (a renewal test that freezes time only at noon
  UTC covers no zone boundary)
- **Shared helpers and types** that encode a rule (`Money`, `BillingPeriod`,
  a transition table): the rule is what they do, and a site that bypasses
  them is a candidate
- **The majority implementation**: when four of five sites round per line,
  the fifth is the candidate — an inferred oracle, to confirm in `decisions`
- **Domain facts** that need no source in the repository: calendar rules,
  a currency's minor unit, Unicode equivalence. Name the fact in the oracle

| Rule | Oracle (`path:line` or domain fact) | Kind | Covers boundary values? |
|---|---|---|---|

A rule with no oracle in the repository and no domain fact behind it is
still reviewed, but its findings are at most `Suspected` and the rule goes to
`decisions`.

## 4. Settings that change results

Results depend on more than the code. Record what the repository fixes and
what it leaves to the environment:

- **Time zone**: the server's and the database session's (`TZ` in container
  files, `config.time_zone`, `TIME_ZONE`, `timezone` in connection settings),
  and where each customer's zone is stored
- **Locale and encoding**: default locale, collation, number and date formats
- **Numeric settings**: decimal contexts and rounding modes, currency
  configuration
- **Feature flags** and per-tenant settings that switch a rule, with their
  defaults
- **Library versions** whose behaviour on edge values changed (date libraries,
  decimal libraries), from the lock files

| Setting | Value or "not in the repository" | Source (`path:line`) | Rules it affects |
|---|---|---|---|

A setting the repository does not fix makes a finding that rests on it
`Environment-dependent`.

## 5. Fixes in the window

- **Fix commits** (`fixes` in `recon-git.json`): non-merge commits whose
  message marks a fix, as whole words, so `prefix`, `debug` and `fixture` do
  not count. Pass `--fix-pattern` to follow the repository's convention
  (conventional commits, issue labels). Keep the fixes whose `files` include a
  rule site from §2: those touched rule code. `matched_in: body` means only
  the message body matched: read each fix (`git show -s <hash>`) before
  citing it. A fix that changed a rule's result, or corrected results by hand
  (a refund script, a data correction), is the High evidence: the rule
  already went wrong there
- **Words that mark logic defects** in messages, to widen the search:
  `rounding`, `off by one`, `timezone`, `DST`, `leap`, `month end`, `null`,
  `zero`, `duplicate`, `double`, `wrong total`, `mismatch`, and their
  equivalents in the repository's language
- **A fix applied to one copy of a rule**: for each fix commit, check whether
  the other sites of the same rule (§2) received the same change. One that did
  not is a lead for `Rule duplication and drift`

## 6. Rule-code churn

`hotspots` in `recon-git.json` gives the churn per source file in the window,
most commits first, leaving out lock files (`*.lock`, `package-lock.json`,
`pnpm-lock.yaml`, `go.sum`), the `--exclude` globs and test files. The script
holds one definition of a test file (`test_file_rule` in its output): a file
under a directory named `test`, `tests`, `__tests__`, `__mocks__`, `spec`,
`e2e` or `Tests`, or ending in `.Tests`; or a file named `*_test.*`,
`*.test.*`, `*.spec.*`, `*.test-d.*`, `*.cy.*`, `*_spec.rb`, `test_*.py`,
`conftest.py`, `*Test.java`, `*Test.kt` or `*Tests.swift`. `*` stays inside
one path segment, so `test_utils/` is not a test. When the repository's
layout differs, name the misread files in `limitations` and read them by
hand. Read the rows for the sites in §2: rule code that changes often is
where copies drift. With fewer than about 100 commits in the window
(`commits`), read the fix commits (§5) one by one instead, and skip this
section and function-level churn; say so in scratch.

Function-level churn, when a site's file is large (`<window start>` is
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

## 7. Input classes that occur

Whether the counterexample's input occurs in normal use decides whether a
defect on a core flow is Medium or only Info; High also needs incident
evidence (§5, `SKILL.md`).
Record what the repository shows about real input: fixtures and seeds built
from production samples, documented customer segments (countries, zones,
currencies), supported locales, limits in forms, support notes and FAQs in
the repository, and sizes of real batches. Some classes need no record
because they occur for every customer over time: month ends, leap days, the
first and last day of any period, zero and one, and DST changes where the
customers' zones observe them (Japan's does not).

| Input class | Occurs? | Source (`path:line`, or "calendar") |
|---|---|---|

## 8. Recurring rule implementations

For each recurring concern, how most of the codebase does it, with the count:
range conventions, absence checks, money types and rounding, time zones and
calendar arithmetic, status transitions, aggregation grain, text
normalisation, error handling on core flows. This is the input to the logic
rule ledger (`reference/conventions.md`).

## 9. Output of recon

In scratch: the core-flow and rule table with every implementing site, the
oracle table, the settings table, the unit list in core-flow order, the fix
commits on rule code, the churn rows for rule sites, the input classes, the
rule counts. End by deriving the logic rule ledger.
