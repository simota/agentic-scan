# test-gap-scan

An agent skill for a **static, read-only review of your own application's
test suite**. It maps the critical flows, the defects that already escaped,
the hotspots and what each test actually checks, then finds where a defect
would reach production without a test failing — and turns each gap into a
named remedy with the outcomes the test must assert, how directly a test can
reach the behaviour, and green steps, sequenced into a plan of reviewable
batches.

> The skill reads source, tests, CI configuration and, read-only, the git
> history; it does not write tests, does not run the suite and does not run
> the application. The one exception is GUARD: on request and with
> permission, it adds the tests a finding names to the repository's suite,
> runs them, and shows each one fails with the behaviour broken. Writing the
> tests is a separate request; the plan is written so an agent or a person can
> execute it.

## What it does

```
RECON ─► CHECKLIST ─► REVIEW ─► VERIFY ─► PLAN ─► REPORT
 critical flows,      gaps      reach,    DAG,    findings.json
 escaped defects,     per unit  exposure, batches ├─ dashboard.html
 test map, runner,    + what    tests     ├─ report.md
 idiom ledger         to assert today,    └─ chat summary
                                testability
```

- **Recon** builds the risk map: critical flows and their entry points,
  hotspots, fix commits whose change touched no test, the test map (which
  test reaches which behaviour, at which level, with which doubles, asserting
  what), and what the runner and CI actually run
- **Test idiom ledger** — how this suite already handles fixtures, doubles,
  the clock, test data, assertions, isolation and the runner; new tests and
  drift are judged against it, never against a textbook
- **Perspectives** — twelve (untested critical paths, error and edge cases,
  assertion strength, mock fidelity, nondeterminism and flakiness, isolation
  and shared state, integration and contract seams, test level balance,
  regression pinning, test data and fixtures, disabled and skipped tests,
  suite execution in CI) with hunt steps and sound look-alikes
- **Remedies** — each gap maps to a named remedy with preconditions, typical
  steps and the pitfalls of adding a seam
- **Three axes** — severity is exposure (critical flow, escaped defects),
  testability is how directly a test reaches the behaviour (`Direct` /
  `Seam` / `Restructure`), confidence is how sure the finding is
- **Plan** — `depends_on` forms a DAG; seams and fakes come before the tests
  that use them; findings are grouped into batches, each one green,
  reviewable pull request

Coverage percentage is not the measure: a line run by a test that asserts
nothing is untested, and an uncovered line no flow needs is not a finding.

## Outputs

Every output is rendered from one record, `findings.json`, which the agent
builds from JSON fragments rather than heredocs:

```sh
python3 skills/test-gap-scan/scripts/findings.py merge out/findings.json frag-001.json
python3 skills/test-gap-scan/scripts/findings.py renumber out/findings.json  # severity, then path
python3 skills/test-gap-scan/scripts/render.py out/findings.json --out out   # language: meta.lang
python3 skills/test-gap-scan/scripts/findings.py check out --repo /path/to/assessed/checkout
python3 skills/test-gap-scan/scripts/findings.py counts out/findings.json    # n_* summary counts
```

`findings.py check` enforces the run contract: exactly `findings.json`,
`dashboard.html` and `report.md`; gapless `F-NNN` IDs in severity, then path
order; every perspective recorded; High and Medium findings traced, with
exposure, the tests today, the outcomes to assert and steps; a coverage
record consistent with itself and with testability (a `Restructure` finding
names what blocks the test); every step saying how it is verified;
`depends_on` without cycles; every open Medium-or-higher finding in exactly
one plan batch after its dependencies, a `Restructure` finding (the
production restructuring only; its tests are a dependent finding) alone in its
batch; every inferred idiom put to a person in `decisions`; and rendered files
that match a fresh render. It checks shape and consistency, not whether a
finding is true.

## Install

```sh
make link                 # symlink into every installed host's skills dir
make link AGENT=claude    # one host only
make status
make unlink
```

Then invoke `test-gap-scan` (or `/test-gap-scan`).

## Layout

```
skills/test-gap-scan/
  SKILL.md                     phases, run contract, severity/testability, decisions, rules
  reference/recon.md           critical flows, hotspots, escaped defects, test map, runner and CI
  reference/conventions.md     the test idiom ledger, trace rows, close-check
  reference/perspectives.md    the twelve perspectives, hunt steps and sound constructs
  reference/remedies.md        remedies, preconditions, steps, seam pitfalls
  reference/validation.md      verdicts, the four claims, proving a test (GUARD)
  reference/plan.md            dependencies, batches, effort, steps, hand-off
  reference/findings-schema.md findings.json shape, merge semantics, what check enforces
  reference/report.md          checklist and findings report formats
  scripts/findings.py          merges fragments; renumbers; checks the run contract (stdlib only)
  scripts/render.py            findings.json -> dashboard.html / report.md (stdlib only)
  scripts/recon.py             git history for RECON: window, hotspots, fixes (stdlib only)
  scripts/markdown_safe.py     escapes recorded text for Markdown (stdlib only)
  scripts/drafts.py            findings.json -> plan.md and one issue per finding (stdlib only)
  scripts/scan_report_kit/     bundled report kit
  templates/issue.{ja,en}.md   one finding as one issue
  templates/plan.{ja,en}.md    the plan handed to an executor
examples/findings.sample.json  fictional sample for make demo / make check
tests/                         offline tests for the scripts and the documents
```

## Development

```sh
make test    # offline unit tests
make check   # tests plus citations resolve, references headed, frontmatter valid,
             # scripts parse,
             # sample renders in ja/en and passes the run contract
make demo    # render the sample into a new private temp dir (LANG_OUT=en for English)
```

Requirements: Python 3.9+. No third-party packages.

The dashboard uses the report kit bundled under
`skills/test-gap-scan/scripts/scan_report_kit/`, which is maintained in this repository; edit it in place.
