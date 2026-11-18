# logic-scan

An agent skill for a **static, read-only review of your own application's
business logic**: the code that computes prices, tax, entitlements, deadlines,
states and totals. It maps the core flows and the rules each must obey, every
place that implements each rule, where the right answer is stated and the
fixes that already patched a rule, then finds where the code returns a wrong
result on input it will really see — and turns each defect into a
counterexample, a named remedy, the rules that must hold, what enforces them
today, how far the fix reaches, and steps that each leave the build green,
sequenced into a plan of reviewable batches.

> The skill reads source, tests, documentation and, read-only, the git
> history; it does not run the application, its tests or its scripts. The
> one exception is REPRO: on request and with permission, it writes a
> finding's counterexample as a failing test in the repository's own suite
> and runs it. Writing the fix is a separate request (the plan is
> written so an agent or a person can execute it).

## What it does

```
RECON ─► CHECKLIST ─► REVIEW ─► VERIFY ─► PLAN ─► REPORT
 core flows,          defects   reach,       DAG,    findings.json
 rules and every      per unit  counter-     batches ├─ dashboard.html
 implementing site,   + the     example,             ├─ report.md
 oracles, settings,   rules     exposure,            └─ chat summary
 logic rule ledger              enforcement,
                                change
```

- **Recon** builds the logic map: core flows and the rules they obey, every
  site implementing each rule (the rule-backward pass), the oracles that state
  the right answer (specs, ADRs, tests, shared helpers, the majority
  implementation), the settings that change results (time zone, locale,
  rounding, flags), and fix commits on rule code
- **Logic rule ledger** — where this codebase states its rules; defects and
  drift are judged against it, never against a textbook
- **Perspectives** — twelve (boundaries and ranges, conditions and branches,
  null/empty/missing, numbers and money, dates/times/time zones, state and
  lifecycle, collections and aggregation, text/encoding/locale, in-process
  concurrency and ordering, rule duplication and drift, error paths and
  defaults, equality and types) with hunt steps and sound look-alikes
- **Counterexamples** — every High and Medium finding carries one concrete
  input, the expected result, the actual result traced through the code, and
  the oracle that states the expected one
- **Remedies** — each defect maps to a named remedy with preconditions,
  typical steps and the pitfalls of changing a result other code relies on
- **Three axes** — severity is exposure (core flow, realistic input,
  evidence), change is how far the fix reaches (`Local` / `Shared` /
  `Correction`), confidence is how sure the finding is
- **Plan** — `depends_on` forms a DAG; a rule gets one source before the fixes
  that build on it; findings are grouped into batches, each one reviewable
  pull request that leaves the build green

Taste is not the measure: code that reads oddly but returns the right result
is not a finding, and a defect no caller reaches costs nothing.

## Outputs

Every output is rendered from one record, `findings.json`, which the agent
builds from JSON fragments rather than heredocs:

```sh
python3 skills/logic-scan/scripts/findings.py merge out/findings.json frag-001.json
python3 skills/logic-scan/scripts/findings.py renumber out/findings.json  # severity, then path
python3 skills/logic-scan/scripts/render.py out/findings.json --out out   # language: meta.lang
python3 skills/logic-scan/scripts/findings.py check out --repo /path/to/assessed/checkout
python3 skills/logic-scan/scripts/findings.py counts out/findings.json    # n_* summary counts
```

`findings.py check` enforces the run contract: exactly `findings.json`,
`dashboard.html` and `report.md`; gapless `F-NNN` IDs in severity, then path
order; every perspective recorded; High and Medium findings traced, with a
counterexample, exposure, enforcement today, the rules that must hold and
steps; an enforcement record consistent with itself; `change_reason` on every
`Shared` and `Correction` finding; every step saying how it is verified;
`depends_on` without cycles; every open Medium-or-higher finding in exactly
one plan batch after its dependencies, a `Correction` finding alone in its
batch; every inferred rule put to a person in `decisions`; and rendered files
that match a fresh render. It checks shape and consistency, not whether a
finding is true.

## Install

```sh
make link                 # symlink into every installed host's skills dir
make link AGENT=claude    # one host only
make status
make unlink
```

Then invoke `logic-scan` (or `/logic-scan`).

## Layout

```
skills/logic-scan/
  SKILL.md                     phases, run contract, severity/change, decisions, rules
  reference/recon.md           core flows and rules, every site, oracles, settings, fixes, input classes
  reference/conventions.md     the logic rule ledger, trace rows, close-check
  reference/perspectives.md    the twelve perspectives, hunt steps and sound constructs
  reference/remedies.md        remedies, preconditions, steps, preservation pitfalls
  reference/validation.md      verdicts, the five claims, reproducing a counterexample (REPRO)
  reference/plan.md            dependencies, batches, effort, steps, hand-off
  reference/findings-schema.md findings.json shape, merge semantics, what check enforces
  reference/report.md          checklist and findings report formats
  scripts/findings.py          merges fragments; renumbers; checks the run contract (stdlib only)
  scripts/render.py            findings.json -> dashboard.html / report.md (stdlib only)
  scripts/recon.py             git history for RECON: window, churn, fixes (stdlib only)
  scripts/markdown_safe.py     escapes recorded text for Markdown (stdlib only)
  scripts/drafts.py            findings.json -> plan.md and one issue per finding (stdlib only)
  scripts/compare.py           an earlier run vs a later one: new, resolved, persisting; carried
                               Accepted status; --fail-on regression gate (stdlib only)
  scripts/sarif.py             findings.json -> SARIF 2.1.0 for code scanning and IDEs (stdlib only)
  scripts/report_style.py      loads report_assets/dashboard.css, the dashboard stylesheet
  templates/issue.{ja,en}.md   one finding as one issue
  templates/plan.{ja,en}.md    the plan handed to an executor
examples/findings.sample.json  fictional sample for make demo / make check
benchmarks/                    seeded-defect fixtures, their ground truth and score.py
tests/                         offline tests for the scripts and the documents
```

## Development

```sh
make test    # offline unit tests
make check   # tests plus citations resolve, references headed, frontmatter valid,
             # scripts parse,
             # sample renders in ja/en and passes the run contract
make demo    # render the sample into a new private temp dir (LANG_OUT=en for English)
make bench-score FINDINGS=out/findings.json [TRUTH=ground-truth-console.json]
             # score a run on a benchmarks/ fixture: recall, step, decoys flagged
```

The benchmark is run by copying one `benchmarks/fixture-*` directory, alone, into a
fresh git repository, running the skill on it, and scoring the `findings.json`. The
reviewing agent must never see `benchmarks/`, which holds the answers. Both fixtures
are found in full by the current skill, so the benchmark guards against regressions;
it does not measure headroom.

Requirements: Python 3.9+. No third-party packages.

The dashboard uses the stylesheet in
`skills/logic-scan/scripts/report_assets/dashboard.css`, which is maintained in this repository; edit it in place.
