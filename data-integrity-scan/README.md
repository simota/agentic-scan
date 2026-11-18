# data-integrity-scan

An agent skill for a **static, read-only review of your own application's
data layer**: its schema, migrations, transactions and the code that writes
its data. It maps the core tables and every path that writes them, the
schema source of truth, how migrations reach production and the fixes that
already patched data, then finds where data can be corrupted, lost or locked
in production — and turns each hazard into a named remedy with the
invariants that must hold, what enforces them today, how the fix can roll
out, and steps that each leave production working, sequenced into a plan of
reviewable batches.

> The skill reads source, schema files, migrations, deploy configuration and,
> read-only, the git history; it never connects to a database, never runs a
> migration, and does not run the application or its tests. The one
> exception is GUARD: on request and with permission, it runs the migrations
> against a disposable local database, or adds a constraint-violation test to
> the repository's suite, showing the invariant a finding names now holds.
> Writing the fix is a separate request (`coding-implement` takes the plan as
> input).

## What it does

```
RECON ─► CHECKLIST ─► REVIEW ─► VERIFY ─► PLAN ─► REPORT
 core tables,         hazards   reach,      DAG,    findings.json
 every writer,        per unit  exposure,   batches ├─ dashboard.html
 schema, migrations,  + the     enforcement ├─ report.md
 deploy order,        invariants today,     └─ chat summary
 data rule ledger               rollout
```

- **Recon** builds the data map: core tables and every writer of each (the
  writer-backward pass), the schema source of truth, the migration tool and
  how migrations run in deploy, fix commits that touched data code,
  migrations changed in the window, and table size hints the repository
  records
- **Data rule ledger** — where this codebase states its data rules (schema
  constraints, ORM validations, migration conventions, ADRs, the majority
  pattern); fixes and drift are judged against it, never against a textbook
- **Perspectives** — twelve (schema constraints, application-only invariants,
  migration locking and rewrites, irreversible and destructive changes,
  deploy compatibility, backfills and data migrations, transaction
  boundaries, concurrency and lost updates, deletion and cascades, types and
  precision, keys and identity, backup and restore assumptions) with hunt
  steps and sound look-alikes
- **Remedies** — each hazard maps to a named remedy with preconditions,
  typical steps and the per-engine pitfalls of rolling it out
- **Three axes** — severity is exposure (core table, realistic path,
  evidence), rollout is how the fix reaches production (`Online` /
  `Staged` / `Downtime`), confidence is how sure the finding is
- **Plan** — `depends_on` forms a DAG; writer fixes and cleanups come before
  the constraints that would refuse them; findings are grouped into batches,
  each one reviewable pull request that leaves production working

A missing constraint is not the measure: a constraint no write path could
violate is not a finding, and a hazard on data nobody depends on costs
little.

## Outputs

Every output is rendered from one record, `findings.json`, which the agent
builds from JSON fragments rather than heredocs:

```sh
python3 skills/data-integrity-scan/scripts/findings.py merge out/findings.json frag-001.json
python3 skills/data-integrity-scan/scripts/findings.py renumber out/findings.json  # severity, then path
python3 skills/data-integrity-scan/scripts/render.py out/findings.json --out out   # language: meta.lang
python3 skills/data-integrity-scan/scripts/findings.py check out --repo /path/to/assessed/checkout
python3 skills/data-integrity-scan/scripts/findings.py counts out/findings.json    # n_* summary counts
```

`findings.py check` enforces the run contract: exactly `findings.json`,
`dashboard.html` and `report.md`; gapless `F-NNN` IDs in severity, then path
order; every perspective recorded; High and Medium findings traced, with
exposure, enforcement today, the invariants that must hold and steps; an
enforcement record consistent with itself and with the rollout (a `Downtime`
finding names what forces the maintenance window); every step saying how it
is verified; `depends_on` without cycles; every open Medium-or-higher finding
in exactly one plan batch after its dependencies, a `Downtime` finding alone
in its batch; every inferred rule put to a person in `decisions`; and
rendered files that match a fresh render. It checks shape and consistency,
not whether a finding is true.

## Install

```sh
make link                 # symlink into every installed host's skills dir
make link AGENT=claude    # one host only
make status
make unlink
```

Then invoke `data-integrity-scan` (or `/data-integrity-scan`).

## Layout

```
skills/data-integrity-scan/
  SKILL.md                     phases, run contract, severity/rollout, decisions, rules
  reference/recon.md           core tables and writers, schema, migrations, deploy order, fixes, sizes
  reference/conventions.md     the data rule ledger, trace rows, close-check
  reference/perspectives.md    the twelve perspectives, hunt steps and sound constructs
  reference/remedies.md        remedies, preconditions, steps, per-engine rollout pitfalls
  reference/validation.md      verdicts, the four claims, proving an invariant (GUARD)
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

The record format, scripts and run contract are forked from the sibling
`test-gap-scan` skill (itself forked from `refactor-scan`: same verdicts, plan
model and report shape), adapted to data-layer review. The dashboard uses
[scan-report-kit](https://github.com/simota/scan-report-kit), whose copy in
`skills/data-integrity-scan/scripts/scan_report_kit/` is maintained in this repository (scan-report-kit is retired); edit it in place.
