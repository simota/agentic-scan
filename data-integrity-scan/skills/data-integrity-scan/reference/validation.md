# Validation — is each hazard real, does it matter, and how does the fix ship?

**Read when:** VERIFY, for every finding before it reaches the report; GUARD,
for what a proven invariant may and may not establish.

A missing constraint or a reviewer's taste is a hypothesis. Keep the recorded
verdict in `validation` (`reference/findings-schema.md`). Severity, rollout,
confidence, verdict and verification basis are separate axes. Nothing is
deleted: a finding judged false stays in the record with its exclusion and
evidence.

## Verdicts

| Verdict | Meaning | Who may set it |
|---|---|---|
| `Valid` | The hazard is traced on code or migrations that will run, the condition that triggers it is shown to occur — the writers that can break the invariant with none enforcing it on every path (integrity hazards), the deploy path that runs the migration and the table's size (locking and rewrites), the deploy order (compatibility), the data a step removes or rewrites (backfills, irreversible changes), the restore path the repository relies on (backup) — and the exposure its severity claims follows from the core tables, the write paths, the repository's size and deploy records or recorded history (an `Info` finding claims none) | Agent or person, with evidence |
| `Likely` | Strong signals, one necessary link not yet confirmed (a constraint may live in another repository's migrations, one writer unread, the deploy order not in the repository) | Agent or person |
| `Unverified` | Not yet examined | Agent or person: the verdict a finding starts with, always recorded explicitly |
| `Unlikely` | Signals point away, but the claim has not been ruled out | Agent or person |
| `FalsePositive` | Evidence contradicts the claim (a constraint added in a later migration enforces it; the only writer locks the row) | Agent or person, with evidence |
| `NotApplicable` | A fix here has no point (a table nothing writes or reads — a `prune-scan` item; a table scheduled for removal with a date; generated code) | Agent or person, with evidence |

`Valid`, `FalsePositive` and `NotApplicable` require nonblank
`validation.evidence` citing `path:line`; a duplicate marked `NotApplicable`
may instead be only the name of the finding it repeats (`Duplicate of F-004`,
`重複: F-004`), when that finding is itself not excluded.

## Four claims for every finding

1. **Reach** — the write path runs: registered, imported, reachable from an
   entry point, a job or a deploy step. Search for its name as a string in
   config, schedulers, routes and deploy scripts before calling it dead. A
   table nothing writes is `NotApplicable`
2. **Exposure** — a hazard here costs: the core table it sits on, the write
   paths that reach it, fix commits by hash that patched its data, the
   table's size where the repository records it, the deploy order. Read each
   fix commit before counting it; a fix to docs or tests is not a data
   incident. Without usable history or a named core table, confidence is
   `Environment-dependent` or `Suspected`, never `Confirmed`
3. **Enforcement today** — everything that enforces the invariant, found in
   the schema source of truth, the migrations, the models and every writer
   from the writer-backward pass, at `path:line`. A check on some write paths
   only, or only in application code, is `net: partial`, and the paths it
   misses go in `enforcement.gaps`. This and the invariants decide the remedy
4. **Rollout** — whether the fix ships as one migration or change while
   traffic runs (`Online`, with the pitfalls in `reference/remedies.md` ruled
   out for the engine and version the repository targets), over several
   deploys (`Staged`), or only in a maintenance window (`Downtime`). A
   `Staged` or `Downtime` finding names in `rollout_reason` what forces the
   stages or the window

## Falsification

Try to disprove each High and Medium finding before recording it `Valid`:
search every migration, including later ones, for a constraint that already
enforces the invariant; search for every writer of the table, including
scripts, jobs, admin tools and other services; check whether a lock, a
version column or a unique key elsewhere makes the race impossible; check
whether the deploy runs migrations in an order that removes the window;
check whether the table is small or being retired. Record the check, the
observation and any counterevidence. A second reviewer re-reads High
findings when the host can run one; otherwise say so in `limitations`.

## Static support and analysis

`validation.method: "static"` — established by reading. It does not mean
anything was executed.

`analysed` requires a recorded `analysis` with the tool, the command and the
result. Allowed analysis is read-only and local: `git log`, `git show` and
`git blame` queries, a schema dump or migration linter output already in the
repository read as is, a migration linter run on the migration files without
a database connection where the tool offers one. Name the tool before running
it. Never connect to a database, never run migrations, the application or its
test suite, never install packages, never contact external services.

## Proving an invariant (GUARD)

With explicit permission, GUARD shows that the invariant a finding names now
holds: it runs the repository's migrations against a disposable local
database, or adds a constraint-violation test to the repository's own suite.
Running either executes the repository's own code (migration files,
`conftest.py`, package scripts, build hooks): ask for permission saying so,
and run it in a sandbox without credentials or network where one is
available. Never point it at a shared or production database. Each proof:

- uses a database created for the proof and discarded after it, never one
  that holds real data
- shows the bad write refused, or the race lost safely, after the fix (an
  order for a missing customer refused, two concurrent debits leaving one
  refusal), and shows the same write accepted on a scratch copy without the
  fix; the copy is discarded, never committed
- follows the codebase's data rules (`reference/conventions.md`), is
  deterministic and names the finding (`F-…`) it proves

Record it with one fragment that marks the finding `Fixed`, updates what now
enforces it, and keeps the rest of the record on the assessed revision:
`{"findings": [{"id": "F-002", "status": "Fixed", "enforcement": {"net": "enforced", "sites": ["app/jobs/merge_customers_job.rb:14"], "gaps": "none; transaction added and proved by GUARD on a disposable database at 8ab40fc, a raise between the writes left both customers unchanged"}}], "meta": {"method": "Static review; git log 12 months; GUARD: merge transaction for F-002 proved on a disposable database at 8ab40fc"}}`
(`meta.method` is replaced whole, so it repeats what it said before; each
enforcement site is cited at its constraint's or transaction's line).
Then render and check again.

`status: Fixed` records that the work was done: a fix written by
`coding-implement`, a person, or proved by GUARD. `status: Accepted` records
that a person chose to leave the hazard as it is; only they set it, and
`decisions` names the finding, who decided and why. Neither needs a plan
batch.

## Reporting and limits

- Headline totals exclude `FalsePositive` and `NotApplicable`; exclusions stay
  visible with their evidence
- State the `Unverified` and `Likely` counts separately from `Valid`
- Schema checks prove structure, not truth; zero findings is not evidence
  that the data cannot be corrupted, lost or locked, and no migration was run
  by this review unless GUARD ran it on a disposable database
