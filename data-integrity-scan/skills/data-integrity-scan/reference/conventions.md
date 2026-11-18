# Conventions — the data rule ledger, trace rows and close-check

**Read when:** end of RECON (derive the ledger), CHECKLIST (deliver it),
REVIEW (hunt each entry and close each unit). **Reader:** the agent running
the skill, cold. **Decision it supports:** what rules this codebase already
states for its data, what counts as drift, and when a review unit is done.

A data rule the codebase states and every writer follows is cheap to rely on;
a writer that follows another rule (its own raw SQL beside the model, a float
where every other amount is decimal, a migration that builds an index the
blocking way when the rest build it online) is where data goes wrong first.
Drift is judged only against the codebase's own rules. A practice this
codebase never adopted is not a rule to write towards.

## 1. Derive rules from where the codebase states them

Strongest first:

1. **Enforced in the schema or tooling** — constraints in the schema source of
   truth, migration linters (`strong_migrations`, `squawk`, `django-pg-zero-
   downtime-migrations`), database settings committed in the repository
2. **Documents** — ADRs, migration guides, `CONTRIBUTING`, runbooks, README
   sections on the database
3. **The majority** — if 9 money columns are `decimal(12,2)` and one is
   `float`, the 9 state the rule; record the counts
4. **Recent direction** — a change in progress (every table created in the
   last months uses `bigint` keys, every recent migration sets a lock
   timeout)
5. **Comments, reviews, issues** — "never delete customers", TODOs naming the
   target

A rule from sources 3–5 only is `inferred`, and goes to `decisions` so a
person can confirm the intended direction before any fix is written towards
it.

## 2. The ledger

| ID | Rule | Source | Concern | Units that must follow it | Status |
|---|---|---|---|---|---|

The record keeps the rule in the `idiom` field, the key every scan's ledger
shares. Concerns: `SCHEMA` (keys, constraints, nullability, references),
`MIGRATION` (how migrations are written and run: online index builds,
timeouts, expand and contract, reversibility), `TRANSACTION` (where
transactions begin and end, side effects after commit), `LOCKING` (row locks,
version columns, idempotency keys), `VALIDATION` (where invariants are checked
and by what), `DELETION` (hard or soft delete, cascades, archival), `TYPES`
(money, time, text lengths, character sets), `OTHER`. *Status*:

- `drifted` — at least one traced site follows another rule with exposure
  (a core table, a fix commit, a large table)
- `holds` — every site found by search was read and follows it, or deviates
  only where the drift has no exposure (variant and count in `checked_ok`)
- `partly read` — some sites were not read, none read drifts; the count goes
  to `limitations`
- `not checked` — no site was read; `reason` says why

Every `drifted` entry is cited in the `convention` of a `Valid` or `Likely`
finding; a `Valid` finding cites only `drifted` entries. Drift on non-core
data without evidence may be a Low finding; drift with no exposure at all
stays `holds` with the variant and its count in `checked_ok`, not a finding.

In a checklist deliverable nothing has been hunted: Status reads `to trace`.

## 3. Trace rows

For each entry, one row per site:

| Entry | Site (`path:line`) | Variant | Core table? | Verdict |
|---|---|---|---|---|

*Variant* names the way this site does it (`decimal(12,2)`, `float`,
`algorithm: :concurrently`, `blocking index`). *Verdict*: `follows`,
`drifts`, or `lead`.

For each hazard found during the perspective sweep, record one row too:

| Step | Site (`path:line`) | Hazard | Exposure evidence | Remedy | Invariant | Verdict |
|---|---|---|---|---|---|---|

## 4. Close-check per review unit

A unit closes when: every core table in the unit has a writer row for each
write path found (`reference/recon.md` §2); every owned ledger entry has a row
per site found by search (record the search and its hit count); every
applicable perspective's hunt steps were applied or left out with a reason;
every hazard row has *Exposure evidence* filled (the table, hashes or counts,
or `none` — which caps the finding at `Info`); every `lead` is resolved into a
finding, a `checked_ok` line or a `limitations` line. Record the counts
(`tables 4, writers 17, entries 5, sites 31, hazards 6, blank 0`) in scratch.
