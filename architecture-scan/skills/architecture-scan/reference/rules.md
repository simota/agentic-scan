# Rules — derive this codebase's design rules, then hunt their violations

**Read when:** end of RECON (derive the ledger), CHECKLIST (deliver it), REVIEW
(hunt each entry), REPORT (write traces and fix directions). **Reader:** the
agent running the skill, cold. **Decision it supports:** which edges and paths
to trace, and what counts as a violation in *this* codebase.

The design problems that matter are violations of rules this codebase already
states for itself: *the domain does not import the ORM*, *only the billing
module writes invoices*, *every consumer is idempotent*, *controllers call
services, never repositories*, *errors are translated once at the edge*. No
generic rule knows them, so they are written down before the code is judged.
A rule the codebase never adopted is not a rule to hold it to for structure
or change cost; a traced defect (a lost write, a dual write that diverges) is a
finding under the family's `baseline` entry whatever the codebase adopted.

## 1. Derive rules from where the codebase already states them

Strongest first:

1. **Enforced config** — import-lint contracts, module boundaries in the build,
   `internal` packages, visibility modifiers, workspace dependency lists
2. **Documents** — ADRs, architecture docs, README sections, diagrams,
   `CONTRIBUTING`
3. **Structure** — directory layout and naming that every module follows
4. **The majority of modules** — if nine modules go through a repository and
   one writes the table directly, the nine state the rule
5. **Tests** — architecture tests, contract tests, tests that pin a behaviour
   to one module
6. **Comments, reviews, issues** — "do not call X from Y", TODOs about layering

Write each rule with its source (`path:line`). A rule inferred only from
sources 3–6 is marked `inferred`, and the rule itself goes to `decisions` so a
person can confirm the intent. A `baseline` entry (§2) is the exception: it
states a general family rule, not this codebase's intent, so it does not go to
`decisions`.

## 2. The ledger

| ID | Rule | Source | Family | Edges or paths that must keep it | Status |
|---|---|---|---|---|---|

Families:

- **LAYER** — dependencies point in the declared direction; no cycles
- **BOUND** — modules are used through their public surface only
- **OWN** — each core store and each business rule has one owner; others go
  through it
- **TX** — each core flow is consistent under partial failure and retry
- **FAIL** — failures propagate under one error model and are never silently
  dropped on a core flow
- **CONTRACT** — external APIs and events are separate from internal models
  and evolve compatibly
- **SEAM** — time, randomness, I/O and vendors are reachable through a seam
  where the code needs to be tested or replaced

Seed the ledger with one `baseline` entry per family that applies (e.g. `R-01
LAYER baseline: no cycles between top-level modules`), then add codebase-
specific entries. A baseline entry has no document to cite: its `source` is
`baseline`, followed by the module or config that already keeps it when one
does (e.g. `baseline; shared/db.py:12 wraps every write`), and it is
`inferred`. *Status* is `holds`, `violated`, `partly read` or `not
checked` (with a reason):

- `violated` — at least one traced edge breaks the rule; it wins over the others
  even when some edges were not read
- `holds` — every edge found by search was read, and all keep the rule
- `partly read` — some edges were not read and none of those read breaks the
  rule; the count of unread edges goes to `limitations`
- `not checked` — no edge was read; `reason` says why

A `Valid` finding that cites a rule cites one recorded as `violated` (it is a
traced break, so the rule cannot be merely `partly read`); a `Likely` one may
cite a `violated` or `partly read` rule. `check` refuses anything else. The
ledger describes the assessed revision: after a fix, the rule stays
`violated` and the finding's `status` becomes `Fixed`. A defect claim may cite no codebase rule at all
(`reference/validation.md`, claim 4); it then names its family's `baseline`
entry when the ledger has one.

In a checklist deliverable nothing has been hunted yet: the Status column reads
`to trace`, and no `findings.json` is written.

## 3. Trace rows

For each ledger entry, one row per edge, writer or path that must keep it:

| Entry | From (`path:line`) | To (`path:line`) | What crosses | Control | Verdict |
|---|---|---|---|---|---|

- *What crosses*: an import, a call, a write, a message, a shared type
- *Control* names the mechanism that keeps the rule on this edge — a lint
  contract, a facade, a repository that is the only writer, a transaction
  wrapper, an outbox, an idempotency key — at `path:line`, or `NONE`, `N/A`
  (reason) or `UNKNOWN` (what would decide it)
- *Verdict*: `holds`, `violated`, or `lead` (needs VERIFY)

## 4. Close-check per review unit

A unit closes when: every owned entry has rows for every edge or writer found
by search (record the search and its hit count); every *Control* cell is
filled (zero blank); every `lead` is resolved into a finding, a `checked_ok`
line or a `limitations` line. Record the counts (`entries 5, edges 23, rows
23, blank 0`) in scratch.

## 5. From a violated row to a finding

Each finding carries:

- `scenario` — the core flow or change scenario that pays for it
- `blast_radius` — the modules, files, stores or clients it reaches, with
  counts (e.g. "3 modules, 14 import sites; invoices table")
- `trace` — numbered steps: the dependency path, the writers side by side, the
  failure point in the flow, or the walk through a change scenario
- `contrast` — the module or path that keeps the rule, at `path:line`, or
  "none"
- `impact` — expected (the rule) vs actual, and the bounded consequence:
  the defect it allows, or the change cost the history shows
- `rule` — the ledger ID
- `fix` — one line: the rule restored and the smallest change that does it
  (move the write behind the owner's API at `path:line`, add an outbox, invert
  the dependency with an interface in the domain)
- `guard` — at least one fitness function or test that would keep the rule:
  an import contract, a cycle check, a single-writer search in CI, a contract
  test, an idempotency test that delivers the same message twice
