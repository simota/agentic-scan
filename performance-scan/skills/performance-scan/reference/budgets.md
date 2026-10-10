# Budgets — derive this app's bounds, then hunt their violations

**Read when:** end of RECON (derive the ledger), CHECKLIST (deliver it), REVIEW
(hunt each entry), REPORT (write reproduction steps). **Reader:** the agent
running the skill, cold. **Decision it supports:** which paths to trace and
what counts as a violation in *this* application.

The problems generic tools miss are violations of bounds that exist only in
this application: *the order list answers within the gateway timeout for the
largest tenant*, *a dashboard costs a constant number of queries*, *the nightly
sync finishes before the next run*, *the initial bundle stays under the CI
budget*. No default rule knows them, so they are written down before the code
is judged.

## 1. Derive budgets from where the app already states them

A budget is a sentence that must stay true for every workload as the scale
drivers grow. Derive it from evidence in the repository, strongest first:

1. **Stated targets** — SLO documents, CI performance budgets, load-test
   thresholds, query-count tests
2. **Hard limits** — request, job and gateway timeouts; container memory;
   pool sizes; plan limits; body and upload limits. Confirm what a timeout
   bounds: Node's `server.requestTimeout` and `headersTimeout` bound receiving
   the request only, and Express has no handler deadline
3. **The majority of handlers** — if nine list endpoints paginate and one does
   not, the nine state the bound and the one breaks it
4. **Data model** — caps on child counts, unique constraints, indexes that show
   which access paths were meant to be fast
5. **Client behaviour** — polling intervals, infinite scroll page sizes,
   debounce settings
6. **Docs, comments, issues** — "this must stay fast", known-slow notes

Write each budget with its source (`path:line`). A budget inferred only from
sources 3–6 is marked `inferred`, and the bound itself goes to `decisions` so a
person can confirm it. Budgets from sources 1–2 are not `inferred`.

## 2. The ledger

| ID | Budget | Source | Family | Paths that pay it | Status |
|---|---|---|---|---|---|

Families:

- **QRY** — queries per request are constant, or bounded by page size, not by
  a scale driver
- **SIZE** — results, responses, exports and in-memory collections are bounded
- **CPLX** — work per request is at most linear (or `n log n`) in a bounded
  input
- **LAT** — no hot path waits on avoidable sequential or blocking I/O, and
  every wait has a timeout below the caller's
- **RES** — shared resources (pools, locks, event loop, memory) are held
  briefly and released on every path
- **FE** — front-end payload and main-thread work stay within budget

Seed the ledger with one `baseline` entry per family that applies (e.g. `B-01
QRY baseline: every hot list endpoint issues a constant number of queries`; for
jobs, `QRY baseline: jobs issue queries per batch, not per row`),
then add app-specific entries. A baseline entry uses `source: "baseline"` plus
any supporting `path:line` and `inferred: false`, and is never a decision: code
that contradicts it is a finding. Only inferred bounds go to `decisions`.
*Status* is `holds`, `violated`, `partly read`
or `not checked` (with a reason).

## 3. Cost-trace rows

For each ledger entry, one row per path that pays it and scale driver that path
iterates; a path with constant cost gets one row with Driver `none`. A branch
inside a handler that costs differently (e.g. key vs session auth) is a separate
path. Costs paid in shared middleware ("every route through X") get their rows
in the cross-cutting unit, and domain units cite those rows:

| Entry | Path | Driver | Hops (entry → loop → sink, `path:line`) | Cost | Mitigation | Verdict |
|---|---|---|---|---|---|---|

- *Cost* is a formula in the driver: `1 + N` queries, `N × M` comparisons,
  `N` sequential HTTP calls, whole file in memory
- *Mitigation* names the cap, eager load, index, batch, cache or timeout at
  `path:line`, or `NONE`, `N/A` (reason) or `UNKNOWN` (what would decide it).
  Inherited mitigations (base query, default scope, serializer prefetch,
  middleware) count only with their `path:line`
- *Verdict*: `holds`, `violated`, or `lead` (needs VERIFY)

## 4. Review units and close-check

Group the workload inventory by domain, plus one cross-cutting unit (DB and
HTTP client setup, middleware, caching layer, runtime and build config). A
ledger entry belongs to every unit that has a path paying it: each unit writes
rows only for its own paths, and the coordinator sets the entry's status from
all units' rows. With subagents, one reviewer per unit; without, the same units
sequentially. Reviewer notes stay in scratch.

A unit closes when, for every owned entry, rows = the sum over its paths of
max(1, drivers that path iterates); every
*Mitigation* cell is filled (zero blank); every `lead` is resolved into a
finding, a `checked_ok` line or a `limitations` line. Record the counts
(`entries 4, paths 11, rows 15, blank 0`) in scratch.

## 5. From a violated row to a finding

Each finding carries:

- `workload` — who pays it and how often
- `scale_driver` — what grows, its owner and what (if anything) caps it
- `cost_model` — the formula from the row
- `request` — numbered preconditions (data shape, e.g. "a tenant with N
  orders"), then numbered request shapes (method, path, parameter names)
- `contrast` — the sibling path that keeps the budget, at `path:line`, or
  "none"
- `impact` — expected (the budget) vs actual (the cost model), and the bounded
  consequence (timeouts at the gateway limit, pool exhaustion, memory growth)
- `budget` — exactly one ledger ID; name any other violated budget in `impact`
  (the report's *Cited by* column picks up IDs named there too)
- `fix` — one line: the bound restored and where (eager load at `path:line`,
  `LIMIT` with a cursor, a batch call, a composite index on named columns)
- `regression_test` — at least one deterministic assertion: query or call
  count stays constant as N grows, response size bounded, input of size N
  completes within a step count; prefer counts over wall-clock thresholds
