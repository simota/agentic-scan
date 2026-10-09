---
name: performance-scan
description: "Static performance review of an application's own source: maps hot paths, workloads and data volumes, then checks N+1 and unbounded queries, indexes, complexity, memory, blocking I/O, caching, pools, payloads, front-end bundle and rendering, jobs and config. Outputs a dashboard and a report. Read-only. Use to find bottlenecks or scalability risks, or to list what to check."
allowed-tools: Read, Grep, Glob, Bash, Write
---

## Owns

Finding performance and scalability problems in a codebase the requester owns,
**by reading it**. The output is a ranked list of findings, each with a
`file:line`, the workload that reaches it, the scale driver that makes it grow,
a cost model (how many queries, calls, bytes or steps per request as a function
of that driver), what goes wrong and how sure the finding is — or, when only a
plan is asked for, a checklist tailored to this application.

It does not optimise code and does not send load to any deployed environment.
Fixing is a separate, later request. On an explicit request it can run a
benchmark, profiler or query-count test on the requester's own local or
throwaway environment (MEASURE); it never load-tests a shared, staging,
production or third-party system.

Phases: `RECON → CHECKLIST → REVIEW → VERIFY → REPORT`.

## Before starting

- **Confirm scope in one line.** The repository is the requester's, the review
  is static, and no deployed system receives load. If the request implies a
  load test or profiling, see the measurement row in *Decide first*
- **Name the workloads before reading handlers**: interactive requests (per
  screen or API call), API clients and integrations, background jobs and
  schedules, imports and exports, startup and deploy. A cost is only a problem
  relative to how often and how latency-sensitively it is paid
- **Name the scale drivers**: what grows — rows per tenant, items per order,
  users per organisation, file sizes, fan-out targets, concurrent users,
  history length. Severity is judged by what grows without a cap on a hot path
- **Derive the budgets before hunting**: the bounds this app must keep — latency
  targets, timeouts, page-size defaults, queries per request, payload and
  bundle size, memory limits, job deadlines (`reference/budgets.md`). Essential
  performance problems are violations of these bounds on some path; a generic
  linter cannot see them because the bounds exist only in this app
- **Create a new, empty output directory** outside the audited repository and
  follow the *Run contract* below

## Run contract

| Item | Fixed choice |
|---|---|
| Independence | Never read another assessment's outputs (an earlier `findings.json`, another host's report) unless the request is to merge or compare them |
| Review units | Group the workload inventory by domain: one unit per domain plus one cross-cutting unit (DB and HTTP client setup, middleware, caching layer, runtime and build config). Each unit first hunts the budget ledger entries it owns, then sweeps every applicable perspective once over the unit. A unit closes only when its close-check matches (`reference/budgets.md` §4). With subagents, one reviewer per unit; without, the same units sequentially. Reviewer notes stay in scratch |
| Granularity | One finding per root cause, i.e. per fix location. The same N+1 helper used by several endpoints is one finding that lists them in `request`; problems needing different fixes are separate findings |
| IDs | `P-001`… numbered without gaps in severity order (then path). No other prefixes |
| Severity | The table below, decided before confidence; confidence never raises or lowers it |
| Outputs | Exactly `findings.json`, `dashboard.html`, `report.md`, in the requester's language. No extra files unless asked (`findings.py check --allow NAME`) |
| `meta.assessor` | Host and model, e.g. `Claude Code (<model>)`, `Codex (<model>)` |
| Budget (effort) | When the effort runs short, close units in impact order (highest-frequency workloads and uncapped scale drivers first) instead of thinning every unit. `limitations` gives the count of unreached units, entry points and ledger entries |
| Scratch | A new, empty directory for working records (recon map, ledger, cost-trace rows, fragments), outside both the audited repository and the output directory: the host's session scratch when it names one, otherwise a fresh directory under `$TMPDIR`. Name its path in the chat summary |
| Writing the record | Never build `findings.json` with a shell heredoc, `echo`/`printf` redirection or a generated script. Write each batch of one to five findings as a JSON fragment with the host's file-write tool into scratch, then `scripts/findings.py merge <out>/findings.json <fragment>…`. The first fragment carries `meta` (`reference/findings-schema.md`). One REPORT coordinator runs all merges to the same `findings.json` sequentially; parallel reviewers write scratch fragments only. Atomic replacement does not detect concurrent updates |
| Read-only | Read, search and run this skill's scripts; the file-write tool is for scratch records and fragments only; write nothing inside the audited repository |

| Severity | When |
|---|---|
| High | On a hot path (an interactive request, a frequent API call, a job with a deadline), cost grows with a scale driver that has no cap — a query per row, an unpaginated query on a growing table, quadratic work over tenant data, a whole result set or file held in memory — or one request blocks a shared resource (event loop, global lock, connection pool) so that other requests stall. Also a leak (memory, connections, handles) that grows with uptime |
| Medium | A High-class growth that needs one condition the code does not control (a large tenant, a missing index that the migrations do not show either way, a feature flag), a large bounded cost on a hot path (many sequential outbound calls, multi-megabyte responses, a render that redoes all work per keystroke), or uncapped growth on a warm path |
| Low | Inefficiency on a cold path (admin, one-off, startup), a missed cache with small cost, constant-factor waste |
| Info | A tuning or observability note with no demonstrated cost path |

Each further condition the code does not control lowers severity one level. An
`Environment-dependent` finding is graded as if its stated condition holds, and
names that condition and the threshold (e.g. "above ~10k rows per tenant").

## Phases

| Phase | Do | Reference |
|---|---|---|
| RECON | Build the hot-path map: stack and versions, every entry point with its workload and frequency, the data model with indexes and expected volumes, I/O sinks (queries, outbound calls, file and cache access), concurrency model and pool sizes, runtime and build config, existing performance evidence (benchmarks, load-test config, APM, slow-query notes). End by deriving the budget ledger | `reference/recon.md`, `reference/budgets.md` |
| CHECKLIST | Ledger first: each budget with its source and every hot path that must keep it. Then the perspectives that apply, keeping only hunt steps no ledger entry covers; attach early suspicions marked unverified | `reference/budgets.md`, `reference/perspectives.md`, `reference/report.md` |
| REVIEW | One pass (or one reviewer) per review unit. For each owned budget, trace every path that pays it with one cost-trace row per path: entry point → loop/fan-out → sink, citing each hop as `path:line` and writing the cost as a function of the scale driver ("1 + N queries, N = items per order, uncapped"). Every mitigation cell names the cap, index, batch or cache at `path:line`, or `NONE` / `N/A` / `UNKNOWN` with a reason — never "the ORM handles it". Then the sink-backward pass (every query and outbound call inside a loop maps to a row), then sweep every applicable perspective's hunt steps | `reference/budgets.md`, `reference/perspectives.md` |
| VERIFY | Record evidence-linked reachability, scale, mitigations and impact; try to falsify each claim (an upstream cap, eager loading, a cache, a batch API); keep unknown data volumes and deployed settings explicit; distinguish static support from local measurement | `reference/validation.md` |
| REPORT | Write `findings.json` through fragments and `scripts/findings.py merge`; render with `scripts/render.py <out>/findings.json --out <out> --lang <ja or en>`; pass `scripts/findings.py check <out>`; then give the summary in chat | `reference/findings-schema.md`, `reference/report.md` |
| MEASURE *(on request)* | With an explicit go-ahead, on the requester's own local or throwaway environment only: a query-count test, a micro-benchmark or a profiler run on synthetic data shaped by the scale driver. Record command, environment and result in `measurement`; an unrun or failed measurement never becomes support | `reference/validation.md` |
| VERIFY-FIX *(on request)* | With explicit permission, add a regression check in the repo's own suite that fails before the fix and passes after it — a query-count assertion, a complexity guard on a growing input, a size budget — plus a positive control that the result is unchanged | `reference/validation.md` |

## Outputs

| Output | What it is |
|---|---|
| Chat summary | First line status and counts, findings by severity, decisions for a human |
| `findings.json` | The single source every other output is rendered from |
| `dashboard.html` | Self-contained dashboard: counts, filterable findings, budgets, perspective coverage |
| `report.md` | The written assessment: scope, findings, budgets, coverage, sound items, limitations, next steps |

Skip the files when only a checklist was asked for. Render them in the
requester's language (`--lang ja|en`).

## Decide first

| Situation | How to proceed |
|---|---|
| Asked "what should we check" or "list the items" | RECON and CHECKLIST only, then stop and deliver the checklist |
| Asked to check, audit, scan or find bottlenecks | All five phases |
| Asked about one slow screen, endpoint or job | Scope the review units to the paths that serve it, plus the cross-cutting unit; say the rest was not read in `limitations` |
| No document states a latency target or limit | Infer the budget from timeouts, page-size defaults, existing pagination and the majority of handlers; mark it `inferred` in the ledger, hunt it anyway, and put the bound itself in `decisions` |
| The ORM loads relations lazily by default | List every relation accessed inside a loop or a serializer over a collection, and check each for eager loading on that path. This list is the N+1 hunt list |
| Whether an index exists depends on the production schema | Read the migrations and schema files. If they show it, cite them; if they do not, report `Environment-dependent` and name the index to confirm |
| A finding's cost depends on data volume | State the volume at which it matters and where the volume comes from; never present a guess of production size as fact |
| A cache sits in front of the cost | Check the key, the invalidation, the TTL, the bound on size and what happens on a miss storm. A cache does not mitigate a cold path or a per-user key on a shared cost |
| The framework is async or event-loop based | Hunt synchronous blocking calls (file, crypto, DNS, sync HTTP or DB clients, CPU-heavy loops) on the loop. One is enough to stall every concurrent request |
| A front end is in the repo | Apply the *Front end* perspective; read the build config and the largest routes. Bundle size from a local build is a measurement and needs the MEASURE go-ahead |
| The requester wants numbers (latency, throughput, memory) | MEASURE only on their own local or throwaway environment after an explicit go-ahead; never production, never shared environments, never third-party endpoints. Without measurement, report cost models, not milliseconds |
| Asked to confirm a fix or guard against regression | VERIFY-FIX: a deterministic assertion (query count, call count, allocation or size budget) in the repo's own suite, red before and green after. Prefer counts over wall-clock thresholds, which flake |
| The host cannot run a second, independent reviewer | Record that in `limitations`; High findings stay `Likely` unless the reporting agent traced them end to end. Never invent a second reviewer |
| Asked to file findings as issues or write them up for an owner | Draft from `findings.json`: `templates/issue.<lang>.md` per finding (one root cause per issue), `templates/report.<lang>.md` for one report covering several. Filing or sending is the requester's step |

## Always / Never

- Always: anchor every finding to `file:line` and name the workload, the scale
  driver and the cost model as a function of that driver
- Always: give every finding static reproduction steps — workload, data shape
  as numbered preconditions (e.g. "a tenant with N orders, each with M items"),
  the request shape (method, path, parameter names), the `Contrast:` path that
  keeps the budget, and expected vs actual naming the violated budget — a
  one-line fix direction stated as the bound restored, and at least one
  regression assertion (`reference/budgets.md` §5)
- Always: grade **severity** (High / Medium / Low / Info) and **confidence**
  (Confirmed / Environment-dependent / Suspected) separately, and keep the
  verification basis (`static` or `measured`) separate from both
- Always: list what was checked and found sound. A report with no negatives
  cannot be told apart from a report that did not look
- Always: say what static reading cannot show — production data volumes,
  deployed indexes and pool sizes, cache hit rates, network latency, the real
  traffic mix
- Never: edit source, configs or dependencies during the review
- Never: send load, benchmarks or profilers to deployed systems or third-party
  endpoints
- Never: state a latency, throughput or memory figure that was not measured.
  Write the cost model instead ("2N+1 queries"), and label any estimate as one
- Never: report a High or Medium finding you have not traced end to end yourself
- Never: delete a finding judged false — mark it `FalsePositive` or
  `NotApplicable` with evidence so the exclusion is visible
- Never: recommend a micro-optimisation as a finding when no workload pays the
  cost often enough to matter; record it as Info or leave it out

## Verify with

- Every High and Medium finding is traced entry point → loop or fan-out → sink
  by the agent writing the report, with each hop at `path:line`
- Every N+1 claim is checked against eager-loading, prefetch, batch loaders and
  caches on that exact path, including ones inherited from a base query or
  serializer
- Every "unbounded" claim is checked for a cap upstream: request validation,
  pagination defaults, model limits, plan limits, a `LIMIT` added by a helper
- Static support is never labelled a measurement; a measurement on synthetic
  local data never establishes production behaviour; skipped, failed and
  errored runs never become support
- `Unverified`, `Likely` and `Unlikely` remain verification-incomplete; recorded
  verdicts are not upgraded automatically

## Done when

`scripts/findings.py check <out>` passes, every entry point on a hot workload
has been read, every budget ledger entry has a status (holds on all paths,
violated, partly read, or not checked with the reason), every review unit's
close-check matches with zero blank cells, every perspective in
`reference/perspectives.md` is recorded as applied, N/A or not checked, every
High and Medium finding has a recorded verdict and evidence, and the report
states its own blind spots.
