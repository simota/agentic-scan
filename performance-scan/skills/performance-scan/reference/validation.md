# Validation — is each finding real and does it matter here?

**Read when:** VERIFY, for every finding before it reaches the report; MEASURE
and VERIFY-FIX, for what a run may and may not establish.

A pattern match or a reviewer's claim is a hypothesis. Keep the recorded
verdict in `validation` (`reference/findings-schema.md`). Severity, confidence,
verdict and verification basis are separate axes. Nothing is deleted: a
finding judged false stays in the record with its exclusion and evidence.

## Verdicts

| Verdict | Meaning | Who may set it |
|---|---|---|
| `Valid` | The workload reaches the path, the scale driver and cost model are supported, and the claimed budget violation remains after accounting for caps and other mitigations | Agent or person, with evidence |
| `Likely` | Strong signals, but at least one link in the code is not yet confirmed (e.g. whether this route uses the serializer that issues the query, or whether a shared helper applies a cap). A production condition the repository cannot show (data volume, a deployed index) is not a missing link: it is carried in `confidence: Environment-dependent`, and such a finding can still be `Valid`. A `Suspected` finding is never `Valid` | Agent or person |
| `Unverified` | Not yet examined | Default |
| `Unlikely` | Signals point away, but the claim has not been ruled out | Agent or person |
| `FalsePositive` | Evidence contradicts the claimed cost in this code (e.g. an eager load on this exact path) | Agent or person, with evidence |
| `NotApplicable` | The assessed workload does not use the path, or evidence shows that its caps and other mitigations keep the claimed cost within the relevant budget | Agent or person, with evidence |

`Valid`, `FalsePositive` and `NotApplicable` require nonblank
`validation.evidence` citing `path:line`.

A cap alone does not rule out a finding. For example, a hot endpoint capped at
100 items can still exceed its outbound-call budget by making 100 sequential
calls. Compare the cost at the cap with the relevant budget; retain the finding
when that violation is supported. Large bounded costs can be `Medium`, and
blocking a shared resource can be `High` under the severity table in `SKILL.md`.

## Four claims for every finding

State the finding as: which workload enters through which path, iterating which
scale driver, with which mitigations, costing what. Check each claim:

1. **Reachability** — the entry point is registered and the hot workload
   reaches the loop or sink. Trace entry point → loop or fan-out → sink, each
   hop at `path:line`. A helper that looks slow but is only called from a cold
   path is a different severity
2. **Scale** — establish the driver's range and any cap in validation, model
   limits, plan limits or pagination upstream. For bounded inputs, compare the
   cost at the cap with the budget. Where the size depends on production data,
   say so and name the threshold at which the cost matters
3. **Mitigations** — check whether eager loading, prefetch, batch loaders,
   indexes, caches, memoisation, bulk APIs, limits or timeouts keep the claimed
   cost within its budget on this path. Read the layers the first pass skipped:
   base queries, default scopes, serializer setup, middleware, ORM config,
   cache decorators
4. **Impact** — the cost model is right: count the queries or calls per
   iteration (including ones issued by nested serializers and callbacks), and
   state the consequence in bounded terms (gateway timeout, pool exhaustion,
   memory growth per request), not in invented milliseconds

## Falsification

Try to disprove each High and Medium finding before recording it `Valid`:
search for eager loading or caching applied elsewhere on the path, a cap
applied by a shared helper, a feature flag that disables the path, and tests
that assert a query count. Record the check, the observation and any
counterevidence. A second reviewer re-reads the evidence for High findings
when the host can run one; otherwise say so in `limitations`.

## Static support and measurement

Static support can establish a finding when every claim is supported. Label it
`validation.method: "static"`. It does not mean anything was run.

`measured` requires a recorded `measurement` with the command, the environment
(local or throwaway, synthetic data and its shape) and the result. Rules:

- Only after an explicit go-ahead, only on the requester's own local or
  throwaway environment, with synthetic data. Never production, staging,
  shared environments or third-party endpoints; stub external services
- Prefer deterministic counts (queries, calls, allocations, bytes) over
  wall-clock time. Labelled examples: a query-count assertion or a test DB
  callback; Python `django_assert_num_queries`; Go `testing.AllocsPerRun`, `go test
  -bench -benchmem`, `sqlmock` or a GORM callback for query counts, `goleak`. If time is measured, vary N at least three sizes and report
  the growth, not one number
- A local measurement on synthetic data does not prove production behaviour;
  keep the production condition in the finding as `Environment-dependent` when
  it is the deciding factor
- `skip`, `error`, timeout and an undiscovered test are not support and not
  proof of absence. A measurement that shows the cost at the claimed workload
  and scale stays within its budget contradicts that budget violation; bounded
  growth alone does not.
  Resolve counterevidence rather than choosing a favourable run

## Fix verification (VERIFY-FIX)

A fix is verified by a regression check in the repo's own suite that:

- fails before the fix and passes after it (e.g. query count for N=1 and N=50
  is the same; a list endpoint returns at most the page size; a function
  completes within a step budget for an input of size N)
- is paired with a positive control showing the result is unchanged
- is deterministic; wall-clock thresholds are a last resort and are labelled as
  such

`status: Fixed` records that a fix was made. It is not proof of a retest
unless the before and after runs are recorded in `measurement`.

## Reporting and limits

- Headline totals exclude `FalsePositive` and `NotApplicable`; exclusions stay
  visible with their evidence
- State the `Unverified` and `Likely` counts separately from `Valid`
- Schema checks prove structure, not truth; zero findings is not evidence that
  the application is fast under production load
