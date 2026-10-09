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
| `Valid` | The workload reaches the path, the scale driver grows as claimed, no mitigation bounds it, and the cost model follows | Agent or person, with evidence |
| `Likely` | Strong signals, at least one necessary link not yet confirmed (e.g. production volume, index presence) | Agent or person |
| `Unverified` | Not yet examined | Default |
| `Unlikely` | Signals point away, but the claim has not been ruled out | Agent or person |
| `FalsePositive` | Evidence contradicts the claimed cost in this code (e.g. an eager load on this exact path) | Agent or person, with evidence |
| `NotApplicable` | The path is not used, the driver is capped, or the workload never pays it often enough to matter | Agent or person, with evidence |

`Valid`, `FalsePositive` and `NotApplicable` require nonblank
`validation.evidence` citing `path:line`.

## Four claims for every finding

State the finding as: which workload enters through which path, iterating which
scale driver, past which missing mitigation, costing what. Check each claim:

1. **Reachability** — the entry point is registered and the hot workload
   reaches the loop or sink. Trace entry point → loop or fan-out → sink, each
   hop at `path:line`. A helper that looks slow but is only called from a cold
   path is a different severity
2. **Scale** — the driver actually grows: no cap in validation, model limits,
   plan limits or pagination upstream. Where the size depends on production
   data, say so and name the threshold at which the cost matters
3. **Mitigations** — test the claim that no eager load, prefetch, batch
   loader, index, cache, memoisation, bulk API, limit or timeout bounds the
   cost on this path. Read the layers the first pass skipped: base queries,
   default scopes, serializer setup, middleware, ORM config, cache decorators
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
  wall-clock time. If time is measured, vary N at least three sizes and report
  the growth, not one number
- A local measurement on synthetic data does not prove production behaviour;
  keep the production condition in the finding as `Environment-dependent` when
  it is the deciding factor
- `skip`, `error`, timeout and an undiscovered test are not support and not
  proof of absence. A measurement that shows the cost bounded contradicts
  `Valid`; resolve it rather than choosing a favourable run

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
