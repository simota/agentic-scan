# Validation — is each finding real and does it matter here?

**Read when:** VERIFY, for every finding before it reaches the report; GUARD,
for what a fitness function may and may not establish.

A pattern match or a reviewer's opinion is a hypothesis. Keep the recorded
verdict in `validation` (`reference/findings-schema.md`). Severity, confidence,
verdict and verification basis are separate axes. Nothing is deleted: a
finding judged false stays in the record with its exclusion and evidence.

## Verdicts

| Verdict | Meaning | Who may set it |
|---|---|---|
| `Valid` | The violation exists on the traced path, no mechanism compensates, and the consequence (defect or change cost) follows | Agent or person, with evidence |
| `Likely` | Strong signals, at least one necessary link not yet confirmed (e.g. delivery semantics, history too short) | Agent or person |
| `Unverified` | Not yet examined | Default |
| `Unlikely` | Signals point away, but the claim has not been ruled out | Agent or person |
| `FalsePositive` | Evidence contradicts the claim (e.g. the second writer delegates to the owner) | Agent or person, with evidence |
| `NotApplicable` | The rule does not apply here (dead code, a deliberate documented exception, a module scheduled for removal with a date) | Agent or person, with evidence |

`Valid`, `FalsePositive` and `NotApplicable` require nonblank
`validation.evidence` citing `path:line`; a duplicate marked `NotApplicable`
opens instead with a sentence that only names the reported finding it repeats
(`Duplicate of A-004.`, `重複: A-004。`).

## Four claims for every finding

1. **Reach** — the violating edge, writer or flow exists in code that runs:
   registered, imported, reachable from an entry point. Before calling code
   dead, search for its name as a string in config, DI registrations and
   routing tables. Dead code is `NotApplicable`, or a *Dependencies and
   evolution* finding of its own
2. **Consequence** — what the violation allows or costs. For a defect: the
   concrete sequence (which call fails after which commit, which writer skips
   which rule). For change cost: history evidence (co-change counts, churn, the
   file count of a recent comparable change)
3. **Mitigations** — test the claim that nothing compensates: a facade that all
   callers actually use, an outbox, an idempotency key, a reconciliation job,
   a lint contract, a test that pins the rule. Read the layers the first pass
   skipped: base classes, decorators, middleware, framework config
4. **Rule** — the violated rule is this codebase's own (cited source), or is
   marked `inferred` with the rule in `decisions`. A rule from a textbook that
   this codebase never adopted does not make a change-cost or structure
   finding by itself. A defect claim — incorrect behaviour or data damage on a
   traced path — needs no adopted rule: cite the family's `baseline` entry
   (`reference/rules.md` §2)

## Falsification

Try to disprove each High and Medium finding before recording it `Valid`:
search for every other writer, caller or copy; check whether one delegates to
another; look for a documented exception (ADR, comment) that makes the
deviation deliberate; check whether the module is being retired. Record the
check, the observation and any counterevidence. A second reviewer re-reads the
evidence for High findings when the host can run one; otherwise say so in
`limitations`.

## Static support and analysis

`validation.method: "static"` — established by reading. It does not mean
anything was executed.

`analysed` requires a recorded `analysis` with the tool, the command and the
result. Allowed analysis is read-only and local: `git log` and `git
blame`-style history queries, an already-installed dependency-graph or
import-lint tool run against the checkout without writing into it. Name the
tool before running it. Never install packages into the audited repository,
never run the application, never contact external services.

History shows what changed together, not why; a co-change pair can be one
feature delivered across layers on purpose. Treat it as evidence for a
change-cost claim, not proof of a defect.

## Fitness functions (GUARD)

A rule is locked in by a fitness function in the repo's own suite that:

- fails on the current violation and passes after the fix (e.g. an import
  contract that lists the forbidden edge; a test that delivers the same message
  twice and asserts one effect; a CI search that finds writes to a table
  outside its owner)
- is deterministic and cheap enough to run on every change
- names the rule (`R-…`) it encodes

`status: Fixed` records that a fix was made; the guard is the evidence that it
stays fixed. Record it with one fragment, keeping the proposed check and adding
where it now lives and the revisions it was red and green at:
`{"findings": [{"id": "A-001", "status": "Fixed", "guard": "R-01: CI search fails on writes to invoices outside api/billing/ — ci/single_writer_test.py, red at 8ab40fc, green at 1c2d3e4"}]}`.
When the fix was shown only on a scratch copy (the default), the finding stays
`Open` and the guard says so:
`{"findings": [{"id": "A-001", "guard": "R-01: CI search fails on writes to invoices outside api/billing/ — ci/single_writer_test.py, red at 8ab40fc; passes on a scratch copy with the fix"}]}`.
The rest of the record still describes the assessed revision (`meta.commit`):
the rule stays `violated`, and the finding still counts in the headline;
`scripts/findings.py counts` reports `n_fixed` beside it. Without
`meta.method`, both outputs say that nothing was changed or run, so the same
fragment records the GUARD step there too:
`{"meta": {"method": "Static review; GUARD: ci/single_writer_test.py added for R-01, red at 8ab40fc"}}`.
Then render and check again.

## Reporting and limits

- Headline totals exclude `FalsePositive` and `NotApplicable`; exclusions stay
  visible with their evidence
- State the `Unverified` and `Likely` counts separately from `Valid`
- Schema checks prove structure, not truth; zero findings is not evidence that
  the design is sound for changes no one has made yet
