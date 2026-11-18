# Validation — is each gap real, does it matter, and can a test reach it?

**Read when:** VERIFY, for every finding before it reaches the report; GUARD,
for what a proven test may and may not establish.

A missing test file or a reviewer's taste is a hypothesis. Keep the recorded
verdict in `validation` (`reference/findings-schema.md`). Severity,
testability, confidence, verdict and verification basis are separate axes.
Nothing is deleted: a finding judged false stays in the record with its
exclusion and evidence.

## Verdicts

| Verdict | Meaning | Who may set it |
|---|---|---|
| `Valid` | The behaviour runs, every test that reaches it was found and none would fail if it broke, and the exposure its severity claims follows from the critical flows or recorded history (an `Info` finding claims none) | Agent or person, with evidence |
| `Likely` | Strong signals, one necessary link not yet confirmed (a test in another repository may cover it, one fixture unread) | Agent or person |
| `Unverified` | Not yet examined | Agent or person: the verdict a finding starts with, always recorded explicitly |
| `Unlikely` | Signals point away, but the claim has not been ruled out | Agent or person |
| `FalsePositive` | Evidence contradicts the claim (a test under another name asserts it; the fix did add a regression test) | Agent or person, with evidence |
| `NotApplicable` | A test here has no point (dead code — an item for a removal review; generated code; a module scheduled for removal with a date) | Agent or person, with evidence |

`Valid`, `FalsePositive` and `NotApplicable` require nonblank
`validation.evidence` citing `path:line`; a duplicate marked `NotApplicable`
may instead be only the name of the finding it repeats (`Duplicate of F-004`,
`重複: F-004`), when that finding is itself not excluded.

## Four claims for every finding

1. **Reach** — the code runs: registered, imported, reachable from an entry
   point. Search for its name as a string in config, DI registrations and
   routing tables before calling it dead. Dead code is `NotApplicable`
2. **Exposure** — a defect here costs: the critical flow it sits on, fix
   commits by hash whose change touched no test, the window's churn on the
   untested code. Read each fix commit before counting it; a fix to docs or
   tests is not a product defect. Without usable history or a named flow,
   confidence is `Environment-dependent` or `Suspected`, never `Confirmed`
3. **Tests today** — every test that reaches the behaviour, found by import,
   name, fixture and entry-point search, at `path:line`, with what it asserts.
   A test that reaches the code without asserting the behaviour is recorded
   with `net: partial` and named in `coverage.gaps`. This and the asserts
   decide the remedy
4. **Testability** — whether a test can reach the behaviour through today's
   entry points (`Direct`), needs a behaviour-preserving seam (`Seam`, with
   the pitfalls in `reference/remedies.md` ruled out) or a restructuring
   (`Restructure`, with what blocks the test in `coverage.gaps`)

## Falsification

Try to disprove each High and Medium finding before recording it `Valid`:
search for every test that reaches the behaviour, including end-to-end,
contract and other-language suites; check whether the fix commit's test was
added in a neighbouring commit or another repository; check whether the
double is itself checked by a contract test; check whether CI runs the suite
in a job you have not read; check whether the code is being retired. Record
the check, the observation and any counterevidence. A second reviewer
re-reads High findings when the host can run one; otherwise say so in
`limitations`.

## Static support and analysis

`validation.method: "static"` — established by reading. It does not mean
anything was executed.

`analysed` requires a recorded `analysis` with the tool, the command and the
result. Allowed analysis is read-only and local: `git log`, `git show` and
`git blame` queries, an existing coverage report file read as is, a test
discovery listing that does not execute tests where the runner offers one
without importing test modules. Name the tool before running it. Never
install packages, never run the application or its test suite, never contact
external services.

## Proving a test (GUARD)

With explicit permission, GUARD adds the tests a finding names to the repo's
own suite. Running that suite executes the repo's own code (`conftest.py`,
package scripts, build hooks): ask for permission saying so, and run it in a
sandbox without credentials or network where one is available. Each test:

- passes on the current code (it pins today's behaviour; a behaviour that
  looks wrong is pinned as it is and goes to `decisions`)
- fails on a scratch copy of the checkout with the asserted behaviour broken
  (flip the rounding, drop the permission check, return early); the copy is
  discarded, never committed
- drives the behaviour through the unit's public entry, follows the suite's
  idioms (`reference/conventions.md`), is deterministic and names the finding
  (`F-…`) it closes

Record it with one fragment that marks the finding `Fixed`, updates the tests
it now has, and keeps the rest of the record on the assessed revision:
`{"findings": [{"id": "F-002", "status": "Fixed", "coverage": {"net": "covered", "tests": ["tests/test_payments.py:22"], "gaps": "none; FakeGateway added by GUARD, green at 8ab40fc, red with the amount check removed"}}], "meta": {"method": "Static review; git log 12 months; GUARD: FakeGateway for F-002 added, green at 8ab40fc"}}`
(`meta.method` is replaced whole, so it repeats what it said before; each test
is cited at its test function's line).
Then render and check again.

`status: Fixed` records that the work was done: tests written by
an agent, a person, or GUARD. `status: Accepted` records that a person
chose to leave the gap as it is; only they set it, and `decisions` names the
finding, who decided and why. Neither needs a plan batch.

## Reporting and limits

- Headline totals exclude `FalsePositive` and `NotApplicable`; exclusions stay
  visible with their evidence
- State the `Unverified` and `Likely` counts separately from `Valid`
- Schema checks prove structure, not truth; zero findings is not evidence that
  the tests catch every defect, and a test that passes was not run by this
  review unless GUARD ran it
