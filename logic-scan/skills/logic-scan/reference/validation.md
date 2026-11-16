# Validation — is each defect real, does it matter, and how far does the fix reach?

**Read when:** VERIFY, for every finding before it reaches the report; REPRO,
for what a reproduced counterexample may and may not establish.

An odd-looking line or a reviewer's taste is a hypothesis. Keep the recorded
verdict in `validation` (`reference/findings-schema.md`). Severity, change,
confidence, verdict and verification basis are separate axes. Nothing is
deleted: a finding judged false stays in the record with its exclusion and
evidence.

## Verdicts

| Verdict | Meaning | Who may set it |
|---|---|---|
| `Valid` | The defect is traced on code that runs, the counterexample's input reaches it from a named entry point, every step from that input to the wrong result is read with nothing on the way correcting it, the oracle states the expected result, and the exposure its severity claims follows from the core flows, the callers or recorded history (an `Info` finding claims none) | Agent or person, with evidence |
| `Likely` | Strong signals, one necessary link not yet confirmed (one caller unread, the oracle ambiguous, the production setting the result depends on not in the repository) | Agent or person |
| `Unverified` | Not yet examined | Agent or person: the verdict a finding starts with, always recorded explicitly |
| `Unlikely` | Signals point away, but the claim has not been ruled out | Agent or person |
| `FalsePositive` | Evidence contradicts the claim (an upstream validation excludes the input; a later step corrects the value; the oracle states the result the code gives) | Agent or person, with evidence |
| `NotApplicable` | A fix here has no point (code nothing reaches — a `prune-scan` item; a flow retired with a date; generated code) | Agent or person, with evidence |

`Valid`, `FalsePositive` and `NotApplicable` require nonblank
`validation.evidence` citing `path:line`; a duplicate marked `NotApplicable`
may instead be only the name of the finding it repeats (`Duplicate of F-004`,
`重複: F-004`), when that finding is itself not excluded.

## Five claims for every finding

1. **Reach** — the code runs: registered, imported, reachable from an entry
   point, a job or a scheduled task. Search for its name as a string in
   config, schedulers, routes and templates before calling it dead. Code
   nothing reaches is `NotApplicable`
2. **Counterexample** — one concrete input, written as values, that enters at
   a named entry point and reaches the site; the expected result from the
   oracle; the actual result computed by following the code step by step
   (each step's value written in `trace`). Check every validation, coercion
   and default on the way: an input the entry point refuses is not a
   counterexample. The oracle names where the expected result is stated, or the
   domain fact it rests on (a calendar rule, a currency's minor unit); the
   reviewer's own idea of how the business should behave is a `Suspected`
   oracle
3. **Exposure** — a wrong result here costs: the core flow it sits on, the
   callers that reach it, fix commits by hash that patched the same rule,
   records that the input occurs (`reference/recon.md` §7). Read each fix
   commit before counting it; a fix to docs or tests is not an incident.
   Without usable history or a named core flow, confidence is
   `Environment-dependent` or `Suspected`, never `Confirmed`
4. **Enforcement today** — everything that keeps the rule true, at
   `path:line`: tests that assert it (and which values they cover), types,
   shared helpers, validations upstream. A test that covers the rule but not
   the counterexample's value is `net: partial`, and the uncovered values go
   in `enforcement.gaps`
5. **Change** — whether the fix changes only the wrong result at the site
   (`Local`, with the pitfalls in `reference/remedies.md` ruled out), also
   results other callers see (`Shared`), or leaves results already produced
   wrong (`Correction`). A `Shared` or `Correction` finding names in
   `change_reason` the callers or the results

## Falsification

Try to disprove each High and Medium finding before recording it `Valid`:
search for a validation upstream that excludes the input; follow the result
past the site to see whether a later step corrects it (a second rounding that
happens to repair the first, a display layer that recomputes); read the oracle
again for a case that states the code's result; check whether the setting the
result rests on is fixed in the repository; check whether the caller is dead
or the flow retired. Record the check, the observation and any
counterevidence. A second reviewer re-reads High findings when the host can
run one; otherwise say so in `limitations`.

## Static support and analysis

`validation.method: "static"` — established by reading. It does not mean
anything was executed.

`analysed` requires a recorded `analysis` with the tool, the command and the
result. Allowed analysis is read-only and local: `git log`, `git show` and
`git blame` queries, and an expression evaluated in a fresh interpreter, run
outside the audited repository and importing nothing from it, to confirm a
language's own behaviour (`0.1 + 0.2`, Python's `round(0.5)`). Name the tool
before running it. Never run the application, its test suite, its scripts or
its configured linters and type checkers (their configuration and plugins are
the repository's code), never install packages, never contact external
services.

## Reproducing a counterexample (REPRO)

With explicit permission, REPRO writes a finding's counterexample as a test in
the repository's own suite and runs it. Running the suite executes the
repository's own code (`conftest.py`, package scripts, build hooks, fixtures):
ask for permission saying so, and run it in a sandbox without credentials or
network where one is available. Never point it at shared or production
systems. Each reproduction:

- uses the counterexample's input as written, through the entry point the
  finding names, with the oracle's expected result as the assertion
- shows the test failing on the assessed revision with the actual result the
  finding recorded; a test that passes means the finding is wrong or its
  trace missed a step — record that and re-verify
- follows the codebase's test conventions, is deterministic (time frozen,
  zone and locale set explicitly) and names the finding (`F-…`) it reproduces

Record it with one fragment that keeps the finding `Open` and changes its
method, and keeps the rest of the record on the assessed revision:
`{"findings": [{"id": "F-003", "validation": {"verdict": "Valid", "method": "analysed", "evidence": "tests/billing/test_renewal.py:40 freezes 2026-10-31 16:00 UTC; renewal not run; app/jobs/renew_subscriptions.py:12 date.today()"}, "analysis": {"tool": "pytest", "command": "pytest tests/billing/test_renewal.py -k F003", "result": "1 failed: expected renewed, got pending"}}], "meta": {"method": "Static review; git log 12 months; REPRO: F-003 reproduced by a failing test"}}`
(`meta.method` is replaced whole, so it repeats what it said before). When the
fix has been written and the same test passes, a later fragment marks the
finding `Fixed` and updates `enforcement` to cite the test. Then render and
check again.

`status: Fixed` records that the work was done: a fix written by
`coding-implement` or a person, with the counterexample's test passing.
`status: Accepted` records that a person chose to leave the result as it is;
only they set it, and `decisions` names the finding, who decided and why.
Neither needs a plan batch.

## Reporting and limits

- Headline totals exclude `FalsePositive` and `NotApplicable`; exclusions stay
  visible with their evidence
- State the `Unverified` and `Likely` counts separately from `Valid`
- A traced counterexample shows one wrong result, not that every other input
  is right; zero findings is not evidence that the code computes the right
  results, and no code was executed by this review unless REPRO ran a test
