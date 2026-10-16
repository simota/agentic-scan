# Validation — is each finding real and does it apply here?

**Read when:** VERIFY, for every finding before it reaches the report; GUARD,
for what a check may and may not establish.

A pattern match or a reviewer's claim is a hypothesis. Keep the recorded
verdict in `validation` (`reference/findings-schema.md`). Severity, confidence,
verdict and verification basis are separate axes. Nothing is deleted: a
finding judged false stays in the record with its exclusion and evidence.

## Verdicts

| Verdict | Meaning | Who may set it |
|---|---|---|
| `Valid` | The flow carries the named elements to the sink, no control stops it, and the commitment is broken | Agent or person, with evidence |
| `Likely` | Strong signals, at least one link not yet confirmed (an SDK option set by environment, a region outside the repository) | Agent or person |
| `Unverified` | Not yet examined | Agent or person (record it; there is no default verdict) |
| `Unlikely` | Signals point away, but the claim has not been ruled out | Agent or person |
| `FalsePositive` | Evidence contradicts the claim (a scrubber removes the field; the payload is built from an allow-list) | Agent or person, with evidence |
| `NotApplicable` | The flow is dead code, the element is not personal in this context, or a commitment explicitly allows it | Agent or person, with evidence |

`Valid`, `FalsePositive` and `NotApplicable` require nonblank
`validation.evidence` citing `path:line`; so does every reported High and
Medium finding, whatever its verdict (for `Likely` or `Unverified`, name the hop
not yet read). Evidence names fields, settings and
locations, never values: paraphrase the code instead of pasting a line, and
replace any literal from code, fixtures, config or comments with a
`<placeholder>`. The merge guard catches only e-mail addresses and long digit
runs; names, street addresses and tokens are on you.

## Four claims for every finding

1. **Reach** — the flow runs: the collection point is registered, the code
   path to the sink is reachable from it, and it runs in production
   configuration (not only in a debug branch)
2. **Data** — the elements that actually arrive at the sink: read the payload,
   serializer, log format or event builder that runs, including object
   `__repr__`/`toString`, implicit request logging and SDK auto-collection
3. **Controls** — test the claim that nothing stops it: redaction filters,
   scrubbing hooks, consent gates, allow-lists, retention jobs, deletion
   cascades, encryption, SDK options. Read the layers the first pass skipped:
   logger config, middleware, SDK init, framework defaults cited by version
4. **Commitment** — the broken commitment is the app's own (cited source) or a
   requirement of a regulation the requester named; otherwise it is marked
   `inferred` with the commitment in `decisions`. Never judge legal compliance

## Falsification

Try to disprove each High and Medium finding before recording it `Valid`:
search for scrubbers and filters configured elsewhere (logger setup, SDK init,
a log shipper's config in the repository), consent gates upstream, jobs that
clean the store later, and documentation that lists the recipient. Record the
check, the observation and any counterevidence. A second reviewer re-reads
the evidence for High findings when the host can run one; otherwise say so in
`limitations`.

## Static support and analysis

`validation.method: "static"` — established by reading.

`analysed` requires a recorded `analysis` with the tool, the command and the
result. Allowed analysis is read-only and over source only: `git log`, an
already-installed data-flow or schema scanner run against the checkout without
writing into it. Name the tool before running it. Never query databases, logs,
analytics or backups, and never run the application against real data.

## Guards (GUARD)

Only on explicit request; it is the one time the skill writes into the audited
repository (the test, and the fix only if that is asked for too). A commitment
is locked in by a check in the repo's own suite that:

- uses synthetic data only (placeholders such as `user@example.com`)
- fails on the current gap and passes after the fix (the captured log output
  contains a redaction marker instead of the synthetic email; deleting a
  synthetic user leaves no row in each listed store; the SDK spy records no
  call while consent is absent)
- names the finding (`PV-…`) and the commitment (`C-…`) it encodes
- asserts on keys and markers, and never prints captured output: a failing
  assertion must not dump what a real run might have logged

Steps:

1. Write the test in the suite's own conventions and run it: it must fail
   (red) at the assessed revision.
2. If no fix was requested, leave the test marked as expected to fail (the
   suite's xfail/skip-with-reason mechanism) with the finding ID, and say so.
3. If a fix was requested, apply it and run the test again: it must pass
   (green), and a positive control (the feature still works) must pass too.
4. If the suite cannot run here (dependencies missing, no network), do not
   install anything: deliver the test, say it was not run, and claim neither
   red nor green.
5. After a fix, merge `status: Fixed` for the finding, re-render and pass
   `check`; note in `limitations` that the fix post-dates `meta.commit`.

`status: Fixed` records that a fix was made; the guard is the evidence that it
stays fixed.

## Reporting and limits

- Headline totals exclude `FalsePositive` and `NotApplicable`; exclusions stay
  visible with their evidence
- State the `Unverified` and `Likely` counts separately from `Valid`
- State that the review is technical and not legal advice, and that data
  actually present, vendor-side settings and contracts were not observed
- Schema checks prove structure, not truth; zero findings is not evidence of
  compliance
