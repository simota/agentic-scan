# Conventions — the test idiom ledger, trace rows and close-check

**Read when:** end of RECON (derive the ledger), CHECKLIST (deliver it),
REVIEW (hunt each entry and close each unit). **Reader:** the agent running
the skill, cold. **Decision it supports:** how new tests in *this* suite
should be written, what counts as drift, and when a review unit is done.

A test written against the suite's own idioms is cheap to review and keeps
working when shared fixtures change; a test written another way (its own
clock patch, its own data builder, its own mock of a client the suite fakes
elsewhere) is the one that turns flaky or silently stops checking. Drift is
judged only against the suite's own idioms. A practice this suite never
adopted is not a rule to write towards.

## 1. Derive idioms from where the suite states them

Strongest first:

1. **Enforced config** — runner configuration, lint rules for tests
   (`no-only-tests`, `pytest-randomly`, banned imports), fixtures declared
   `autouse`
2. **Documents** — `CONTRIBUTING`, testing guides, ADRs, README sections
3. **The majority** — if 23 tests freeze time with `frozen_clock` and 2 patch
   `datetime` themselves, the 23 state the idiom; record the counts
4. **Recent direction** — a migration in progress (a new factory library used
   by every test added in the last months)
5. **Comments, reviews, issues** — "use the fake gateway", TODOs naming the
   target

An idiom from sources 3–5 only is `inferred`, and goes to `decisions` so a
person can confirm the intended direction before any test is written towards
it.

## 2. The ledger

| ID | Idiom | Source | Concern | Units that must follow it | Status |
|---|---|---|---|---|---|

Concerns: `FIXTURE` (setup and teardown), `DOUBLE` (mocks, fakes, stubs and
how clients are injected), `CLOCK` (time and randomness), `DATA` (factories,
builders, fixture files), `ASSERT` (assertion style and helpers), `ISOLATION`
(database reset, temp directories, global state), `RUNNER` (markers, test
commands, CI jobs), `OTHER`. *Status*:

- `drifted` — at least one traced site follows another idiom with exposure
  (a critical flow, a flaky test, a double that hid a defect)
- `holds` — every site found by search was read and follows it, or deviates
  only where the drift has no exposure (variant and count in `checked_ok`)
- `partly read` — some sites were not read, none read drifts; the count goes
  to `limitations`
- `not checked` — no site was read; `reason` says why

Every `drifted` entry is cited in the `convention` of a `Valid` or `Likely`
finding; a `Valid` finding cites only `drifted` entries. Drift in code below
the hotspot bar may be a Low finding; drift with no exposure at all stays
`holds` with the variant and its count in `checked_ok`, not a finding.

In a checklist deliverable nothing has been hunted: Status reads `to trace`.

## 3. Trace rows

For each entry, one row per site:

| Entry | Site (`path:line`) | Variant | Critical flow or hotspot? | Verdict |
|---|---|---|---|---|

*Variant* names the way this site does it (`frozen_clock`, `patches
datetime`, `factory`, `raw dict`). *Verdict*: `follows`, `drifts`, or `lead`.

For each gap found during the perspective sweep, record one row too:

| Step | Site (`path:line`) | Gap | Exposure evidence | Remedy | What to assert | Verdict |
|---|---|---|---|---|---|---|

## 4. Close-check per review unit

A unit closes when: every critical-flow branch in the unit has a test-map row;
every owned ledger entry has a row per site found by search (record the
search and its hit count); every applicable perspective's hunt steps were
applied or left out with a reason; every gap row has *Exposure evidence*
filled (the flow, hashes or counts, or `none` — which caps the finding at
`Info`); every `lead` is resolved into a finding, a `checked_ok` line or a
`limitations` line. Record the counts (`branches 12, entries 4, sites 31,
gaps 6, blank 0`) in scratch.
