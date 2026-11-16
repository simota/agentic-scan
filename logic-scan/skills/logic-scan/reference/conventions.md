# Conventions — the logic rule ledger, trace rows and close-check

**Read when:** end of RECON (derive the ledger), CHECKLIST (deliver it),
REVIEW (hunt each entry and close each unit). **Reader:** the agent running
the skill, cold. **Decision it supports:** what rules this codebase already
states for its logic, what counts as drift, and when a review unit is done.

A rule the codebase states and every site follows is cheap to rely on; a site
that follows another rule (its own rounding beside the shared helper, an
inclusive end where every other range is half-open, `date.today()` where the
rest take the customer's zone) is where results go wrong first. Drift is
judged only against the codebase's own rules. A practice this codebase never
adopted is not a rule to write towards.

## 1. Derive rules from where the codebase states them

Strongest first:

1. **Enforced by types or tooling** — a `Money` or `Decimal` type the code
   uses end to end, a transition table a library enforces, lint rules
   (no floating point on amounts, no naive date-times, exhaustive matches)
2. **Documents** — specifications, ADRs, domain notes, API documentation,
   `CONTRIBUTING` sections on money, time or text
3. **Tests that assert the rule** — a test case is a stated rule for the
   values it covers, and only for those
4. **The majority** — if 9 sites take the customer's zone and one takes the
   server's, the 9 state the rule; record the counts
5. **Recent direction** — a change in progress (every new range in the last
   months is half-open, every new amount uses the `Money` type)
6. **Comments, reviews, issues** — "never round twice", TODOs naming the
   target

A rule from sources 4–6 only is `inferred`, and goes to `decisions` so a
person can confirm the intended direction before any fix is written towards
it.

## 2. The ledger

| ID | Rule | Source | Concern | Units that must follow it | Status |
|---|---|---|---|---|---|

The record keeps the rule in the `idiom` field, the key every scan's ledger
shares. Concerns: `BOUNDARIES` (range ends, limits, thresholds, tiers),
`NUMBERS` (money types, rounding place and mode, units), `TIME` (zones,
calendar arithmetic, granularity of comparisons), `STATE` (allowed states and
transitions, which field is the source of truth), `NULLS` (how absence is
represented and tested), `TEXT` (normalisation, locale, length units),
`CONCURRENCY` (shared in-process state, async ordering), `ERRORS` (what a
failure on a core flow returns, defaults and fallbacks), `OTHER`. *Status*:

- `drifted` — at least one traced site follows another rule with exposure
  (a core flow, a fix commit, a counterexample that gives a wrong result)
- `holds` — every site found by search was read and follows it, or deviates
  only where the result is still right (variant and count in `checked_ok`)
- `partly read` — some sites were not read, none read drifts; the count goes
  to `limitations`
- `not checked` — no site was read; `reason` says why

Every `drifted` entry is cited in the `convention` of a `Valid` or `Likely`
finding; a `Valid` finding cites only `drifted` entries. Drift on a non-core
flow without evidence may be a Low finding; drift whose result is still right
stays `holds` with the variant and its count in `checked_ok`, not a finding.

In a checklist deliverable nothing has been hunted: Status reads `to trace`.

## 3. Trace rows

For each entry, one row per site:

| Entry | Site (`path:line`) | Variant | Core flow? | Verdict |
|---|---|---|---|---|

*Variant* names the way this site does it (`floor per line`,
`round() on total`, `date.today()`, `customer zone`). *Verdict*:
`follows`, `drifts`, or `lead`.

For each defect found during the perspective sweep, record one row too:

| Step | Site (`path:line`) | Defect | Counterexample (input → expected / actual) | Oracle | Exposure evidence | Remedy | Verdict |
|---|---|---|---|---|---|---|---|

## 4. Close-check per review unit

A unit closes when: every core rule implemented in the unit has a site row for
each site found (`reference/recon.md` §2); every owned ledger entry has a row
per site found by search (record the search and its hit count); every
applicable perspective's hunt steps were applied or left out with a reason;
every defect row has *Counterexample*, *Oracle* and *Exposure evidence* filled
(`none` in exposure caps the finding at `Info`; no counterexample means it is
not a finding yet, but a `lead`, whatever its severity would be); every `lead` is resolved into a finding, a
`checked_ok` line or a `limitations` line. Record the counts
(`rules 6, sites 23, entries 5, defects 4, leads 0, blank 0`) in scratch.
