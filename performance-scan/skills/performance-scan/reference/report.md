# Report — output formats

**Read when:** CHECKLIST, to deliver a checklist; REPORT, to deliver findings.
Write in the requester's language.

## Checklist deliverable

- First line: how many budgets were derived, how many perspectives apply, and
  that suspicions are unverified
- **Budget ledger first** (`reference/budgets.md` §2): each budget with its
  source, the paths that pay it and which of them to trace; mark `inferred`
  bounds as questions for the requester
- Then one section per perspective from `reference/perspectives.md`, most
  important first, listing only the hunt steps no ledger entry covers; list the
  ones judged N/A with a reason
- Each item: the question, concrete routes/files, and an optional
  `initial note (unverified)`
- Close with the recommended starting point and one decision for the requester

## Findings report (chat summary)

1. **First line** — severity counts and review scope; whether the work was
   static or included authorised local measurements; the `Likely`,
   `Unverified` and `Unlikely` counts and how many High findings are not
   `Valid`
2. **Evidence line** — assessed revision, what was read, what the reporting
   agent traced end to end, what remains environment-unknown (data volumes,
   deployed indexes and settings), and the scratch directory's path
3. **Findings, by severity** — one line each (`P-NNN`, severity, confidence,
   verdict, title, location), then the full block below for High findings
   only; `report.md` carries every block:

   ```
   P-NNN [High|Medium|Low|Info][Confirmed|Environment-dependent|Suspected] one-line title
     perspective: category (hunt step)
     location: path:line at the assessed revision
     workload: who pays it and how often
     scale driver: what grows, and its cap (or "uncapped")
     cost model: formula in the driver
     steps: numbered preconditions (data shape), numbered request shapes
     contrast: the sibling path that keeps the budget, path:line (or "none")
     budget: the ledger ID
     what happens: expected (the budget) vs actual (the cost model) and its consequence
     recorded verdict / verification: Valid … / static or measured
     fix direction: one line — the bound restored and where
     regression test: at least one deterministic assertion
   ```

4. **Checked and sound** — what was examined and held
5. **Decisions for a human** — bounds to confirm, production volumes and
   settings to check, trade-offs (e.g. cache staleness)
6. **Next step** — the fix order (highest-frequency workload and uncapped
   driver first), and whether a MEASURE go-ahead would settle open findings
7. **Files** — link `dashboard.html` and `report.md` rendered from
   `findings.json` (`reference/findings-schema.md`). The output directory holds
   exactly the set named in `SKILL.md` (*Run contract*)

Use the same verdicts, confidence and verification basis in chat, dashboard
and report. `findings.json` is the record; every chat finding must exist there.

State limitations prominently: static cost models are not measurements, a
local measurement on synthetic data is not production behaviour, and zero
findings is not evidence that the application is fast under real load.
