# Report — output formats

**Read when:** CHECKLIST, to deliver a checklist; REPORT, to deliver findings.
Write in the requester's language.

## Checklist deliverable

- First line: how many critical flows, hotspot units, idioms and applicable
  perspectives, and that suspicions are unverified
- **Critical-flow and hotspot tables first** (`reference/recon.md` §2–§3):
  each flow with its entry points, the top units by churn, the fix commits
  that changed no test, and the history window
- **Test idiom ledger** (`reference/conventions.md` §2): each idiom with its
  source and counts; `inferred` idioms as questions for the requester
- Then one section per applicable perspective from
  `reference/perspectives.md`, ordered by where the critical flows are,
  listing hunt steps with concrete files and an optional `initial note
  (unverified)`
- Close with the recommended starting unit and one decision for the requester

## Findings report (chat summary)

1. **First line** — when the history is missing, shallow or squashed, that
   first (`reference/recon.md` §2); then, from `scripts/findings.py counts`,
   severity counts, the testability mix (`Direct`/`Seam`/`Restructure`), the
   number of plan batches, review scope, and the `Unverified`, `Likely` and
   `Unlikely` counts. Counts leave out `FalsePositive` and `NotApplicable`
2. **Evidence line** — assessed revision, history window and whether it is
   usable, critical flows traced, units read, the scratch directory's path,
   and what remains unknown (tests in other repositories, CI configuration
   not in the repository)
3. **Findings, by severity** — each as:

   ```
   [High|Medium|Low|Info][Direct|Seam|Restructure][S|M|L] one-line title
     location: path:line at the assessed revision
     gap → remedy: Partial refunds untested → Add Behaviour Test
     exposure: the critical flow, fix hashes that changed no test, churn
     tests today: path:line and what they assert; gaps
     assert: the outcomes the test must check
     steps: numbered, each with verify:
     depends on: F-… (or none)
     recorded verdict / confidence / verification: Valid / Confirmed / static
   ```

4. **Plan** — the batches in order, each with its findings and prerequisite
5. **Checked and adequately tested** — what was examined and the tests that
   cover it, with what they assert
6. **Decisions for a human** — inferred idioms to confirm, behaviour that
   looked wrong (pinned as it is, never fixed in passing), gaps someone may
   choose to accept
7. **Next step** — batch 1, and the hand-off (`templates/plan.<lang>.md` to
   `coding-test`); questions for `refactor-scan`, `architecture-scan` or
   `prune-scan`
8. **Files** — link `dashboard.html` and `report.md` rendered from
   `findings.json`. The output directory holds exactly the set named in
   `SKILL.md` (*Run contract*)

Use the same verdicts, testability and confidence in chat, dashboard and
report. `findings.json` is the record; every chat finding must exist there.

State limitations prominently: static reading does not run the tests, a test
that looks right may still not fail when the behaviour breaks until it is
seen failing, and zero findings is not evidence that the tests catch every
defect.
