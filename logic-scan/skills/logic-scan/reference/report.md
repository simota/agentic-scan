# Report — output formats

**Read when:** CHECKLIST, to deliver a checklist; REPORT, to deliver findings.
Write in the requester's language.

## Checklist deliverable

- First line: how many core flows, rules, implementing sites, oracles and
  applicable perspectives, and that suspicions are unverified
- **Core-flow and rule tables first** (`reference/recon.md` §2–§5): each core
  flow with its rules and every site implementing them, the oracles and which
  boundary values they cover, the settings the repository fixes and leaves
  open, the fix commits on rule code, and the history window
- **Logic rule ledger** (`reference/conventions.md` §2): each rule with its
  source and counts; `inferred` rules as questions for the requester
- Then one section per applicable perspective from
  `reference/perspectives.md`, ordered by where the core flows are, listing
  hunt steps with concrete files and an optional `initial note (unverified)`
- Close with the recommended starting unit and one decision for the requester

## Findings report (chat summary)

1. **First line** — when the history is missing, shallow or squashed, that
   first (`reference/recon.md` §2); then, from `scripts/findings.py counts`,
   severity counts, the change mix (`Local`/`Shared`/`Correction`), the
   number of plan batches, review scope, and the `Unverified`, `Likely` and
   `Unlikely` counts. Counts leave out `FalsePositive` and `NotApplicable`
2. **Evidence line** — assessed revision, history window and whether it is
   usable, core flows and rules traced, units read, the scratch directory's
   path, and what remains unknown (the server's time zone or locale, flag
   values in production, rules stated outside the repository)
3. **Findings, by severity** — each as:

   ```
   [High|Medium|Low|Info][Local|Shared|Correction][S|M|L] one-line title
     location: path:line at the assessed revision
     defect → remedy: charge and invoice round tax differently → Centralise Rounding
     counterexample: input → expected / actual; oracle path:line
     exposure: the core flow, callers, fix hashes that patched the same rule
     enforcement today: net; path:line of each test, type or check; gaps
     change reason: callers whose results move, or results already wrong (omit for Local)
     rules that must hold: the assertions
     steps: numbered, each with verify:
     depends on: F-… (or none)
     recorded verdict / confidence / verification: Valid / Confirmed / static
   ```

4. **Plan** — the batches in order, each with its findings and prerequisite;
   a `Correction` batch with the decision it needs
5. **Checked and found sound** — what was examined and what enforces it, at
   `path:line`
6. **Decisions for a human** — inferred rules to confirm, oracles that
   disagree with each other, results already produced wrong and whether to
   correct them, defects someone may choose to accept
7. **Next step** — batch 1, and the hand-off (`templates/plan.<lang>.md` to
   whoever writes the fix); questions that belong to a data-integrity,
   security, reliability, test-gap or deletion review (out of scope here)
8. **Files** — link `dashboard.html` and `report.md` rendered from
   `findings.json`. The output directory holds exactly the set named in
   `SKILL.md` (*Run contract*)

Use the same verdicts, changes and confidence in chat, dashboard and report.
`findings.json` is the record; every chat finding must exist there.

State limitations prominently: static reading does not execute the code, so
results that depend on the server's settings or on data are known only as far
as the repository records them; a traced counterexample shows one wrong result,
not that other inputs are right; and zero findings is not evidence that the
code computes the right results.
