# Report — output formats

**Read when:** CHECKLIST, to deliver a checklist; REPORT, to deliver findings.
Write in the requester's language.

## Checklist deliverable

- First line: how many rules were derived, how many perspectives apply, and
  that suspicions are unverified
- **Rules ledger first** (`reference/rules.md` §2): each rule with its source,
  the edges or paths that must keep it and which to trace; mark `inferred`
  rules as questions for the requester
- Then one section per perspective from `reference/perspectives.md`, most
  important first, listing only the hunt steps no ledger entry covers; list the
  ones judged N/A with a reason
- Each item: the question, concrete modules/files, and an optional
  `initial note (unverified)`
- Close with the recommended starting point and one decision for the requester

## Findings report (chat summary)

1. **First line** — severity counts and review scope; whether the work was
   static or included read-only analysis (history, dependency graph); the
   `Unverified` and `Likely` counts, highlighting High findings. Severity
   counts leave out `FalsePositive` and `NotApplicable`, exactly as the first
   line of `report.md` does
2. **Evidence line** — assessed revision, what was read, the history window
   used, what the reporting agent traced end to end, the scratch directory's
   path (these come from scratch notes, not the record), and what remains
   unknown
   (runtime topology, delivery semantics, ownership)
3. **Findings, by severity** — each as:

   ```
   [High|Medium|Low|Info][Confirmed|Environment-dependent|Suspected] one-line title
     location: path:line at the assessed revision
     scenario: the core flow or change scenario that pays for it
     blast radius: modules, files, stores or clients reached, with counts
     trace: numbered steps (dependency path, writers, failure point, change walk)
     contrast: the module or path that keeps the rule, path:line (or "none")
     expected vs actual: the rule; what the code does and its consequence
     recorded verdict / verification: Valid … / static or analysed
     fix direction: one line — the rule restored, smallest change first
     guard: at least one fitness function or test
   ```

4. **Checked and sound** — what was examined and held
5. **Decisions for a human** — inferred rules to confirm, documented intent that
   the code contradicts, trade-offs to accept
6. **Next step** — the fix order (core-flow defects first, then hotspots), and
   which guards to add so the rules stay kept
7. **Files** — link `dashboard.html` and `report.md` rendered from
   `findings.json` (`reference/findings-schema.md`). The output directory holds
   exactly the set named in `SKILL.md` (*Run contract*)

Use the same verdicts, confidence and verification basis in chat, dashboard
and report. `findings.json` is the record; every chat finding must exist there.

State limitations prominently: static reading does not show runtime topology
or delivery semantics, history shows co-change but not intent, and zero
findings is not evidence that the design will absorb changes no one has made
yet.
