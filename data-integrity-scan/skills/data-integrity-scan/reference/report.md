# Report — output formats

**Read when:** CHECKLIST, to deliver a checklist; REPORT, to deliver findings.
Write in the requester's language.

## Checklist deliverable

- First line: how many core tables, writers, rules and applicable
  perspectives, and that suspicions are unverified
- **Core-table and writer tables first** (`reference/recon.md` §2–§4): each
  core table with every writer, the schema source of truth and the deploy
  order, the fix commits that touched data code, the migrations changed in
  the window, and the history window
- **Data rule ledger** (`reference/conventions.md` §2): each rule with its
  source and counts; `inferred` rules as questions for the requester
- Then one section per applicable perspective from
  `reference/perspectives.md`, ordered by where the core tables are, listing
  hunt steps with concrete files and an optional `initial note (unverified)`
- Close with the recommended starting unit and one decision for the requester

## Findings report (chat summary)

1. **First line** — when the history is missing, shallow or squashed, that
   first (`reference/recon.md` §2); then, from `scripts/findings.py counts`,
   severity counts, the rollout mix (`Online`/`Staged`/`Downtime`), the
   number of plan batches, review scope, and the `Unverified`, `Likely` and
   `Unlikely` counts. Counts leave out `FalsePositive` and `NotApplicable`
2. **Evidence line** — assessed revision, history window and whether it is
   usable, core tables and writers traced, units read, the scratch
   directory's path, and what remains unknown (table sizes, the deploy order,
   schema held in another repository, production settings)
3. **Findings, by severity** — each as:

   ```
   [High|Medium|Low|Info][Online|Staged|Downtime][S|M|L] one-line title
     location: path:line at the assessed revision
     hazard → remedy: Orders can reference deleted customers → Add Foreign Key
     exposure: the core table, write paths, fix hashes that patched its data, size
     enforcement today: net; path:line of each constraint or check; gaps
     rollout reason: what forces Staged or Downtime (omit for Online)
     invariants: the statements that must hold
     steps: numbered, each with verify:
     depends on: F-… (or none)
     recorded verdict / confidence / verification: Valid / Confirmed / static
   ```

4. **Plan** — the batches in order, each with its findings and prerequisite;
   a `Downtime` batch with the window it needs
5. **Checked and found sound** — what was examined and what enforces it, at
   `path:line`
6. **Decisions for a human** — inferred rules to confirm, existing rows that
   look wrong (reported, never rewritten in passing), who owns orphaned or
   duplicated data, hazards someone may choose to accept
7. **Next step** — batch 1, and the hand-off (`templates/plan.<lang>.md` to
   whoever writes the fix); questions that belong to an architecture,
   performance, privacy, test-gap or deletion review (out of scope here)
8. **Files** — link `dashboard.html` and `report.md` rendered from
   `findings.json`. The output directory holds exactly the set named in
   `SKILL.md` (*Run contract*)

Use the same verdicts, rollouts and confidence in chat, dashboard and report.
`findings.json` is the record; every chat finding must exist there.

State limitations prominently: static reading does not connect to a
database, so table sizes, production settings and the data already stored are
known only as far as the repository records them; a constraint that looks
right is not proven until it is seen refusing a bad row; and zero findings is
not evidence that the data cannot be corrupted, lost or locked.
