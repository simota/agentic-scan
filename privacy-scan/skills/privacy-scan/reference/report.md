# Report — output formats

**Read when:** CHECKLIST, to deliver a checklist; REPORT, to deliver findings.
Write in the requester's language. Never include personal data values in any
deliverable here — checklist notes included; name fields and use placeholders.

## Checklist deliverable

Delivered in chat; write a file only when the requester asks for one (no
output directory is needed).

- First line: how many commitments were derived (baseline entries included),
  how many perspectives apply, that suspicions are unverified, and that this is
  not legal advice
- **Commitments ledger first** (`reference/commitments.md` §2): each commitment
  with its source, the flows that must keep it and which to trace; mark
  `inferred` commitments as questions for the requester. Leave *Status* out:
  nothing has been checked yet
- Then one section for every perspective in `reference/perspectives.md`, most
  important first: the hunt steps no ledger entry covers, and the steps judged
  N/A with a reason (a perspective fully covered by the ledger says so in one
  line)
- Each item: the question, concrete files and flows, and an optional
  `initial note (unverified)`
- Close with the recommended starting point and one decision for the requester

## Findings report (chat summary)

1. **First line** — severity counts and review scope; that the review was
   static, read no data store and is not legal advice; the `Unverified` and
   `Likely` counts, highlighting High findings
2. **Evidence line** — assessed revision, what was read, which commitments and
   regulations were the reference, what the reporting agent traced end to end,
   and what remains unknown (vendor settings, contracts, data present, regions)
3. **Findings, by severity** — each as:

   ```
   PV-NNN [High|Medium|Low|Info][Confirmed|Environment-dependent|Suspected] one-line title
     location: path:line at the assessed revision
     data: elements by field name and category
     subjects: whose data, and which of them
     flow: numbered steps from collection to sink, with when
     contrast: the flow that keeps the commitment, path:line (or "none")
     expected vs actual: the commitment; what the code does and who receives the data
     recorded verdict / verification: Valid … / static or analysed
     fix direction: one line — the commitment restored and where
     guard: at least one check with synthetic data
   ```

4. **Checked and sound** — what was examined and held
5. **Decisions for a human** — inferred commitments to confirm, recipients
   whose contracts are unknown, retention periods to set
6. **Next step** — the fix order (sensitive categories and third-party flows
   first, then deletion gaps), and which guards to add
7. **Files** — link `dashboard.html` and `report.md` rendered from
   `findings.json` (`reference/findings-schema.md`). The output directory holds
   exactly the set named in `SKILL.md` (*Run contract*)
8. **Scratch** — the path of the scratch directory holding the data map,
   ledger, flow rows and fragments (`SKILL.md`, *Run contract*)

Use the same verdicts, confidence and verification basis in chat, dashboard
and report. `findings.json` is the record; every chat finding must exist there.
Never include personal data values anywhere; name fields and use placeholders.

State limitations prominently: static reading does not show data actually
present or vendor-side configuration, the review is not a legal opinion, and
zero findings is not evidence of compliance.
