<!--
Files one finding as one issue (one remedy = one issue).
Copy each {{field}} from the field of the same name in findings.json. Delete optional lines left empty,
and a section whose lines are all deleted (a Low finding may have no enforcement today, exposure, invariants or steps);
then drop the Done-when items that name a deleted section.
- {{location}}: one code span per location, comma-separated
- {{invariants}}: one bullet per invariant
- {{steps}}: keep the numbered steps and their verify: lines, one per line
- {{enforcement.sites}}: one code span per site
- {{depends_on}}: the finding IDs (`F-…`), which whoever files the issues replaces with links to them, or "none"
- ({{step}}): optional; when absent, delete it with its parentheses and keep the perspective

Before filing:
- Never file a FalsePositive or NotApplicable finding
- Text copied from the repo can hold @mentions and owner/repo#N links that notify people when filed:
  put such text in code spans
- A Likely, Unverified or Unlikely finding is not written as established: say what is still open
- State how the data can be corrupted, lost or locked and the exposure evidence, not a list of missing constraints
- Source excerpts, table names and row counts carry the repository's confidentiality
-->

**Title:** [data][{{severity}}/{{rollout}}] {{title}} ({{id}})

## Summary

| Item | Value |
|---|---|
| ID | {{id}} |
| Severity (exposure) / rollout / effort | {{severity}} / {{rollout}} / {{effort}} |
| Rollout reason | {{rollout_reason}} |
| Confidence / verdict | {{confidence}} / {{validation.verdict}} (verification: {{validation.method}}) |
| Hazard → remedy | {{hazard}} → {{remedy}} |
| Perspective | {{category}} ({{step}}) |
| Location | {{location}} |
| Assessed revision / history window | {{meta.commit}} / {{meta.window}} |

## What can happen to the data

{{impact}}

- **Exposure:** {{exposure}}
- **Scenario:** {{scenario}}
- **Blast radius:** {{blast_radius}}

## Trace

{{trace}}

## Enforcement today

- **Net:** {{enforcement.net}}
- **Sites:** {{enforcement.sites}}
- **Gaps:** {{enforcement.gaps}}

## Invariants

{{invariants}}

## Fix direction

{{fix}}

## Steps (each one deploy or less; production keeps working after each)

{{steps}}

- **Depends on:** {{depends_on}}

## Evidence

{{validation.evidence}}

## Done when

- [ ] Every invariant above is enforced by the schema or by every write path, merged with the build and tests green
- [ ] Each new constraint or lock was seen refusing the bad write it is for, on a staging copy or a disposable database
- [ ] Each step shipped without blocking writes beyond what the rollout allows; existing rows that looked wrong are filed separately
- [ ] `status` in findings.json is `Fixed` through a fragment merged with `findings.py merge`, then rendered and checked
