<!--
Files one finding as one issue (one remedy = one issue).
Copy each {{field}} from the field of the same name in findings.json. Delete optional lines left empty,
and a section whose lines are all deleted (a Low finding may have no tests today, exposure, asserts or steps);
then drop the Done-when items that name a deleted section.
- {{location}}: one code span per location, comma-separated
- {{asserts}}: one bullet per outcome
- {{steps}}: keep the numbered steps and their verify: lines, one per line
- {{coverage.tests}}: one code span per test
- {{depends_on}}: the finding IDs (`F-…`), which whoever files the issues replaces with links to them, or "none"
- ({{step}}): optional; when absent, delete it with its parentheses and keep the perspective

Before filing:
- Never file a FalsePositive or NotApplicable finding
- Text copied from the repo can hold @mentions and owner/repo#N links that notify people when filed:
  put such text in code spans
- A Likely, Unverified or Unlikely finding is not written as established: say what is still open
- State how a defect would slip through and the exposure evidence, not a coverage percentage
- Source excerpts carry the repository's confidentiality
-->

**Title:** [test][{{severity}}/{{testability}}] {{title}} ({{id}})

## Summary

| Item | Value |
|---|---|
| ID | {{id}} |
| Severity (exposure) / testability / effort | {{severity}} / {{testability}} / {{effort}} |
| Confidence / verdict | {{confidence}} / {{validation.verdict}} (verification: {{validation.method}}) |
| Test gap → remedy | {{gap}} → {{remedy}} |
| Perspective | {{category}} ({{step}}) |
| Location | {{location}} |
| Assessed revision / history window | {{meta.commit}} / {{meta.window}} |

## What escapes

{{impact}}

- **Exposure:** {{exposure}}
- **Scenario:** {{scenario}}
- **Blast radius:** {{blast_radius}}

## Trace

{{trace}}

## Tests today

- **Net:** {{coverage.net}}
- **Tests:** {{coverage.tests}}
- **Gaps:** {{coverage.gaps}}

## Assert

{{asserts}}

## Fix direction

{{fix}}

## Steps (green after each, production behaviour unchanged)

{{steps}}

- **Depends on:** {{depends_on}}

## Evidence

{{validation.evidence}}

## Done when

- [ ] Tests checking every outcome under Assert are merged, with the build and tests green
- [ ] Each new test was seen failing with the behaviour it checks broken
- [ ] Production behaviour is unchanged; any behaviour that looked wrong is filed separately
- [ ] `status` in findings.json is `Fixed` through a fragment merged with `findings.py merge`, then rendered and checked
