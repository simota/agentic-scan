<!--
Files one finding as one issue (one remedy = one issue).
Copy each {{field}} from the field of the same name in findings.json. Delete optional lines left empty,
and a section whose lines are all deleted (a Low finding may have no counterexample, enforcement today, exposure,
rules or steps); then drop the Done-when items that name a deleted section.
- {{location}}: one code span per location, comma-separated
- {{invariants}}: one bullet per rule
- {{steps}}: keep the numbered steps and their verify: lines, one per line
- {{enforcement.sites}}: one code span per site
- {{depends_on}}: the finding IDs (`F-…`), which whoever files the issues replaces with links to them, or "none"
- ({{step}}): optional; when absent, delete it with its parentheses and keep the perspective

Before filing:
- Never file a FalsePositive or NotApplicable finding
- Text copied from the repo can hold @mentions and owner/repo#N links that notify people when filed:
  put such text in code spans
- A Likely, Unverified or Unlikely finding is not written as established: say what is still open
- State the wrong result with its counterexample and the exposure evidence, not a list of style complaints
- Source excerpts, amounts and customer-like values carry the repository's confidentiality
-->

**Title:** [logic][{{severity}}/{{change}}] {{title}} ({{id}})

## Summary

| Item | Value |
|---|---|
| ID | {{id}} |
| Severity (exposure) / change / effort | {{severity}} / {{change}} / {{effort}} |
| Change reason | {{change_reason}} |
| Confidence / verdict | {{confidence}} / {{validation.verdict}} (verification: {{validation.method}}) |
| Defect → remedy | {{hazard}} → {{remedy}} |
| Perspective | {{category}} ({{step}}) |
| Location | {{location}} |
| Assessed revision / history window | {{meta.commit}} / {{meta.window}} |

## Counterexample

- **Input:** {{counterexample.input}}
- **Expected:** {{counterexample.expected}}
- **Actual:** {{counterexample.actual}}
- **Oracle:** {{counterexample.oracle}}

## What goes wrong

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

## Rules that must hold

{{invariants}}

## Fix direction

{{fix}}

## Steps (each ends with the build green; the fix lands with the counterexample as a test)

{{steps}}

- **Depends on:** {{depends_on}}

## Evidence

{{validation.evidence}}

## Done when

- [ ] The counterexample is a test that fails with the fix reverted and passes with it, merged with the build and tests green
- [ ] Every rule above is asserted by a test, including the boundary values the counterexample sits on
- [ ] Every caller whose result changes was checked, and results already produced wrong are filed as a decision, not rewritten in passing
- [ ] `status` in findings.json is `Fixed` through a fragment merged with `findings.py merge`, then rendered and checked
