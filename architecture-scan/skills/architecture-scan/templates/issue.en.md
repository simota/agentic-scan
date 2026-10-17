<!--
Files one finding as one issue (one root cause = one fix location or design decision = one issue).
Copy each {{field}} from the field of the same name in findings.json. Delete optional lines left empty, and a
section whose only content is empty (e.g. References when the finding has none).
- {{location}}: one code span per location, comma-separated
- ({{step}}): drop the parentheses when the finding has no step
- {{rule}}: each ID, then the statement and source from the rules[] entry with that id
- {{trace}}: keep the numbered steps, one per line
- {{meta.commit}}: UNKNOWN when meta.commit is absent, as report.md shows it; keep the row
- {{references[].title}}: the URL when the title is absent or empty, as report.md labels it
- Open questions: no field holds them; write the conditions static reading could not settle

Before filing:
- Never file a FalsePositive or NotApplicable finding
- A Likely, Unverified or Unlikely finding is not written as an established fact: say what was traced and
  what is still open (Open questions)
- State the defect or change cost, not a preference. Link the rule's source (ADR, lint config, majority pattern)
- Source excerpts carry the repository's confidentiality. Leave them out when the issue is
  visible to more people than the repository
-->

**Title:** [{{severity}}] {{title}} ({{id}})

## Summary

| Item | Value |
|---|---|
| ID | {{id}} |
| Severity | {{severity}} |
| Confidence | {{confidence}} (if Environment-dependent, name the condition under *Open questions*) |
| Verdict | {{validation.verdict}} (verification: {{validation.method}}) |
| Perspective | {{category}} ({{step}}) |
| Location | {{location}} |
| Assessed revision | {{meta.commit}} |
| Date / assessor | {{meta.date}} / {{meta.assessor}} |

## What happens

{{impact}}

- **Scenario:** {{scenario}}
- **Blast radius:** {{blast_radius}}
- **Violated rule:** {{rule}}

## Trace

{{trace}}

**Contrast (the module or path that keeps the rule):** {{contrast}}

<!-- List every affected call site or writer here; the same root cause stays in one issue. -->

## Evidence

{{validation.evidence}}

<!-- If analysed: {{analysis.tool}} `{{analysis.command}}` → {{analysis.result}} -->

## Fix direction

{{fix}}

- **Guard (fitness function):** {{guard}}

## References

- [{{references[].title}}]({{references[].url}})

## Open questions

<!-- Conditions static reading cannot show (delivery semantics, runtime topology, intended ownership). -->
- 

## Done when

- [ ] The fix is merged
- [ ] The guard fails on the old structure and passes after the fix
- [ ] Behaviour of the affected flow is unchanged (positive control)
- [ ] `status` in findings.json is `Fixed`
