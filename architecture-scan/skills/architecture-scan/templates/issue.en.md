<!--
Files one finding as one issue (one root cause = one fix location or design decision = one issue).
Copy each {{field}} from the field of the same name in findings.json. Delete optional lines left empty.

Before filing:
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
| Verdict | {{validation.verdict}} (method: {{validation.method}}) |
| Perspective | {{category}} ({{step}}) |
| Location | `{{location}}` |
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
