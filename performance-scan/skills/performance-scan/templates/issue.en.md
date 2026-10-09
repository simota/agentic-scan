<!--
Files one finding as one issue (one root cause = one fix location = one issue).
Copy each {{field}} from the field of the same name in findings.json. Delete optional lines left empty.

Before filing:
- No latency or memory figures that were not measured. Give the cost model instead
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

- **Workload:** {{workload}}
- **Scale driver:** {{scale_driver}}
- **Cost model:** {{cost_model}}
- **Violated budget:** {{budget}}

## Static reproduction

{{request}}

**Contrast (the path that keeps the budget):** {{contrast}}

<!-- List every affected entry point here; the same root cause stays in one issue. -->

## Evidence

{{validation.evidence}}

<!-- If measured: {{measurement.command}} on {{measurement.environment}} → {{measurement.result}} -->

## Fix direction

{{fix}}

- **Regression test asserts:** {{regression_test}}

## References

- [{{references[].title}}]({{references[].url}})

## Open questions

<!-- Conditions static reading cannot show (production data volume, deployed indexes, pool sizes). -->
- 

## Done when

- [ ] The fix is merged
- [ ] A deterministic regression check fails before the fix and passes after it
- [ ] The result of the affected path is unchanged (positive control)
- [ ] `status` in findings.json is `Fixed`
