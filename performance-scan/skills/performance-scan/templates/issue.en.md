<!--
Files one finding as one issue (one root cause = one fix location = one issue).
scripts/issues.py fills this template from findings.json; edit its drafts rather than starting here.
Copy each {{field}} from the field of the same name in findings.json. Delete optional lines left empty,
and a whole section (heading included) when all of it is empty, e.g. References with no references.
Wrap code identifiers in backticks (`*sql.Tx`, `order_items`) so Markdown keeps * and _ literal.
Write each location in backticks, separated by <br> in the table cell; split {{request}} into one line
per numbered step. If confidence is Environment-dependent, name the condition and threshold
(from scale_driver or impact) under Open questions, with the related limitations items.
Write the perspective without "()" when step is absent, UNKNOWN for an empty meta.commit, one
path:line per line when location is a list, and the URL as the link text when a reference title is blank.

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
| Confidence | {{confidence}} |
| Verdict | {{validation.verdict}} (method: {{validation.method}}) |
| Perspective | {{category}} ({{step}}) |
| Location | {{location}} |
| Assessed revision | {{meta.commit}} |
| Date / assessor | {{meta.date}} / {{meta.assessor}} |

## What happens

{{impact}}

- **Workload:** {{workload}}
- **Scale driver:** {{scale_driver}}
- **Cost model:** {{cost_model}}
- **Violated budget:** {{budget}} — {{budgets[id=budget].statement}}

## Static reproduction

{{request}}

**Contrast (the path that keeps the budget):** {{contrast}}

<!-- List every affected entry point here; the same root cause stays in one issue. For a stalled
shared resource, name the workload that causes the stall and the workloads that wait on it. -->

## Evidence

{{validation.evidence}}

<!-- If measured, remove the comment markers and keep this block (environment: {{measurement.environment}}); otherwise delete it
## Measurement log

Before: {{measurement.before.result}}

```text
$ {{measurement.before.command}}
{{measurement.before.log}}
```

After: {{measurement.after.result}}

```text
$ {{measurement.after.command}}
{{measurement.after.log}}
```
-->

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
- [ ] `status` in findings.json is `Fixed` (`findings.py set … --status Fixed`)
