<!--
Files one finding as one issue (one root cause = one fix location = one issue).
Copy each {{field}} from the field of the same name in findings.json. Delete optional lines left empty.

Before filing:
- No personal data values: name fields and use placeholders (<customer email>)
- An unfixed (status: Open) High goes to a private tracker, not a public issue
- This is a technical finding, not a legal opinion. Route compliance questions to counsel or the DPO
-->

**Title:** [{{severity}}] {{title}} ({{id}})

## Summary

| Item | Value |
|---|---|
| ID | {{id}} |
| Severity | {{severity}} |
| Confidence | {{confidence}} (if Environment-dependent, name the setting under *Open questions*) |
| Verdict | {{validation.verdict}} (method: {{validation.method}}) |
| Perspective | {{category}} ({{step}}) |
| Location | `{{location}}` |
| Assessed revision | {{meta.commit}} |
| Date / assessor | {{meta.date}} / {{meta.assessor}} |

## What happens

{{impact}}

- **Personal data:** {{data}}
- **Data subjects:** {{subjects}}
- **Broken commitment:** {{commitment}} — {{commitments[id].statement}} (source: {{commitments[id].source}}; mark it inferred when `inferred` is true)

## Flow

{{flow}}

**Contrast (the flow that keeps the commitment):** {{contrast}}

<!-- List every affected call site; the same root cause stays in one issue. -->

## Evidence

{{validation.evidence}}

## Fix direction

{{fix}}

- **Guard (synthetic data only):** {{guard}}

## References

- [{{references[].title}}]({{references[].url}})

## Open questions

<!-- Conditions static reading cannot show: vendor-side settings, contracts and DPAs, data actually present, deployed regions. -->
- 

## Done when

- [ ] The fix is merged
- [ ] The guard fails before the fix and passes after it, with synthetic data
- [ ] The affected feature still works (positive control)
- [ ] Data already sent or retained before the fix has an owner and a decision (purge, notify, accept)
- [ ] `status` in findings.json is `Fixed`

---

_Technical finding from a static source review, not a legal opinion._
