<!--
File one finding as one issue (one root cause = one fix location = one issue).
Copy each {{field}} from the same field in findings.json. By hand, delete a table row or section whose fields are all empty and write — in any other empty field.
scripts/export.py issues fills this template for every finding and drops the comments, empty rows and empty sections.

Before filing:
- Do not write a working instruction-override (jailbreak or injection) string; name the weakness and the variable
- Do not write secret or personal-data values; give location and kind only
- Prompt text carries the repository's confidentiality; omit excerpts if the issue is visible more widely
-->

**Title:** [{{severity}}][{{kind}}] {{title}} ({{id}})

## Summary

| Item | Value |
|---|---|
| ID | {{id}} |
| Kind | {{kind}} (defect / improvement) |
| Severity | {{severity}} |
| Confidence | {{confidence}} (if Model-dependent, the eval case under "How to check" settles it) |
| Verdict | {{validation.verdict}} (method: {{validation.method}}) |
| Perspective | {{category}} |
| Prompt | {{prompt}} |
| Location | `{{location}}` |
| Revision | {{meta.commit}} |
| Date / assessor | {{meta.date}} / {{meta.assessor}} |

## Symptom

{{symptom}}

## Cause

{{cause}}

## Impact

{{impact}}

## Fix direction

{{fix}}

## Proposal

<!-- Required for improvements; include for defects when a rewrite exists. -->

Current:

```
{{proposal.before}}
```

Proposed:

```
{{proposal.after}}
```

## How to check

<!-- The eval case (input, expected property of the output, how it is judged) or test assertion. -->
{{test}}

## Evidence

{{validation.evidence}}

## Done when

- [ ] The fix is merged
- [ ] The eval case or test under "How to check" is added and passes after the fix
- [ ] Existing eval cases for the same prompt still pass
- [ ] `status` in findings.json is `Fixed` (eval runs are recorded separately in `eval_runs`)
