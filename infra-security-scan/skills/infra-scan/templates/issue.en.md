<!--
Template for filing one finding as one issue (one root cause = one fix location = one issue).
Copy each {{field}} from the same field in findings.json. Delete empty optional rows.

Before filing:
- Never put an unfixed High or Medium in a public issue. Use a private tracker or a Security Advisory
- Mask account IDs, project IDs, bucket names and IP addresses to match the issue's audience
- Never write a secret's value; location and kind only
- No step-by-step intrusion or escalation instructions; express the path as permissions and resource addresses
-->

**Title:** [{{severity}}] {{title}} ({{id}})

## Summary

| Item | Value |
|---|---|
| ID | {{id}} |
| Severity / confidence | {{severity}} / {{confidence}} |
| Verdict | {{validation.verdict}} |
| Perspective | {{category}} |
| Provider | {{provider}} |
| Resources | `{{resources}}` |
| Location | `{{location}}` |
| Attack paths | {{attack_paths}} |
| Benchmark / CWE | {{controls}} / {{cwe}} |
| Revision | {{meta.commit}} |
| Date / assessor | {{meta.date}} / {{meta.assessor}} |

## What happens

{{impact}}

## Attack path (static)

**Entry actor:** {{actor}}

**Edges (each with its `path:line`):**

{{path}}

**Contrast (a sibling configured soundly):** 

<!-- If Environment-dependent, state the assumed setting ({{condition}}) here. -->

## Evidence

{{validation.evidence}}

## Fix direction

{{fix}}

- **Policy-as-code regression guard:** {{regression}}

## References

- [{{references[].title}}]({{references[].url}})

## Open questions

<!-- Conditions configuration cannot show: SCPs / org policies, manual changes, variable values. -->
- 

## Done when

- [ ] The IaC fix is merged and applied
- [ ] The regression policy runs in CI
- [ ] A post-apply plan or snapshot shows the path blocked
