<!--
Template for reporting several findings to infrastructure owners or a security contact (email, private ticket).
Copy findings from findings.json. Count from findings.json too: n_* excludes FalsePositive /
NotApplicable findings and I-* findings covered by an F-* (the dashboard summary shows the same counts).

Before sending:
- The recipients may see the accounts / projects concerned
- No secret values, no intrusion steps
- Unverified / Likely / Unlikely findings are not stated as established
-->

**Subject:** [Infrastructure assessment] {{meta.project}} — High {{n_high}} / open attack paths {{n_open_paths}} ({{meta.date}})

## 1. Summary

<!-- One-line conclusion first. E.g. "Any GitHub repository can assume the production deploy role." -->


| Severity | Count | Of which Valid |
|---|---|---|
| High | {{n_high}} | |
| Medium | {{n_medium}} | |
| Low | {{n_low}} | |
| Info | {{n_info}} | |

Excluded (FalsePositive / NotApplicable): {{n_excluded}}. Covered by a review finding: {{n_covered}}. Unverified: {{n_unverified}}.

## 2. Scope and method

| Item | Value |
|---|---|
| Target | {{meta.project}} |
| Scope (accounts / projects / environments) | {{meta.scope}} |
| Inputs | {{meta.inputs}} |
| Revision | {{meta.commit}} |
| Method | {{meta.method}} |
| Date / assessor | {{meta.date}} / {{meta.assessor}} |

This was a static review of configuration. No cloud API was called and no deployed resource was contacted.

## 3. Open attack paths

<!-- attack_paths with status: open only. Entry → target, and the findings that open it. -->
- **{{attack_paths[].id}}:** {{attack_paths[].entry}} → {{attack_paths[].target}} ({{attack_paths[].findings}})

## 4. Fix first

<!-- High and Medium findings in severity order, three to five lines each. -->
### {{id}} [{{severity}}] {{title}}

- **Resource / location:** `{{resources}}` / `{{location}}`
- **Entry actor:** {{actor}}
- **Impact:** {{impact}}
- **Fix:** {{fix}}

## 5. Checked and sound

{{checked_ok}}

## 6. Decisions needed

{{decisions}}

## 7. Limitations

{{limitations}}

## 8. Next steps

{{next_steps}}

Attached: dashboard.html, assessment.pdf
