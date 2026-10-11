<!--
Template for reporting a prompt review to the owners of the prompts (email, ticket or document).
Copy the counts and each finding from findings.json so the report and the dashboard agree.

Before sending:
- Recipients can read the repository; otherwise remove prompt excerpts
- No working instruction-override string, secret or personal-data value is included
- Unverified / Likely / Unlikely and Model-dependent findings are not stated as settled
-->

**Subject:** [Prompt review] {{meta.target}} — {{n_defect}} defects / {{n_improvement}} improvements ({{meta.date}})

## 1. Summary

<!-- Lead with the conclusion, e.g. "One defect: the answer JSON's field names do not match the parser, so the feature's output is discarded." -->


| Severity | Defects | Improvements |
|---|---|---|
| High | {{n_high_defect}} | {{n_high_improvement}} |
| Medium | {{n_medium_defect}} | {{n_medium_improvement}} |
| Low | {{n_low_defect}} | {{n_low_improvement}} |
| Info | {{n_info_defect}} | {{n_info_improvement}} |

Excluded (FalsePositive / NotApplicable): {{n_excluded}}.

## 2. Target and method

| Item | Value |
|---|---|
| Target | {{meta.target}} |
| Scope | {{meta.scope}} |
| Revision | {{meta.commit}} |
| Date / assessor | {{meta.date}} / {{meta.assessor}} |

This is a static reading of the prompts and the code around them. Prompts were {{"sent to a model as recorded in eval_runs" or "not sent to any model"}}.

## 3. What to fix first

<!-- By severity; repeat the block per finding. Link the issue filed from templates/issue.en.md. -->

### {{id}}: {{title}}

- **Kind / severity / confidence / verdict:** {{kind}} / {{severity}} / {{confidence}} / {{validation.verdict}}
- **Location:** `{{location}}` ({{prompt}})
- **Symptom:** {{symptom}}
- **Impact:** {{impact}}
- **Fix direction:** {{fix}}

## 4. Checked and sound

- {{checked_ok[]}}

## 5. Decisions for a human

- {{decisions[]}}

## 6. Limitations

- {{limitations[]}}

## 7. Next steps

- {{next_steps[]}}

See the attached report.pdf and dashboard.html for every finding.
