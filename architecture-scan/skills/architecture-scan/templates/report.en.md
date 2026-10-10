<!--
Reports design findings to the owner, a tech lead or a manager. One report can carry several findings.
Copy the counts and each finding from findings.json so the report never disagrees with the dashboard.
Every {{n_*}} value comes from `python3 scripts/findings.py counts <out>/findings.json`, counted as the
counts line under report.md's title: excluded verdicts (FalsePositive, NotApplicable) are not counted.

Before sending:
- Each finding states a defect or a change cost backed by evidence, not a preference
- Unverified, Likely and Unlikely findings are not written as established facts
-->

**Subject:** [Architecture report] {{meta.project}} — {{n_high}} High / {{n_medium}} Medium ({{meta.date}})

## 1. Summary

<!-- Conclusion first, e.g. "Invoices have two writers and the refund path skips the tax rules; route it through billing first." -->


| Severity | Count | Of which Valid |
|---|---|---|
| High | {{n_high}} | {{n_high_valid}} |
| Medium | {{n_medium}} | {{n_medium_valid}} |
| Low | {{n_low}} | {{n_low_valid}} |
| Info | {{n_info}} | {{n_info_valid}} |

Excluded (FalsePositive / NotApplicable): {{n_excluded}}. Likely: {{n_likely}}. Unverified: {{n_unverified}}. Unlikely: {{n_unlikely}}.

## 2. Scope and method

| Item | Value |
|---|---|
| System | {{meta.project}} |
| Scope | {{meta.scope}} |
| Revision | {{meta.commit}} |
| Method | {{meta.method}} |
| Date / assessor | {{meta.date}} / {{meta.assessor}} |

No code was changed and the application was not run.

## 3. Findings to act on first

<!-- The High and Medium findings, in severity order; repeat the block per finding and link the issue filed
from templates/issue.en.md. Low and Info stay in the attached report.md. -->

### {{id}}: {{title}}

- **Severity / confidence / verdict:** {{severity}} / {{confidence}} / {{validation.verdict}}
- **Location:** `{{location}}`
- **Scenario / blast radius:** {{scenario}} / {{blast_radius}}
- **What happens:** {{impact}}
- **Fix direction:** {{fix}}
- **Guard:** {{guard}}
- **Tracked in:** <issue URL>

## 4. Design rules

<!-- rules[]: each rule, its source and status. Inferred rules are questions for the owner. -->
- 

## 5. Checked and sound

<!-- checked_ok: what was examined and held. -->
- 

## 6. What could not be checked

<!-- limitations: runtime topology, delivery semantics, team ownership, roadmap. -->
- 

## 7. Decisions needed

<!-- decisions: rules to confirm, documented intent the code contradicts, trade-offs. -->
- 

## 8. Recommended order of work

<!-- next_steps. -->
1. 

## Attachments

- `report.md` — the written assessment
- `dashboard.html` — every finding, works offline
