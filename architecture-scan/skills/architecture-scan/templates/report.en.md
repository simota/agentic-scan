<!--
Reports design findings to the owner, a tech lead or a manager. One report can carry several findings.
Copy the counts and each finding from findings.json so the report never disagrees with the dashboard.

Before sending:
- Each finding states a defect or a change cost backed by evidence, not a preference
- Unverified, Likely and Unlikely findings are not written as established facts
-->

**Subject:** [Architecture report] {{meta.project}} — {{n_high}} High / {{n_medium}} Medium ({{meta.date}})

## 1. Summary

<!-- Conclusion first, e.g. "Invoices have two writers and the refund path skips the tax rules; route it through billing first." -->


| Severity | Count | Of which Valid |
|---|---|---|
| High | {{n_high}} | |
| Medium | {{n_medium}} | |
| Low | {{n_low}} | |
| Info | {{n_info}} | |

Excluded (FalsePositive / NotApplicable): {{n_excluded}}. Likely: {{n_likely}}. Unverified: {{n_unverified}}.

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

<!-- In severity order; repeat the block per finding and link the issue filed from templates/issue.en.md. -->

### {{id}}: {{title}}

- **Severity / confidence / verdict:** {{severity}} / {{confidence}} / {{validation.verdict}}
- **Location:** `{{location}}`
- **Scenario / blast radius:** {{scenario}} / {{blast_radius}}
- **Impact:** {{impact}}
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
