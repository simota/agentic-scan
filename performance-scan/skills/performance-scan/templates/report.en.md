<!--
Reports performance findings to the owner or a manager. One report can carry several findings.
Copy the counts and each finding from findings.json so the report never disagrees with the dashboard.
Counts are not fields: n_<severity> counts findings of that severity whose verdict is not
FalsePositive/NotApplicable; n_excluded counts the rest; n_likely, n_unverified and n_unlikely count
verdicts among the included findings. "Of which Valid" counts verdict Valid per severity.
Optional fields: write UNKNOWN for an empty meta.commit, and delete lines whose field is absent.

Before sending:
- No latency, throughput or memory figures that were not measured
- Unverified, Likely and Unlikely findings are not written as established facts
-->

**Subject:** [Performance report] {{meta.project}} — {{n_high}} High / {{n_medium}} Medium ({{meta.date}})

## 1. Summary

<!-- Conclusion first, e.g. "The order list issues one query per line item; it will reach the gateway timeout as orders grow." -->


| Severity | Count | Of which Valid |
|---|---|---|
| High | {{n_high}} | |
| Medium | {{n_medium}} | |
| Low | {{n_low}} | |
| Info | {{n_info}} | |

Excluded (FalsePositive / NotApplicable): {{n_excluded}}. Likely: {{n_likely}}. Unverified: {{n_unverified}}. Unlikely: {{n_unlikely}}.

## 2. Scope and method

| Item | Value |
|---|---|
| System | {{meta.project}} |
| Scope | {{meta.scope}} |
| Revision | {{meta.commit}} |
| Method | {{meta.method}} |
| Date / assessor | {{meta.date}} / {{meta.assessor}} |

No load was sent to any deployed environment.

## 3. Findings to act on first

<!-- In severity order; repeat the block per finding and link the issue filed from templates/issue.en.md. -->

### {{id}}: {{title}}

- **Severity / confidence / verdict:** {{severity}} / {{confidence}} / {{validation.verdict}}
- **Location:** `{{location}}`
- **Workload / scale driver:** {{workload}} / {{scale_driver}}
- **Cost model:** {{cost_model}}
- **Impact:** {{impact}}
- **Fix direction:** {{fix}}
- **Tracked in:** <issue URL>

## 4. Budgets

<!-- budgets[]: each bound, its source and status. Inferred bounds are questions for the owner. -->
- 

## 5. Checked and sound

<!-- checked_ok: what was examined and held. -->
- 

## 6. What could not be checked

<!-- limitations: production data volumes, deployed indexes and settings, real traffic mix. -->
- 

## 7. Decisions needed

<!-- decisions: bounds to confirm, trade-offs to accept. -->
- 

## 8. Recommended order of work

<!-- next_steps. -->
1. 

## Attachments

- `report.md` — the written assessment
- `dashboard.html` — every finding, works offline
