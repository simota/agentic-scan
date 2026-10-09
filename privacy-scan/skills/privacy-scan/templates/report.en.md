<!--
Reports privacy findings to the owner, a DPO or a manager. One report can carry several findings.
Copy the counts and each finding from findings.json so the report never disagrees with the dashboard.

Before sending:
- No personal data values anywhere; field names and placeholders only
- Unverified, Likely and Unlikely findings are not written as established facts
- The report is a technical review, not legal advice
-->

**Subject:** [Privacy report] {{meta.project}} — {{n_high}} High / {{n_medium}} Medium ({{meta.date}})

## 1. Summary

<!-- Conclusion first, e.g. "Checkout errors send customers' addresses to the error tracker; turn request capture off before anything else." -->


| Severity | Count | Of which Valid |
|---|---|---|
| High | {{n_high}} | |
| Medium | {{n_medium}} | |
| Low | {{n_low}} | |
| Info | {{n_info}} | |

Excluded (FalsePositive / NotApplicable): {{n_excluded}}. Unverified: {{n_unverified}}.

## 2. Scope and method

| Item | Value |
|---|---|
| System | {{meta.project}} |
| Scope | {{meta.scope}} |
| Revision | {{meta.commit}} |
| Method | {{meta.method}} |
| Date / assessor | {{meta.date}} / {{meta.assessor}} |

Source code was read; no data store, log or backup was accessed. This is a technical review, not legal advice.

## 3. Findings to act on first

<!-- In severity order; repeat the block per finding and link the issue filed from templates/issue.en.md. -->

### {{id}}: {{title}}

- **Severity / confidence / verdict:** {{severity}} / {{confidence}} / {{validation.verdict}}
- **Location:** `{{location}}`
- **Personal data / subjects:** {{data}} / {{subjects}}
- **Impact:** {{impact}}
- **Fix direction:** {{fix}}
- **Tracked in:** <issue URL>

## 4. Commitments

<!-- commitments[]: each commitment, its source and status. Inferred commitments are questions for the owner. -->
- 

## 5. Checked and sound

<!-- checked_ok: what was examined and held. -->
- 

## 6. What could not be checked

<!-- limitations: vendor-side settings, contracts, data actually present, deployed regions. -->
- 

## 7. Decisions needed

<!-- decisions: commitments to confirm, recipients whose contracts are unknown, data already sent or retained. -->
- 

## 8. Recommended order of work

<!-- next_steps. -->
1. 

## Attachments

- `report.md` — the written assessment
- `dashboard.html` — every finding, works offline
