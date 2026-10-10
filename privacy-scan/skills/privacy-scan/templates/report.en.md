<!--
Reports privacy findings to the owner, a DPO or a manager. One report can carry several findings.
Copy each finding from findings.json, verbatim and in the record's language, so the report never disagrees
with the dashboard. Take every {{n_…}} count from `python3 scripts/findings.py counts <out>/findings.json`
(severity counts cover reported findings; excluded ones are counted separately). Delete optional lines left
empty. Write <to fill in> where the record has no source (issue URLs, decisions on data already sent).

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
| High | {{n_high}} | {{n_high_valid}} |
| Medium | {{n_medium}} | {{n_medium_valid}} |
| Low | {{n_low}} | {{n_low_valid}} |
| Info | {{n_info}} | {{n_info_valid}} |

Excluded (FalsePositive / NotApplicable): {{n_excluded}}. Not yet verified — Likely: {{n_likely}}, Unverified: {{n_unverified}}, Unlikely: {{n_unlikely}}.

## 2. Scope and method

| Item | Value |
|---|---|
| System | {{meta.project}} |
| Scope | {{meta.scope}} |
| Revision | {{meta.commit}} |
| Method | {{meta.method}} (when absent, the review-method line of report.md) |
| Date / assessor | {{meta.date}} / {{meta.assessor}} |

Source code was read; no data store, log or backup was accessed. This is a technical review, not legal advice.

## 3. Findings to act on first

<!-- Every reported High and Medium finding, in ID order; repeat the block per finding and link the issue filed from templates/issue.en.md. -->

### {{id}}: {{title}}

- **Severity / confidence / verdict:** {{severity}} / {{confidence}} / {{validation.verdict}}
- **Location:** `{{location}}`
- **Personal data / subjects:** {{data}} / {{subjects}}
- **Broken commitment:** {{commitment}} — {{commitments[id].statement}}
- **Conditions (Environment-dependent only):** {{conditions}}
- **Impact:** {{impact}}
- **Fix direction:** {{fix}}
- **Guard:** {{guard}}
- **Data already sent or retained:** <to fill in: owner and decision (purge, notify, accept)>
- **Tracked in:** <to fill in: issue URL>

## 4. Commitments

<!-- commitments[]: id, statement, family, source and status, with the reason whenever one is recorded (required for not checked); mark inferred ones, which are questions for the owner. -->
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
