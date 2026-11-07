<!--
`scripts/drafts.py` fills this template from findings.json by these rules; check its output, then write what
no field holds.
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
Since the assessment: Fixed {{n_fixed}}, Accepted {{n_accepted}} (included in the counts above, which describe the assessed revision).

## 2. Scope and method

| Item | Value |
|---|---|
| System | {{meta.project}} |
| Scope | {{meta.scope}} |
| Revision | {{meta.commit}} | <!-- UNKNOWN when meta.commit is absent, as report.md shows it -->
| Method | {{meta.method}} | <!-- without meta.method, copy the method line under report.md's title -->
| Date / assessor | {{meta.date}} / {{meta.assessor}} |

No code was changed and the application was not run.
<!-- If GUARD ran, replace the sentence above: name the fitness function added, where it lives, and whether a fix was applied. -->

## 3. Findings to act on first

<!-- The High and Medium findings whose verdict is not FalsePositive or NotApplicable, in severity order;
repeat the block per finding and link the issue filed from templates/issue.en.md. Low and Info stay in the
attached report.md. -->

### {{id}}: {{title}}

- **Severity / confidence / verdict:** {{severity}} / {{confidence}} / {{validation.verdict}}
- **Location:** {{location}} <!-- one code span per location, comma-separated -->
- **Scenario / blast radius:** {{scenario}} / {{blast_radius}}
- **What happens:** {{impact}}
- **Fix direction:** {{fix}}
- **Guard:** {{guard}}
- **Tracked in:** {{issue}} <!-- the recorded issue; `<issue URL>` until `findings.py triage --issue` records it -->

## 4. Architecture: before and after

<!-- Copy both ```mermaid blocks and the change list from report.md's architecture section unchanged, so the
report shows the same graph as the dashboard. Before is the assessed revision with the edges the findings cite
in red; after is the same graph with the fix directions applied. Say in one line what the after diagram
changes, e.g. "The refund job stops writing invoices and goes through billing." -->

### Before

### After

### What changes

- 

## 5. Design rules

<!-- rules[]: each rule, its source and status. Inferred rules are questions for the owner; a baseline
entry (source `baseline…`) is a general family rule, not a question. -->
- 

## 6. Checked and sound

<!-- checked_ok: what was examined and held. -->
- 

## 7. What could not be checked

<!-- limitations: runtime topology, delivery semantics, team ownership, roadmap. -->
- 

## 8. Decisions needed

<!-- decisions: rules to confirm, documented intent the code contradicts, trade-offs. -->
- 

## 9. Recommended order of work

<!-- next_steps. -->
1. 

## Attachments

- `report.md` — the written assessment, with the before and after architecture diagrams
- `dashboard.html` — every finding, works offline
