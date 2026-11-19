# 02 CI Pipeline Run Log

Mockup: `02-ci-pipeline.html`

## Concept

Present each scan as 1 CI run. Include the following elements.

- Stage graph (RECON → CHECKLIST → REVIEW → VERIFY → REPORT)
- Summary by severity
- Matrix by perspective
- An annotation for each finding (file:line)
- A log that traces 1 finding through the stages

## Why It Fits agentic-scan

- The LP shows the stages from each skill's README as a `.pipe`. This design makes those stages the structure of the report.
- The VERIFY in 「読んで、反証してから、渡す」 is visible as a distinct stage. The VERIFY stage shows the verdict breakdown (Valid 2 · Likely 1 · Unverified 3 · FalsePositive 1).
- Treat perspectives as matrix jobs. File handling is marked 「対象外」 and styled as a skipped job. Readers can see at a glance what was left unchecked.
- Use red only for High, following the LP rule. Symbols use severity colors or ink, dropping the usual CI convention of green for success.

## Adapting It to Other Skills

- Use the stage names from each skill's README. According to the LP, bug-scan has 8 stages and ux-scan has 6, including FLOWS. To accommodate different stage counts, change only the number of grid columns in the graph.
- Limit each one-line stage summary to values that can be derived mechanically from `findings.json` (counts and verdict breakdowns). Durations and job numbers are absent from the records and are omitted.
- The annotation format (file:line + title + ID · verdict · status) can be shared across all skills. It also maps readily to SARIF exports.

## Changes and Estimated Effort for the Existing render.py / dashboard.css

- Replace the current dashboard hero and cards with the stage graph and a summary box. Replace the register table with the annotation list or retain the table.
- Use CSS to style expanded details (`tr.detail`) as a log with line numbers.
- Add per-stage summary values to the payload. This calls for roughly 1 additional dictionary in `render_dashboard()` in render.py.
- Replacing the CSS and HTML template takes 1–2 days per skill. With shared components, the second and subsequent skills take less time.
- The README is the only source of truth for stage names and order. `findings.json` has no stage records. Displaying stages requires per-skill constants.

## Limitations

- Every stage reads 「完了」, so the graph itself conveys no information. Only the VERIFY breakdown varies.
- Readers unfamiliar with CI interfaces may miss the run, matrix, and annotation metaphors.
- Too close a resemblance to an existing CI interface can make the report look like another company's service. This mockup avoids matching any specific service's brand name, colors, or icons.
