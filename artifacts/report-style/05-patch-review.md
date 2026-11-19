# 05 Patch Review

## Concept

Read findings as a file-by-file patch review. Start with the file list on the left, then move to the hunk heading, evidence of the current behavior, and proposed fix on the right.

## Why It Fits agentic-scan

Set `r--`, finding IDs, paths, and verification verdicts in monospace, and Japanese text in Gothic type. Pair symbols with headings, using `−` for evidence and `+` for fix direction. Use the LP's `--mark` for fix direction and `--high` for High. The list also shows the verdict for the false positive F-004.

## Adapting It to Other Skills

- **ux-scan** puts screen and component names where file paths would go, and pairs the observed state with proposed design changes.
- **bug-scan** puts affected files and lines and the evidence in the hunk, and maps the recorded cause to the fix and recurrence prevention measures. If 1 finding spans multiple files, list the locations under the same finding ID.

## Integration and Effort

**Medium, about 1–2 person-days** (initial integration and verification in security-scan). In `DASHBOARD` in `render.py`, restructure the list and lazily expanded details as a file list and hunks. Connect the existing filters, anchors, and expansion and focus handling. For the PDF, use the same heading structure in the finding bodies in `render_assessment_html()`. Add LP-derived tokens, a responsive switch from 2 columns to 1, and hunk and print styles to each `dashboard.css`. Use the existing model for counts and verification verdicts.

## Limitations

`−` and `+` can look like actual removed and added lines, so each block needs a heading. The patch metaphor is less effective for findings whose causes span multiple files or proposals that cannot be reduced to a single edit.
