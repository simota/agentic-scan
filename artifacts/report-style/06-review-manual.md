# 06 Review Specification

## Concept

Follow numbered sections for scan scope, counts, the findings list, and details, as in a man page or RFC. Keep the text at a consistent reading width and connect the list to the details with section links.

## Why It Fits agentic-scan

Use the LP's cool gray, ink-colored rules, and `r--`. Monospace skill names, section numbers, files and lines, and verification verdicts serve as reference points. Evidence and fix direction use Japanese Gothic type. The list explicitly shows the verdict for false positives.

## Adapting It to Other Skills

- **ux-scan** lists screens, viewports, and primary flows in the scan scope, with observation conditions and proposed improvements in the details.
- **bug-scan** puts the originating commit, affected locations, and evidence in the detail definition list. Section anchors and finding IDs can be referenced in review meetings and shared PDFs.

## Integration and Effort

**Small to medium, about 1–1.5 person-days** (initial integration and verification in security-scan). Add section titles and anchors to the existing index and finding bodies in `render_assessment_html()` in `render.py`. Add typography, table-of-contents, rule, narrow-width table, and page-break styles to the PDF's `document.css` and the dashboard's `dashboard.css`. In `DASHBOARD`, reuse the existing section navigation and findings table, and insert section numbers and reference links. Connect search and filtering to the existing UI.

## Limitations

Counts and controls have little visual emphasis. Relying on the table of contents and static list takes more steps when monitoring abrupt changes in counts or filtering repeatedly. At narrow widths, long finding names and paths make table rows taller.
