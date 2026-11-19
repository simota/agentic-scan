# 04 LP-Aligned Editorial (Baseline)

Mockup: `04-lp-editorial.html`

## Concept

Build the report using only components from `site/styles.css`. This design serves as a baseline for comparing the other concepts.

| LP Component | Use in the Report |
|---|---|
| Hero and ledger `.term` | Counts |
| Skills list | Findings list |
| Install section's 2 columns | Details for 1 finding |
| Inverted verify band | Items requiring a decision |

## Why It Fits agentic-scan

- Readers familiar with the LP can open the report and navigate it easily. The tokens, typefaces, spacing, and border radii match the LP.
- Headings state only facts about counts and status. Examples: 「指摘は 7 件。」「未解決の High が 2 件あります」. In keeping with the LP's copy guidelines, all numbers come from the sample data.
- The ledger note quotes the evidence for F-004 (false positive). This follows the structure of the LP hero note.
- The inverted band contains decisions. It puts the LP rule 「decide: 決めるのは人です」 into practice in the report.

## Adapting It to Other Skills

- Use the same section order across skills (counts → list → details → decisions). Generate each section heading mechanically from the counts.
- Use the line on the left of the list (`border-left`) to mark the selection. Add skill-specific information as dt / dd pairs in the facts column on the left of the 2-column detail view. Examples include ux-scan screens, logic-scan counterexamples, and bug-scan reproduction steps.
- The same components can be used in assessment.html (print). This aligns the print design with the LP as well.

## Changes and Estimated Effort for the Existing render.py / dashboard.css

- The smallest initial change is to swap the tokens.
  - The current dashboard.css uses a paper-like palette with `--bg:#f6f5f1` and a Mincho `--serif`. Replace these with the LP's cool gray and `--mono` / `--sans`.
  - The severity colors already match the LP values.
  - The 11 dashboard.css files fall into 2 families. Add the token block to both. This takes about half a day in total.
- To align the components as well, use these mappings.
  - masthead → `.bar` and wordmark
  - summary-banner → hero
  - priority-item → list `li`
  - 1–2 days per skill.
- Dashboard search, filters, and the register table fit poorly into the editorial structure. One option is to align only the dashboard components and reserve this structure for assessment.html.

## Limitations

- The layout reads well, but the list gets long with dozens of findings. It is less suitable for comparison and filtering.
- It is hard to distinguish from the LP. Readers may confuse the promotional page with the scan results.
- The design offers nothing new. Its purpose as a baseline is to show where the other concepts improve on it.
