# Validation

**Read when:** VERIFY — before any finding is merged with a verdict.

Every finding answers four questions, each with evidence (`path:line`, flow id,
inventory key, screenshot the requester supplied):

1. **Criterion** — which rule does it fail, and how authoritative is it: a
   WCAG 2.2 success criterion, the app's own documented token or pattern, a
   platform guideline, or a named usability heuristic?
2. **Reached** — does a user meet it: is the route linked, the component
   rendered on the flow, the state reachable, the viewport and locale
   supported? Dead code, stories, fixtures and unreleased flags are not reached.
   A viewport or locale the product plans to support (a documented roadmap
   item or issue) is reached one condition later: lower severity one level. One
   it does not and will not support makes the finding `NotApplicable`. Assumed
   viewports (SKILL.md *Decide first*) count as supported
3. **Compensated or intentional?** — a global focus style, a wrapper component
   that adds the label or key handler, a parent error boundary or `Suspense`,
   CSS that sets `aspect-ratio`, an i18n layer that sets `dir`, a documented
   design decision. Look before concluding
4. **Impact** — on which step of which flow, for whom (keyboard, screen reader,
   small screen, longest locale, slow network), and what they lose

Then try to falsify it: search for the conforming form elsewhere on the same
screen, for a later change that already fixes it, for the style or prop applied
at run time.

## Verdicts

| Verdict | When |
|---|---|
| `Valid` | All four answered with evidence; the defect is reached and not compensated |
| `Likely` | Defect confirmed in code; its rendered effect or reach not fully shown |
| `Unverified` | A candidate not yet read in context. A working state only: `scripts/contract_check.py` rejects a record that still has one |
| `Unlikely` | Evidence points to compensation, intent or a state nobody reaches |
| `FalsePositive` | Not a defect (the inventory matched something the criterion allows) — kept, excluded from counts |
| `NotApplicable` | Outside the agreed scope (a viewport or locale the product does not and will not support, a third-party widget the app does not configure) — kept, excluded from counts |

## Confidence

| Confidence | When |
|---|---|
| `Confirmed` | The code alone shows the defect and its reach: a missing label, a handler on a `div`, a width larger than the smallest viewport with no override |
| `Runtime-dependent` | The defect is real but its visible effect depends on rendering not observed: text widths, overlap, contrast of computed colours, image sizes |
| `Suspected` | It rests on something not read: a runtime theme, a library's internals, server behaviour |
