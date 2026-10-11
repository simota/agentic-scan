# ux-scan

An agent skill that reviews an app's **design, layout and UI/UX** by reading
its repository — navigation, layout and grid, responsive behaviour, visual
hierarchy, components, interaction states, forms, feedback, microcopy,
accessibility, motion, internationalized layout and perceived performance —
and reports every place the interface gets in the way of a user's task.

Built on the method of [security-scan](https://github.com/simota/security-scan):
a fixed run contract, phases, perspectives with hunt steps, a severity table
decided before confidence, verdicts with falsification, one finding per fix
location, JSON fragments merged by a checker, and a dashboard plus a PDF report
rendered with the shared [scan-report-kit](https://github.com/simota/scan-report-kit) format.
Its layout mirrors the sibling [brand-scan](https://github.com/simota/brand-scan).

It is read-only and judges against a stated criterion, not taste: "the cards
feel cramped" is not a finding; "`.card` uses `padding: 13px` where the spacing
scale is 4/8/12/16" is. Brand voice and palette canon are brand-scan's.

```
RECON → FLOWS → CHECKLIST → REVIEW → VERIFY → REPORT
          │                                       │
   flows.json (primary tasks, screens,     findings.json ─→ dashboard.html
   token scales, viewports, locales)                     ─→ report.html / report.pdf
          │
   inventory.py --flows ─→ inventory.json (candidates, never findings)
```

## Install

```sh
make link                 # symlink skills/ux-scan into Claude Code, Codex and Antigravity
make link AGENT=claude    # one host
make status
```

Then ask the agent, e.g. "ux-scan this repository" or "review the sign-up and
checkout UI for usability and accessibility problems".

## What it checks

| Family | Examples |
|---|---|
| Information architecture | Primary flows reachable from navigation, orphan routes, current location |
| Layout and grid / Responsive | Off-scale spacing, z-index conflicts, overflow, fixed widths at the smallest viewport, tap targets, zoom locks |
| Visual hierarchy / Components | Competing primary actions, type scale, design-system bypass, duplicate components |
| Interaction states / Forms | Focus visibility, pending and disabled states, labels, validation timing, input types and autocomplete, preserved input |
| Feedback / Microcopy | Loading, empty and error states, destructive actions without undo, actionable error text |
| Accessibility / Motion | Keyboard reach, focus management, accessible names, contrast, ARIA misuse, reduced motion |
| Internationalized layout / Perceived performance | Text expansion and truncation, RTL, skeletons, layout shift from unsized media |

The full list with hunt steps is `skills/ux-scan/reference/perspectives.md`.

## Scripts (standard library only)

| Script | Does |
|---|---|
| `scripts/inventory.py REPO --out inventory.json [--flows flows.json]` | Routes and orphan routes, token sources, spacing / type / breakpoint / z-index literals, fixed widths, tap targets, focus outlines, zoom locks, click handlers on non-interactive elements, images, inputs, icon-only buttons, missing state branches, destructive actions, motion, truncation, locale expansion; with flows, values off the token scales and widths beyond the smallest viewport |
| `scripts/findings.py flows|merge|check|renumber` | Validate the flows and findings; merge JSON fragments atomically; renumber findings into severity order |
| `scripts/render.py findings.json --out DIR --lang ja|en --repo REPO` | Dashboard, report and PDF via the vendored scan-report-kit |
| `scripts/contract_check.py OUT [--no-pdf]` | Exactly the contracted outputs, valid records, every perspective family recorded, no `Unverified` finding, pages stamped with the current record |

## Develop

```sh
make test       # unit tests
make check      # tests + doc refs + skill consistency + sample inventory and render
make demo       # render the sample (examples/tasklane) with PDF into $TMPDIR/ux-scan-demo
make inventory TARGET=/path/to/repo FLOWS=flows.json OUT=inventory.json
```

`skills/ux-scan/scripts/scan_report_kit/` is a vendored copy of
scan-report-kit; `make check` verifies it against its MANIFEST. Change it
upstream and re-vendor (`make vendor DEST=<this repo>/skills/ux-scan/scripts`
in scan-report-kit), never in place.

`examples/tasklane/` is a fictional app with deliberate UX defects; the sample
flows and findings in `examples/` describe it and are not a review of any real product.
