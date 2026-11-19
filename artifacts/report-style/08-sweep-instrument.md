# Pattern 08: Scan Sweep Instrument Panel (`08-sweep-instrument.html`)

## Concept
Present static source review results as the front panel of a precision instrument. Group the severity breakdown (Severity Meter), sweep results for 6 perspectives (Perspective Sweep), and verification progress (Verification Scale) in the top instrument cluster. Use the 2 lower panes (signal register and inspection probe) to examine individual findings.

## Why It Fits agentic-scan
- **A literal representation of scanning and measuring**: Use the LP's cool gray background, monospace labels, 1px rules, and `r--` wordmark. Avoid effects such as neon on black and glow to convey the credibility of a read-only scanner that measures facts without hype.
- **Visible coverage and false-positive exclusions**: Give per-perspective sweep results (`CH-01`–`CH-06`) a prominent place. Retain the `FalsePositive` (F-004) and highlight it with `--mark` to make the brand principle 「読んで、反証してから、渡す」 visible at a glance.

## Adapting It to Other Skills
- **Perspective Sweep (`CH-01..N`)**: Map each skill's existing perspective and coverage list directly to channel rows (primary flows in `ux-scan`, layers and boundaries in `architecture-scan`, bug introduction paths in `bug-scan`, and removal unit types in `prune-scan`).
- **Severity Meter**: In skills such as `prompt-scan`, which distinguish defects from improvement suggestions, put 2 segmented SVG bars side by side to retain the instrument design.
- **Inspection Probe**: Accommodate skill-specific fields (`logic-scan` counterexamples, `ux-scan` target screens and viewports, and `data-integrity-scan` migration target tables) by adding or removing entries and blocks in the probe's `<dl class="probe-grid">` and sections.

## Changes and Estimated Effort for the Existing `render.py` and `dashboard.css`
- **Scope of changes**:
  - `dashboard.css`: Replace the current Mincho and off-white palette (Academic layer) with LP tokens (cool gray, monospace headings and labels, and sans-serif body text). Add layouts for the instrument cluster (`.cluster`, `.inst`) and 2 panes (`.workbench`).
  - `render.py`: Reuse the existing data structures for `#cards` / `#perspectives` / `#findings`. Add an SVG segment bar generator (about 15 lines) and replace the JS to render the selected table row in the right-hand probe or detail pane.
  - Print `assessment.html` (`document.css`): Align only the color tokens and typography with the LP.
- **Estimated effort**: Medium (1–1.5 days per skill). For skills using the shared `report_assets/dashboard.css`, updating the shared kit and integrating it into each skill takes about 2–3 days.

## Limitations
- **Using 2 panes with many findings (over 50–100)**: As the signal list in the left pane grows taller, it gets harder to relate the scroll position to the probe on the right. Use a fixed-height scrollable list or improve the filter and search bar.
- **Information density in PDF printouts**: The interactive probe shows only the 1 selected finding when printed. A separate print layout on the `assessment.html` side must expand all findings.
