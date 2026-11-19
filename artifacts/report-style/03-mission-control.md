# 03 Mission Control Monitoring Console

Mockup: `03-mission-control.html`

## Concept

Make the report a monitoring console that shows the overall state on 1 screen. Include the following elements.

- Top band with a status readout (open 4 / closed 2 / excluded 1)
- Severity tiles with 1 cell per finding
- Verdict strip chart
- Perspective indicators
- Finding alert stream
- Inspector for the selected finding

## Why It Fits agentic-scan

- Use the LP's only inverted band (`--band`) for the top status display. Set the `r--` wordmark and skill name in monospace inside the band.
- Draw the severity tiles with 1 cell per finding. Filled cells are open and outlined cells are closed. The shapes distinguish statuses without inflating counts.
- Give FalsePositive a separate accent-colored segment in the verdict strip. This visualizes the rule that false positives remain in the record and count.
- Follow the LP in avoiding neon, glow, scan lines, and green on black. The indicators are flat circles without glow.

## Adapting It to Other Skills

- Build the tiles, verdicts, and perspective indicators from `severity`, `validation.verdict`, `status`, and `perspectives`. These shared fields work across all skills.
- Vary the inspector fields (location / request / actor, etc.) by skill. Keep the order fixed as 該当 → 根拠 → 修正方針 (location → evidence → fix direction).
- Add 1 panel for a skill-specific visualization, such as ux-scan screens, bug-scan relationship diagrams, or architecture-scan dependency diagrams. With a 12-column grid, placement requires only `grid-column`.

## Changes and Estimated Effort for the Existing render.py / dashboard.css

- The current security-scan dashboard already has an appbar, sidebar, cards, register, and tr.detail (the `DASHBOARD` template in `render.py`).
  - Make these 3 changes.
    - Replace the sidebar with a 12-column grid.
    - Turn the cards into tiles.
    - Move row details from inline expansion to the inspector on the right.
  - The inspector needs a small amount of JS to change the selected row. Extend the existing JS that builds the DOM.
- Rewrite much of the layout in dashboard.css. Match the tokens to the LP values.
- Estimated effort is 2–3 days per skill. Consolidating the 2 dashboard.css families into shared components takes extra work the first time.

## Limitations

- The layout is dense and becomes 1 long column at 360px. It looks most like a console on screens 1024px and wider.
- The monitoring metaphor suggests continuous observation, while the report is a one-time static record.
- With many findings, the inspector and alert stream move far apart. Making the inspector sticky complicates printing.
- The instrumentation can look similar to 08 (Scan Sweep Instrument Panel). This design omits meters and pie charts to distinguish the two.
