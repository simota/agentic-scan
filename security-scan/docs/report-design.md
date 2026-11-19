# Report design direction

Moved: the design system for `assessment.html` / `assessment.pdf` and
`dashboard.html` (decided here 2026-10-07) is now the shared report
format. It lives in `skills/security-scan/scripts/report_assets/`, with the stylesheets it
governs.

In security-scan:

- (`report_style.py`, `report_pdf.py`, `report_output.py`) and `skills/security-scan/scripts/report_assets/`
  (stylesheets, PDF engine, safe writes) are maintained in this repository; edit
  them in place.
- `skills/security-scan/scripts/render.py` inlines the shared stylesheets first and
  appends only the rules for security-scan record types (verification,
  workflow, expert and three-pass records, evidence cells) in `ASSESSMENT_CSS`
  and `DASHBOARD_CSS`, plus one register rule that widens the Confidence and
  Validation columns so their enumerated values (`Environment-dependent`,
  `NotApplicable`) are not split inside a word.
- The running footer, `SECURITY ASSESSMENT` (ja `セキュリティ診断`), is passed
  to `document_css()` from the `a_running_footer` label.
- The console-triage layer (2026-11-19) is inlined last into both pages:
  `report_assets/console.css` (brand tokens from the site, band header,
  severity tiles, verdict strip, perspective lamps, four-lane board,
  inspector) and, in `dashboard.html` only, `report_assets/console.js`, which
  draws the `console` model that `console_model()` in `render.py` embeds.
  Lanes come from `action_kind()` (FIX NOW / VERIFY FIRST) plus closed
  statuses and excluded verdicts; `assessment.html` prints the same four lanes
  top to bottom. These two asset files are copies of
  `artifacts/report-style/console/` at the repository root; change them there
  and copy them back.
