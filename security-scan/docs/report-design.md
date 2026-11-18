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
