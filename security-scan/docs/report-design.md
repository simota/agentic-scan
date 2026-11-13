# Report design direction

Moved: the design system for `assessment.html` / `assessment.pdf` and
`dashboard.html` (decided here 2026-10-07) is now the shared format of every
*-scan skill. It lives in the scan-report-kit repository (its design document
is `design.md` under that repository's docs directory), next to the
stylesheets it governs.

In security-scan:

- `skills/security-scan/scripts/scan_report_kit/` is a vendored copy of the kit
  (stylesheets, PDF engine, safe writes). To change it, change the kit upstream,
  then run its `make vendor DEST=<this repo>/skills/security-scan/scripts`;
  `make check` fails if the copy is edited in place.
- `skills/security-scan/scripts/render.py` inlines the shared stylesheets first and
  appends only the rules for security-scan record types (verification,
  workflow, expert and three-pass records, evidence cells) in `ASSESSMENT_CSS`
  and `DASHBOARD_CSS`, plus one register rule that widens the Confidence and
  Validation columns so their enumerated values (`Environment-dependent`,
  `NotApplicable`) are not split inside a word.
- The running footer, `SECURITY ASSESSMENT` (ja `セキュリティ診断`), is passed
  to `document_css()` from the `a_running_footer` label.
