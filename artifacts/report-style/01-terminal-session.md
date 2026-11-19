# 01 Terminal Session Transcript

Mockup: `01-terminal-session.html`

## Concept

Present the report as a transcript of a session running jq on `findings.json`. Each block follows the same order: command → output → a one-line note for the reader.

## Why It Fits agentic-scan

- Carry the LP's central promise into the report: “Show the actual product where it runs” (`artifacts/lp/creative-strategy.md`). All 4 jq commands in the mockup were run against `security-scan/examples/findings.sample.ja.json` to verify that the output matched.
- Reuse the LP's `.term` and `.ln-mark` visual vocabulary. Monospace type carries the brand, and notes use a Japanese sans-serif. Highlight and retain the F-004 (FalsePositive) line, as in the LP's signature line.
- A note marks additions drawn over the output (count bars and the 「該当」「根拠」「修正方針」 tags) with 「コマンドの出力ではない」 (not part of the command output).

## Adapting It to Other Skills

- The 4 blocks (meta, counts by severity, list, and details for 1 finding) can use the same structure across skills. Only the jq paths change.
- The detail block's `paths(scalars)` automatically flattens and displays skill-specific fields. Examples include screens and flow in ux-scan, reproduction steps and relationships in bug-scan, and counterexamples in logic-scan.
- The key names determine which lines to highlight (該当, 根拠, 修正方針). Configure 3 key names per skill.

## Changes and Estimated Effort for the Existing render.py / dashboard.css

- Adding 1 new static output page, `session.html`, is the safest approach. The current dashboard search and keyboard interactions can stay in place.
  - Add 1 template function to render.py. Implement the same formatting as jq (tsv, `paths`) in Python.
  - Store the displayed command strings as constants.
  - Half a day to 1 day per skill.
- Replacing the dashboard itself would require rebuilding the filter and expansion UI. That would take several days per skill.
- If dashboard.css needs only token changes (matching `--bg` and similar tokens to the LP values), the updates can be applied mechanically across all skills. The 11 dashboard.css files fall into 2 families (8 with 282 lines and 3 with 270 lines), so 2 replacements are enough.

## Limitations

- Once there are more than a few dozen findings, the list block gets long. It has no filtering or sorting.
- The displayed commands must keep working. Update them whenever the schema changes.
- At 360px, long jq commands wrap to 4–5 lines and take up space.
- This design is unsuitable for readers unfamiliar with terminals, such as executives.
