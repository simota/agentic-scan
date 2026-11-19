# Design spec (terminal / agent version)

All tokens live in `:root` in `site/styles.css`; no other values are used.

## Wordmark

`r--` + `agentic-scan`.

- `r--` is the permission string of a read-only file, a symbol for the product's first promise (it does not rewrite code).
- It is set in monospace inside a small ink-colored tag, followed by the name in bold monospace.
- The favicon is the same `r--`.

## Color

| Token | Light | Dark | Role |
|---|---|---|---|
| `--bg` | #f4f5f7 | #0f1217 | Background. A cool gray, not a paper color |
| `--surface` | #ffffff | #151a21 | Buttons, input samples, image backing |
| `--term` | #eceef2 | #0a0d11 | Terminal output blocks |
| `--ink` | #12161c | #e3e7ec | Text and the primary button |
| `--muted` | #545d68 | #9ba4ae | Supporting text, prompt symbols |
| `--line` | #d3d8df | #29313b | Borders and dividers |
| `--accent` | #1f3f66 | #a9c3e6 | Links, FalsePositive, labels (same value as the dashboard accent) |
| `--mark` | #dfe7f2 | #1a2638 | The signature row (F-004) and emphasis underlines |
| `--high` / `--medium` / `--low` / `--info` | #8a1c1c / #7a4800 / #24476e / #5a5a5a | #f2a19a / #e8bf7a / #a9c3e6 / #b3aea4 | Severity. Same values as the skills' dashboard (`report_assets/dashboard.css`) |
| `--band` family | Ink band | Surface band | Inverts only the verify section |

Red is used only to show High. Interactive elements use ink and the accent color.

## Type

- `--mono`: ui-monospace, SF Mono, Menlo, Consolas … → Japanese falls back to Hiragino Kaku Gothic / Noto Sans JP. The typeface that carries the brand.
- `--sans`: Hiragino Sans, Noto Sans JP, Yu Gothic UI … Body text and headings.
- Headings are Gothic at weight 800. Each phrase is `inline-block` so lines never break mid-word.
- Terminal blocks use `--fs-term`. The hero ledger (52 columns) scales its font size to the container width (`100cqi / 31.5`). All 7 rows fit in 343px (a 375px screen) without horizontal scrolling.
- No web fonts are loaded (no dependencies, no layout shift).

## Spacing, shape, motion

- Spacing: `--s1`–`--s9` (4px–112px), `--gutter` 16px / 32px, maximum body width `--measure` 40em.
- Shape: border radius is only `--radius` 4px and `--radius-s` 2px. Lines are 1px / 2px. Tap targets are `--tap` 44px; index links are `--target` 28px.
- Motion: `--t-fast` 120ms (press, hover), `--t` 220ms, `--stagger` 70ms.
  - The only entrance effect is on the 7 rows of the hero ledger, which appear one after another at 70ms intervals (opacity and a horizontal shift of 0.5 characters).
  - No imitation of typing.
  - Under `prefers-reduced-motion: reduce`, all effects stop and the final state shows immediately (measured opacity is 1 for all 7 rows).

## Responsive

- Below 720px:
  - Hide the nav (the wordmark and install button remain).
  - Make the primary CTA full width.
  - Extend the hero ledger to the screen edges.
  - Lay out the `make list` index in 2 columns.
  - Swap dashboard images for versions captured at 390px width.
- 1024px and up: the hero has 2 columns (1.2 : 1). skills has 2 columns: index (sticky) and body.
- 1200px and up: skill descriptions in 2 columns.

## Components

- Terminal block `.term`: a header row (stating what the output is), a body (`$` command lines, output), and a note. No window-frame decoration.
- `.ln-mark`: fills the signature row across the full width.
- Tabs: the WAI-ARIA tabs pattern. With JS disabled, all 4 are shown.
- Copy button: writes to the clipboard and reports the result with its label and a toast.
