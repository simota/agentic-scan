# PDCA report (terminal / agent version)


The owner's assessment was 「AI 生成感が強い」 ("it feels strongly AI-generated"). Both the previous version and the ui-deslop rewrite used ink black, off-white, Mincho serif type, and rules — a common pattern in AI-generated LPs. So the brand was rebuilt, in the "terminal / agent" direction the owner chose. The scoring criteria are the same as before (FV 20, value 20, CTA 15, design 15, responsive 10, UX/a11y 10, performance/SEO 10). Images are in `screenshots/rebrand/cycles/`.

| Cycle | Score | Main problems | What was done | Verification result |
|---|---|---|---|---|
| R1 | 64 | At 320 / 375px the width was 568px (grid columns were pulled by `<pre>`). At 1440px the H1 broke mid-word (「触れず/に、」, 「指摘/を。」). Ledger rows had a blank line between every row. The jq command was cut off on the right. Dashboards were white in full-page screenshots (the capture script did not trigger lazy loading) | Initial implementation | In the 12 capture combinations, 320 / 375 had horizontal scrolling |
| R2 | 78 | Commands did not wrap. At 320px the H1 was 4 lines. The separator dots in the kicker and spec fell to the start of a line. In the 4-column rules, a heading split as 「ませ/ん。」 | Set `minmax(0, 1fr)` and `min-width: 0` on columns. Made rows inline-block. Capped the H1 font size and set the column ratio to 1.2 : 1. Set the ledger font size to `100cqi / 31.5`. Dropped separator symbols in favor of spacing. rules in 2 columns | No horizontal scrolling in any of the 12. All 7 rows visible at 375px without horizontal scrolling |
| R3 | 82 | The `make list` table of contents had a blank line between every row. Dashboards were still white in full-page screenshots | Fixed command wrapping (selector specificity) | Checked individually, the images loaded normally (rendered at 1119px width). Identified as a problem with full-page screenshots only |
| R4 | 86 | The table-of-contents box stretched to the column height. 「右の指摘は」 ("the findings on the right") did not match the layout on mobile | Made table-of-contents rows inline-block. The capture script switches lazy images to eager before capturing | Dashboards appear in full-page images. The mobile table of contents is readable in 2 columns |
| R5 | 89 | Lighthouse mobile a11y was 97 (the wordmark's aria-label did not match the visible text; index links were 20px) | `align-self: start` on the table-of-contents box. Changed the sentence to 「添えた指摘は」 ("the accompanying findings"). Removed the aria-label. Index links to 28px. Replaced remaining hard-coded values with tokens | Lighthouse 100 on all 4 categories on both mobile and desktop. All interaction checks passed (qa-report) |

## R5 score breakdown

| Item | Score | Rationale |
|---|---:|---|
| FV | 18 / 20 | What the product is, what you get, and the CTAs fit in the first screen at every width. At 1024px and up, the real-data ledger and the signature row (F-004) are also visible. At 375px the ledger only slightly reaches the bottom edge |
| Value | 18 / 20 | Findings with verdicts, keeping false positives, and each skill's procedure are shown with the product's own data. The agent actually running (a session) is not shown, since it would have to be fabricated |
| CTA | 12 / 15 | The flow and copy work. Because the repository is private, visitors without access cannot install |
| Design | 13 / 15 | The `r--` wordmark, monospace type, severity colors, and inverted band clearly differ from the previous version. However, the skills section is text-heavy and the middle is monotonous. Only the dashboard screens are in the Mincho editorial style and do not match the LP's look |
| Responsive | 10 / 10 | No breakage across 6 widths × 2 themes. Mobile-specific layout (ledger to the screen edges, 2-column table of contents, mobile images) |
| UX/a11y | 9 / 10 | Keyboard, focus, reduced motion, and JS disabled all checked. Screen readers and real devices not verified |
| Performance/SEO | 9 / 10 | Lighthouse 100 on all 4 categories. No OGP image |
| **Total** | **89** | |

## Why it did not reach 90

1. The private repository (CTA). This cannot be solved on the LP side.
2. The density of the skills section. Showing all 12 without mixing in anything fabricated took priority.
3. The look of the dashboard screens does not match the LP. That is the skills' design, outside this scope (`site/` only).
