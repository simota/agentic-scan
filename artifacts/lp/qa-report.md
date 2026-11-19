# QA report (terminal / agent version)

Browser checked: Google Chrome on macOS (Playwright `channel="chrome"`, headless). The page was served locally with `python3 -m http.server`. Chrome and the local server were run outside the sandbox.

## What was done

| Check | Result | Record |
|---|---|---|
| 320 / 375 / 768 / 1024 / 1440 / 1920px × light / dark (12 combinations) | In all 12: no horizontal scrolling, no overflowing elements, no console errors, no failed requests | `screenshots/rebrand/layout.json` |
| First view | At every width, the H1 and primary CTA fit in the first screen. At 1024px and up, the ledger is also in the first view. At 375px the ledger heading and command reach the bottom edge | `screenshots/rebrand/final/` |
| Heading line breaks | From 320 to 1920px, the H1 fits in 2 lines: 「コードに触れずに、/ 裏の取れた指摘を。」 | Checked visually |
| In-page links | Every link starting with `#` has a target (0 links without a target) | `interactions.json` |
| Copy buttons | For both, the clipboard contents match `data-copy`. The label changes to 「コピー済み」 ("Copied") and a toast appears | Same as above |
| Tab keyboard operation | → moves to ux-scan and the panel switches. End moves to the last, Home to the first | Same as above |
| FAQ | Opens on click | Same as above |
| Focus indicator | On the 2nd Tab, a 2px solid outline appears on the wordmark | `final/focus-1440.webp` |
| Reduced motion | All 7 ledger rows have opacity 1 right after load | `interactions.json` |
| JS disabled | All 4 output samples are shown | Same as above |
| ui-deslop detector | `3 files, 0 open hits, 0 exempt, 34 cues` (the 34 cues were checked by reading their context; details in pdca-report) | — |
| Is the terminal output real | The page's 3 output blocks match the saved run results character for character | `qa/transcripts/` |

## Lighthouse 12.2.1 (lab measurement; served locally, headless Chrome)

| | Performance | Accessibility | Best Practices | SEO | LCP | CLS | TBT |
|---|---|---|---|---|---|---|---|
| Mobile | 100 | 100 | 100 | 100 | 1.1 s | 0 | 0 ms |
| Desktop | 100 | 100 | 100 | 100 | 0.3 s | 0 | 0 ms |

In the first measurement, mobile Accessibility was 97. There were 2 causes; both were fixed and re-measured.

- The wordmark's `aria-label` did not contain the visible text.
- The `make list` index links were only 20px tall (under 24px).

Reports are in `lighthouse/rebrand/`.

## Defects found and fixed

- At 320 / 375px the width expanded to 568px. Grid columns were being pulled by the width of `<pre>`; fixed with `minmax(0, 1fr)` and `min-width: 0`.
- Output rows had a blank line between every row. Block-level spans overlapped with newline characters; fixed with inline-block.
- At 1440px the H1 broke mid-word (「触れず/に、」). Fixed by revising the font-size cap and column ratio.
- Command lines were cut off instead of wrapping. It was a selector specificity problem.
- The `make list` box stretched to the full column height (fixed with `align-self: start`).
- The sentence 「右の指摘は」 ("the findings on the right") did not match the layout on mobile.
- The 2 Lighthouse issues (above).

## Not verified

- Safari, Firefox, real smartphones (iOS / Android)
- Screen reader output (VoiceOver / NVDA)
- Responsiveness in real interaction (INP). Only lab TBT; no real-user data
- Production-equivalent delivery (compression, caching, CDN)
- What is shown when opening the GitHub link without access
- Contrast ratio calculation. The Lighthouse color-contrast audit passed, but not every combination was calculated by hand
- How the monospace type looks in environments where ui-monospace does not resolve to SF Mono, such as Windows
- Review by an independent evaluator
