# Before/after mockups

**Read when:** REPORT — the requester asked for mockups or a before/after
comparison of findings.

A mockup shows one finding as the user meets it today (`before`) and as its
`fix` proposes (`after`). It illustrates the finding; it is not a redesign and
never replaces `path:line` evidence. It lives in `findings.json`, never in the
reviewed repository, and `render.py` publishes it as `mockups.html` beside the
dashboard. The PDF does not include it.

## When to attach one

- Only when asked, and only to findings whose verdict is `Valid` or `Likely`.
  Mockups on `FalsePositive` or `NotApplicable` findings are kept in the record
  but not published
- Prefer findings a picture explains better than prose: layout and responsive
  defects, hierarchy, states, forms, feedback. A missing `alt` or an ARIA
  attribute shows nothing; leave those without one
- One mockup per finding. When the requester names findings, mock those; when
  not, the High findings on primary flows first, and say in `limitations`
  which findings got none

## Writing the two sides

`mockup` sits on the finding (`reference/findings-schema.md`):

```json
"mockup": {"viewport": "360x640",
           "before": "<style>.sidebar{width:480px;flex-shrink:0}</style><div class=\"layout\">…</div>",
           "after": "<style>@media(max-width:639px){.sidebar{display:none}}</style><div class=\"layout\">…</div>",
           "note": "Below 640px the sidebar becomes a drawer."}
```

- `before` and `after` are HTML fragments: body markup with its own `<style>`
  elements, at most 64 KiB each, measured as UTF-8 (about 21,000 Japanese
  characters). Each is rendered as a complete page inside a
  sandboxed frame: no scripts run, nothing is fetched, forms do not submit.
  Images and fonts work only as `data:` URLs. `<link>` elements are refused,
  since resource hints such as `preconnect` reach the network outside the
  frame's content policy: put styles in `<style>`. The check is textual: `<link`
  followed by whitespace, `/` or `>` is refused anywhere, comments and CSS
  strings included; write `&lt;link&gt;` to show the text
- Rebuild the affected region from the code read in REVIEW: the same
  structure, the app's real copy (from its locale files), its token values
  and the defect exactly as `observed` describes it. `after` changes only what
  `fix` changes, so the difference between the sides is the fix
- Never copy credentials, tokens, personal data or other secret values into a
  mockup: unlike source excerpts, mockups are published as written, without
  secret masking. Use placeholder data shaped like the real values
- Keep both sides the same size and content, so the slider compares like with
  like; mock the region the finding is about, not the whole app. Fit each side
  within the viewport height: a taller side scrolls inside its own frame, and
  the two frames then scroll apart under the slider
- `viewport` is the size the mockup opens at; it falls back to the finding's
  `viewport`, then the first `flows.json` viewport. The page also offers every
  `flows.json` viewport, so write responsive CSS when the defect depends on
  width
- `note` is optional prose shown above the comparison: what to look at.
  `renumber` rewrites finding ids in `note`, never in `before` or `after`
- To take a mockup off a finding (not wanted, or holding something it should
  not), merge a fragment with `{"id": "U-006", "mockup": null}`

## What the page does

`mockups.html` lists each finding with a mockup, in record order, with its
screen, viewport, location and flow, and shows the two sides side by side, under
a slider, or one at a time, at any `flows.json` viewport, scaled to fit. Until
the viewer picks a view, a comparison is shown side by side, or under the
slider when side by side would shrink it below half size, where its text is
too small to read; the choice is made again when the viewport or the window
size changes. The
dashboard's header links to it, and each finding in the dashboard and the
report names its anchor (`mockups.html#U-006`). It carries the same
fingerprints as the other pages: `contract_check.py` requires it exactly when
an included finding has a mockup, and a second-language render
(`--allow ja|en`) needs its own copy.
