# Before/after mockups

**Read when:** REPORT — the requester asked for mockups, a before/after
comparison of findings, more than one design proposal for a fix, or a
comparison across screen states or screens.

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
- One mockup per finding, unless the defect shows on more than one screen or
  region (*Several mockups*); alternative proposals and screen states go
  inside it (*Alternative proposals*, *States*). When the requester names
  findings, mock those; when not, the High findings on primary flows first,
  and say in `limitations` which findings got none

## Writing the two sides

`mockup` sits on the finding (`reference/findings-schema.md`). All its
fragments together, states, alternatives and several mockups included, are at
most 1 MiB as UTF-8, since they are published in one page:

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
  `renumber` rewrites finding ids in `title`, `note` and `label` (the states'
  and alternatives' too), never in `before` or `after`
- To take a mockup off a finding (not wanted, or holding something it should
  not), merge a fragment with `{"id": "U-006", "mockup": null}`

## Alternative proposals

When the requester asks for several designs, or the fix has more than one
reasonable shape with different trade-offs, the mockup can carry up to five
`alternatives` besides its `after`:

```json
"mockup": {"viewport": "360x640", "label": "Drawer",
           "before": "…", "after": "…", "note": "…",
           "alternatives": [{"label": "Chip row", "after": "…",
                             "note": "Every list one tap away; costs 48px of height."}]}
```

- `after` stays the proposal `fix` describes; it is the recommendation.
  `label` names it, and is required once there are alternatives
- Each alternative is `label` (required) and `after` (required, the same
  fragment rules as the two sides) with an optional `note`. Labels name the
  design in a few words and are unique within the mockup, the fix's included
- Every alternative must meet `expected` as fully as `after` does: a weaker
  option is not an alternative. Build it from the same `before`, changing only
  what that design changes, at the same size, so each proposal compares like
  with like
- Write the alternative's `note` as its trade-off against `after` (what it
  gains, what it costs), so the reader can choose; the mockup's own `note`
  stays what to look at
- `fix` names the recommended design; mention the alternatives there only when
  the choice is the requester's to make
- An alternative is replaced with the whole mockup: merge the full `mockup`
  object to add, change or drop one

## States

When the defect or its fix differs by screen state (empty, loading, error,
success, a long or a short list), the mockup can replace `before` and `after`
with two to four `states`, compared one state at a time:

```json
"mockup": {"viewport": "360x640", "label": "Inline retry",
           "states": [{"label": "Loading", "before": "…", "after": "…"},
                      {"label": "Error", "before": "…", "after": "…", "note": "The retry keeps the typed text."}],
           "alternatives": [{"label": "Toast", "note": "…",
                             "states": [{"label": "Loading", "after": "…"}, {"label": "Error", "after": "…"}]}]}
```

- Each state is `label` (required, unique within the mockup), `before` and
  `after` (required, the same fragment rules) and an optional `note` on what
  to look at in that state. A mockup has either `states` or `before` and
  `after`, never both
- Mock only the states the finding is about: a state whose two sides are the
  same shows nothing. Keep every state at the same size and region
- With states, each alternative gives `states` instead of `after`: one
  object of `label` and `after` per state of the mockup, with the same labels
  in the same order, so every proposal is shown in every state

## Several mockups

When one finding shows on more than one screen or region (a drawer missing on
both the task list and settings), `mockup` can be a list of two to four
mockups, each with a `title` naming its screen or region, unique within the
finding. Each is a complete mockup with its own `viewport`, `states` and
`alternatives`, and gets its own section: the first keeps the finding's
anchor (`mockups.html#U-006`), the others add their position
(`mockups.html#U-006-2`). Merge the whole list to change any of them.

## What the page does

`mockups.html` lists each finding with a mockup, in record order, with its
screen, viewport, location and flow, and shows the two sides side by side, under
a slider, or one at a time, at any `flows.json` viewport, scaled to fit. A
mockup with alternatives adds a proposal picker: every view compares `before`
with the chosen proposal, whose note is shown above it under its label, and an
*All proposals* view sets `before` beside every proposal, in as many columns
as stay readable. A mockup with states adds a state picker that switches every
side and the state's note together. Frames load as they are shown.
Without scripts every side and note is shown. Until
the viewer picks a view, a comparison is shown side by side, or under the
slider when side by side would shrink it below half size, where its text is
too small to read; the choice is made again when the viewport or the window
size changes. The
dashboard's header links to it, and each finding in the dashboard and the
report names its anchor (`mockups.html#U-006`). It carries the same
fingerprints as the other pages: `contract_check.py` requires it exactly when
an included finding has a mockup and otherwise rejects it, even with `--allow`, and a second-language render
(`--allow ja|en`) needs its own copy.
