# Perspectives

**Read when:** CHECKLIST (choose the perspectives that apply) and REVIEW (sweep
each one over every review unit).

Each family has an id and hunt steps. A step is done when every screen in the
unit has been read for it, in every state the flow reaches. Record the result
per family in `perspectives` (`name`, `result`, `note`), the `name` starting
with the family id (`AX Accessibility`), for all thirteen families — one with nothing to check as `N/A` with the reason, one not reached
as `not checked`. Inventory keys that feed a step are named in brackets.

## Information architecture and navigation (`IA`)

- IA1 Every primary flow starts from the navigation or the landing screen in
  the expected number of steps; the route map and the navigation agree
  [`routes`]
- IA2 Orphan and dead-end screens: routes nothing links to, screens with no way
  back or onward, a modal that opens another modal [`orphan_routes`]
- IA3 Where am I: the active navigation item (`aria-current`), a title and
  heading per screen, breadcrumbs in deep hierarchies, the document title per
  route
- IA4 Labels and grouping: navigation labels match the screen titles they open;
  one destination is named one way; menus no deeper than the content needs

## Layout and grid (`LG`)

- LG1 Alignment: containers, gutters and column widths shared across sibling
  screens; magic offsets and one-off widths that break the grid
- LG2 Spacing and sizing literals against the token scale; tokens defined but
  bypassed [`spacing`, `off_scale`, `token_sources`]
- LG3 Stacking: z-index values against the layer scale; overlays covering each
  other in the wrong order (dropdown over a modal, toast under it) [`z_index`]
- LG4 Overflow and clipping: `overflow: hidden` cutting focus rings, menus or
  content; long names, numbers and user content in fixed boxes; accidental
  horizontal scroll
- LG5 Safe areas and fixed elements: `env(safe-area-inset-*)` on notched
  devices; fixed headers, footers and banners covering content, anchors or the
  on-screen keyboard

## Responsive (`RS`)

- RS1 Breakpoints against the system, and the layout at each supported
  viewport: what collapses, what hides, what is lost on small screens
  [`breakpoints`]
- RS2 Fixed widths and min-widths wider than the smallest supported viewport;
  tables, code and media without a small-screen strategy [`fixed_widths`]
- RS3 Touch targets at least 24 × 24 CSS px (WCAG 2.2 SC 2.5.8) and the
  platform's 44 / 48 px for primary controls; spacing between adjacent targets
  [`tap_targets`]
- RS4 Zoom and orientation: `user-scalable=no`, `maximum-scale`, orientation
  locks, text that does not reflow at 320 CSS px (SC 1.4.10) [`viewport_meta`]
- RS5 Hover-only affordances (menus, tooltips, row actions revealed on hover)
  with no touch or keyboard equivalent

## Visual hierarchy and typography (`VH`)

- VH1 One primary action per view; competing primaries; a destructive action
  styled as the primary
- VH2 Type scale: font sizes against the scale; body text size on small
  screens; line length and line height for reading [`font_sizes`]
- VH3 Heading levels follow the visual hierarchy: one `h1`, no levels skipped
  or chosen for their size
- VH4 Grouping and density: related controls grouped, groups separated by
  space, scanning order matching task order

## Components and consistency (`CC`)

- CC1 Same component, same meaning: variants used for their documented role,
  one-off variants, the same control looking different on two screens
- CC2 Design-system bypass: hand-rolled buttons, links, inputs or dialogs;
  inline styles replacing tokens [`token_sources`, `off_scale`]
- CC3 Duplicate components (two `Modal`, two `Button` implementations) that
  have drifted apart
- CC4 Patterns repeated across screens: the same action placed and labelled the
  same way (primary/cancel order, close position, save behaviour)

## Interaction states (`ST`)

- ST1 Hover, active and selected states present on interactive components and
  distinct from one another and from disabled
- ST2 Focus visible on every focusable element, with 3:1 contrast against its
  surroundings [`focus_outline`]
- ST3 Pending and disabled: submit controls during a request (double submit),
  disabled controls that never explain why [`state_branches`]
- ST4 Selected, current, expanded and pressed states exposed both visually and
  programmatically (`aria-selected`, `aria-expanded`, `aria-pressed`)

## Forms and input (`FM`)

- FM1 Every field has a visible, persistent label tied to it in code — not a
  placeholder that disappears [`inputs`]
- FM2 Required and optional marking, format hints before input, field width and
  grouping matching the expected value
- FM3 Validation timing: errors on blur or submit, not on the first keystroke;
  errors cleared as soon as the value is fixed
- FM4 Input `type`, `inputmode` and `autocomplete` tokens for email, phone,
  passwords, names, addresses and one-time codes [`inputs`]
- FM5 Input preserved across errors, navigation and reloads; errors next to the
  field and linked to it (`aria-describedby`); focus moved to the first error

## Feedback and system status (`FB`)

- FB1 Every data-backed view has loading, empty, error and success states
  [`state_branches`]
- FB2 Errors say what happened and how to recover, with a retry where it makes
  sense; no silent failures (a promise with no `catch`)
- FB3 Optimistic updates roll back on failure and say so
- FB4 Destructive and irreversible actions: confirmation in proportion to the
  loss, or undo [`destructive_actions`]
- FB5 Long operations show progress; success is confirmed on screen and
  announced to assistive technology (live region)

## Content and microcopy (`CP`)

- CP1 Buttons and links say what happens (verb + object), not "OK", "Submit" or
  "Click here"
- CP2 Error, empty and help text is specific and actionable; no status codes,
  stack traces or internal jargon shown to users
- CP3 One concept, one word within the UI copy, for clarity (brand terminology
  and voice are brand-scan's)
- CP4 Instructions where they are needed, not relying on shape, colour or
  position alone ("press the green button")

## Accessibility (`AX`)

- AX1 Semantics: landmarks, headings, lists, buttons versus links, data tables;
  `lang` on `<html>`
- AX2 Keyboard: every interactive element reachable and operable without a
  mouse [`click_handlers`]
- AX3 Focus management: order follows the visual order; dialogs move focus in,
  keep it inside, close on Escape and return it; focus moves on route change
  [`positive_tabindex`]
- AX4 Accessible names: icon-only buttons, links, images (`alt`), form
  controls; names that contain the visible label [`icon_buttons`, `images`]
- AX5 Contrast: text 4.5:1 (3:1 for large text), UI components and focus
  indicators 3:1, in every theme
- AX6 ARIA misuse: roles that contradict the element, `aria-hidden` on focusable
  content, missing live regions for asynchronous updates

## Motion (`MO`)

- MO1 Motion explains a change and is short (UI transitions around 100–300 ms);
  nothing animates in the way of the task [`motion`]
- MO2 `prefers-reduced-motion` honoured for large movement, parallax and
  auto-playing animation [`motion`]
- MO3 Anything that moves for more than five seconds can be paused (SC 2.2.2);
  nothing flashes more than three times a second

## Internationalized layout (`IN`)

- IN1 Text expansion: the longest shipped locale fits labels, buttons, tabs and
  table headers [`locale_expansion`, `truncation`]
- IN2 Truncation hides meaning: ellipsis on labels, names or amounts with no
  way to see the full text [`truncation`]
- IN3 Right-to-left: logical properties, mirrored directional icons, the `dir`
  attribute [`physical_properties`]
- IN4 Concatenated strings, hard-coded order of name, date and number parts,
  fonts without glyphs for a shipped script

## Perceived performance (`PP`)

- PP1 Skeletons or placeholders shaped like the result instead of blank areas
  or full-page spinners [`state_branches`]
- PP2 Layout shift: images and embeds without dimensions or `aspect-ratio`,
  late fonts, banners inserted above content [`images`]
- PP3 Immediate response to input (pressed state, optimistic update); nothing
  essential waits on a non-essential request
- PP4 The primary content and action are visible first, before secondary data
  arrives
