# Recon and flows

**Read when:** RECON (mapping the app) and FLOWS — before any finding is
written, and whenever REVIEW meets a screen or task no flow covers yet.

Flows are the review units, the way a canon is for brand-scan: every finding
cites the flow it affects, and severity is judged by which task a defect blocks.

## 1. RECON: what to map

| Item | Where to look | Record |
|---|---|---|
| Stack and rendering | `package.json`, framework config, entry files | Framework, router, styling system (CSS modules, Tailwind, CSS-in-JS), component library |
| Routes and screens | Router config (`<Route path>`, `routes` arrays), file-based routes (`app/**/page.*`, `routes/**/+page.svelte`), `pages/`, `screens/`, `views/`; inventory `routes`, `screens`, `orphan_routes` | Every route with its screen file; routes nothing links to |
| Design system | Tokens (`tokens.*`, `theme.*`, `tailwind.config.*`, CSS custom properties on `:root`), shared components, Storybook, design docs; inventory `token_sources` | Spacing, type, breakpoint and layer scales; which components are shared |
| Breakpoints | Media queries, container queries, `useMediaQuery`, Tailwind `screens`; inventory `breakpoints` | The breakpoints in use and those the system defines |
| Supported viewports | Design docs, `browserslist`, end-to-end test viewports, the requester | Width × height in CSS px for each supported class (phone, tablet, desktop) |
| Locales | Locale files and the i18n setup; inventory `locale_expansion` | Shipped locales, the source locale, any RTL locale |

## 2. FLOWS: what a flow is

A flow is one task an actor comes to do, with its screens in task order.

| Field | Rules |
|---|---|
| `id` | `FL-` and two or three digits, unique |
| `name`, `goal` | What the actor is trying to get done, in their words ("Pay for an order"), not the screen name |
| `priority` | `primary` (the product's reason to exist: sign-up, the core create/find/buy task), `secondary` (settings, history, admin aids), `shared` (the app shell, navigation, global styles and shared components — one unit, reviewed once) |
| `actor` | Who performs it (new visitor, signed-in member, admin) |
| `source` | `documented` (product docs, specs, analytics the repo cites), `stated` (the requester said so), `inferred` (navigation prominence, landing route) |
| `evidence` | Where the source says it (`path:line` or a short reason) |
| `screens` | Each step: `name`, optional `route`, and the `location` (`path:line`) of the screen or component |

At least one flow must be `primary`. Keep the list short: three to eight flows
cover most apps; a flow that is only one screen is fine.

## 3. `flows.json`

Written as fragments in scratch and merged with
`scripts/findings.py flows <out>/flows.json <fragment>…` (run from the skill's
directory by absolute path, SKILL.md *Paths*): a flow is added, or
replaces the flow with the same id; `app`, `viewports`, `locales` and `tokens`
are replaced when a fragment carries them. The command refuses a change that
would leave a finding in `findings.json` beside it citing a flow that no longer
exists.

```json
{
  "app": "Tasklane",
  "viewports": ["360x640", "768x1024", "1280x800"],
  "locales": ["en", "de", "ja"],
  "tokens": {"source": "src/styles/tokens.css:2", "spacing": [4, 8, 12, 16, 24, 32],
             "font_sizes": [12, 14, 16, 20, 24, 32], "breakpoints": [640, 1024], "z_index": [10, 100, 1000]},
  "flows": [
    {"id": "FL-01", "name": "Sign up", "priority": "primary", "actor": "New visitor",
     "goal": "Create an account with email and password.", "source": "documented", "evidence": "docs/design.md:5",
     "screens": [{"name": "Sign-up form", "route": "/signup", "location": "src/components/SignupForm.tsx:4"}]},
    {"id": "FL-05", "name": "App shell and shared styles", "priority": "shared", "actor": "Every user",
     "goal": "Navigation, page frame and the styles every screen inherits.", "source": "inferred",
     "evidence": "index.html and app.css load on every route",
     "screens": [{"name": "Global styles", "route": "*", "location": "src/styles/app.css:1"}]}
  ]
}
```

`viewports` are `WIDTHxHEIGHT` in CSS px. `tokens` is optional; when present it
needs `source` (`path:line`) and any of `spacing`, `font_sizes` and
`breakpoints` (px numbers) and `z_index` (plain numbers).
`scripts/inventory.py --flows` measures the repository against these scales and
the smallest viewport, and lists physical direction properties only when a
locale is right-to-left.
