# prune-scan

An agent skill for **minus design** (design by subtraction, マイナスデザイン):
it reads an app's repository and reports what can be **removed, reduced or
consolidated** — dead code, unused features and routes, settled flags and
finished experiments, dependencies, configuration, data, assets, tests and
tooling, duplicates, API surface, permissions and integrations — and features
that are **over-built** for the service's scale or **outside its purpose**.

The question for every element is not only "is it used?" but "what would the
core jobs lose if it were gone?" An element that earns nothing for the core
jobs is a candidate even when it is used. The burden of proof is on keeping,
but every finding rests on stated evidence — a purpose baseline recorded with
its sources, usage, scale, reference searches — never taste.

Built on the method of [security-scan](https://github.com/simota/security-scan):
a fixed run contract, phases, perspectives with hunt steps, a severity table
decided before confidence, verdicts with falsification, one finding per fix
location, JSON fragments merged by a checker, and a dashboard plus a PDF report
rendered with the shared [scan-report-kit](https://github.com/simota/scan-report-kit) format.
Its layout mirrors the siblings [ux-scan](https://github.com/simota/ux-scan) and
[brand-scan](https://github.com/simota/brand-scan).

It is read-only and never deletes anything; removal is a later request.

```
RECON → UNITS → CHECKLIST → REVIEW → VERIFY → REPORT
          │                                       │
   units.json (purpose baseline, entry     findings.json ─→ dashboard.html
   points, consumers, review units)                      ─→ report.html / report.pdf
          │                                                 (next steps open with the
   inventory.py --units ─→ inventory.json                    subtraction summary)
          (candidates, never findings)
```

## Install

```sh
make link                 # symlink skills/prune-scan into Claude Code, Codex and Antigravity
make link AGENT=claude    # one host
make status
```

Then ask the agent, e.g. "prune-scan this repository" or "what in this app can
we delete or simplify?".

## What it checks

| Family | Examples |
|---|---|
| Dead code / Unused features | Unreferenced functions and modules, commented-out code, routes and screens nothing calls or links, debug routes left mounted, unscheduled jobs |
| Feature flags / Dependencies | Always-on or always-off flags, finished experiments still running, unimported or duplicated packages, packages the platform replaces |
| Configuration / Data | Settings never read, secrets for removed services, unused tables and columns, write-only data, stale seeds |
| Assets / Tests and tooling | Unreferenced images, fonts, CSS classes, locale keys and docs; skipped tests, dead CI jobs, stale scripts and generators |
| Duplication / API surface / Integrations | Two implementations of one capability, forwarding wrappers, expired shims, deprecated API versions, unused OAuth scopes and webhooks |
| Purpose fit / Over-built | Features outside the purpose or serving a non-goal, duplicate user paths, rebuilt commodities; settings nobody changes, abstractions with one implementation, scale machinery the product does not have |

The full list with hunt steps is `skills/prune-scan/reference/perspectives.md`;
the purpose baseline is described in `skills/prune-scan/reference/units.md`.

## Scripts (standard library only)

| Script | Does |
|---|---|
| `scripts/inventory.py REPO --out inventory.json [--units units.json]` | Unreferenced symbols, orphan files, unimported / duplicated / platform-replaceable dependencies, env vars read versus declared, feature flags and their values, unreferenced locale keys, assets and CSS classes, routes nothing names, uninvoked scripts and targets, loose files, skipped tests, commented-out code, dated deprecation markers, unreferenced tables and columns; capped after measuring, with `limits` and `truncated` |
| `scripts/findings.py units|merge|check|renumber` | Validate the units and findings; merge JSON fragments atomically; renumber findings into severity order |
| `scripts/render.py findings.json --out DIR --lang ja|en --repo REPO` | Dashboard, report and PDF via the vendored scan-report-kit |
| `scripts/contract_check.py OUT [--no-pdf]` | Exactly the contracted outputs, valid records, every perspective family recorded, no `Unverified` finding, every `Purpose-dependent` finding in decisions, pages stamped with the current record |

## Develop

```sh
make test       # unit tests
make check      # tests + doc refs + skill consistency + sample inventory and render
make demo       # render the sample (examples/larder) with PDF into $TMPDIR/prune-scan-demo
make inventory TARGET=/path/to/repo UNITS=units.json OUT=inventory.json
```

`skills/prune-scan/scripts/scan_report_kit/` is a vendored copy of
scan-report-kit; `make check` verifies it against its MANIFEST. Change it
upstream and re-vendor (`make vendor DEST=<this repo>/skills/prune-scan/scripts`
in scan-report-kit), never in place.

`examples/larder/` is a fictional app with deliberate unneeded, over-built and
out-of-purpose elements; the sample units and findings in `examples/` describe
it and are not a review of any real product.
