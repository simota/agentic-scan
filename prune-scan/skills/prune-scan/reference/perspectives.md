# Perspectives

**Read when:** CHECKLIST (choose the perspectives that apply) and REVIEW (sweep
each one over every review unit).

Each family has an id and hunt steps. A step is done when every entry point and
path of the unit has been read for it. Record the result per family in
`perspectives` (`name`, `result`, `note`), the `name` starting with the family
id (`DC Dead code`), for all thirteen families — one with nothing to check as
`N/A` with the reason, one not reached as `not checked`. Inventory keys that
feed a step are named in brackets.

The minus-design question applies to every step, not only PX and OB: for each
element, what would the core jobs lose if it were gone? "Nothing" makes it a
candidate even when something calls it; the evidence then says why that caller
does not need it.

## Dead code (`DC`)

- DC1 Functions, classes, constants and exports nothing references, after
  checking dynamic dispatch (getattr, reflection, registries, decorators,
  templates) [`unreferenced_symbols`]
- DC2 Modules, files and components nothing imports, or only their own tests
  import [`orphan_files`]
- DC3 Commented-out code kept "for later"; version control keeps it
  [`commented_code`]
- DC4 Unreachable branches: code after an unconditional return or raise,
  conditions that are always true or false, cases of enums no value reaches

## Unused features (`UF`)

- UF1 Endpoints and API routes no client, consumer or job calls
  [`unreferenced_routes`, `routes`]
- UF2 Screens and pages the navigation no longer links, or that call APIs that
  no longer exist [`unreferenced_routes`]
- UF3 Debug, test, seed, admin and internal tools left mounted where users or
  the internet reach them [`unreferenced_routes`]
- UF4 CLI commands, scheduled jobs, queue consumers and event handlers that
  nothing schedules, produces for or invokes

## Feature flags and experiments (`FF`)

- FF1 Flags that are always on or always off, with both branches maintained or
  the dead branch still shipped [`feature_flags`]
- FF2 Finished experiments still assigning, logging or writing data
  [`markers`]
- FF3 Kill switches and operational toggles nobody has flipped, and flags
  defined in a flag service but not in code (or the reverse) [`feature_flags`]

## Dependencies (`DP`)

- DP1 Declared packages nothing imports or invokes, including script-only
  entries whose scripts are dead [`unimported_dependencies`]
- DP2 Two packages for one purpose (two date libraries, two HTTP clients, two
  test runners) [`duplicate_purpose`]
- DP3 Packages the platform or standard library now covers
  [`platform_replaceable`]
- DP4 A heavy dependency used for one trivial function; an unused dependency
  with install scripts or known vulnerabilities (High)

## Configuration and environment (`CF`)

- CF1 Settings and environment variables declared but never read
  [`env_declared_not_read`]
- CF2 Settings for services the app no longer uses, above all secret-bearing
  ones [`env_read`]
- CF3 Options whose default no configuration file, environment example or
  deployment manifest ever overrides

## Data and schema (`DA`)

Schema, migrations and code only; never query a database.

- DA1 Tables, columns and indexes no code reads or writes
  [`sql_tables_unreferenced`, `sql_columns_unreferenced`]
- DA2 Write-only data: written on some path, read on none (logs, assignments,
  denormalized copies)
- DA3 Obsolete migrations kept outside the migration tool, seeds and fixtures
  nothing loads [`unreferenced_files`]
- DA4 Buckets, queues, caches and search indexes declared in code or
  infrastructure files but unused

## Assets and content (`AS`)

- AS1 Images, fonts, media and downloads nothing references
  [`assets_unreferenced`]
- AS2 CSS classes and style rules no markup uses [`css_unreferenced`]
- AS3 Locale keys never referenced, and locales nobody ships
  [`i18n_unreferenced`]
- AS4 Orphan docs, examples and templates nothing links [`unreferenced_files`]

## Tests and tooling (`TT`)

- TT1 Tests that exercise only deleted or dead code [`orphan_files`
  `test_importers`]
- TT2 Skipped, disabled or assertion-free tests [`skipped_tests`]
- TT3 CI jobs and workflows that cannot run or deploy to retired targets
  [`scripts`]
- TT4 Stale scripts, Make targets, generators and generated files
  [`uninvoked_scripts`, `unreferenced_files`]

## Duplication (`DU`)

- DU1 Two implementations of one capability, especially ones that have drifted
  apart
- DU2 Wrappers and adapters that only forward to another function
- DU3 Compatibility shims, polyfills and adapters past their stated deadline or
  for platforms no longer supported [`markers`]

## API surface (`AP`)

- AP1 Public endpoints, parameters and response fields no declared consumer
  uses [`routes`]
- AP2 Deprecated API versions still served [`markers`]
- AP3 Exports of a published package no known consumer imports (always
  `Externally-dependent` without usage data)

## Permissions and integrations (`PI`)

- PI1 OAuth scopes, API permissions and IAM roles beyond what the code calls
- PI2 Webhooks and callbacks of integrations that were removed
- PI3 Third-party SDKs, scripts, pixels and trackers that no feature uses

## Purpose fit (`PX`)

Measured against the purpose items in `units.json`; every finding cites one
(`purpose_ref`). Used features are in scope: usage alone does not earn a place.

- PX1 Features outside the stated purpose or target users
- PX2 Features that serve a documented non-goal
- PX3 Duplicate paths to the same job from the user's side (two ways to add,
  two settings screens for one choice)
- PX4 Build versus buy: a commodity rebuilt outside the core (a homegrown
  mailer, scheduler, auth or analytics stack) where the core jobs gain nothing
  from owning it

## Over-built (`OB`)

Measured against the core jobs and the scale in `units.json`; cite the evidence
of scale or usage (one implementation behind an interface, one locale, one
tenant, an option never changed from default).

- OB1 Configurability nobody uses: options, channels, themes and settings no
  configuration changes from default [`env_read_not_declared`]
- OB2 Abstraction layers, plugin systems and registries with one
  implementation
- OB3 Multi-tenant, multi-region, multi-locale or role systems beyond the scale
  the product has
- OB4 Admin tooling, dashboards and settings screens far beyond what operating
  the core jobs needs
- OB5 Generic engines (rules, workflow, query or form builders) serving one case

Each PX and OB finding states the purpose item, the evidence of excess, the
smaller version that remains and what would be lost
(`reference/findings-schema.md`).
