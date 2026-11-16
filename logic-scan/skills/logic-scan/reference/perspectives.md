# Perspectives — the review perspectives and their hunt steps

**Read when:** CHECKLIST, to choose which perspectives apply; REVIEW, after the
logic rule ledger hunt (`reference/conventions.md`), as the coverage sweep;
REPORT, to fill the `perspectives` table in `findings.json`. **Reader:** the
agent running the skill.

A logic defect is a hypothesis that code returns a wrong result. Every
finding has a counterexample (one concrete input, the expected result, the
actual result traced through the code, and the oracle that states the expected
one) and a remedy that closes it (`reference/remedies.md`); `check` requires
the counterexample on High and Medium, and a Low or Info finding records it
the same way when it has one. A finding is above `Info` only with exposure (a
core flow, the callers that reach the site, an input that occurs, a fix commit
that already patched the same rule). Apply each
perspective within every review unit, core flows first, and record every
perspective in the report — including the ones that found nothing and the ones
not run. The names below are the exact values of `perspectives[].name` and
`findings[].category`.

| Perspective | The question it asks |
|---|---|
| Boundaries and ranges | Does every range, limit and threshold include and exclude exactly what the rule says? |
| Conditions and branches | Does every condition decide what the rule decides, for every combination of its inputs? |
| Null, empty and missing | Is "absent" kept apart from zero, false and empty everywhere it means something different? |
| Numbers and money | Is every amount computed in exact arithmetic, rounded once, at the place and in the mode the rule says, in the right unit? |
| Dates, times and time zones | Is every date taken in the zone the rule means, and every period computed on the calendar, not by counting seconds? |
| State and lifecycle | Can an entity reach only the states the rule allows, through the transitions it allows, and do all its fields agree on which state it is in? |
| Collections and aggregation | Does every sum, count, grouping, deduplication and ordering count each thing once, in the order the rule needs? |
| Text, encoding and locale | Are strings compared, measured, parsed and formatted the way the people who type them mean them? |
| In-process concurrency and ordering | Do concurrent requests, callbacks and async results inside the process keep each result tied to the request that asked for it? |
| Rule duplication and drift | Is each business rule implemented once, or do its copies agree with each other and with where the rule is stated? |
| Error paths and defaults | When a step fails or a value is missing, does the flow stop or say so, rather than continue with a plausible wrong value? |
| Equality and types | Do comparisons compare values of the same type and meaning, by value where value is meant? |

Rules:

- A perspective not applicable to this codebase is `N/A` with a reason (no
  money anywhere, a single-locale internal tool, no stateful entities)
- A perspective that could not be checked statically is `not checked` with
  what would be needed (the rule is stated only in a document outside the
  repository, the production time zone is not recorded)
- Every finding names the perspective that surfaced it in `category`, and,
  when one hunt step surfaced it, that step in `step`
- A hunt step covered by a logic rule ledger entry cites it (`C-…`) in the
  perspective's `note` instead of being re-run
- The `note` lists the step IDs applied and each one left out with its reason
- A step is `sound` only when its *Sound when* cell can be filled with
  `path:line` evidence

## Hunt steps per perspective

The bars below are starting points, not rules: a defect needs a counterexample
that reaches it, and code that reads oddly but returns the right result is not
a finding.

### Boundaries and ranges (BD)

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| BD1 | Range ends included or excluded against the rule: `<=` where the period is half-open, `BETWEEN` on timestamps, "until the 31st" compared with a date-time, page `offset` off by one, a quota checked before or after the increment | Period and range checks on core flows; pagination; quota, limit and age checks; the oracle that defines each range (`reference/recon.md` §3) | Every range on the flow uses one convention (half-open is the usual one), named in a helper or a test at the boundary value — because each end is a value real input lands on, every period and every quota |
| BD2 | Empty, single and extreme inputs: an empty cart, one line, the maximum quantity, a zero amount, a division by a count that can be zero, `first`/`last` of what can be empty | Aggregations, averages, ratios, `[0]` and `[-1]` indexing, `max()`/`min()` of possibly empty sequences | Each case returns the result the rule states, shown by a test or an explicit guard — because empty and single are the inputs every new customer starts with |
| BD3 | Thresholds and tiers compared with the wrong operator or in the wrong order: a discount at "10 or more" written `> 10`, tier tables checked top-down that overlap or leave a gap | Pricing tiers, discounts, eligibility, rate limits, grade bands | Tiers are data with tested edges, contiguous and non-overlapping — because the edge customer gets the wrong tier on every order |

### Conditions and branches (CB)

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| CB1 | Conditions that decide the opposite or a different set: an inverted test, a negation pushed through `and`/`or` wrongly, `and`/`or` precedence without parentheses, a copy-pasted condition testing the wrong variable | Eligibility, permission-as-business-rule (not authorization), discount and fee conditions; conditions changed in fix commits | A table of the rule's cases maps to the code, and tests cover each row — because a condition wrong for one combination is right in every demo |
| CB2 | Case analysis that is not exhaustive: a `switch`/`match` whose `default` silently accepts a new enum value, an `if`/`elif` chain with no final case, a status list copied into several filters | Every branch on a status, type, plan, country or currency; the enum's definition and when it last grew | The language checks exhaustiveness, or the default raises — because the next value added falls into whatever the default does |
| CB3 | Order of guards and flags: an early return before a required step, a short-circuit that skips a side effect, feature-flag combinations never tested together | Guard clauses at the top of core functions; `&&`/`||` with calls on the right; flags read on one flow | Each guard's order is forced by the rule, and flag combinations on the flow are enumerated — because the skipped step is invisible until its absence costs |

### Null, empty and missing (NE)

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| NE1 | Zero, false or empty read as absent: `if amount:`, `x || default`, `x or default`, `?:` on numbers, `filter(Boolean)` over values that can be 0 | Truthiness tests on numeric and boolean fields; defaults in function signatures and config readers | Absence is tested explicitly (`is None`, `??`, `has_key`) wherever 0, false or "" are valid — because a zero discount, a free plan or a false opt-out becomes the default |
| NE2 | Missing, null and empty treated as one when the rule distinguishes them: "not answered" vs "answered no", an empty list meaning "all" in one place and "none" in another, a cleared field vs a field not sent in a partial update | Partial-update handlers (`PATCH`), filters and search parameters, optional fields in forms and imports | Each meaning has its own representation, and the code that reads it matches — because a filter with no values that means "all" exposes or charges everything |
| NE3 | Lookups whose miss turns into a value: `dict.get(k, 0)`, `find` returning the first element on no match, an ORM `first()` that is `None` passed on, a default rate when the country is unknown | Lookups of prices, rates, settings and mappings; fallbacks in config | A miss raises or is reported, or the default is stated by the rule — because a missing price that becomes 0 sells for free |

### Numbers and money (NM)

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| NM1 | Binary floating point for money or exact counts: `float`, `double`, JavaScript `number` arithmetic on amounts, `parseFloat` of a price, sums of floats compared for equality | Amount fields, price calculations, parsers of amounts from input or files; a float column itself is `data-scan`'s, the arithmetic in code is this step's | Amounts are integers in minor units or a decimal type end to end — because 0.1 + 0.2 is not 0.3, and the difference is charged |
| NM2 | Rounding at the wrong place, in the wrong mode or more than once: per line vs per total, half-up vs half-even vs down, rounding an intermediate and then rounding again, integer division that truncates, rounding in two implementations of one rule | Tax, discounts, currency conversion, proration, splitting an amount into parts (the parts must sum to the whole) | One function rounds, in the mode the oracle states, at the step it states, and splits allocate the remainder — because each other place produces a different total for the same order |
| NM3 | Units and scale mixed: cents and yen, percent and fraction, milliseconds and seconds, inclusive and exclusive tax, quantities in different units of measure; overflow of a fixed-width integer | Function boundaries that pass bare numbers; config values; conversion helpers; arithmetic on counters and ids | Units are in names or types, and conversions happen in one place — because a bare `100` means a different amount on each side of a call |

### Dates, times and time zones (DT)

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| DT1 | The current date or day boundaries taken in the wrong zone: `date.today()`, `new Date()`, `Time.now` on a server zone compared with a customer's local date; naive and aware date-times mixed; the end of "today" computed in UTC for a customer in JST | Renewals, deadlines, expiry, daily limits, "today's" reports, cut-off times; the runtime's zone setting (`reference/recon.md` §4) | Each flow names the zone its rule means and converts once at the edge — because for nine hours a day UTC and JST disagree on the date |
| DT2 | Calendar arithmetic done by counting: adding 30 days for a month, 86,400 seconds for a day across DST, the 31st plus one month, February 29th, week start and week numbering, business days and holidays | Billing periods, proration, subscription anniversaries, SLAs, schedules | A calendar library adds months and days in the rule's zone, with tests at month end, leap day and the DST change — because those dates arrive every year |
| DT3 | Comparing at the wrong granularity: a date compared with a timestamp, `<= end_date` that drops the last day's events, string comparison of dates in a non-sortable format, two clocks (database `now()` and application `now()`) compared | Range filters in queries and code; expiry checks; dates stored as strings | Both sides are the same type and granularity, and the end is exclusive at the next day's start — because everything after midnight on the last day falls out |

### State and lifecycle (SL)

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| SL1 | Transitions the rule forbids still allowed in code (a schema constraint that would refuse them is `data-scan`'s): refund after refund, cancel after shipping, reopening a closed period, a status assigned directly by an admin tool or an import, bypassing the transition function | Every assignment to a status field (the rule-backward pass, `reference/recon.md` §2); state machine definitions; admin and import paths | One function owns the transitions, every writer goes through it, and it refuses the forbidden ones — because a second path that sets the field directly skips every check |
| SL2 | States some readers do not handle: a new status missing from a report's filter, a UI's label map, a job's `WHERE`, so those entities silently disappear or are processed twice | Lists of statuses in queries, filters, mappings and switches, compared with the full set | Readers derive their sets from one definition, or are exhaustive (CB2) — because the entity in the forgotten state is neither billed nor shown |
| SL3 | Fields that encode the same state and can disagree as the code writes them (a `CHECK` that would keep them consistent is `data-scan`'s): `status = 'paid'` with `paid_at` null, `is_active` and `deleted_at` both set, a cached flag beside the value it caches | Entities with a status plus timestamps or booleans; updates that set one field and not the other | State is one field with the others derived, or every writer sets them together — because each reader trusts a different field |

### Collections and aggregation (CA)

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| CA1 | Counting or summing the wrong thing: a join that multiplies rows before `COUNT`/`SUM`, `DISTINCT` missing or on the wrong column, grouping by a non-unique key, totals summed over rounded parts | Reports, dashboards, invoices and statements; queries joining one-to-many relations before aggregating | The aggregate's grain is stated and the query or code keeps it, tested with a one-to-many fixture — because the first order with two payments counts twice |
| CA2 | Order assumed where none is guaranteed: "the latest" taken from a query without `ORDER BY`, iteration order of a hash map or set, an unstable sort followed by "first", ties left to chance | "Latest", "first", "current" lookups; sorts by non-unique keys; pagination over unordered results | Every order the rule depends on is explicit and total (a unique tiebreaker) — because the database and the runtime change their order without notice |
| CA3 | Collections changed while shared or iterated: a mutable default argument, a list mutated while looping over it, a shallow copy whose nested objects are still shared, a cached object modified by one caller | Default arguments; in-place `sort`/`reverse`/`append` on inputs; objects returned from caches or module-level constants | Inputs are copied before change, and shared objects are immutable — because the next caller sees the previous caller's edit |

### Text, encoding and locale (TE)

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| TE1 | Comparison without normalisation: case, surrounding whitespace, Unicode normalisation (NFC/NFKC), full-width and half-width forms, katakana and hiragana where the rule treats them alike | Login and lookup by email or name, deduplication, search, uniqueness checks in code | Text is normalised the same way where it is stored and where it is compared — because "ＡＢＣ" and "ABC" are the same customer to the customer |
| TE2 | Parsing and formatting that depend on the locale: decimal comma, thousands separators, date order, `toLocaleString` on the server, number parsing that stops at the first unexpected character | Imports, user input of amounts and dates, CSV and PDF generation, emails | Locale is explicit at every parse and format on the flow — because the server's default locale is a deployment accident |
| TE3 | Length and truncation in the wrong unit: bytes vs code points vs grapheme clusters, slicing that splits a surrogate pair or a combining sequence, limits that differ between the frontend and the backend | Field length validation, truncation for display or storage, SMS and email subject limits | Each limit is defined in one unit and checked the same way on both sides — because a name that passes the form fails at save, or is cut in the middle of a character |

### In-process concurrency and ordering (CO)

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| CO1 | Check-then-act on in-memory state shared across requests: a module-level cache, a singleton holding request data, a counter incremented without a lock in threaded code | Module and class-level mutable state; caches; workers with thread pools. Database-level races belong to `data-scan` | Shared state is immutable, per-request, or guarded by one lock around the check and the act — because two requests interleave between the two lines |
| CO2 | Async results applied out of order: a slow response overwriting a newer one, a promise not awaited so the next step reads the old value, an event handler assuming delivery order | Frontend data fetching, debounced search, `async` functions without `await`, event consumers | Each result carries what it answers and stale ones are dropped, every promise is awaited or deliberately detached — because the network reorders responses |
| CO3 | Multi-step updates to shared objects that others can observe half-done: a total updated before its lines, two fields of one object set in separate steps across an `await` | Objects shared between coroutines or threads; UI state updated in pieces | The update is built aside and swapped in whole — because a reader between the steps sees a state that never existed |

### Rule duplication and drift (RD)

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| RD1 | One rule implemented in several places that disagree: frontend and backend validation, price in checkout and in the invoice, eligibility in the API and in the batch job, copy-pasted conditions that later diverged; a value derived locally (a health summary, an alert, a remaining count) beside an authoritative one the upstream already reports (a blocked status, a remaining quota) | The rule-backward pass (`reference/recon.md` §2): every site implementing each core rule | Each rule has one implementation the others call, or a shared test runs every copy against the same cases — because the copies drift with every fix applied to one of them |
| RD2 | Constants and parameters defined more than once: a tax rate, a limit, a fee, a grace period, a currency's minor unit, hard-coded in one place and configured in another | Literals on core flows (`grep` the value), config files, environment variables | Each parameter has one source that every site reads — because the next change edits one copy |
| RD3 | The code against the stated rule: a specification, ADR, product doc or test that states one result while the code gives another; a test that asserts the wrong result and so protects the defect | The oracles (`reference/recon.md` §3) against the code they describe | Code and oracle agree, or the difference is a recorded decision — because whichever is wrong, someone relies on the other |

### Error paths and defaults (ER)

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| ER1 | Errors in the process's own steps turned into plausible values: `except: return 0` around a computation, a parse failure that yields a default amount or date, an in-memory lookup miss that falls back to a default rate | `try`/`catch`/`rescue` blocks around parsing, lookups and arithmetic on core flows | The failure stops the flow or is reported as a failure — because a zero that means "unknown" is added to a total as a zero. A failed call to another service that falls back to a default, retries and timeouts belong to `reliability-scan` |
| ER2 | Partial results treated as complete: a loop that skips failed items and reports success, pagination that stops at the first page, a batch whose count of processed items is never compared with its input | Batch jobs, imports, exports, report generation, list fetches from APIs | Completeness is checked (processed equals expected) or the partial result is labelled — because the report looks right and is missing a page |
| ER3 | Fallback branches that change the business outcome: a default currency, country, plan or price list when the real one is missing; a feature flag's off state that keeps a rule no longer stated | Default arguments and config fallbacks on core flows; flag-guarded branches | Every fallback is stated by the rule, or the missing value is an error — because the fallback is applied silently to the customers it does not fit |

### Equality and types (EQ)

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| EQ1 | Comparisons across types: a string id compared with a number, `==` with coercion, an enum compared with its label, a `Decimal` compared with a `float`, a query parameter compared as text | Id and enum comparisons across layers (JSON, query strings, database rows); loose equality in JavaScript and PHP | Values are parsed to one type at the edge, and comparisons are strict — because "10" and 10 are equal in one layer and not in the next |
| EQ2 | Reference compared where value is meant, or the reverse: object identity for dates or amounts, `is` for strings or numbers, float equality on computed values | Equality on value objects, dates, amounts; `includes`/`in` over objects | Value objects define equality, and computed numbers are compared exactly or by the rule's tolerance — because two equal amounts are two objects |
| EQ3 | Keys normalised differently where stored and where looked up, or `hash`/`equals` that disagree: a map keyed by an unnormalised email, a set of objects whose equality ignores a field their hash uses | Maps and sets of business keys; custom `__eq__`/`__hash__`, `equals`/`hashCode` | Keys go through one normaliser, and equality and hash use the same fields — because the lookup misses the entry that is there |

## Sound constructs

Look-alikes that are not defects, and what makes them so:

| Looks like | Is sound when |
|---|---|
| An inclusive end (BD1) | The rule states an inclusive end, and every other range on the flow uses the same convention |
| A truthiness test on a number (NE1) | Zero is not a valid value there by the rule (a quantity validated to be at least one before it arrives), named at `path:line` |
| A float (NM1) | It holds a measurement where rounding is acceptable (a ratio for display, a coordinate), never money or a count |
| Rounding in two places (NM2) | Both call the same function, or the rule states two different roundings for two different documents |
| Server-local time (DT1) | The repository fixes the server zone and the rule means that zone (an internal tool in one office) |
| A status assigned directly (SL1) | Only in a migration or seed that sets the initial state, never on a live path |
| A duplicated literal (RD2) | It is a different parameter that happens to have the same value (a 10% tax and a 10% discount) |
| A `catch` returning a default (ER1) | The default is what the rule states for the failure (a recommendation list that may be empty), and the failure is logged |
