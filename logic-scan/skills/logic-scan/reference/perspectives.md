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
| NM1 | Binary floating point for money or exact counts: `float`, `double`, JavaScript `number` arithmetic on amounts, `parseFloat` of a price, sums of floats compared for equality | Amount fields, price calculations, parsers of amounts from input or files; a float column itself belongs to a data-integrity review (out of scope here), the arithmetic in code is this step's | Amounts are integers in minor units or a decimal type end to end — because 0.1 + 0.2 is not 0.3, and the difference is charged |
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
| SL1 | Transitions the rule forbids still allowed in code (a schema constraint that would refuse them belongs to a data-integrity review, out of scope here): refund after refund, cancel after shipping, reopening a closed period, a status assigned directly by an admin tool or an import, bypassing the transition function | Every assignment to a status field (the rule-backward pass, `reference/recon.md` §2); state machine definitions; admin and import paths | One function owns the transitions, every writer goes through it, and it refuses the forbidden ones — because a second path that sets the field directly skips every check |
| SL2 | States some readers do not handle: a new status missing from a report's filter, a UI's label map, a job's `WHERE`, so those entities silently disappear or are processed twice | Lists of statuses in queries, filters, mappings and switches, compared with the full set | Readers derive their sets from one definition, or are exhaustive (CB2) — because the entity in the forgotten state is neither billed nor shown |
| SL3 | Fields that encode the same state and can disagree as the code writes them (a `CHECK` that would keep them consistent belongs to a data-integrity review, out of scope here): `status = 'paid'` with `paid_at` null, `is_active` and `deleted_at` both set, a cached flag beside the value it caches | Entities with a status plus timestamps or booleans; updates that set one field and not the other | State is one field with the others derived, or every writer sets them together — because each reader trusts a different field |

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
| CO1 | Check-then-act on in-memory state shared across requests: a module-level cache, a singleton holding request data, a counter incremented without a lock in threaded code | Module and class-level mutable state; caches; workers with thread pools. Database-level races belong to a data-integrity review, out of scope here | Shared state is immutable, per-request, or guarded by one lock around the check and the act — because two requests interleave between the two lines |
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
| ER1 | Errors in the process's own steps turned into plausible values: `except: return 0` around a computation, a parse failure that yields a default amount or date, an in-memory lookup miss that falls back to a default rate | `try`/`catch`/`rescue` blocks around parsing, lookups and arithmetic on core flows | The failure stops the flow or is reported as a failure — because a zero that means "unknown" is added to a total as a zero. A failed call to another service that falls back to a default, retries and timeouts belong to an architecture review of failure handling, out of scope here |
| ER2 | Partial results treated as complete: a loop that skips failed items and reports success, pagination that stops at the first page, a batch whose count of processed items is never compared with its input | Batch jobs, imports, exports, report generation, list fetches from APIs | Completeness is checked (processed equals expected) or the partial result is labelled — because the report looks right and is missing a page |
| ER3 | Fallback branches that change the business outcome: a default currency, country, plan or price list when the real one is missing; a feature flag's off state that keeps a rule no longer stated | Default arguments and config fallbacks on core flows; flag-guarded branches | Every fallback is stated by the rule, or the missing value is an error — because the fallback is applied silently to the customers it does not fit |

### Equality and types (EQ)

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| EQ1 | Comparisons across types: a string id compared with a number, `==` with coercion, an enum compared with its label, a `Decimal` compared with a `float`, a query parameter compared as text | Id and enum comparisons across layers (JSON, query strings, database rows); loose equality in JavaScript and PHP | Values are parsed to one type at the edge, and comparisons are strict — because "10" and 10 are equal in one layer and not in the next |
| EQ2 | Reference compared where value is meant, or the reverse: object identity for dates or amounts, `is` for strings or numbers, float equality on computed values | Equality on value objects, dates, amounts; `includes`/`in` over objects | Value objects define equality, and computed numbers are compared exactly or by the rule's tolerance — because two equal amounts are two objects |
| EQ3 | Keys normalised differently where stored and where looked up, or `hash`/`equals` that disagree: a map keyed by an unnormalised email, a set of objects whose equality ignores a field their hash uses | Maps and sets of business keys; custom `__eq__`/`__hash__`, `equals`/`hashCode` | Keys go through one normaliser, and equality and hash use the same fields — because the lookup misses the entry that is there |

## Sound constructs

A trace row is `conforms` on these grounds only for a construct in the *Sound*
column, cited at `path:line`; an *Unsound* construct is a candidate even when
it looks deliberate. Every named API is a labelled example (`e.g.`), not a list
to grep for: find this stack's equivalent, and check the version the
repository pins before relying on a behaviour.

| Step | Sound (labelled examples) | Unsound look-alike (labelled examples) | Why |
|---|---|---|---|
| BD1 | One half-open convention in a helper: `start <= t < end`; SQL `created_at >= :start AND created_at < :next_start`; Ruby `from...to` (exclusive range); Postgres `tstzrange(a, b, '[)')`. An inclusive end only where the rule states one and every range on the flow agrees | SQL `BETWEEN :from AND :to` on a timestamp with date bounds; Rails `where(created_at: from..to)` with `Date` objects; JS `t <= endDate` where `endDate` is midnight; a quota checked with `<=` before the increment | A date bound on a timestamp column is midnight, so the last day's rows fall outside |
| BD2 | An explicit empty case returning the rule's value; `sum(xs) / len(xs) if xs else 0` where the rule says 0; SQL `COALESCE(AVG(x), 0)` where the rule says 0 | `sum(xs) / len(xs)`; JS `xs.reduce((a, b) => a + b)` with no initial value (throws on `[]`); Java `stream().average().getAsDouble()`; Python `statistics.mean([])`; SQL `AVG` read as a number when no row matched | The empty input is the new customer, the first day, the filtered-out list |
| NE1 | Python `x is not None`; JS `x ?? fallback`, `x !== undefined`; Ruby `x.nil?` (0 and `""` are truthy in Ruby); a validated guard that makes zero impossible, cited at `path:line` | Python `if amount:`, `amount or default`; JS `amount \|\| default`, `if (!count)`; Go code that treats the zero value as "not set" with no `ok` or pointer | `0`, `""` and `false` are values the rule uses: free, none, no |
| NE2 | The three states kept apart: `Optional`/nullable types, a tri-state enum, JSON `null` and a missing key read differently (`"k" in obj`); SQL `col IS DISTINCT FROM 'x'`, `NOT EXISTS`, `COUNT(*)` where rows are meant | SQL `col <> 'x'` (drops `NULL` rows), `NOT IN (subquery)` whose subquery can return `NULL` (returns no rows), `COUNT(col)` where rows are meant (skips `NULL`); `bool(answer)`; Kotlin `flag == true` collapsing `null` into `false` | SQL comparisons with `NULL` are unknown, not false, so the row silently leaves the result |
| NE3 | A miss raises or returns an explicit absence the caller must handle: `dict[key]` with a handled `KeyError`, Go `v, ok := m[k]` with `ok` checked, Java `Optional`, JS `find()` result checked before use | Python `dict.get(k, 0)`, Java `map.getOrDefault(k, 0)`, Go `v := m[k]` (zero value), JS `xs.find(...)?.price ?? 0`, `next(iter, xs[0])` where the rule makes a miss an error | The default is a real value (free plan, zero price) indistinguishable from a hit |
| NM1 | Integer minor units; Python `Decimal("1.10")` from a string; Java `new BigDecimal("1.10")` or `BigDecimal.valueOf(long, scale)`; a decimal library in JS (e.g. `decimal.js`, `big.js`); database `NUMERIC`/`DECIMAL` | `float`, `double`, JS `number` arithmetic on amounts (`price * 1.1`); Python `Decimal(0.1)` and Java `new BigDecimal(0.1)` (built from the binary float); JS `amount.toFixed(2)` as rounding (`(1.005).toFixed(2)` is `"1.00"`); `REAL`/`DOUBLE PRECISION` columns for money | Binary floats cannot hold most decimal fractions, so totals drift by a minor unit |
| NM2 | One rounding helper with an explicit mode and place: `quantize(Decimal("1"), rounding=ROUND_HALF_UP)`, `setScale(0, RoundingMode.HALF_UP)`, applied where the rule says (per line or per total) | Python `round()` (half to even: `round(2.5)` is `2`); JS `Math.round` and Java `Math.round` (half toward +∞: `Math.round(-2.5)` is `-2`); rounding per line in one place and per total in another; rounding twice | The mode decides the cent on exact halves, and two places disagree on every multi-line order |
| NM3 | Units in names or types (`amount_minor`, `timeout_ms`, a `Money` type); one conversion function; division semantics the rule wants, written out | Python `//` floors toward −∞ (`-7 // 2` is `-4`) where Java, Go and C truncate toward zero; SQL integer division (`5 / 2` is `2` on integer columns in PostgreSQL); JS `Date.now()` (ms) mixed with Unix seconds; a percent used as a fraction | A unit or division mismatch is off by a constant factor or by one on negatives |
| DT1 | The business zone named: `datetime.now(ZoneInfo("Asia/Tokyo"))`; Java `LocalDate.now(ZoneId.of(...))` or an injected `Clock`; Rails `Date.current`, `Time.zone.today`; Go `time.Now().In(loc)` | Python `date.today()`, naive `datetime.now()`, `datetime.utcnow()`; Java `LocalDate.now()` (JVM default zone); Rails `Date.today` (system zone); JS `new Date().toISOString().slice(0, 10)` (the UTC date) | Between midnight and 09:00 in Tokyo the server's or UTC date is yesterday |
| DT2 | Calendar arithmetic that clamps: Python `relativedelta(months=1)`; Java `plusMonths(1)`; `date-fns` `addMonths`; Rails `1.month.since`; day arithmetic in the business zone across DST | `timedelta(days=30)` for a month; JS `d.setMonth(d.getMonth() + 1)` (31 Jan becomes 3 Mar, or 2 Mar in a leap year); Go `t.AddDate(0, 1, 0)` (31 Oct becomes 1 Dec, normalised, not clamped); `+ 86400` seconds for a day in a DST zone | Month lengths and DST make counted units drift from the calendar the rule means |
| DT3 | Both sides at one granularity: date with date, instant with instant, the end converted to the next start | JS `new Date("2026-11-30")` (UTC midnight) beside `new Date("2026-11-30T00:00")` (local midnight); a `date` compared with a `datetime`; `<= end_date` against a timestamp | Mixed granularity drops or adds the boundary day |
| SL1 | One transition table or state machine that every write goes through, refusing what it does not list | Status assigned directly on a live path; a "cancellable" set that includes a state the rule excludes; a guard on one entry point only. (A status set in a migration or seed that creates the initial state is sound) | A forbidden transition becomes reachable from the path that skips the guard |
| SL2, CB2 | Exhaustive handling the compiler or a test checks: TypeScript `const _exhaustive: never = s`; a Java or Kotlin `switch`/`when` expression over an enum or sealed type with no `default`/`else`; Python `match` with `case _: raise`; a test that iterates every state | `default: return true` / `else` that accepts any new value; a status list hard-coded in a query or report filter; a label or badge map whose fallback hides a missing key | A new state is handled by whatever the fallback happens to do |
| CA1 | Aggregate before joining: `SUM` in a subquery per order, then join; `COUNT(DISTINCT o.id)`; a test with two payments on one order | `SUM(o.amount)` across `JOIN payments` (or any one-to-many); `COUNT(*)` after a join; `DISTINCT` on the summed value | Each extra child row repeats the parent's amount |
| CA2 | `ORDER BY` with a unique tiebreaker (`created_at DESC, id DESC`) before `LIMIT`/`OFFSET`; keyset pagination; explicit sorting before "first" or "latest" | `LIMIT 1` with no `ORDER BY`; `ORDER BY created_at` alone with ties across pages; Go map iteration (randomised); JS default `sort()` on numbers (`[10, 9, 1].sort()` is `[1, 10, 9]`); "latest" taken as `xs[0]` of an append-ordered list | Without a total order the database or runtime may return any row, and pages skip or repeat rows |
| CA3 | New collections per call (`def f(xs=None): xs = [] if xs is None else xs`); copies before mutation (`sorted(xs)`, `[...xs].sort()`, `toSorted()`) | Python mutable default `def f(xs=[])` and mutable class attributes; JS `Array(3).fill([])` (one shared array); `xs.sort()` on a caller's array; removing items while iterating | Shared or mutated collections leak state between callers |
| TE1 | One normalising key function at store and at lookup: `unicodedata.normalize("NFKC", s).casefold().strip()`; JS `s.normalize("NFKC").trim().toLowerCase()`; Java `toLowerCase(Locale.ROOT)`; a database collation or a `lower()` unique index matching the rule | `==` on raw input; `lower()` at lookup but not at store; Java `toUpperCase()` with the default locale (Turkish `i`); full-width and half-width forms compared raw | Two spellings of one key create duplicates or miss matches |
| TE2 | Parsing and formatting with an explicit locale: `babel.numbers.parse_decimal(s, locale="de_DE")`; `Intl.NumberFormat("ja-JP")`; Java `NumberFormat.getInstance(Locale.GERMANY)`; `Locale.ROOT` for machine formats | `float(s.replace(",", ""))` on a decimal-comma source; JS `parseFloat("1.234,56")` (`1.234`); `toLocaleString()` or Java `String.format("%.2f")` with the default locale for a machine-read value | The same digits mean a thousand times more or less under another locale |
| TE3 | Limits counted in the unit the rule names: code points (`len(s)` in Python, `[...s].length` in JS) or grapheme clusters (`Intl.Segmenter`, a grapheme library); truncation that keeps whole characters | JS `s.length` and `s.slice(0, n)` (UTF-16 units: an emoji is 2 and can be split); byte slicing of UTF-8 then decoding with `errors="ignore"`; MySQL `utf8` (3-byte) columns for text that may hold emoji | The count differs by a factor of up to four for Japanese and emoji |
| CO1 | Request-scoped state passed explicitly; shared state keyed by the session or tenant and guarded; the cache documented as read-only | A module-level dict, a singleton or a class attribute written on a request path in a multi-threaded or async server; one key for every session | Concurrent requests read each other's state |
| CO2 | A stale result discarded: `AbortController` on the previous request; a request sequence number compared before applying; React effect cleanup that ignores a stale response | `await fetch(...)` then render with no check, on input that fires per keystroke; un-awaited promises whose order decides the state | A slower earlier response overwrites the newer one |
| RD1, RD2 | One definition imported by every surface, or generated from one schema (OpenAPI `minimum`/`maximum` read by both the form and the API); a test that compares the copies | The same limit, rate or threshold written in the backend and the front end, or redefined in a second module; a copy that already differs. (A different parameter that happens to share a value, such as a 10% tax and a 10% discount, is sound) | Copies drift, and the first drift is already a defect |
| ER1, ER3 | A failure that propagates, or a default the rule states for that failure, logged: an empty recommendation list when the service is down | Python `except Exception: return 0`; JS `.catch(() => 0)`; Go `n, _ := strconv.Atoi(s)` (0 on error); a default currency, plan, rate or price list when the lookup fails | The default is a plausible business value, so nobody notices the failure |
| ER2 | Completion recorded only when every part succeeded, or partial success recorded as partial: `Promise.allSettled` results checked per item; a batch status of `partial` with the failed IDs | A loop that logs and `continue`s, then marks the batch done; `Promise.allSettled` counted as success; pagination that stops at the first page because the cursor key was misread | Reported success hides the items that never happened |
| EQ1 | Values parsed to one type at the boundary, then compared; JS `===`; typed IDs | JS `==` with coercion (`"0" == 0`); strings compared as numbers (`"10" >= "2"` is `False`); Python `"2" >= 2` (`TypeError` on the path that mixes them); Java boxed `Integer` compared with `==` (true only within the −128..127 cache) | The comparison is right for some values and wrong for others |
| EQ2 | Value equality: Java `BigDecimal.compareTo(...) == 0`; JS `a.getTime() === b.getTime()`; Python `==` for dates and numbers | Java `BigDecimal.equals` (`1.0` is not equal to `1.00`: scale counts); JS `===` on two `Date` objects; Python `is` on dates, numbers or strings | Identity or scale-sensitive equality is false for equal values |
| EQ3 | One key function for store and lookup; `equals` and `hashCode` (or `__eq__` and `__hash__`) derived from the same fields | A map keyed by a normalised string in one place and the raw string in another; `equals` overridden without `hashCode`; a mutable object used as a key | Lookups miss entries that are there |
