# Remedies — logic changes, preconditions and pitfalls

**Read when:** REVIEW, to name the remedy a defect needs; VERIFY, to check its
preconditions and how far it reaches; PLAN, to write steps. **Reader:** the
agent running the skill. **Decision it supports:** which change to the code
closes the defect, what it needs first, and how to break it into steps that
each leave the build green and every other result unchanged.

`findings[].remedy` is one name from the first column, exactly; a finding
needing several uses the first and lists the rest in `steps`, or is split
into findings linked by `depends_on` (`reference/plan.md`).

Every remedy carries the same test: the counterexample becomes a test that
lands in the same change as the fix, and is seen failing with the fix
reverted. A fix without that test may close a different defect. The steps
below number the test first for reading order; it ships with the fix, so no
step leaves the build red.

## Remedies

| Remedy | Closes | Preconditions to check | Typical steps |
|---|---|---|---|
| Fix Range Boundary | BD1, BD3, DT3 | The convention the rule states for the range (inclusive or half-open) is known, and every reader of the same range is found | 1. Test at the boundary value and one either side. 2. Change the comparison, or move the range into one helper every reader uses |
| Handle Empty and Extreme Inputs | BD2 | What the rule says for the empty, single and maximum cases is known (an error, zero, a stated default) | 1. Tests for empty, one and the maximum. 2. Add the explicit case before the general path |
| Correct the Condition | CB1 | The rule's cases are written as a table, each with its expected outcome | 1. One test per row of the table. 2. Rewrite the condition from the table; name intermediate conditions |
| Make Case Analysis Exhaustive | CB2, SL2 | The full set of values is defined in one place (an enum, a constant list) | 1. Make the language check exhaustiveness, or make the default raise. 2. Handle each value explicitly. 3. Derive every reader's list from the one definition |
| Reorder Guards | CB3 | The order the rule requires is known, and which steps must always run | 1. Test the path where the guard fires. 2. Move the required step before the guard, or the guard after it |
| Distinguish Missing from Zero | NE1, NE2 | Which values are valid (0, false, "", empty list) and what absence means are stated | 1. Tests with each valid falsy value and with absence. 2. Test absence explicitly (`is None`, `??`), never truthiness |
| Make Absence Explicit | NE3, ER1 | What the flow should do on a miss is decided (stop, report, a default the rule states) | 1. Test the miss. 2. Make the lookup raise or return an explicit missing value, and handle it where the decision belongs |
| Use Exact Arithmetic | NM1 | Every place that reads or writes the amount is known, and the rounding of existing values is decided | 1. Test the case floats get wrong. 2. Move amounts to integers in minor units or a decimal type at the edge, end to end |
| Centralise Rounding | NM2 | The oracle states the place, the mode and the step of rounding; every implementation of it is found | 1. Test the counterexample through every caller. 2. One function rounds; every caller uses it. 3. Splits give the remainder to a stated part |
| Make Units Explicit | NM3 | Each value's unit is known on both sides of every boundary it crosses | 1. Test across the boundary. 2. Put the unit in the name or a type, and convert in one place |
| Use Zone-Aware Time | DT1 | The zone each rule means is stated (the customer's, the shop's, UTC) and where the customer's zone is stored | 1. Test at a time when the zones disagree on the date. 2. Take "now" once, aware, and convert to the rule's zone at the edge |
| Use Calendar Arithmetic | DT2 | The calendar rule is stated (what one month after the 31st is, whether a day is 24 hours or a calendar day) | 1. Tests at month end, leap day and the DST change. 2. Use the calendar library's month and day arithmetic in the rule's zone |
| Compare at the Right Granularity | DT3 | Which granularity the rule means (a date or an instant) is known for both sides | 1. Test the last moment of the last day. 2. Convert both sides to one type; end ranges at the next period's start, exclusive |
| Enforce Transitions in One Place | SL1 | The allowed transitions are listed, and every writer of the state is found | 1. Test a forbidden transition from each path. 2. Route every writer through one transition function that refuses the rest |
| Derive State from One Source | SL3 | Which field is the source of truth is decided, and every reader is found | 1. Test an entity whose fields disagree. 2. Derive the others from the source, or set them together in one place |
| Fix Aggregation Key | CA1 | The aggregate's grain is stated (per order, per customer, per payment) | 1. Test with a one-to-many fixture. 2. Aggregate at the stated grain: `DISTINCT` on the key, or aggregate before the join |
| Make Ordering Explicit | CA2 | The order the rule needs is known, with a unique tiebreaker | 1. Test with ties and with a shuffled input. 2. Sort explicitly by a total order |
| Copy Before Mutating | CA3 | Which callers share the object is known | 1. Test two callers in sequence. 2. Copy on input, or make the shared object immutable |
| Normalise Before Comparing | TE1, EQ3 | The normalisation the rule means is stated (case, NFKC, width, trimming) and applied where values are stored | 1. Test with each variant. 2. One normaliser at storage and at comparison. 3. Existing stored values that differ go to `decisions` |
| Parse and Format with Explicit Locale | TE2 | The locale each input and output means is known | 1. Test with a locale that differs from the server's. 2. Pass the locale explicitly at every parse and format |
| Measure Text in Characters | TE3 | The unit of each limit is stated (bytes for storage, characters for people) and the same on every side | 1. Test with multi-byte, combining and emoji input. 2. Measure and truncate in the stated unit, on grapheme boundaries where people see it |
| Make Check-and-Act Atomic | CO1, CO3 | The state is in process (database races go to `data-integrity-scan`) and which code shares it is known | 1. Test with interleaved callers where the language allows it deterministically. 2. Remove the sharing, or hold one lock across check and act, or build aside and swap |
| Discard Stale Results | CO2 | What each result answers is known (a request id, a query, a version) | 1. Test a slow first response arriving after a fast second one. 2. Tag requests and drop results that are not the latest; await every promise the flow depends on |
| Single Source for the Rule | RD1, RD2 | Every copy of the rule is found, and their differences are listed as decisions where they disagree | 1. A shared test that runs every copy against the same cases. 2. Make one implementation the source; others call it or are generated from it |
| Align Code with the Stated Rule | RD3 | Whether the code or the oracle is right is decided by the rule's owner | 1. Test the oracle's case. 2. Change the code, or record the decision and change the oracle; fix any test that asserted the wrong result |
| Propagate Errors Instead of Defaults | ER1, ER3 | Which caller decides what a failure means is known | 1. Test the failure. 2. Let the error or an explicit missing value reach that caller; keep a default only where the rule states it |
| Track Completeness | ER2 | What "complete" means is countable (items in, items out, pages) | 1. Test a run where one item fails. 2. Compare processed with expected, and report or fail a partial run |
| Compare by Value with Matching Types | EQ1, EQ2, EQ3 | The type each value should have is known at every layer it crosses; for a custom type, which fields make two values equal | 1. Test across the layers with each representation, and two equal values in a set or map. 2. Parse to one type at the edge; compare strictly and by value; define equality and hash on the same fields |

## Preservation pitfalls

A remedy changes the results some callers see, so each step must change only
the wrong result. Check these in VERIFY before calling a finding `Local`:

| Pitfall | What to check |
|---|---|
| Other callers rely on the wrong result | Every caller of the changed function (the rule-backward pass); a caller that compensates for the defect (adds back the lost yen, subtracts a day) breaks when it is fixed — fix both together and mark the finding `Shared` |
| Results already produced | Stored totals, documents sent, points awarded, reports filed: fixing the code does not fix them. The finding is `Correction`, and correcting them is a decision for the rule's owner, never a silent step |
| Tests that assert the defect | A test expecting the wrong result passes today and fails after the fix; it is changed with the fix, and named in `trace` |
| Contracts outside the repository | An API response, an export file, a webhook payload whose values change; consumers outside the repository may depend on them — `Shared`, with the consumers named in `change_reason` |
| Rules that differ on purpose | Two roundings or two calendars the rule states for two documents; centralising them would break one — read the oracle before merging copies |
| Behaviour hidden behind flags | A fix on one side of a feature flag leaves the other side wrong; name both sides in `steps` |

A pitfall that applies and cannot be ruled out statically raises `change` to
`Shared` or `Correction`, and is named in `change_reason`.
