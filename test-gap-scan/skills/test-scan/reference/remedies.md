# Remedies — test changes, preconditions and seam pitfalls

**Read when:** REVIEW, to name the remedy a gap needs; VERIFY, to check its
preconditions; PLAN, to write steps. **Reader:** the agent running the skill.
**Decision it supports:** which change to the tests closes the gap, what it
needs first, and how to break it into green steps.

`findings[].remedy` is one name from the first column, exactly; a finding
needing several uses the first and lists the rest in `steps`, or is split
into findings linked by `depends_on` (`reference/plan.md`). A `Restructure`
gap is always split: one finding restructures production code (usually
*Introduce Test Seam*), with steps that keep behaviour and verify the existing
tests green, and a second finding adds the tests and depends on it.

## Remedies

| Remedy | Closes | Preconditions to check | Typical steps |
|---|---|---|---|
| Add Behaviour Test | UC1, UC2, UC3, TL2 | The behaviour can be driven from a public entry point; the outcome is observable (a return value, a row, a call at a boundary, an error) | 1. Write the test with today's inputs and the outcomes in `asserts`. 2. Confirm it fails when the behaviour is broken on a scratch copy |
| Add Edge Case Tests | EE2, TD2 | The boundaries the code distinguishes are listed from the code, not guessed | 1. One case per boundary, table-driven where the suite does that. 2. Confirm each fails on its own when its boundary is broken |
| Add Error Path Test | EE1, EE3 | The failure can be forced from outside: a double that raises, input that is refused, a denied principal | 1. Force the failure. 2. Assert what the caller sees and what is left behind (no partial write, the rollback ran) |
| Add Regression Test | RP1, RP2 | The fix commit and the defect it fixed are identified | 1. Write the test that reproduces the defect. 2. Confirm it fails on the fix's parent and passes on the fix |
| Strengthen Assertions | AS1, AS3, DS2 | The outcome the test exists for is identifiable from its name and the code | 1. Replace the weak assertion with the outcome. 2. Use literal expected values |
| Assert Outcomes, Not Interactions | MF3, AS2 | The outcome can be read back (the stored row, the returned value, the sent payload) | 1. Assert the outcome beside the interaction. 2. Remove the interaction assertion when it adds nothing |
| Replace Mock with Fake | MF1, MF2 | The real dependency's rules that matter are known from its documentation, its errors in history, or a contract | 1. Write a fake that enforces those rules. 2. Move tests to it one file at a time. 3. Remove the permissive mock |
| Add Contract Test | IC1, IC3 | The contract's source of truth exists (an OpenAPI file, a schema, recorded responses, the producer's code) | 1. Test the client against the contract. 2. Test the double against the same contract |
| Add Integration Test | IC2, TL2 | The production engine or service can run in the test environment the suite already uses (a container, a test database) | 1. Add one test through the real wiring. 2. Keep unit tests for the rules |
| Add Property Test | EE2, AS3 | The behaviour has a stated invariant (round-trip, ordering, conservation of totals) and the suite has or allows a property library | 1. State the invariant. 2. Generate inputs within the domain. 3. Keep the shrunk failing cases as examples |
| Control Time and Randomness | ND1 | Time and randomness can be injected or frozen with the suite's existing tool | 1. Freeze or inject in the test. 2. Assert with fixed values |
| Wait on Condition, Not Sleep | ND2 | The condition the sleep waits for is observable | 1. Replace the sleep with a bounded wait on the condition |
| Isolate Shared State | IS1, IS2, ND3 | Every writer of the shared state is found, including other tests | 1. Give each test its own state or reset it in teardown. 2. Run the affected tests alone and in reverse order |
| Build Data with Factories | TD1, TD2 | The suite has or accepts a factory idiom (`reference/conventions.md`) | 1. Add or extend the factory with defaults. 2. Move tests one file at a time, each stating only the fields that matter |
| Re-enable or Delete Skipped Test | DS1, ND3 | The reason for the skip is known; the behaviour still exists | 1. Fix and re-enable, or delete with the reason in the commit when the behaviour is gone |
| Run Tests in CI | CI1, CI2 | The test command and the job that should run it are known | 1. Add the directory or job. 2. Make the job fail the build. 3. Mark it required where the repository documents its protection |
| Introduce Test Seam | UC1, ND1, MF2; precondition of every `Seam` finding, and the usual remedy of a `Restructure` finding | The production change only adds a parameter, constructor argument or adapter defaulting to today's value; existing callers are unchanged | 1. Add the seam with today's default. 2. Confirm the existing tests stay green. 3. Use the seam in the new test |

## Preservation pitfalls when adding a seam

A seam changes production code, so it must keep behaviour. Check these in
VERIFY before calling a `Seam` step behaviour-preserving:

| Language | Pitfalls |
|---|---|
| Python | Default argument evaluated once at definition (`clock=time.time()` freezes the clock; use `clock=time.time`); module import side effects; keyword-only vs positional parameters callers rely on |
| TypeScript / JavaScript | `this` binding when passing a method as the default; optional parameters changing a function's `length` used by a framework; DI tokens resolved by string |
| Java / Kotlin | Frameworks constructing the class by reflection (Spring, JPA) need a no-argument or annotated constructor; a new constructor overload can change which one is injected |
| Go | Adding a parameter changes every caller; prefer a field on the struct or a functional option; exported vs unexported fields by case |
| Ruby | Keyword argument defaults evaluated per call (unlike Python); autoload and constant lookup when moving construction |
| Any | Construction moved later changes when errors surface (start-up vs first call); a default created per call instead of once changes connection pooling or caching |

A pitfall that applies and cannot be ruled out statically raises
`testability` to `Restructure` and is named in `coverage.gaps`; the seam then
becomes its own finding, and the tests a second one that depends on it.
