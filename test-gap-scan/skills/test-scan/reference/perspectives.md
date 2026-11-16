# Perspectives — the review perspectives and their hunt steps

**Read when:** CHECKLIST, to choose which perspectives apply; REVIEW, after the
idiom ledger hunt (`reference/conventions.md`), as the coverage sweep; REPORT,
to fill the `perspectives` table in `findings.json`. **Reader:** the agent
running the skill.

A test gap is a hypothesis that a defect could reach production without a
test failing. It becomes a finding above `Info` only with exposure (a
critical flow, an escaped defect, churn on the untested code) and a remedy
that closes it (`reference/remedies.md`). Apply each perspective within every
review unit, critical flows first, and record every perspective in the report
— including the ones that found nothing and the ones not run. The names below
are the exact values of `perspectives[].name` and `findings[].category`.

| Perspective | The question it asks |
|---|---|
| Untested critical paths | Does every branch of a critical flow have a test that would fail if it broke? |
| Error and edge cases | Are the failure paths and boundaries tested, not only the happy path? |
| Assertion strength | Does each test check the outcome it exists for? |
| Mock fidelity | Do the test doubles behave like what they replace? |
| Nondeterminism and flakiness | Does each test give the same result every run, in any order, at any time? |
| Isolation and shared state | Can each test run alone and in any order? |
| Integration and contract seams | Is every boundary with another system tested against its real contract? |
| Test level balance | Are behaviours tested at the cheapest level that can catch their defects? |
| Regression pinning | Did every fixed defect leave a test behind? |
| Test data and fixtures | Does test data make each case's intent visible and stay valid as the schema moves? |
| Disabled and skipped tests | Is every skipped, ignored or quarantined test tracked to a decision? |
| Suite execution in CI | Does CI run every test the suite holds, and fail the build when one fails? |

Rules:

- A perspective not applicable to this codebase is `N/A` with a reason
- A perspective that could not be checked statically is `not checked` with
  what would be needed
- Every finding names the perspective that surfaced it in `category`, and,
  when one hunt step surfaced it, that step in `step`
- A hunt step covered by an idiom ledger entry cites it (`C-…`) in the
  perspective's `note` instead of being re-run
- The `note` lists the step IDs applied and each one left out with its reason
- A step is `sound` only when its *Sound when* cell can be filled with
  `path:line` evidence

## Hunt steps per perspective

The bars below are starting points, not rules: a gap needs exposure, and an
untested function nothing depends on is not a finding.

### Untested critical paths (UC)

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| UC1 | Critical-flow branches no test reaches: walk each named flow from its entry point and mark each branch with the test that drives it | Entry points from `reference/recon.md` §2; the test map | Every branch that moves money, grants access or deletes data has a test that fails when it breaks — because the untested branch is where the costly defect ships |
| UC2 | Hotspot code without a behaviour test: files in the top decile of churn whose behaviour no test asserts | Hotspot table × test map | Each hotspot behaviour is asserted — because code that changes often breaks often |
| UC3 | Recently added behaviour with no test in the same or the next commit | `git log --since=<window start> --diff-filter=A` on source files; the commits that added them | New behaviour arrived with its tests — because a feature without tests is the next escaped defect |

### Error and edge cases (EE)

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| EE1 | Error paths no test triggers: `except`/`catch`/`if err != nil` blocks, rollback and compensation code, retries' final failure | Error handling in critical flows | A test forces each failure that changes what the caller sees — because an untested error path fails the first time it runs, in production |
| EE2 | Boundaries no test probes: empty, zero, one, maximum, negative, rounding edges, time zones and DST, Unicode, pagination ends | Validation, arithmetic, date and string handling | The boundary cases the code itself distinguishes are each tested — because off-by-one and rounding defects live exactly there |
| EE3 | Authorization denial paths no test exercises: the other tenant, the missing role, the expired token | Permission checks on critical flows | A test asserts each denial — because a test suite that only logs in as admin cannot see a missing check |

### Assertion strength (AS)

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| AS1 | Tests that assert only a status code, `is not None`, "no exception" or a truthy value where the outcome is a value, a row or a call | Test bodies of critical-flow tests | Each test asserts the outcome its name promises — because a test that would pass with the wrong total catches nothing |
| AS2 | Snapshot or golden-file tests over large output where the behaviour is one field | Snapshot files and their update history | The snapshot is small and reviewed, or the field is asserted directly — because a snapshot updated on every change is approved, not read |
| AS3 | Assertions that restate the implementation: the expected value computed by the same function or formula as the code | Tests that import the helper they check | Expected values are literals or computed independently — because a test that repeats the code repeats its defect |

### Mock fidelity (MF)

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| MF1 | Doubles more permissive than the real dependency: a mock that accepts any argument and returns success | Shared fixtures, `conftest`, test helpers; fix commits that mention the dependency | The double refuses what the real one refuses, or a contract test checks it — because a mock that always succeeds hides every misuse |
| MF2 | Tests that mock the unit under test, or so many collaborators that only the call order is left to check | Patch and mock counts per test | The unit's own logic runs, with only its boundaries replaced — because a test of mocks tests nothing |
| MF3 | Interaction assertions where an outcome exists: `assert_called_with` on a repository instead of reading what was stored | Verify/assert-called patterns | Outcomes are asserted where they can be read — because interaction tests break on refactoring and pass on wrong data |

### Nondeterminism and flakiness (ND)

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| ND1 | Wall clock, time zone or randomness read without control: `now()`, `Date.now`, `random`, UUIDs compared by value | Production code reached by tests; test bodies | Time and randomness come from a controlled source in tests — because a test that depends on the hour fails near midnight |
| ND2 | Sleeps and fixed timeouts waiting for asynchronous work | `sleep`, `setTimeout`, `waitForTimeout` in tests | Tests wait on a condition with a bound — because a fixed sleep is too short on a slow runner and too long everywhere else |
| ND3 | Retry-on-failure and rerun settings that hide flaky tests | Runner config (`--reruns`, `retries`, `flaky` markers), CI retry steps | Reruns are tracked to named flaky tests with an owner — because an automatic rerun turns a real intermittent defect green |

### Isolation and shared state (IS)

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| IS1 | State shared across tests: module globals, singletons, class attributes, environment variables, a database not reset between tests | Fixtures' scope, setup and teardown | Each test sets up and cleans what it uses — because shared state makes results depend on order |
| IS2 | Tests that depend on another test's side effects or on run order | Tests reading data another test writes; ordered test names | Each test passes when run alone — because an order dependency breaks under parallel or filtered runs |

### Integration and contract seams (IC)

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| IC1 | External APIs exercised only through hand-written mocks, with no contract or recorded-response test | Clients for payment, email, storage, third-party APIs | A contract test or a recorded real response pins the shape — because the other side changes without telling the mock |
| IC2 | Database queries tested only against an in-memory substitute that differs from production (SQLite for Postgres, a fake repository) | Test database configuration; raw SQL and dialect features | Queries that use dialect features run against the production engine in some test — because constraint, locking and type behaviour differ |
| IC3 | Message, event or webhook payloads with no test of the consumer's view of the producer's shape | Producers and consumers of the same topic or endpoint | Both sides are tested against one schema — because a renamed field breaks the consumer silently |

### Test level balance (TL)

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| TL1 | Logic tested only through slow end-to-end or UI tests | E2E suites vs unit tests for the same rules | Rules are tested at unit level, with a few end-to-end paths on top — because an end-to-end-only rule is tested rarely and debugged slowly |
| TL2 | Wiring tested only at unit level: routes, DI registration, middleware order, migrations never exercised together | Integration test presence per entry point | Each entry point is reached at least once through the real wiring — because every unit can pass while the app does not start |

### Regression pinning (RP)

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| RP1 | Fix commits in the window whose diff touched no test | Fix hashes from `reference/recon.md` §4, `git show --stat <hash>` | Each fix added or changed a test that fails without it — because an unpinned fix can be undone by the next change |
| RP2 | Incident or bug references (issue numbers, postmortem links) with no matching test | Commit messages, CHANGELOG, comments naming issues | Each recorded defect has a test that names it — because the same defect returns |

### Test data and fixtures (TD)

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| TD1 | Large shared fixtures and raw dict or JSON blobs where the case's relevant field is buried | Fixture files, factories, inline literals | Each test states the fields that matter and defaults the rest — because a reader cannot tell what the test is about, and a schema change breaks every blob |
| TD2 | Test data that cannot reach the case it claims: fixtures missing the states the code branches on | Fixtures vs the branches in UC1 and EE2 | The data covers the branching states — because a fixture with only active users never tests suspended ones |

### Disabled and skipped tests (DS)

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| DS1 | Skipped, ignored, `xfail`, `.only`, commented-out or quarantined tests | `skip`, `xit`, `@Ignore`, `t.Skip`, `xfail`, commented test bodies | Each has a reason, an owner or issue, and a date; `.only` appears nowhere — because a skipped test reports green forever |
| DS2 | Tests that cannot fail: empty bodies, assertions in unreached branches, `try` blocks that swallow the assertion error | Test bodies | Every test can fail — because a test that cannot fail is a skipped test with a green tick |

### Suite execution in CI (CI)

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| CI1 | Tests the CI jobs never run: directories outside the runner's path, markers excluded, a second suite with no job | CI workflows, runner config, test discovery patterns | Every test directory is run by a job — because a test that never runs protects nothing |
| CI2 | Test failures that do not fail the build: `continue-on-error`, a test command whose exit status is discarded, allowed failures, a test job that is not required for merge | CI workflows, branch protection as documented in the repository | A failing test blocks the merge — because a red test nobody must fix is ignored |

## Sound constructs

Look-alikes that are not gaps, and what makes them so:

| Looks like | Is sound when |
|---|---|
| Untested code (UC2) | It is generated, a thin pass-through with no branching, or reached by a contract or end-to-end test that asserts its outcome |
| A mock of an external API (MF1) | A contract test or recorded-response test in the repository checks the same shape |
| A snapshot test (AS2) | The snapshot is small, its updates are rare and each update is reviewed |
| A skipped test (DS1) | It is platform-specific with a stated condition (`skipif(sys.platform == "win32")`) and runs on the platform it targets |
| A sleep in a test (ND2) | It tests a timeout itself, with a controlled clock |
| A shared fixture (IS1) | It is immutable or session-scoped read-only data |
