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

A hunt step is `sound` on these grounds only for a construct in the *Sound*
column, cited at `path:line`; an *Unsound* construct is a candidate gap even
when it looks deliberate. Every named API is a labelled example (`e.g.`), not
a list to grep for: find this suite's equivalent, and check the version the
repository pins (language, runner, mocking library) before relying on a
behaviour.

| Step | Sound (labelled examples) | Unsound look-alike (labelled examples) | Why |
|---|---|---|---|
| UC2 | Code with no behaviour test of its own that is generated (e.g. protobuf `_pb2.py`, an OpenAPI client), a thin pass-through with no branching, or reached by a contract or end-to-end test that asserts its outcome | A line counted as covered because a test executed it without asserting on its result; coverage.py `# pragma: no cover` or `/* istanbul ignore next */` on a branch that holds a rule | Coverage records execution, not checking, and an exclusion comment hides the branch from the number as well as from the tests |
| MF1, IC1 | A double of an external API whose shape a contract test or recorded-response test in the repository checks: e.g. a Pact consumer test whose pact the provider build verifies; VCR.py or Ruby `vcr` cassettes recorded from the real service | A hand-written JSON fixture never compared with the real API; a Pact consumer test whose pact no provider build verifies; a cassette edited by hand | The other side changes without telling the double |
| MF1 | Doubles that refuse what the real one refuses: Python `create_autospec(Gateway, instance=True)` or `mock.patch(..., autospec=True)` (a call with the wrong arguments raises `TypeError`); RSpec `instance_double(Gateway)` (stubbing a method the class lacks, or with the wrong arity, fails); Mockito `eq(...)`, or an `ArgumentCaptor` whose captured value is asserted; Mockito 2.1.0+ `any(Money.class)` (type-checked, rejects `null`) | Python bare `Mock()` or `MagicMock()` as a client (any attribute, any arguments, every call returns a truthy mock), and `Mock(spec=Gateway)` (checks attribute names, not call signatures); RSpec plain `double("gateway")`, and `instance_double("Gateway")` while that constant is not loaded (not verified unless `verify_doubled_constant_names` is set); Mockito `any()` (matches anything, `null` included), `any(Money.class)` before Mockito 2.1.0 (no type check, matches `null`), and `verify(repo).save(any())` where the saved value is the outcome; Jest `expect.anything()` where the value is known (it matches anything but `null` and `undefined`) | A double that accepts any argument stays green when the call is wrong |
| MF1 | The double is installed where the code looks the name up: Python `mock.patch("app.billing.send_email")` when `app/billing.py` does `from app.mail import send_email`; Jest `jest.mock("./mailer")` at the top level of the test file (hoisted above the imports), its factory referencing only variables prefixed `mock`; per-test variants with `jest.doMock` after `jest.resetModules()`, then `require` or `await import(...)`; Vitest `vi.mock` with shared values created in `vi.hoisted(...)` | Python `mock.patch("app.mail.send_email")` while `app.billing` imported the name with `from app.mail import send_email` (billing keeps the real function); Jest `jest.mock` inside a `test` or `beforeEach` body for a module the file already imported at the top (it is hoisted only to the top of that function, after the import ran); Jest `jest.mock` for a static `import` under native ESM, where it is not hoisted (Jest's ESM docs use `jest.unstable_mockModule` before a dynamic `import()`) | The test runs against the real dependency while its author believes it is replaced |
| DS2 | Assertions that can fail: `mock.assert_called_once_with(x)` (since Python 3.5 a misspelt name starting with `assert` raises `AttributeError`), best on an autospecced mock, which refuses every attribute its spec lacks; `assert mock.call_args == call(x)`; JUnit 5 `assertThrows(Declined.class, () -> pay(order))`; pytest `with pytest.raises(Declined):` around the raising call alone, the assertions after the block; Jest `.resolves`/`.rejects` assertions that are `await`ed or returned | `assert mock.called_once_with(x)` on a plain `Mock`: before Python 3.12 the misspelling creates a child mock, which is truthy, so it always passes (3.12+ raises `AttributeError`); assertions inside `with pytest.raises(...)` after the raising line (never reached); Java `try { pay(order); } catch (Declined e) { }` with no `fail()` after the call; Jest `expect(value)` with no matcher; `expect(promise).resolves.toBe(x)` neither awaited nor returned (the test can finish before it runs) | A test that cannot fail is a skipped test with a green tick |
| AS2 | A small snapshot of the field or structure the behaviour is about, e.g. Jest or Vitest `toMatchInlineSnapshot()`, its rare updates each reviewed in the diff; Jest `--ci` (on by default when Jest detects CI), where a missing snapshot fails instead of being written | A snapshot of a whole rendered page or response holding timestamps or IDs, updated on every change; `jest -u` (`--updateSnapshot`) or `vitest -u` in a CI or `npm test` script, which rewrites every snapshot, so it passes | A snapshot updated on every change is approved, not read |
| ND1 | Time controlled at its source: Python `freezegun` `@freeze_time("2026-03-29T00:30:00Z")` or an injected clock; Java an injected `Clock` (`Clock.fixed(instant, zone)`) read with `LocalDate.now(clock)`; Jest `jest.useFakeTimers()` with `jest.setSystemTime(...)` (modern fake timers, the default since Jest 27, also fake `Date`); Vitest `vi.useFakeTimers()` with `vi.setSystemTime(...)`; Go a `now func() time.Time` field the test sets | `freeze_time` around code whose time comes from the database (`NOW()`, `CURRENT_TIMESTAMP`, a column default), whose clock is not frozen; Java a `Clock` injected but `LocalDate.now()` called without it; Jest legacy fake timers (`jest.useFakeTimers("legacy")`, or `{ legacyFakeTimers: true }` in later versions), which leave `Date` real | A test that depends on the hour fails near midnight, at month end or on a DST change |
| ND2 | A sleep that tests a timeout itself, with a controlled clock. Otherwise a wait on a condition with a bound: Playwright web-first assertions (`await expect(locator).toHaveText("Paid")`, retried until the timeout) or `page.waitForResponse(...)`; Cypress `.should(...)` chained to the query (retried); Java Awaitility `await().atMost(5, SECONDS).until(...)`; Go a `select` on the result channel with `time.After` as the bound | `time.sleep`, `Thread.sleep`, Playwright `page.waitForTimeout(2000)` or Cypress `cy.wait(2000)` (a number, not an alias) before an assertion; Playwright `expect(await locator.textContent()).toBe("Paid")` (read once, not retried); Cypress assertions inside `.then(...)` (not retried) | A fixed sleep is too short on a slow runner and too long everywhere else |
| IS1, IS2 | A shared fixture that is immutable, or session-scoped read-only data. State reset per test: pytest `monkeypatch.setenv` and `monkeypatch.setattr` (undone at teardown); `mock.patch` as a decorator or context manager, or `patcher.start()` paired with `addCleanup(patcher.stop)`; unittest `setUp` (runs per test); JUnit 5 instance fields (a new instance per test method by default); Jest `restoreMocks: true`, or `mockRestore()` after `jest.spyOn`; Go `t.Setenv` (Go 1.17+) and `t.Cleanup` | A pytest fixture with `scope="module"` or `scope="session"` returning a dict or list that tests mutate; `os.environ[...] = ...`, or `patcher.start()` with no `stop`; state built in unittest `setUpClass` and changed by tests; JUnit 5 `static` fields, or instance fields under `@TestInstance(Lifecycle.PER_CLASS)`; `jest.spyOn` with no restore, leaking into later tests in the file; Go `os.Setenv` with no restore (`t.Setenv` panics in a test that calls `t.Parallel`, so that pairing fails loudly) | Shared state makes the result depend on order and on which tests a filter selects |
| TD2 | Go table tests whose parallel subtests each read their own row: `go 1.22` or later in `go.mod` (one loop variable per iteration), or `tt := tt` before `t.Run`; a subtest without `t.Parallel()` runs before the loop moves on | Subtests that call `t.Parallel()` and read the loop variable `tt` in a module whose `go.mod` says `go 1.21` or earlier: every subtest sees the last row. The `go` line in `go.mod` decides, not the installed toolchain | Every subtest checks the last row, so the other cases claim coverage they do not have |
| DS1 | A skip with a stated condition and reason that runs where it targets: `@pytest.mark.skipif(sys.platform == "win32", reason=...)` with a CI job on the other platform; `pytest.mark.xfail(strict=True, reason="#123")` (an unexpected pass fails the run); RSpec `pending` (the example runs, and fails when it passes); JUnit 5 `@Disabled("#123: ...")`. Focus markers refused in CI: Playwright `forbidOnly: !!process.env.CI`, Mocha `--forbid-only`, ESLint `jest/no-focused-tests` | A `skipif` whose condition is always true in CI (e.g. `skipif(not os.environ.get("DATABASE_URL"))` where no job sets it); `xfail` without `strict` (an unexpected pass is reported `XPASS` and the run stays green); RSpec `skip` or `xit`, Jest `it.skip` or `xit`, JUnit 5 `@Disabled` with no issue; JUnit 5 `assumeTrue(...)` or Go `t.Skip` on a missing environment (reported as skipped or aborted, not failed); a committed `.only`, `fit`, `fdescribe`, Playwright `test.only`, or RSpec `focus: true` with `filter_run_when_matching :focus` (Jest then skips the rest of that file; Mocha and RSpec run only the focused examples) | A skipped test reports green forever, and a focus marker silently skips the rest |
| IC2 | Queries that use dialect features run against the production engine in some test, e.g. Testcontainers (Java, Python, Go, Node) or a Postgres service in the CI job; SQLite only for code with no dialect features | SQLite standing in for Postgres: it does not enforce `VARCHAR(n)` lengths, stores `'abc'` in an `INTEGER` column (outside `STRICT` tables, SQLite 3.37+), checks foreign keys only after `PRAGMA foreign_keys = ON` on each connection, matches `LIKE` case-insensitively for ASCII, and rejects `SELECT ... FOR UPDATE`, so locking code is stubbed or skipped in tests | Constraint, type, collation and locking behaviour differ, so the test passes on what production refuses |
