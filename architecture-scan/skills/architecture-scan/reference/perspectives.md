# Perspectives — reviewing from more than one angle

**Read when:** CHECKLIST, to choose which perspectives apply; REVIEW, after the
rules hunt (`reference/rules.md`), as the coverage sweep; REPORT, to fill the
`perspectives` table in `findings.json`. **Reader:** the agent running the
skill.

The rules ledger finds what this codebase's own rules forbid. The perspectives
then make sure nothing outside the ledger is skipped: apply each one within
every review unit (`SKILL.md`, *Run contract*), work through its hunt steps
below, and record every perspective in the report — including the ones that
found nothing and the ones not run. The names below are the exact values of
`perspectives[].name` and `findings[].category`.

| Perspective | The question it asks |
|---|---|
| Boundaries and layering | Do dependencies point the declared way, without cycles, through public surfaces? |
| Cohesion and responsibility | Does each module, class and handler do one job, and is each job in one place? |
| Coupling | Can one module change without forcing changes in others? |
| Domain model and data ownership | Does each business rule and each core store have exactly one owner? |
| Consistency and transactions | Does each core flow stay consistent under partial failure, retry and concurrency? |
| Failure handling | Do failures propagate under one model and never vanish on a core flow? |
| API and event contracts | Are external contracts separate from internal models and evolved compatibly? |
| Configuration and environment | Is configuration read in one place and kept out of business logic? |
| Testability | Can the core rules be tested without the database, the network or the clock? |
| Operability | Can the system be deployed, migrated and diagnosed safely? |
| Duplication and consistency of patterns | Is each concept implemented once, and each recurring problem solved one way? |
| Dependencies and evolution | Are frameworks and vendors kept at the edges, and is dead structure removed? |

Rules:

- A perspective not applicable to this application is recorded as `N/A` with a
  reason (e.g. `API and event contracts: N/A — CLI tool, no external API`)
- A perspective that could not be checked statically is recorded as `not
  checked` with what would be needed
- Every finding names the perspective that surfaced it in `category`
- A hunt step covered by a rules ledger entry cites it (`R-…`) in the
  perspective's `note` instead of being re-run
- The `note` lists the hunt step IDs applied and each one left out with its
  reason
- A step is `sound` only when its *Sound when* cell can be filled with the
  mechanism's `path:line`. "The framework separates it" is not evidence

## Hunt steps per perspective

Each step says **what** to hunt, **where** to look, and what evidence makes it
**sound** — with the reason. Framework names are examples only. Steps marked
*(sound constructs)* have a table at the end of this file. The ledger family
(`reference/rules.md` §2) that usually covers a perspective is in brackets.

### Boundaries and layering (BL) [LAYER, BOUND]

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| BL1 | *(sound constructs)* Dependency direction: domain or application code importing presentation, framework, ORM or vendor SDKs | Import graph (`reference/recon.md` §3) | Every edge points the declared way, or crosses through an interface the inner layer owns — because an inner layer that imports an outer one changes with it |
| BL2 | Cycles between modules or layers | Import graph | No cycle, or the cycle is broken by an interface or event — because a cycle makes both modules one unit for every change and test. An interface the callee declares to call its own caller back (in Go, satisfied implicitly and wired in `main`) does not break the cycle; it hides it from the import graph, which a compiler that rejects import cycles shows as clean |
| BL3 | *(sound constructs)* Reaching into internals: imports that bypass a module's public surface, shared mutable types exported by accident | Imports that target non-index files of another module | All cross-module use goes through the public surface, enforced at `path:line` — because an unenforced boundary erodes with each change |
| BL4 | Layer skipping: handlers calling repositories or SDKs directly while the rest go through services | Entry points vs the majority pattern | The same path as sibling handlers — because the skipped layer is where rules live |

### Cohesion and responsibility (CR)

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| CR1 | God modules and classes: one unit owning several unrelated responsibilities, often a hotspot | Largest files × most-changed files (`reference/recon.md` §8) | Each responsibility has its own unit, or the size is stable and unchanged — because a hotspot with many reasons to change is where conflicts and regressions concentrate |
| CR2 | Fat entry points: business rules in controllers, views, resolvers, consumers or UI components | Handlers longer than their siblings; conditionals on domain state in handlers | Rules live in the domain or application layer the siblings use — because a rule in a handler is skipped by every other entry point |
| CR3 | Scattered features: one concept's logic spread across many modules (shotgun surgery) | Co-change across modules; search for the concept's name | A change to the concept touches one module — because the history shows the cost |

### Coupling (CP)

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| CP1 | Co-change across boundaries: files in different modules that change together | `git log` co-change (`reference/recon.md` §8) | Low co-change, or the pair is intended to be one module — because co-change is coupling measured |
| CP2 | Shared mutable state: globals, singletons, module-level caches, static registries written from several places | Module-level assignments and singletons | One owner writes it, others read through an API, and writes are serialised (lock, actor, atomic swap) when the unit runs threads, workers or async tasks — because hidden shared state makes behaviour order-dependent |
| CP3 | Shared database between deployable units, or reads of another module's tables | Data ownership table (`reference/recon.md` §5) | Each unit reads others' data through their API or a published view — because a shared schema couples deploys and migrations |
| CP4 | Temporal coupling: calls that must happen in a hidden order, initialisation side effects, synchronous call chains across services | Constructors, init hooks, service clients | The order is enforced by types or a single entry point — because a hidden order breaks on the next refactor |

### Domain model and data ownership (DM) [OWN]

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| DM1 | *(sound constructs)* Multiple writers of a core store, applying different rules | Writers column of the data ownership table | One module writes, others call it — because each writer is a place a rule can be missed |
| DM2 | Duplicated business rules: the same calculation or validation implemented in several places (backend and front end, two services, two handlers), and whether they have diverged | Search for the rule's constants, field names and formulas | One implementation, others delegate — because copies diverge, and a diverged rule is a defect |
| DM3 | Invalid states representable: status combinations, nullable fields and loose types (strings for money, IDs, enums) that the domain forbids; naive and aware datetimes mixed, or server-local time in business-day rules | Entity definitions, DTOs | Types or constructors reject the invalid combination — because every caller otherwise re-checks, or does not |
| DM4 | Model leaks: persistence entities used as domain objects and API payloads at once | Entity classes imported by handlers and serializers | Separate shapes where the needs differ — because one change to the table becomes an API change |
| DM5 | Tenant scoping and authorization enforced per call site instead of by one owner: a `tenant_id` filter or permission check repeated in every handler, so one path can lack it | Queries on tenant-owned tables; permission checks in handlers vs services | A repository default scope, row-level security or a policy layer at `path:line` that every path goes through — because each call site is a place the filter is forgotten. Where it is enforced is a design question; how it could be exploited is a security review. When an ADR mandates the per-call-site check, that rule goes to `decisions`, and a call site that lacks it is still the finding |

### Consistency and transactions (TX) [TX]

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| TX1 | *(sound constructs)* Dual writes: a database commit and a message publish or external call in one flow, with no recovery if the second fails | Flows from `reference/recon.md` §6 | An outbox, a saga with compensation, or a reconciliation job at `path:line` — because the second write fails eventually, and then the two systems disagree |
| TX2 | *(sound constructs)* Non-idempotent consumers and handlers on at-least-once channels or client retries | Consumers, webhook handlers, retried jobs | Idempotency key or natural idempotency at `path:line` — because redelivery is normal, not exceptional |
| TX3 | Transaction scope: transactions spanning external calls, missing transactions around multi-row invariants, transactions started in several layers; a declared scope that never applies (Spring `@Transactional` on a method called from its own class, or on a private or final method, as Kotlin methods are unless the `kotlin-spring` plugin opens them; `REQUIRES_NEW` called within one class; rollback that skips checked exceptions without `rollbackFor`); writes in after-commit work with no transaction of their own (`@TransactionalEventListener(AFTER_COMMIT)` without `REQUIRES_NEW`) | Transaction decorators and blocks, and who calls each annotated method | One layer owns the scope and every call into it crosses the proxy (another bean) at `path:line`; multi-row invariants commit together; no external calls inside — because a scope in the wrong place either breaks invariants or holds locks, and an annotation the proxy never sees is no scope at all |
| TX4 | *(sound constructs)* Read-modify-write on shared aggregates without a version or lock | Update paths of core aggregates; in-memory state; scheduled jobs that run in every replica; sync endpoints that resolve conflicts last-write-wins on client timestamps (mobile, offline) | Optimistic version or conditional update — because concurrent updates otherwise lose writes |
| TX5 | Derived copies drift: caches, denormalised columns, search indexes, read models or projections updated on a path not every writer takes | Data-ownership writers (`reference/recon.md` §5) × cache and projection update sites; event handlers per event type | Invalidation or projection update hangs off the owner's single write path or a change stream at `path:line`, and the copy can be rebuilt from the source — because a writer that skips the update serves stale data indefinitely |

### Failure handling (FH) [FAIL]

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| FH1 | *(sound constructs)* Swallowed failures: broad catches that log and continue, ignored return values or promises, `catch {}` on core flows; errors lost in background work (a goroutine, thread or task whose failure never reaches its caller or stops the process, e.g. `sync.WaitGroup` where `errgroup` is needed) | Exception handlers and result handling | Errors propagate or are handled with a defined outcome — because a swallowed error turns into wrong data reported as success |
| FH2 | Inconsistent error model: several exception hierarchies or result types, errors translated in several layers, internal errors reaching clients | Error types and middleware | One model, translated once at the edge — because each translation loses information or leaks it |
| FH3 | Retries without bounds or idempotency, and no defined behaviour on a dependency outage | Client wrappers, job retry config | Bounded retries on idempotent operations, a defined fallback — because unbounded retries amplify an outage |

### API and event contracts (AC) [CONTRACT]

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| AC1 | Internal models exposed as contracts: ORM entities serialised directly, internal enums in public payloads | Serializers, response types, event payloads | Explicit DTOs or schemas — because every internal change becomes a breaking change |
| AC2 | *(sound constructs)* Versioning and evolution: breaking changes without a version, events without a schema or version, removed fields still read by clients | API routes, schema files, event definitions, client code in the repo | A versioning or additive-only policy applied — because consumers deploy on their own schedule |
| AC3 | Inconsistent contract shapes: naming, pagination, error format and ID formats differing between endpoints | Route inventory | One convention, or documented exceptions — because each variant is client code to write and maintain |

### Configuration and environment (CF)

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| CF1 | Scattered config reads: environment variables read deep inside business logic, defaults repeated in several places | Search for env access | One typed config loader, injected — because scattered reads hide what the app needs to run |
| CF2 | Environment branches in business logic: `if env == "production"` changing domain behaviour | Conditionals on environment names | Behaviour switched by explicit config or flags — because untested branches ship to production |
| CF3 | Feature flags never removed, or flags read in many places for one feature | Flag reads | Each flag read in one place with an owner and removal plan — because stale flags multiply paths |

### Testability (TS) [SEAM]

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| TS1 | *(sound constructs)* No seams around time, randomness, I/O and vendors in core rules | Calls to clocks, random, HTTP clients and SDKs inside domain code | Injected or passed in — because a rule that reads the clock cannot be tested at the boundary |
| TS2 | Core rules only testable end to end: tests for core flows need the database, the network or the UI | Test suite structure vs core flows | Core rules have fast unit tests — because slow tests are run less and cover fewer cases |
| TS3 | Tests coupled to implementation: mocks of internals, assertions on private structure | Test files for core modules | Tests assert behaviour at the module's public surface — because refactoring then breaks tests, not behaviour |

### Operability (OP)

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| OP1 | Migrations that break running code: destructive schema changes in the same deploy as the code that stops using them; data migrations and backfills that bypass domain rules, cannot be re-run, or import current ORM models | Migration files vs the code they serve | Expand-and-contract, backward-compatible steps; backfills idempotent and batched, writing through the owner or restating its rules — because old and new code run together during a deploy, and a backfill runs again after a failure |
| OP2 | Diagnosability: no correlation ID across calls and messages, unstructured logs on core flows, no health checks | Logging and middleware setup | Correlation propagated, structured logs, health endpoints — because a failure that cannot be traced is fixed slowly |
| OP3 | Startup coupling: a unit that cannot start when an optional dependency is down | Boot code | Optional dependencies degrade instead of blocking — because one outage then takes down unrelated features |

### Duplication and consistency of patterns (DU)

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| DU1 | Parallel implementations of one concept: two HTTP clients, two date helpers, two permission checks, two state machines for one entity | Search by concept across modules | One implementation — because parallel versions diverge silently |
| DU2 | One recurring problem solved several ways (data access, validation, error handling, state management) without a reason | Majority pattern per problem | One way, or a documented reason for each exception — because each variant costs every reader |

### Dependencies and evolution (DE)

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| DE1 | Framework or vendor lock-in in the core: domain code typed against a vendor SDK or framework base classes | Imports in domain modules | Vendor code behind an interface at the edge — because replacing or upgrading the vendor then touches only the edge |
| DE2 | Dead and speculative structure: unused modules, abstractions with one implementation and no test seam purpose, unreachable code | Import graph leaves, unreferenced exports | Removed, or with a stated purpose — because dead structure is read and maintained for nothing |
| DE3 | End-of-life frameworks and runtimes, and duplicate libraries for one job | Lockfiles vs vendor schedules, checked now, not recalled | Supported and deduplicated — because upgrades postponed grow in cost |

## Sound constructs

A cell is `sound` only for a construct in the *Sound* column, cited at
`path:line`; an *Unsound* construct is a candidate even when it looks like a
control. Every named tool is a labelled example (`e.g.`), not a list to grep
for: find this stack's equivalent.

| Step | Sound (labelled examples) | Unsound look-alike (labelled examples) | Why |
|---|---|---|---|
| BL1 | Enforced import contracts (e.g. Python `import-linter` layers contract; JS `dependency-cruiser` or `eslint-plugin-boundaries`; Java ArchUnit tests, JPMS modules or Spring Modulith `ApplicationModules.verify()`; Gradle `implementation` rather than `api` dependencies and Kotlin `internal`; in Go, a depguard or go-arch-lint rule or an architecture test, since `internal/` only bars importers outside its parent tree and separates nothing inside one module); ports defined in the inner layer, adapters in the outer | A layer diagram in the README with no enforcement; folder names alone; "we never do that" in review comments | Unenforced direction erodes one import at a time |
| BL3 | A public surface per module (e.g. an `index.ts` barrel plus a lint rule forbidding deep imports; Python package `__all__` plus an import-linter forbidden contract; Java package-private types; Go `internal/` against other modules, plus a depguard rule within one) | Everything exported "for convenience"; deep imports into `src/<module>/internal/...` from siblings; relative imports that climb into another workspace package's `src` directory, tsconfig path aliases or phantom dependencies that bypass declared package dependencies | A boundary nothing enforces is a suggestion |
| DM1 | A repository or service that is the only writer, others calling its API; database permissions or schemas per module; a search in CI for writes outside the owner | Two services both running `UPDATE` on the same table; an admin script or job writing directly with its own validation; one repository class called by several services that each apply their own rules (one writer in code, several rule owners) | Each writer is a place a rule can be missed |
| TX1 | Transactional outbox written in the same transaction as the state change and relayed later (e.g. Debezium, a polling relay); saga with compensation; idempotent reconciliation job | Publish after commit with no retry, or with an in-memory retry lost on a crash (Django `transaction.on_commit(task.delay)`, Spring `@TransactionalEventListener(AFTER_COMMIT)` that sends, with nothing reconciling); publish before commit (`.delay()` or `KafkaTemplate.send` inside the transaction; under Django `ATOMIC_REQUESTS` an inner `atomic()` is only a savepoint, so a publish after it still precedes the commit); a Kafka transaction chained to a database one (best-effort one-phase commit, not atomic); a `try/except` that logs a failed publish; "the queue is reliable" | The second write fails eventually; only a recorded intent survives |
| TX2 | Idempotency key stored with a unique constraint and checked in the same transaction; natural idempotency (upsert by business key, set-to-value not increment); deduplication by message ID | Checking "already processed" in a separate read before the write; in-memory dedup per process; increment operations on redelivery; a dedup row committed in the transaction while the side effect is an external call outside it; message-ID dedup when the relay assigns a new ID per retry; an idempotency key made per attempt rather than per logical request | Redelivery and concurrent retries race a separate check |
| TX4 | Optimistic version column; conditional `UPDATE … WHERE version = ?`; `SELECT … FOR UPDATE`; a distributed lease for singleton jobs | A process-local mutex or `synchronized` block guarding state shared across instances; check-then-act in two statements | A process lock does not span replicas |
| FH1 | Exceptions propagate to one edge handler; handled errors produce a defined outcome (retry, compensation, user-visible error); awaited promises and checked results | `except Exception: log; pass`; `catch (e) {}`; fire-and-forget promises on core flows; ignored error returns (in Go `_ = f()`, a bare `f()` statement dropping its error, `defer x.Close()` on a write; `_ = tx.Rollback()` after a failure is the deliberate exception); in Python a bare `except:`, `contextlib.suppress(Exception)`, an `asyncio.create_task` nobody awaits or keeps; in Java `catch (Exception e) {}` and a `CompletableFuture` from `KafkaTemplate.send` nobody inspects; an exception that propagates to a consumer framework that already acked the message or committed the offset (auto-ack before processing, Celery's default early ack without `acks_late`, `ack.acknowledge()` with `MANUAL_IMMEDIATE` inside a transaction that later rolls back) | A swallowed error reports success after partial work |
| AC2 | Clients generated from the OpenAPI, GraphQL or protobuf schema in CI; a schema-compatibility check (e.g. a registry, `buf breaking`); additive-only fields with a supported-app-version window | Hand-written TS or Swift types mirroring DTOs; a `/v2` path with no compatibility test; removing a field still read by shipped mobile builds | Hand-copied types drift silently, and old clients live for months |
| TS1 | Clock, random, ID generator and clients passed in or injected (e.g. a `Clock` interface, `now` parameter, constructor injection) | `datetime.now()`, `Date.now()`, `Math.random()` or a vendor SDK called inside domain rules; monkeypatching in every test | A hidden dependency cannot be controlled at the boundary |
