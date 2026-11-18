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
| Failure handling | Do failures propagate under one model, stay bounded in time and reach, and never vanish on a core flow? |
| API and event contracts | Are external contracts separate from internal models and evolved compatibly? |
| Configuration and environment | Is configuration read in one place and kept out of business logic? |
| Testability | Can the core rules be tested without the database, the network or the clock? |
| Operability | Can the system be deployed, stopped, rolled back, diagnosed and alerted on safely? |
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
- A comment is never the mechanism. "Do not call X from Y", "keep these in
  sync" or a `TODO` naming the proper fix records an unenforced rule; the
  cell is `NONE` with the comment cited as the rule's source, and the comment
  is a DU3 lead

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
| FH3 | Retries that bury a failing dependency: no attempt cap, no backoff or jitter (`while True`, immediate retry on 5xx); retries stacked across layers (the SDK's, the shared client's, the caller's, the queue's redelivery); retries of operations not safe to repeat (a POST, a charge or a send retried on timeout without an idempotency key) | The shared client, retry decorators, SDK defaults, job and consumer retry config | One layer owns retries for each call, attempts are capped and spaced with exponential backoff and jitter, and only idempotent or keyed operations are retried — because 3 × 3 × 3 attempts turn one failure into 27 calls, and a timeout does not mean the first attempt failed |
| FH4 | *(sound constructs)* Waits with no bound: outbound calls with no timeout or the library's infinite default (HTTP, database drivers, gRPC without a deadline, SDKs, SMTP, cache); pool checkout, lock acquisition, queue `get()`, `Future.get()`, an `await` with no cancellation on a request path; per-attempt timeout × attempts longer than the inbound request, gateway or load-balancer timeout | Outbound call sites (`reference/recon.md` §6); the shared client's construction; driver and SDK config; pools, locks and futures on request paths; gateway, ingress and server timeouts in the repository | Every wait on a core flow has an explicit bound, set at the call or inherited from the shared client at `path:line`, and all attempts fit inside the caller's deadline — because a dependency that stops answering otherwise holds a worker until the pool is gone, and work the caller has given up on still holds resources |
| FH5 | *(sound constructs)* One failing dependency spreads: a core flow that keeps calling a dependency at full rate while it is down; breakers that never open or never close (thresholds no traffic reaches, timeouts not counted, one breaker for unrelated endpoints); one pool, executor or worker concurrency shared by a core dependency and a slow non-core one | Call sites of core dependencies; breaker libraries and their configuration; pool and executor construction and which calls share them | Repeated failures open a breaker scoped to one dependency, or the timeout is short enough that waiting costs little, and core dependencies have their own pool or concurrency limit — because waiting out a timeout per request turns a dependency outage into a latency outage of everything, and a slow export should not take checkout down |
| FH6 | Messages lost or stuck: a poison message retried forever, blocking its partition, or dropped with no record; a visibility timeout, lease or lock shorter than the slowest processing, so a message runs twice in parallel | Consumer error handling; queue, topic and consumer configuration beside the processing it bounds | After a bounded number of attempts a message goes to a dead-letter queue someone watches, and the lease outlasts the slowest processing or is extended while working — because one bad message must not stop the good ones nor vanish, and a second copy running in parallel doubles every effect |
| FH7 | *(sound constructs)* No defined degradation: an optional dependency (recommendations, analytics, a flag service) whose failure fails the whole request; a fallback that hides failure or serves wrong data (a catch-all default, a stale cache with no age limit, no log or metric); overload accepted without limit (unbounded in-memory queues, no concurrency limit, no rejection under pressure) | Composition of core pages and endpoints; handlers around dependency calls; cache reads on error; server and worker concurrency settings | A failing optional call degrades only its part, a fallback is bounded, safe for the caller and counted, and excess work is refused early with a clear status — because a silent fallback is an outage that reports success, and a server that accepts everything under overload serves nobody |

### API and event contracts (AC) [CONTRACT]

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| AC1 | Internal models exposed as contracts: ORM entities serialised directly, internal enums in public payloads | Serializers, response types, event payloads | Explicit DTOs or schemas — because every internal change becomes a breaking change |
| AC2 | *(sound constructs)* Versioning and evolution: breaking changes without a version, events without a schema or version, removed fields still read by clients | API routes, schema files, event definitions, client code in the repo | A versioning or additive-only policy applied — because consumers deploy on their own schedule |
| AC3 | Inconsistent contract shapes: naming, pagination, error format and ID formats differing between endpoints | Route inventory | One convention, or documented exceptions — because each variant is client code to write and maintain |

### Configuration and environment (CF) [SEAM]

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
| OP2 | Diagnosability: correlation or trace context lost at a boundary (outbound calls, published messages, workers starting a fresh context); failure logs without the dependency name or business identifier; core dependencies with no rate, error or duration metric and queues with no depth or age metric; uncaught errors in jobs, threads and async tasks that never reach the error reporter | Logging, metrics and error-reporter setup per process type; client middleware, producers and consumer entry points | Context crosses every boundary, failure logs carry the correlation ID and the identifiers that find the record, each core dependency and queue is measured, and every process type reports uncaught errors — because the first question in an outage is which dependency and which record, and a worker that dies quietly stops the flow it feeds |
| OP3 | Startup coupling: a unit that cannot start, hangs or crash-loops when a dependency is down — eager connections with no timeout, migrations run at boot, a required remote config fetch | Boot code, entry points, init containers | Start-up waits are bounded and optional dependencies degrade instead of blocking — because a restart during an outage otherwise cannot come back, and one outage takes down unrelated features |
| OP4 | Stopping loses work: SIGTERM not handled, in-flight requests cut, a shell-form container entry point that never forwards the signal, a grace period shorter than the slowest request; jobs and consumers with no checkpoint, acked before the work, or holding a lease they do not release | Entry points, server start-up, Dockerfile `CMD`/`ENTRYPOINT`, manifests' termination grace; workers, schedulers, long-running jobs | On SIGTERM the process stops accepting, drains within the grace period and exits, and interrupted work is re-queued or resumed — because every deploy sends SIGTERM |
| OP5 | *(sound constructs)* Health checks that do not tell the truth: liveness that calls the database or a downstream API, so a dependency outage restarts every instance; readiness true before warm-up or migrations, an endpoint that always returns 200, or no probe at all | Health handlers; liveness and readiness probes in manifests; start-up order | Liveness checks the process only, and readiness reflects this instance's own ability to serve (pool initialised, warm-up done, not draining) without failing on a shared downstream outage — because restarting healthy processes cannot fix a database, and traffic sent to a process that cannot serve fails every request |
| OP6 | *(sound constructs)* Failures nobody is paged for, or pages nobody can act on: core flows with no alert on a user-visible symptom (error rate, latency, checkout success), only on causes (CPU, memory), or no alert definitions in the repository; alerts with no runbook, an owner that no longer exists, or a threshold never reached or always exceeded | Alert rules, SLO definitions, dashboards as code, runbooks and ownership docs | Each core flow has a symptom alert that names a runbook and an existing owner, defined where the repository keeps them — because users notice an outage before a CPU alert does, and a page with no procedure is noise |
| OP7 | No fast way back: a release the previous version cannot run beside or after (a changed message format with old consumers running, a removed config key; the migration itself is OP1); risky changes to core flows shipped all at once with no flag or gradual rollout; no rollback step in the pipeline, mutable image tags (`latest`), a runbook that says "redeploy" with no version | Release order, message schemas, config readers; recent changes on core flows and the flag system; pipeline definitions, manifests, deploy docs | The previous version can run against the new state, a risky change can be switched off without a deploy, and the way back is written down or automated — because a rollback that breaks on the new state is not a rollback, and a deploy is the slowest way to undo a change |

### Duplication and consistency of patterns (DU)

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| DU1 | Parallel implementations of one concept: two HTTP clients, two date helpers, two permission checks, two state machines for one entity | Search by concept across modules | One implementation — because parallel versions diverge silently |
| DU2 | One recurring problem solved several ways (data access, validation, error handling, state management) without a reason | Majority pattern per problem | One way, or a documented reason for each exception — because each variant costs every reader |
| DU3 | *(sound constructs)* Rules and workarounds kept as comments: a `TODO`/`HACK`/`FIXME`/"temporary" workaround, or a prose warning ("do not call X from Y", "must run after Z", "never pass null"), standing where a type, test or lint rule should; and whether it has already been copied. A marker alone is a lead, not a finding: report it when the workaround has a second site, or when the comment is the only thing keeping a rule on a core flow | Search for workaround and warning markers on core flows and hotspots; for each, search for the same workaround shape elsewhere and `git log -S` its spread | The rule the comment states is enforced by a type, test or lint rule at `path:line`, and the workaround has one site — because people and coding agents copy the code beside them, not the comment's intent, so a workaround left in place becomes the pattern and a warning in prose stops nothing |

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
| FH4 | A timeout set once on the shared HTTP client, the driver's connection string or the SDK's config object, read at `path:line` | A call with no explicit timeout whose library default is infinite (e.g. Python `requests`, Go `http.Client{}`, Java `HttpURLConnection`, many database drivers' query timeout); a timeout set on connect only; a per-attempt timeout with retries whose total exceeds the inbound deadline | A default nobody read is usually "wait forever" |
| FH5 | A breaker in the client, a sidecar or the gateway that the repository configures; a short timeout on a rarely called dependency; a separate pool or concurrency limit per core dependency | One breaker shared by unrelated endpoints; breaker state per process with many processes and low traffic; a breaker that does not count timeouts; one global thread pool or event loop serving a slow non-core call beside checkout | A breaker that never trips is configuration, not protection |
| FH7 | A fallback whose default is correct for the caller (an empty recommendation list) and that is counted or logged; a stale cache with a maximum age; a concurrency limit or queue bound that rejects with 429 or 503 | `except Exception: return []` on a call whose empty result is read as "no data"; a cache served on error with no age limit; an unbounded in-memory queue in front of workers | A silent fallback reports success during an outage |
| AC2 | Clients generated from the OpenAPI, GraphQL or protobuf schema in CI; a schema-compatibility check (e.g. a registry, `buf breaking`); additive-only fields with a supported-app-version window | Hand-written TS or Swift types mirroring DTOs; a `/v2` path with no compatibility test; removing a field still read by shipped mobile builds | Hand-copied types drift silently, and old clients live for months |
| OP5 | A liveness endpoint that touches only the process; a readiness check that touches the database pool of this instance (initialised), not the database's health | A liveness probe hitting `/health` that queries the database or a downstream API; readiness that returns 200 before warm-up or migrations finish | Restarting every instance cannot fix a shared dependency |
| OP6 | An alert that is a ticket, not a page, and whose rule says so; a symptom alert defined in another repository that this one names | A page per single error; alerts only on CPU and memory; an alert routed to a team that no longer exists | An alert nobody can act on trains people to ignore alerts |
| DU3 | The rule moved into structure: a type or constructor that makes the forbidden call or state unrepresentable, a test that fails when it is broken, a lint or import rule (e.g. a custom ESLint or Ruff rule, ArchUnit, Semgrep in CI); the workaround replaced at its one site, with a test pinning the case it worked around | `// TODO: workaround`, `# HACK`, `XXX: temporary` left on a core flow; "do not call X from Y" or "keep in sync with Z" in prose; a lint suppression whose comment is the only justification; the same workaround copied to a second site; a ticket link in a comment as the only record | Agents and people imitate the surrounding code: one surviving workaround is read as the house style and multiplies, while a rule in prose is enforced by nothing |
| TS1 | Clock, random, ID generator and clients passed in or injected (e.g. a `Clock` interface, `now` parameter, constructor injection) | `datetime.now()`, `Date.now()`, `Math.random()` or a vendor SDK called inside domain rules; monkeypatching in every test | A hidden dependency cannot be controlled at the boundary |
