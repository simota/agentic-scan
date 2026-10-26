# Recon — the module map

**Read when:** RECON, before any finding is written. Nothing in later phases is
trustworthy until this map exists, because a dependency cannot be judged
without knowing which side of which boundary each module sits on.

The map is a working artifact. Keep it in scratch; it is not part of the final
report unless asked.

## 1. Stack and deployable units

- Language, framework, ORM, messaging, front-end framework, with versions from
  lockfiles; monorepo tooling and workspace layout
- Every deployable unit (service, worker, function, front end, CLI) and how it
  is built and started. One repository can hold several units that share code
  or a database

## 2. Modules and their declared layers

- The top-level modules, packages, bounded contexts or feature folders, and the
  layer each claims to be (presentation, application, domain, infrastructure;
  or feature slices)
- Where the intended structure is stated: ADRs, architecture docs, README,
  diagrams, `CODEOWNERS`, import-lint config (e.g. `import-linter`,
  `dependency-cruiser`, ESLint boundaries, ArchUnit, Go `internal/`, Java
  modules), workspace boundaries
- Each module's public surface: what it exports, its facade or index file,
  what other modules are supposed to use

## 3. Dependency graph

Build the module-level import graph from import statements (or an installed
read-only tool — name it first and record it). For each edge: from, to, count
of import sites, an example `path:line`. In TypeScript and JavaScript count
`import type`, re-exports (`export … from`), dynamic `import()` and
`require()`, and resolve `tsconfig` `paths` aliases and each package's
`exports` map before deciding which module an import reaches. In Go,
`go list -f '{{.ImportPath}} -> {{join .Imports " "}}' ./...` gives the graph
(add `-test` and read `XTestImports` for `package x_test`; check `//go:build`
variants); run it with `GOPROXY=off` so it fetches nothing, and keep Go's
own module mode, which reads `vendor/` when the repository has one.

In Python, count function-level imports as well as top-level ones (a
function-level import is the usual way around a circular `ImportError`, so it
often *is* the cycle), treat imports under `if TYPE_CHECKING:` as type-only,
and resolve relative imports and `__init__` re-exports. `pydeps --show-deps
--no-output` prints the graph when installed, and `lint-imports --no-cache`
checks the repository's own contracts (without `--no-cache` it writes a cache
into the checkout); otherwise a stdlib `ast` walk over the checkout, kept in
scratch and run with `python3 -I`, is read-only analysis too (record it as
`analysis`).

On the JVM, module edges come from `project(":x")` in `settings.gradle(.kts)`
and `build.gradle(.kts)`, or `<module>` and `<dependency>` in `pom.xml`;
package edges from `import` and `import static` lines plus fully qualified
names in code and in JPQL strings. `jdeps -verbose:package` reads compiled
classes that already exist (class directories or jars); it builds nothing.
Gradle and Maven run the repository's build scripts, and Gradle compiles
`buildSrc` and included builds into the checkout, so they are not read-only
analysis: run one only with permission, on a copy of the checkout in scratch,
offline with the user's existing caches (`gradle --offline -q projects`, `mvn
-o dependency:tree`; an empty cache cannot resolve plugins offline), and never
a build, compile or test task.

Then flag:

- **Cycles** between modules or layers
- **Upward edges** — domain or application code importing presentation,
  framework, ORM or vendor SDK code, against the declared direction
- **Edges into internals** — imports that bypass a module's public surface
- **Hubs** — modules nearly everything depends on, and what they contain
  (a "utils" or "common" module that holds domain logic is a lead)

Also record the edges no import statement shows: DI container wiring and
component scan, string or dynamic imports (`importlib`, `require(name)`),
decorator or annotation route registration, plugin entry points, and
structural interfaces: in Go a type satisfies an interface without naming it,
so a callee that declares an interface matching its caller's methods, wired
back in `main` or `cmd/`, is an edge from callee to caller. In Django and
Celery: signal receivers connected in `AppConfig.ready()` (module A's code runs
on module B's save), string model references (`ForeignKey("orders.Order")`,
`apps.get_model`), `include("x.urls")`, `autodiscover_tasks` and
`send_task("name")`, `transaction.on_commit` callbacks. In Spring: component
scan (`scanBasePackages`), `@EntityScan`, `ApplicationEventPublisher` to
`@EventListener` and `@TransactionalEventListener`, `@KafkaListener` topics,
aspects. An edge that
cannot be resolved statically gets `UNKNOWN` in its *Control* cell, with what
would decide it.

## 4. Entry points per module

HTTP routes, jobs, consumers, CLI commands and UI routes, grouped by the module
that owns them. An entry point whose handler reaches into several modules'
internals is a lead for the *Cohesion* and *Boundaries* perspectives.

## 5. Data ownership

One row per table, collection, cache keyspace or bucket on a core flow:

| Store | Owning module | Writers (`path:line`) | Readers | Invariants enforced where |
|---|---|---|---|---|

Writers include more than explicit saves: ORM dirty-checking (a JPA or
Hibernate entity mutated inside a transaction with no `save`, SQLAlchemy
autoflush), bulk updates that bypass hooks (`QuerySet.update()`,
`update_all`), cascades, model callbacks and signals, raw SQL, database
triggers and procedures, migrations and backfills, admin panels and management
commands. In Node, the forms are an ORM's write calls (Prisma `update`,
`upsert`, `$executeRaw`; TypeORM `save`, `QueryBuilder.update()`; Knex
`update`, `insert`) and raw driver calls (`pool.query`, `client.query`). In
Go: `database/sql` `Exec`/`ExecContext`, pgx `Exec`/`CopyFrom`, sqlx, gorm
`Save`/`Updates`/`Create`, and the files sqlc generates. In Python: Django
`save`, `create`, `bulk_create`/`bulk_update`, `get_or_create`/
`update_or_create`, `QuerySet.update()` with `F()` expressions, `.delete()` and
its `on_delete` cascades, `connection.cursor().execute` and `.raw()` whose
SQL modifies data (both usually only read),
`RunPython`/`RunSQL` migrations; SQLAlchemy `session.add`/`merge` and
`session.execute(update(...))`. On the JVM: Spring Data
`save`/`saveAll`/`delete*`, `@Modifying @Query` (JPQL and native, which skip
entity callbacks and `@Version`), `JdbcTemplate.update`/`batchUpdate`,
`EntityManager.persist`/`merge`/`remove`, `createNativeQuery(…).executeUpdate()`,
jOOQ and MyBatis, `CascadeType`, `@PreUpdate`, Flyway or Liquibase scripts;
two `@Entity` classes mapped to one table are two writers.
Search for each form and record the hit count.

A store with writers in more than one module, or with rules enforced in some
writers and not others, is a lead. Shared databases between deployable units
are listed separately.

## 6. Integration and messaging

Published and consumed events or messages with their schemas, delivery
semantics stated in config or docs (at-most-once, at-least-once, ordering),
outbound API clients and where they are wrapped, webhooks. For each place where
a database write and a message or external call happen in one flow, record
the order and what happens if the second step fails.

## 7. Conventions

How the codebase handles, and whether it handles consistently:

- Transactions — where they start and end (request middleware, service
  methods, unit of work), and calls made inside them
- Errors — exception hierarchy or result types, where they are caught,
  translated and logged, what reaches the client
- Validation — at the edge, in the domain, or both
- Config — one loader or scattered environment reads; feature flags
- Time, randomness and IDs — injected or global calls
- Logging, metrics and tracing setup

## 8. Change history (read-only)

`git log` over a recent window (e.g. the last 12 months, or the last 500
commits, whichever is available):

- **Hotspots** — files and modules by commit count, cross-referenced with size
- **Co-change** — pairs of files in different modules that change in the same
  commits most often; high co-change across a boundary is evidence of coupling
- **Recent comparable changes** — for each change scenario from *Before
  starting*, a recent commit or PR that did something similar and how many
  files and modules it touched

Record the commands and windows used. Unreadable history goes to
`limitations`.

## 9. Rules the codebase states — input to the rules ledger

Record what the later rules hunt needs (`reference/rules.md`):

- **Layer and dependency rules** — declared direction, lint contracts,
  framework conventions the code clearly follows
- **Boundary rules** — public surfaces, `internal` packages, facades
- **Ownership rules** — the single writer of each core store, the module that
  owns each business rule
- **Consistency rules** — transaction scopes, outbox or saga mechanisms,
  idempotency keys, retry policy
- **Failure rules** — the error model and where errors are translated
- **Contract rules** — API versioning, event schema evolution, DTO vs entity
  separation
- **Seam rules** — how time, randomness, I/O, configuration and vendors are
  reached from the core (§7): injected, passed in, or called directly
