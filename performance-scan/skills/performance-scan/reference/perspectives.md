# Perspectives — reviewing from more than one angle

**Read when:** CHECKLIST, to choose which perspectives apply; REVIEW, after the
budget hunt (`reference/budgets.md`), as the coverage sweep; REPORT, to fill
the `perspectives` table in `findings.json`. **Reader:** the agent running the
skill.

The budget ledger finds what this app's own bounds forbid. The perspectives
then make sure nothing outside the ledger is skipped: apply each one within
every review unit (`SKILL.md`, *Run contract*), work through its hunt steps
below, and record every perspective in the report — including the ones that
found nothing and the ones not run. The names below are the exact values of
`perspectives[].name` and `findings[].category`.

| Perspective | The question it asks |
|---|---|
| Database access | Does each request issue a bounded number of well-indexed queries returning a bounded result? |
| Algorithms and data structures | Does work per request grow faster than its input, or repeat what it already did? |
| Memory | Is anything held whole, retained or grown without bound? |
| I/O and network | Does a hot path wait on blocking, sequential, per-item or untimed I/O? |
| Caching | Is repeated expensive work cached, and is each cache correct, bounded and safe on a miss storm? |
| Concurrency and resources | Are shared resources sized consistently, held briefly and never exhausted by one caller? |
| Payload and API shape | Do responses carry only what the client needs, compressed and paginated, in few round trips? |
| Front end | Does the client ship, parse and render only what the view needs? |
| Background work | Is slow work deferred, batched and scheduled without storms? |
| Startup and configuration | Do the shipped settings run in production mode, and does boot stay fast? |
| Dependencies and platform | Are runtime and libraries free of heavy, duplicated or known-slow choices? |
| Observability | Can the hot paths be measured when a regression happens? |

Rules:

- A perspective not applicable to this application is recorded as `N/A` with a
  reason (e.g. `Front end: N/A — API only, no client in the repo`)
- A perspective that could not be checked statically is recorded as `not
  checked` with what would be needed
- Every finding names the perspective that surfaced it in `category`, and its
  `step`, when present, is one of that perspective's hunt steps. A perspective
  with a finding that is not `FalsePositive` or `NotApplicable` is recorded
  `applied`
- A hunt step covered by a budget ledger entry cites it (`B-…`) in the
  perspective's `note` instead of being re-run. A step is covered only when
  that entry's cost-trace rows already hunt the step's own construct on the
  same paths: a QRY query-count row covers DB1 (N+1) but never DB3–DB5
  (indexes, query shapes, transactions), which are hunted even on paths the
  entry pays. The family in brackets after a heading only says which entries
  may cover some of its steps
- The `note` lists the hunt step IDs applied and each one left out with its
  reason (e.g. `DB1 via B-01; DB2–DB4, DB6 applied; DB5 N/A: no explicit
  transactions`)
- A construct that is not sound but whose workload rate keeps it below every
  severity in `SKILL.md` leaves the status `applied`; its note says `below
  threshold: <rate>, no finding`
- A step is `sound` only when its *Sound when* cell can be filled with the
  mitigation's `path:line` on the path the workload takes. "The ORM optimises
  it" is not evidence

## Hunt steps per perspective

Each step says **what** to hunt, **where** to look, and what evidence makes it
**sound** — with the reason. Framework names are examples only. Steps marked
*(sound constructs)* have a table at the end of this file. The ledger family
(`reference/budgets.md` §2) that usually covers a perspective is in brackets.

### Database access (DB) [QRY, SIZE]

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| DB1 | *(sound constructs)* N+1: a query (or lazy relation access) inside a loop, a serializer over a collection, a template iterating records, a GraphQL field resolver per parent | Loops and serializers on hot list paths; every relation accessed per item | The relation is eager-loaded or batch-loaded on that exact path at `path:line` — because lazy loading issues one query per parent and the loop count is the scale driver |
| DB2 | *(sound constructs)* Unbounded result sets: no `LIMIT`, no pagination, `SELECT *` of wide rows, loading all then filtering in code | List, search, export and job queries | A server-side cap (page size, cursor) and a column list at `path:line` — because the table grows and the query does not |
| DB3 | Index coverage: filters, sorts and joins on hot queries without a matching (composite) index | Hot queries vs migrations and schema files. Primary keys and UNIQUE constraints create indexes; PostgreSQL does not index foreign-key columns automatically, while MySQL InnoDB, Django `ForeignKey` (`db_index` default) and Rails `t.references` do. A composite index serves a filter only through its leftmost columns (equality columns first, then the sort or range column) | A matching index in the migrations at `path:line`; absence from the repo is `Environment-dependent` — because a scan's cost grows with the table, not the result |
| DB4 | Query shapes that defeat indexes: function or cast on an indexed column, leading-wildcard `LIKE`, deep `OFFSET`, `COUNT(*)` on large tables per request, `OR` across columns, implicit type conversion | Raw SQL and ORM query builders | An index-friendly predicate (no function or cast on the indexed column, or an expression index), keyset pagination instead of deep `OFFSET`, an estimated, cached or capped count instead of an exact `COUNT(*)` per request, and an index on each `OR` branch — because a transformed column cannot use a plain index, `OFFSET k` reads and discards k rows, and `COUNT(*)` visits every qualifying row |
| DB5 | Transactions and locks: long or idle-in-transaction sessions, outbound I/O inside a transaction, `SELECT … FOR UPDATE` over more rows than needed or held across I/O, inconsistent lock order across code paths (deadlocks), hot-row updates (counters), lock escalation (SQL Server) | Transaction blocks and the calls inside them; Go `db.Transaction(func…)` / `BeginTx` bodies that call RPC or HTTP | The transaction holds only DB work and touches contended rows last and briefly — because a held connection and lock block every other request on that row or pool |
| DB6 | *(sound constructs)* Write amplification: per-row `INSERT`/`UPDATE`/`DELETE` in a loop, save-per-item, cascades that fan out | Imports, bulk actions, jobs | A bulk statement or batched writes at `path:line` — because each round trip costs latency and log volume |

### Algorithms and data structures (AL) [CPLX]

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| AL1 | *(sound constructs)* Quadratic work: nested loops over two growing collections, linear lookups (`includes`, `in list`, `find`) inside a loop, repeated `filter` per item | Data shaping in handlers, serializers, reports, jobs | A keyed lookup (map, set, index) built once — because N lookups of cost N is N² |
| AL2 | Repeated work: recomputing an invariant inside a loop, compiling a regex or template per call, parsing the same document repeatedly, string concatenation in a loop | Loop bodies and per-request helpers. Check the language before claiming: Python `re` caches compiled patterns (Java `String.matches` compiles per call); string `+=` in a loop is quadratic in Java, C# and Go, usually amortised in CPython and JavaScript; Go `regexp.MustCompile` and `template.Parse` compile on every call (no cache) | Hoisted or memoised work at `path:line` — because the loop multiplies every constant |
| AL3 | Sorting, serialising, diffing or deep-copying large collections per request | Response builders, change tracking | Done once over a bounded input, or done in the database — because these are `n log n` or worse in the full collection |
| AL4 | Backtracking regex on unbounded input | Validation and parsing code | A linear-time engine (e.g. RE2, Go `regexp`, Rust `regex`, .NET `RegexOptions.NonBacktracking`), a pattern without nested or overlapping quantifiers, or a match timeout — because backtracking is exponential in the input; a length cap helps only when the worst case at the cap fits the budget |

### Memory (ME) [SIZE, RES]

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| ME1 | *(sound constructs)* Whole-in-memory: reading files, uploads, result sets or response bodies fully before processing | Imports, exports, downloads, proxies, report generation | Streamed or chunked processing at `path:line` — because memory per request then grows with the input and concurrency multiplies it |
| ME2 | Unbounded growth: module-level maps, caches, registries, queues or listener lists that only grow; fields of long-lived structs built at startup (not only module-level); Go re-slicing `s = s[n:]` keeps the backing array, and Go maps never shrink | Globals, singletons, memoisation helpers | A size bound or eviction, and removal on teardown — because a leak grows with uptime until the process restarts |
| ME3 | Retained references: closures capturing large objects, event listeners and timers never removed, request-scoped data stored globally | Long-lived objects, subscriptions, front-end effects | Paired add/remove or scoped lifetime at `path:line` — because a retained root keeps everything it reaches |
| ME4 | Allocation churn on hot paths: chained `map`/`filter`/spread creating intermediate copies of large collections, per-item object creation or boxing in tight loops, large short-lived buffers per request | Hot loops, serializers, data shaping | A single pass, or reused buffers where the cost model shows the copies scale with a driver — because allocation rate drives garbage-collection pauses that every concurrent request pays |

### I/O and network (IO) [LAT, RES]

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| IO1 | *(sound constructs)* Blocking calls on an event loop or async path: sync file, crypto, DNS, sync DB or HTTP clients, CPU-heavy loops | Async handlers, middleware, Node/Python async code | Async APIs or offloading to a worker at `path:line` — because one blocked loop stalls every concurrent request |
| IO2 | *(sound constructs)* Sequential independent waits: awaits or calls in series that do not depend on each other | Handlers aggregating several sources | Concurrent, bounded execution — because latency becomes the sum instead of the max |
| IO3 | Per-item remote calls: one HTTP, RPC or cache call per element where a batch API exists | Loops containing client calls | A batch or multi-get call — because round-trip latency times N dominates |
| IO4 | Missing timeouts and unbounded retries: outbound calls without timeout, retries without backoff or cap | Client construction and call sites, DB and pool settings; Go `http.DefaultClient`, `http.Get`/`http.Post` and `&http.Client{}` have no timeout, `http.NewRequest` without a context ignores the caller's deadline, and gRPC has no default deadline | A timeout on every attempt, on DB statements (e.g. `statement_timeout`) and on pool acquisition (a library or runtime default counts only when cited and compared, e.g. Node's global `fetch` waits up to 300 s for headers by default), with attempts × timeout + backoff below the caller's deadline, at `path:line` — because a slow dependency or query otherwise holds workers and connections until they run out |
| IO5 | Connection reuse: a new client, connection or TLS session per request | Client construction sites; Go `DefaultTransport` keeps 2 idle connections per host (`MaxIdleConnsPerHost`), so fan-out churns TLS, and a response body not read to EOF before `Close` is not reused | A shared, pooled client at `path:line` — because handshakes cost more than most requests |
| IO6 | Hot-path logging and telemetry: verbose or synchronous logging, serialising large objects into logs | Log calls inside loops and hot handlers | Level-guarded, asynchronous, bounded log output — because log I/O is paid per call |

### Caching (CA)

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| CA1 | Missing cache for repeated expensive reads or pure computations on hot paths (config, permissions, reference data, aggregates) | Hot handlers re-reading the same data | Cached with an owner for invalidation, or shown cheap by the cost model (a single indexed lookup, a bounded constant) — because hot paths pay the cost every time |
| CA2 | *(sound constructs)* Cache correctness and stampede: key missing a dimension (tenant, locale, user), no invalidation on write, TTL-only for mutable data, simultaneous misses recomputing | Cache get/set sites and writers of the cached data | Complete key, invalidation on every writer, and single-flight or early refresh — because a miss storm hits the origin with full concurrency |
| CA3 | HTTP caching: static assets without long-lived immutable caching, cacheable responses without `ETag`/`Cache-Control` | Server and CDN config, static asset pipeline | Fingerprinted assets with long max-age and validators on cacheable responses — because the client otherwise re-downloads |
| CA4 | Unbounded caches (with ME2) | In-process caches | A max size and eviction — because a cache without a bound is a leak |

### Concurrency and resources (CC) [RES]

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| CC1 | Global locks or synchronised sections on hot paths | Mutexes, `synchronized`, file locks, advisory locks; Go `mu.Lock(); defer mu.Unlock()` at the top of a function holds the lock across all of its I/O | The critical section holds no I/O and is short — because every request serialises behind it |
| CC2 | Pool sizing and contention: acquisition waits or timeouts that violate caller deadlines, simultaneous connection holdings that can deadlock, aggregate pool capacity beyond the DB connection budget, thread-pool starvation from blocking calls | Pool and acquisition config, call paths, worker and replica counts, IaC | Acquisition waits are bounded within the caller's time budget, simultaneous holdings cannot deadlock, and total pool capacity fits the DB connection budget, cited — because bounded waiting can protect the DB from excess concurrency |
| CC3 | *(sound constructs)* Unbounded parallelism: `Promise.all`/`gather`/goroutine per element of a growing collection | Fan-out code | A concurrency limit at `path:line` — because N simultaneous calls exhaust pools and trip rate limits |
| CC4 | Contention on shared counters, hot rows, single queues or single partitions (e.g. Rails `touch: true` and `counter_cache`, which update the parent row on every child write) | Counters, sequences, aggregates updated per request | Sharded, batched or asynchronous updates — because a single hot spot caps throughput |
| CC5 | Unbounded queues and missing backpressure: in-process queues or executors that accept work faster than it drains (e.g. the unbounded queue behind Java `Executors.newFixedThreadPool`, `asyncio.Queue()` without `maxsize`, Node stream `write()` ignoring `false`/`drain`), no load shedding on overload; Go: a slice appended per message, `go handle(msg)` per message, consumer prefetch such as NATS `SetPendingLimits`, sarama `ChannelBufferSize`, franz-go `MaxBufferedRecords` | Executors, in-process queues, stream writers, consumer prefetch | A bounded queue with a rejection or backpressure policy, `pipeline()` or an awaited drain, bounded consumer prefetch, at `path:line` — because an unbounded queue turns overload into memory growth and unbounded latency instead of fast rejection |

For CC2, do not report a small pool solely because workers or concurrent demand
outnumber connections. [HikariCP's pool-sizing guidance](https://github.com/brettwooldridge/HikariCP/wiki/About-Pool-Sizing)
explains why a small pool with waiting threads can be appropriate. Check bounded
backpressure and the acquisition wait plus subsequent work against the caller's
deadline; unknown workload or DB capacity is a limitation, not evidence that the
pool should be enlarged. Exception: when the framework holds one connection per
thread for the whole unit of work (e.g. Rails before 7.2 per request, Sidekiq per
job), a pool smaller than that process's thread count fails with checkout
timeouts under load; report it (RES) and cite the pool and thread settings. Go
`database/sql` likewise pins one connection per open `Tx` or `Conn`, and a
caller waits for a connection only as long as its context allows: with
`MaxOpenConns` below the number of concurrent transactions, check every
caller's context deadline (consumers often pass a process context with none).

### Payload and API shape (PA) [SIZE, LAT]

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| PA1 | Over-fetching: responses with every field and nested relation, large blobs in list responses | Serializers and response builders | An explicit output shape per view — because bytes cost serialisation, transfer and parsing |
| PA2 | Unpaginated or uncapped list APIs (with DB2) | API list endpoints | Server-capped pagination — because the response grows with the table |
| PA3 | Chatty APIs: one screen needs many sequential round trips, or the client requests per item | Client code vs API routes | An aggregate endpoint, batch endpoint or query that fetches the view's data — because each round trip pays network latency |
| PA4 | Compression and encoding: large text responses without compression, inefficient formats for large payloads | Server middleware and proxy config | Compression enabled at the layer that answers — because text compresses several-fold |

### Front end (FE) [FE]

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| FE1 | *(sound constructs)* Bundle size: whole-library imports, no route-level code splitting, heavy dependencies for small uses, duplicated packages, dev builds shipped | Bundler config, entry points, imports | Split per route, tree-shakeable imports, production mode at `path:line` — because every byte is downloaded, parsed and executed before interaction |
| FE2 | *(sound constructs)* Rendering: whole-tree re-renders on each change, unstable props defeating memoisation, long lists without virtualisation, expensive work in render | Components on hot screens | Memoised derived data, stable references, virtualised long lists — because render cost multiplies by item count and update frequency |
| FE3 | Assets: unoptimised images, no responsive sizes, no lazy loading below the fold, render-blocking scripts, fonts and CSS | Templates, asset pipeline | Sized, compressed, lazy where appropriate, non-blocking scripts — because they delay first paint |
| FE4 | Data-fetching waterfalls and loops: effects that fetch in sequence, refetch on every render, polling without backoff | Effects, data hooks, loaders | Parallel or server-side loading, stable dependencies, cached queries — because each waterfall step adds a round trip |
| FE5 | Main-thread work: layout thrashing (read/write interleaving), heavy synchronous handlers on input or scroll | Event handlers, animation code | Batched DOM reads and writes, debounced or deferred handlers — because a long task blocks input |

### Background work (BG)

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| BG1 | Slow work in the request: emails, PDF, image processing, third-party calls, recalculation that the response does not need | Handlers with heavy side effects | Enqueued with the response not waiting — because the user pays the slowest dependency |
| BG2 | Jobs that process everything each run: full-table scans, no cursor or batch, no incremental watermark | Scheduled jobs and consumers | Batched with a cursor and incremental selection — because the job grows with total history, not new work |
| BG3 | *(sound constructs)* Storms: retries without backoff or jitter, schedules aligned on the same minute, polling tighter than the data changes | Queue and scheduler config | Capped backoff with jitter, spread schedules — because synchronised retries multiply load at the worst time |

### Startup and configuration (SC)

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| SC1 | Development settings in the production config: debug mode, query logging, template or asset caching off, unminified builds, profiling hooks | Per-environment config files | Production values at `path:line`; values set only by environment variables are `UNKNOWN` — because debug modes often disable caches and log every query |
| SC2 | Boot cost: eager loading of large data at startup, migrations or schema checks at boot, cold-start-heavy imports in serverless functions | Entry modules, initialisers | Lazy or build-time work — because boot time is paid on every deploy, scale-out and cold start |
| SC3 | Resource limits: container memory and CPU, worker counts, heap and GC flags inconsistent with each other | IaC, Dockerfiles, process managers. Labelled examples: Go before 1.25 sizes GOMAXPROCS from the node's CPUs, not the container limit (CFS throttling; check the release notes rather than recall, fix with automaxprocs or a `resourceFieldRef` env var); `GOMEMLIMIT`/`GOGC` against the memory limit; JVM `MaxRAMPercentage`; Node `--max-old-space-size`; an HPA scaling on a throttled CPU metric | Settings consistent with each other and cited — because a mismatched limit leads to OOM kills or idle capacity |

### Dependencies and platform (DP)

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| DP1 | Heavy or duplicated dependencies for small uses; several libraries doing the same job | Manifests and lockfiles | Each heavy dependency has a use that needs it — because each costs install, boot and bundle size |
| DP2 | Runtime or library versions with documented performance regressions or missed improvements | Lockfiles vs vendor release notes, checked now, not recalled | The version is current or the note does not apply — because recalled release notes are unreliable |

### Observability (OB)

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| OB1 | Hot paths without timing, metrics or tracing; slow-query logging off; no performance tests | APM, metrics and tracing setup; test suite; Go `net/http/pprof`, `runtime/metrics`, `sql.DBStats` | Each hot workload is measurable in production or CI — because an unmeasured regression is found by users |

## Sound constructs

A cell is `sound` only for a construct in the *Sound* column, cited at
`path:line` on the workload's path; an *Unsound* construct is a candidate even
when it looks like a mitigation. Every named API is a labelled example (`e.g.`),
not a list to grep for: find this stack's equivalent.

| Step | Sound (labelled examples) | Unsound look-alike (labelled examples) | Why |
|---|---|---|---|
| DB1 | Eager or batch loading on the exact query that feeds the loop (e.g. Django `select_related`/`prefetch_related`; Rails `includes`/`preload`; SQLAlchemy `selectinload`; Prisma `include`; JPA `JOIN FETCH` or entity graphs; GraphQL DataLoader); GORM `Preload`/`Joins`; sqlx `In` or sqlc `= ANY($1)` batch queries | Eager loading on a sibling query but not this one; a prefetch followed by a `.filter()` that re-queries per item; a serializer method that runs its own query; a counter computed with `.count()` per item; a collection eager-join combined with `LIMIT` or pagination (e.g. JPA `JOIN FETCH` on a collection with `setMaxResults` paginates in memory; SQLAlchemy `joinedload` on a collection multiplies rows, prefer `selectinload`) | Lazy access issues one query per parent |
| DB2 | A server-side maximum applied after parsing (e.g. `min(requested, MAX)`; DRF `max_page_size`; keyset or cursor pagination); explicit column lists for wide tables | A client `limit` passed straight through; pagination only in the front end; slicing or `first(n)` after the query was evaluated (e.g. Django `list(qs)[:n]`, Rails `.to_a.first(n)`; slicing an unevaluated QuerySet or `.limit(n)` is a SQL `LIMIT`); `len(qs)` or `if qs:` used only to count or test existence instead of `.count()`/`.exists()` | The table grows; only a server cap bounds the result |
| DB6 | Bulk statements (e.g. Django `bulk_create`/`bulk_update`; Rails `insert_all`/`upsert_all`; SQL multi-row `INSERT`; `COPY`); batched writes in fixed-size chunks | `save()` per item in a loop; a transaction around per-row statements (still N round trips); ORM callbacks firing per row in bulk paths | Round trips scale with N |
| AL1 | A dict/map/set built once and probed in the loop; a database join or `IN` query instead of nested iteration; sorted merge | `list.includes`/`in list`/`Array.find` inside a loop over another growing list; nested `for` over two collections from different scale drivers | N probes of cost N is N² |
| ME1 | Streaming readers and writers with bounded buffering through the reader, driver and consumer (e.g. Python file iteration or `csv` reader over a file object; Node streams and `pipeline`; Java `InputStream` with buffers; Django `.iterator()` with a verified streaming backend and cursor configuration; Rails `find_each` in fixed-size batches); chunked uploads to storage; Go: a `rows.Next()` loop encoding per row, GORM `FindInBatches`/`Rows()`, `io.Copy`, request bodies capped by `http.MaxBytesReader`/`io.LimitReader` | `read()`/`readFileSync` of an unbounded file; `.all()`/`toList()` of an unbounded query; an ORM iterator whose driver buffers the full result; accumulating streamed rows or a whole response body before forwarding; Rails `Relation#each`/`map`/`to_a` over an uncapped scope (sound: `find_each`/`in_batches`); JPA `findAll()`/`getResultList()` in a job (sound: a `Stream` with a fetch size and `clear()` per batch, or `Slice` paging); Go `json.Marshal(all)`, GORM `Find(&all)`, `io.ReadAll` of a request or response body without a cap; `json.NewEncoder(w).Encode(slice)` still builds the whole value before writing, so it is not streaming | Memory per request grows with the input unless buffering is bounded at every layer |
| IO1 | Async drivers and APIs on the loop (e.g. `asyncpg`, `httpx.AsyncClient`, Node `fs.promises`); blocking I/O offloaded (e.g. `run_in_executor`, `asyncio.to_thread`; FastAPI sync `def` routes, which already run in a bounded threadpool); CPU-bound pure-Python work in a process pool or job queue; Node CPU work in worker threads | `requests`, `time.sleep`, sync ORM calls or `fs.*Sync` inside `async def`/async handlers; large `JSON.parse`, synchronous hashing or image work on the loop; pure-Python CPU work sent to a thread executor (the GIL still serialises it); bursts of Node `fs`, `dns.lookup`, `crypto.pbkdf2` or `zlib` calls that saturate the libuv threadpool (`UV_THREADPOOL_SIZE`, default 4). Deliberately slow password hashing (bcrypt, argon2) is not a finding by itself; its synchronous form on the loop is | The loop serves every request; one block stalls all |
| IO2 | Concurrent independent awaits with a bound (e.g. `asyncio.gather` with a semaphore; `Promise.all` over a fixed small set; Go `errgroup` with `SetLimit`) | `await a(); await b();` where `b` does not use `a`; sequential calls in a loop that do not depend on each other | Latency becomes the sum instead of the max |
| CA2 | Keys that include every dimension the value depends on; invalidation from every writer (or versioned keys); single-flight, locking or early refresh on expensive misses; TTL plus jitter | A key without tenant or locale; invalidation only from one of several writers; all keys expiring together; recompute-on-miss with full concurrency | A miss storm sends full concurrency to the origin |
| CC3 | A concurrency limit on fan-out (e.g. `p-limit`, `asyncio.Semaphore`, a bounded worker pool, Go `errgroup.SetLimit`); batching into fixed-size chunks | `Promise.all(items.map(call))` or `gather(*[... for x in items])` over a growing collection; a goroutine per element without a limit; Go `errgroup.Group` without `SetLimit`, a bare `sync.WaitGroup`, or a semaphore acquired inside the goroutine (it bounds the work, not the goroutine count) | N simultaneous calls exhaust pools and rate limits |
| FE1 | Route-level dynamic imports (e.g. `React.lazy`, Next.js automatic splitting, `import()`); per-function imports (e.g. `lodash-es` named imports, `date-fns`); production mode in the bundler config | Whole-library imports (e.g. `import _ from "lodash"`, `moment` with all locales); one entry bundle for every route; dev-mode builds in the shipped config | Every shipped byte is parsed before interaction |
| FE2 | Memoised derived data and stable callbacks where measurable (e.g. `useMemo`, `useCallback`, `React.memo`, Vue `computed`); virtualised long lists (e.g. `react-window`, `@tanstack/virtual`); state kept local to the component that changes; React Compiler enabled in the build config, which memoises automatically (missing manual `useMemo`/`memo` is then not a finding) | Context or store updates that re-render the whole tree per keystroke; inline object or function props into memoised children; rendering thousands of rows | Render cost multiplies by items and update frequency |
| BG3 | Framework retries with exponential backoff and jitter (e.g. Sidekiq's default retry; ActiveJob `retry_on ... wait: :polynomially_longer`; Spring Retry `@Backoff(multiplier = ...)`); schedules spread across minutes | An overridden retry delay returning a constant (e.g. `sidekiq_retry_in { 10 }`); ActiveJob `retry_on` with its default fixed 3 s wait; `@Retryable` without `@Backoff`; every schedule on minute 0 | Synchronised retries multiply load at the worst time |

For ME1, verify the database backend, driver and cursor settings as well as the
consumer. Django's `.iterator()` avoids the QuerySet cache, but that does not
prove bounded driver memory. The [Django 5.2 iterator documentation](https://docs.djangoproject.com/en/5.2/ref/models/querysets/#iterator)
states that MySQL loads the full result into driver memory; PostgreSQL streams
only when server-side cursors are enabled (`DISABLE_SERVER_SIDE_CURSORS=False`).
Check the documented behavior for the repository's actual version and cite the
configuration at `path:line`. If the backend or setting cannot be established,
record the mitigation as `UNKNOWN` with the missing evidence; do not close the
step as `sound` based on the iterator call alone. Also trace the consumer for
`list()`, concatenation or other accumulation that recreates the full result.
