# Recon — the hot-path map

**Read when:** RECON, before any finding is written. Nothing in later phases is
trustworthy until this map exists, because a cost cannot be judged without
knowing which workload pays it and how often.

The map is a working artifact. Keep it in scratch; it is not part of the final
report unless asked.

## 1. Stack and versions

- Language runtime, framework, ORM, database, cache, queue, HTTP client,
  front-end framework and bundler, with versions from lockfiles
- The execution model: threads per request, process workers, async event loop,
  goroutines, serverless invocations. It decides what "blocking" means and
  which resources are shared between requests
- Runtime versions with known, documented performance changes are checked
  against the vendor's current notes when the host can fetch them, not
  recalled; otherwise record the unchecked version in `limitations`

## 2. Entry points and workloads

Everything that does work on behalf of the outside world:

- HTTP routes — **all** route files, API, web, admin and versioned groups;
  GraphQL resolvers; server actions and RPC the framework exposes implicitly
- Server-rendered pages and the data loaders behind them
- Queue consumers, scheduled jobs, cron, CLI commands, imports and exports
- WebSocket channels, streaming endpoints, file watchers, webhooks
- Startup and deploy: boot-time loading, migrations, cache warmers

## 3. Workload inventory

One row per entry point. The columns are what make the later review
mechanical:

| Entry point | Kind | Frequency / sensitivity | Scale drivers | Data access | Outbound I/O | Mitigations seen | Notes |
|---|---|---|---|---|---|---|---|

- *Kind*: `request`, `page`, `job`, `consumer`, `import`, `export`, `startup`,
  `cli`, `stream` (WebSocket and streaming endpoints), `webhook`, `watcher`
- *Frequency / sensitivity*: `hot` (every page view, list screens, polling,
  auth, search, high-volume API), `warm` (regular user actions), `cold`
  (admin, one-off, nightly with slack). Infer from the client code, polling
  intervals, schedules and route names; mark the inference
- *Scale drivers*: every collection whose size the work depends on, with its
  owner (rows per tenant, items per order, members per team, file size). Each
  becomes a cost-trace row (`reference/budgets.md` §3)
- *Data access* and *Outbound I/O*: the queries, cache reads, HTTP calls and
  file reads on the path, with `path:line`
- *Mitigations seen*: pagination, limits, eager loading, caching, batching,
  timeouts, with `path:line`

Then flag:

- **Hot list and search endpoints** — the usual home of N+1 queries, missing
  limits and missing indexes
- **Fan-out paths** — one request that triggers per-item work (notifications,
  webhooks, recalculation, exports)
- **Paths doing synchronous work that could be deferred** — emails, PDF
  generation, image processing, third-party calls inside a request
- **Entry points without a timeout** on the path to a slow dependency

## 4. Data model and volume

- Every table or collection on a hot path, its expected growth (per tenant,
  global, append-only history), and what caps it
- Indexes from migrations and schema files, mapped to the filters, sorts and
  joins the hot queries use. A query whose filter or sort has no matching index
  is a lead. If the migrations form a complete chain (the first revision has no
  parent), its absence in the repository is confirmed and production table size
  is the remaining condition; with a partial history or a schema kept outside
  the repository, whether production has the index is `UNKNOWN` (`SKILL.md`,
  *Decide first*)
- Soft-delete flags, status columns and tenant columns that every query filters
  on — they belong in composite indexes
- Large columns (blobs, JSON documents, long text) that list queries load

## 5. I/O sinks

Where a request spends time outside the CPU: ORM and raw queries, cache reads
and writes, outbound HTTP and RPC, message publishing, file and object storage,
external SDK calls, logging and telemetry on the hot path. For each, where the
client is created (once vs per request) and its timeout and pool settings.

## 6. Caching layers

HTTP caching headers and CDN config, application caches (in-process maps,
memoisation, Redis or Memcached), ORM or query caches, front-end data caches.
For each: key, TTL, invalidation, size bound, and who shares the entry.

## 7. Concurrency and resources

Worker, thread and process counts; DB and HTTP connection pool sizes; queue
concurrency; locks, mutexes and `synchronized` sections; transactions that span
outbound calls; per-request parallelism (`Promise.all`, goroutines, thread
pools) and whether it is bounded.

## 8. Runtime and build config

Production vs development settings: debug mode, query logging, log level,
template and asset caching, source maps, minification, compression, heap and GC
settings, autoscaling and container limits in IaC, bundler config and code
splitting.

## 9. Existing performance evidence

Benchmarks, load-test scripts and their targets, performance tests, query-count
assertions, APM and tracing config, profiling hooks, documented SLOs, and
comments or issues about slowness. They state budgets (§10) and show which
paths someone already measured.

## 10. Bounds the app states — input to the budget ledger

Record what the later budget hunt needs (`reference/budgets.md`):

- **Latency and deadlines** — SLO documents, request and job timeouts, client
  timeouts, gateway limits, job schedules that must finish before the next run
- **Size bounds** — default and maximum page sizes, upload and body limits,
  export caps, plan limits on counts
- **Per-request work bounds** — existing query-count tests, batch sizes, rate
  limits on expensive endpoints
- **Front-end budgets** — bundle-size limits in the build config, performance
  budgets in CI, Lighthouse or Web Vitals thresholds
- **Resource limits** — container memory and CPU, pool sizes, worker counts
