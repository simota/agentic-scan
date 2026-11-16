# Perspectives — the review perspectives and their hunt steps

**Read when:** CHECKLIST, to choose which perspectives apply; REVIEW, after the
data rule ledger hunt (`reference/conventions.md`), as the coverage sweep;
REPORT, to fill the `perspectives` table in `findings.json`. **Reader:** the
agent running the skill.

A data hazard is a hypothesis that data can be corrupted, lost or locked in
production. It becomes a finding above `Info` only with exposure (a core
table, the write paths that reach it, a fix commit that already patched its
data, a migration on a table the repository shows is large) and a remedy that
closes it (`reference/remedies.md`). Apply each perspective within every
review unit, core tables first, and record every perspective in the report —
including the ones that found nothing and the ones not run. The names below
are the exact values of `perspectives[].name` and `findings[].category`.

| Perspective | The question it asks |
|---|---|
| Schema constraints | Does the schema itself refuse the rows the application must never write? |
| Application-only invariants | Does every write path go through the code that enforces an invariant the schema does not? |
| Migration locking and rewrites | Can each migration run on production-sized tables without blocking writes? |
| Irreversible and destructive changes | Can every destructive change be undone, or was its data kept before it ran? |
| Deploy compatibility | Do old and new code both work against old and new schema while a deploy rolls out? |
| Backfills and data migrations | Can each data change run on all rows, be stopped and rerun, without harm? |
| Transaction boundaries | Does every multi-step write commit or roll back as one? |
| Concurrency and lost updates | Do concurrent and retried writes keep every invariant? |
| Deletion and cascades | Does every delete remove exactly what it should, everywhere it should? |
| Types and precision | Does each column store the value exactly as the domain means it? |
| Keys and identity | Is each entity created once, and does its key stay valid and unique for its life? |
| Backup and restore assumptions | Could the data and schema be rebuilt after a loss, as the repository claims? |

Rules:

- A perspective not applicable to this codebase is `N/A` with a reason (no
  database migrations in the repository, a read-only data source)
- A perspective that could not be checked statically is `not checked` with
  what would be needed (a schema held in another repository, a deploy
  pipeline not in the repository)
- Every finding names the perspective that surfaced it in `category`, and,
  when one hunt step surfaced it, that step in `step`
- A hunt step covered by a data rule ledger entry cites it (`C-…`) in the
  perspective's `note` instead of being re-run
- The `note` lists the step IDs applied and each one left out with its reason
- A step is `sound` only when its *Sound when* cell can be filled with
  `path:line` evidence

## Hunt steps per perspective

The bars below are starting points, not rules: a hazard needs exposure, and a
missing constraint on a table nothing writes is not a finding.

### Schema constraints (SC)

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| SC1 | Columns the code always fills or treats as required that the schema leaves nullable | Schema source of truth (`reference/recon.md` §3) × model validations, `presence`, `NOT NULL`, `required` fields | Every column the code relies on is `NOT NULL`, or the code handles null where it reads it — because one writer that skips the validation stores a null every reader trips on |
| SC2 | References without a foreign key: `*_id` columns, polymorphic references, ids stored in JSON | Schema, `add_foreign_key`, `REFERENCES`, `@relation`; writers that delete the referenced rows | Each reference to a core table has a foreign key, or a documented reason and a reconciliation job — because a reference without one survives the delete of what it points at |
| SC3 | Uniqueness, ranges and enumerations checked only in code: `validates_uniqueness_of`, status strings, amounts that must be positive | Validations and enums × unique indexes and `CHECK` constraints | The schema holds a unique index or `CHECK` for each such rule on core tables — because a code-only check races with itself and is skipped by every other writer |

### Application-only invariants (AI)

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| AI1 | Writers that bypass the model's validations and callbacks: bulk updates, `update_all`, `update_column`, `insert_all`, raw SQL, admin tools, scripts, other services writing the same database | The writer-backward pass (`reference/recon.md` §2); `grep` for raw SQL and bulk APIs | Every writer of the core table goes through the code that enforces the invariant, or the schema enforces it — because the invariant holds only on the paths that check it |
| AI2 | Derived and denormalised values kept by code: counters, cached totals, status mirrors, copies of a parent's field | Counter caches, `after_save` callbacks, columns updated in two places | Each derived value is recomputed or reconciled, or written in the same transaction as its source on every path — because one missed path leaves it wrong forever |
| AI3 | Invariants across rows or tables enforced by read-then-check: one default address per user, balance equal to the ledger sum, no overlapping bookings | Services that query before they write; uniqueness or exclusivity rules in prose | A partial unique index, exclusion constraint, trigger or row lock enforces it — because two writers that both read "none yet" both write |

### Migration locking and rewrites (ML)

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| ML1 | Migrations that rewrite a large table: changing a column type, adding a column with a volatile default, adding `NOT NULL` without a validated check, on the engine and version the repository targets | Migrations in the window (`reference/recon.md` §4); table size hints (§6) | No change to a large table holds a write-blocking lock for a time proportional to its size, or the long lock was scheduled — because a rewrite, and also a full scan under `ACCESS EXCLUSIVE` such as PostgreSQL's `SET NOT NULL` (skipped from 12 when a validated `CHECK (col IS NOT NULL)` already proves it), blocks writes for as long as it runs |
| ML2 | Index and constraint creation that blocks writes: an index without `CONCURRENTLY` / `algorithm: :concurrently` / `ALGORITHM=INPLACE`, a foreign key or check added and validated in one step | Migrations; the migration tool's options | Indexes on large tables are built online and constraints added unvalidated, then validated — because a blocking build stops every write to the table |
| ML3 | No lock or statement timeout on migrations, and long data work inside the schema migration's transaction | Migration runner configuration, `lock_timeout`, `statement_timeout`, `disable_ddl_transaction!` | Migrations set a lock timeout and keep data work out of the DDL transaction — because a migration queued behind a long query blocks every query queued behind it |

### Irreversible and destructive changes (IR)

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| IR1 | Drops and renames of columns or tables, and type changes that lose data, in the same release as the code stops using them | Migrations with `remove_column`, `drop_table`, `rename_column`, `DROP`; the code still reading them | Data is removed only after the code stopped reading it in an earlier deploy, and kept (an archive table or export) when it cannot be rebuilt — because a drop cannot be rolled back with the deploy |
| IR2 | Down migrations that are missing, raise, or cannot restore the data the up step removed | `down`, `revert`, `IrreversibleMigration`, migrations without a reverse | Each migration is reversible, or its irreversibility is stated with the backup that covers it — because a failed deploy otherwise has no way back but a restore |

### Deploy compatibility (DP)

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| DP1 | Renames and drops of a column still read or written by the code running before the deploy | Migrations × code at the previous release; ORM column caches (`ignored_columns`, generated clients) | Each rename or drop follows expand and contract over separate deploys — because old instances keep running while the new schema is live |
| DP2 | New required columns that the old code does not write: `NOT NULL` without a default, a new unique key the old code violates | Migrations × the old code's inserts | The column has a default or is filled before it becomes required — because every insert by an old instance fails until it is gone |
| DP3 | The order in which migrations and code deploy: migrations run after the new code starts, or in parallel with it; code that needs a column added in the same release | Deploy scripts, CI pipelines, release hooks (`reference/recon.md` §3) | The documented order makes every release work with the schema before and after its migrations — because the window between the two is when requests fail |

### Backfills and data migrations (BF)

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| BF1 | Backfills as one statement over a large table, or inside a schema migration | Data migrations, rake tasks, `UPDATE` without `WHERE` batches | Backfills run in bounded batches outside the DDL transaction — because one huge update locks rows, bloats the table and cannot be stopped halfway |
| BF2 | Backfills that are not idempotent or not resumable: they double-apply on rerun, or restart from the beginning | The backfill's selection and write | Rerunning the backfill changes nothing already done — because a backfill that fails midway is rerun |
| BF3 | Data migrations that use the application's current models, or that miss rows written between the backfill and the switch | Migrations importing models; dual-write code around the switch | Data migrations use plain SQL or a frozen model, and new rows are written in both shapes until the switch — because the model changes later and replaying the migration breaks, and rows written during the gap are left behind |

### Transaction boundaries (TB)

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| TB1 | Multi-step writes without a transaction: several rows or tables written by one operation that must all land | Services, jobs and controllers on core tables; the writer-backward pass | Each operation that must be atomic runs in one transaction — because a failure between two writes leaves half of it |
| TB2 | Side effects inside or before a transaction: a message published, an email sent or an HTTP call made before the commit that it reports | Calls to queues, mailers and clients inside transaction blocks; `after_save` vs `after_commit` | Side effects run after commit, through an outbox or `after_commit` — because a rolled-back write has already been announced |
| TB3 | Long transactions: a network call, a file upload or a loop over many rows while row locks are held | Transaction blocks and what they call | Transactions hold locks only for the writes themselves — because a held lock blocks every other writer of those rows |

### Concurrency and lost updates (CU)

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| CU1 | Read-modify-write without a lock or version: a value read into the application, changed and saved | Balances, counters, stock levels, JSON documents saved whole | The write is atomic in SQL (`SET x = x - ?` with a guard), locks the row, or checks a version — because two writers both save what they read and one change is lost |
| CU2 | Check-then-act on state: `if order.pending?` then update, without a conditional update | State transitions on core entities | The transition is a conditional update (`WHERE status = 'pending'`) whose affected count is checked, or the row is locked — because two requests both see the old state |
| CU3 | Retried writes that apply twice: jobs retried on error, client retries, webhook redelivery, without an idempotency key | Job retry configuration, webhook handlers, payment and order creation | Each retried write carries a key that a unique constraint or upsert deduplicates — because every queue and client retries |

### Deletion and cascades (DE)

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| DE1 | Cascades that reach core data: `ON DELETE CASCADE`, `dependent: :destroy` chains, or deletes of a parent that the code does not expect to remove children | Foreign key definitions, model associations, admin delete actions | Every cascade's reach is intended and bounded, and deletes of core rows are refused or soft — because one delete can remove a customer's whole history |
| DE2 | Soft delete applied unevenly: queries, unique keys and joins that ignore `deleted_at`, or a hard delete beside a soft one | Default scopes, unique indexes, raw queries | Every reader and every unique key treats soft-deleted rows the same way — because a deleted row reappears or blocks a new one |
| DE3 | Deletes that leave dependants behind: rows, files or search entries of a removed parent, deleted by a path that skips the callbacks that clean them | `delete`, `delete_all`, raw `DELETE`, background cleanups | A foreign key or one consistent deletion path removes or refuses the dependants — because orphans are found later, in reports and invoices |

### Types and precision (TP)

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| TP1 | Money and quantities stored or computed as floating point | Column types (`float`, `double`, `real`), the code's arithmetic on amounts | Money is `decimal`/`numeric` or integer minor units, end to end — because a float cannot store 0.1 and the error is summed |
| TP2 | Timestamps without a zone, or local time stored: `timestamp without time zone` fed by a server's local clock, dates computed in the wrong zone | Column types, the application's and database's time zone settings | Instants are stored in UTC or with zone, and dates are computed in a stated zone — because a zone change or DST shifts every stored value |
| TP3 | Truncation, overflow and encoding: strings longer than the column, silent truncation in a non-strict mode, a 32-bit counter, `utf8` that cannot store every character | Column lengths vs input limits, SQL mode, integer widths, character sets | Inputs are bounded below the column's size, the database refuses what does not fit, and the character set stores all input — because silently changed data is found only when someone reads it |

### Keys and identity (KI)

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| KI1 | Entities created twice: a business key (email, external id, order number) with no unique key, created by a find-or-create in code | Create paths × unique indexes | The business key has a unique index, normalised as it is compared (case, whitespace) — because two concurrent creates both find nothing |
| KI2 | Keys and sequences that can run out: 32-bit primary keys and sequences on growing tables, foreign keys narrower than the key they reference | Key types in the schema; growth hints (`reference/recon.md` §6) | Keys on growing tables are 64-bit, or the headroom is measured and recorded — because inserts stop on the day the sequence passes the type's range |
| KI3 | Natural keys that change used as primary or foreign keys: an email, a username, a code a person can edit; and tables with no primary key at all | Primary keys and references that are not surrogate ids; tables created without one (`id: false`, no `PRIMARY KEY`) | Mutable identifiers are attributes with a unique index, not keys, and every table has a stable primary key — because changing a key must rewrite every reference, and a row without one cannot be updated or deleted alone |

### Backup and restore assumptions (BR)

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| BR1 | Restore never exercised or documented: no runbook, no recorded drill, point-in-time recovery assumed but not described | Ops docs, runbooks, infrastructure code in the repository | The repository records a restore procedure and when it was last run — because a backup nobody has restored is a hope |
| BR2 | Migrations that cannot be replayed from zero, or a schema dump that has drifted from them: edited migrations, migrations that depend on models or seed data, a dump nobody regenerates | Migration history (`reference/recon.md` §4: a migration modified after it was added), schema dump vs migrations | Migrations replay from an empty database to the committed schema — because a rebuilt environment otherwise differs from production |

## Sound constructs

Look-alikes that are not hazards, and what makes them so:

| Looks like | Is sound when |
|---|---|
| A reference without a foreign key (SC2) | It points across databases or services, and a reconciliation job or the owner's contract keeps it valid, named at `path:line` |
| A uniqueness check in code (SC3, KI1) | A unique index on the same columns backs it; the code check only produces a friendlier error |
| A blocking migration (ML1, ML2) | The table is small by the repository's own size hints, or the migration is from before the table had traffic |
| A cascade delete (DE1) | It removes rows owned only by the parent (line items of a draft), and the parent itself is never deleted in production |
| A float column (TP1) | It holds a measurement where rounding is acceptable (a ratio, a coordinate), never money or a count |
| A read-modify-write (CU1) | The row has a single writer by design (one worker per partition), named at `path:line` |
| An irreversible migration (IR2) | It drops data already copied elsewhere, and the copy is named |
