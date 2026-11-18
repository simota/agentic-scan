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
| TP1 | Money and quantities stored as floating point | Column types (`float`, `double`, `real`) in the schema and in migrations; floating-point arithmetic on amounts in code belongs to a business-logic review, out of scope here | Money columns are `decimal`/`numeric` or integer minor units — because a float column cannot store 0.1, and every row keeps the error it was written with |
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

A hazard row is dropped, or a trace row `follows`, on these grounds only for a
construct in the *Sound* column, cited at `path:line`; an *Unsound* construct
is a candidate even when it looks deliberate. Every named API is a labelled
example (`e.g.`), not a list to grep for: find this stack's equivalent, and
check the engine version and library version the repository pins before
relying on a behaviour.

| Step | Sound (labelled examples) | Unsound look-alike (labelled examples) | Why |
|---|---|---|---|
| SC1 | The column itself is `NOT NULL`: Rails `null: false` in the migration; Django fields (`null=False` is the default); Prisma a field without `?`; Laravel a column without `->nullable()` | Rails `validates :email, presence: true` on a column the migration left nullable; Django `blank=False` (form validation only) with `null=True`; JPA `@Column(nullable = false)` or `@NotNull` when the schema comes from Flyway or Liquibase migrations that leave the column nullable (the annotations shape Hibernate's generated DDL, not a hand-written migration) | A validation guards one write path; the column guards all of them |
| SC2 | A foreign key in the schema: Rails `add_foreign_key`, `t.references :customer, foreign_key: true`; Django `ForeignKey` (creates the constraint by default); Prisma `@relation` under the default `relationMode = "foreignKeys"`; Laravel `foreignId('customer_id')->constrained()`. A reference across databases or services without one, when a reconciliation job or the owner's contract keeps it valid, named at `path:line` | Rails `belongs_to` (required by default since Rails 5, but a validation only) or `t.references` without `foreign_key: true` (column and index only); Django `ForeignKey(db_constraint=False)`; Prisma `relationMode = "prisma"` (relations emulated in the client, no foreign keys); Laravel `foreignId()` without `constrained()`; polymorphic pairs (Rails `polymorphic: true`, Laravel `morphs()`); a MySQL MyISAM table (the `FOREIGN KEY` clause is parsed and ignored) | Only the database sees every delete of the referenced row |
| SC3 | A unique index or `CHECK` beside the code check, which then only produces a friendlier error: Rails `add_index …, unique: true` behind `validates …, uniqueness: true`; Django `unique=True`, `UniqueConstraint`, `CheckConstraint`; Prisma `@unique`, `@@unique`; Laravel `->unique()`; PostgreSQL `CHECK (amount > 0)`; MySQL `CHECK` from 8.0.16 | Rails `validates_uniqueness_of` alone (a `SELECT`, then the insert); Rails `enum` and Django `choices` alone (`update_all`, `QuerySet.update()` and raw SQL store any value); a `CHECK` on MySQL before 8.0.16 (parsed and ignored); a unique index over a nullable column read as "one per value" (PostgreSQL and MySQL both accept many `NULL`s; PostgreSQL 15+ `NULLS NOT DISTINCT` refuses them) | A code-only check races with itself and is skipped by every other writer |
| AI1 | Bulk and raw writers used only where the schema enforces the invariant, or that call the same enforcing code; Django code that calls `full_clean()` before `save()` where model validators carry the rule | Rails `update_all`, `update_column`/`update_columns`, `insert_all`/`upsert_all`, `delete_all` (no validations, no callbacks); Django `QuerySet.update()` and `bulk_create()` (no `save()`, no `pre_save`/`post_save` signals), and `save()` itself (model field validators run only in `full_clean()`, which `ModelForm` calls and `save()` does not); Laravel mass `Model::where(…)->update([...])` (no `saving`/`updating`/`updated` events); JPA JPQL bulk `UPDATE`/`DELETE` (no lifecycle callbacks such as `@PreUpdate`, no Bean Validation) | The invariant holds only on the paths that run the code that checks it |
| AI2 | A value derived in the database: PostgreSQL 12+ `GENERATED ALWAYS AS (…) STORED`, MySQL 5.7+ generated columns (same-row values only); a trigger; a total computed on read; a scheduled reconcile (Rails `reset_counters`) | Rails `counter_cache: true` on a child table that any `delete_all`, `update_all` or raw SQL writes; a Django `post_save` handler keeping a total that `QuerySet.update()` and `bulk_create()` never trigger | One missed path leaves the derived value wrong for good |
| AI3 | PostgreSQL partial unique index (`CREATE UNIQUE INDEX … ON addresses (user_id) WHERE is_default`; Rails `add_index …, unique: true, where:`; Django `UniqueConstraint(…, condition=Q(…))`); PostgreSQL exclusion constraint `EXCLUDE USING gist (room_id WITH =, during WITH &&)` (with `btree_gist`); a row lock on the parent before the check | A `SELECT`-then-`INSERT` check at the default isolation (PostgreSQL `READ COMMITTED`; InnoDB `REPEATABLE READ`, where a plain `SELECT` reads a snapshot and locks nothing); Django `UniqueConstraint(condition=…)` on MySQL or MariaDB (no partial indexes there: the constraint is not created, with system check warning `models.W036`) | Two writers that both read "none yet" both write |
| ML1 | PostgreSQL 11+ `ADD COLUMN` with a non-volatile default (a constant, or `now()`, which is stable), or any version with no default; PostgreSQL 9.2+ `varchar(n)` widened, or `varchar` to `text` (no rewrite); MySQL 8.0.12+ `ADD COLUMN … ALGORITHM=INSTANT` (last position only before 8.0.29); PostgreSQL 12+ `SET NOT NULL` after a validated `CHECK (col IS NOT NULL)`. A blocking change on a table that is small by the repository's own size hints, or that ran before the table had traffic | PostgreSQL before 11, `ADD COLUMN` with any default; any version, a volatile default (`clock_timestamp()`, `random()`, `gen_random_uuid()`); PostgreSQL `ALTER COLUMN TYPE integer → bigint` (rewrites the table and its indexes under `ACCESS EXCLUSIVE`); PostgreSQL `SET NOT NULL` with no such check (full scan under `ACCESS EXCLUSIVE`); MySQL changing a column's data type (`ALGORITHM=COPY` only, no concurrent DML); Rails `change_column`, Django `AlterField` and Laravel `->change()` on a column type run these same statements | The table is locked against writes for as long as the rewrite or scan runs |
| ML2 | PostgreSQL `CREATE INDEX CONCURRENTLY` (Rails `algorithm: :concurrently` with `disable_ddl_transaction!`; Django `AddIndexConcurrently` in a migration with `atomic = False`); MySQL InnoDB 5.6+ secondary index `ALGORITHM=INPLACE, LOCK=NONE`; PostgreSQL constraint added `NOT VALID`, then `VALIDATE CONSTRAINT` (Rails `add_foreign_key …, validate: false`, then `validate_foreign_key`). A blocking build on a table small by the size hints, or created in the same migration | PostgreSQL plain `CREATE INDEX` (a `SHARE` lock: reads go on, writes wait); Rails `add_index` without `algorithm:`; Django `AddIndex` or `Meta.indexes`; Prisma Migrate SQL (plain `CREATE INDEX` unless edited); PostgreSQL `ADD FOREIGN KEY` validated in one step (`SHARE ROW EXCLUSIVE` on both tables for the whole scan); an interrupted `CREATE INDEX CONCURRENTLY` (leaves an `INVALID` index that still slows writes) | A blocking build stops every write to the table |
| ML3 | `lock_timeout` and `statement_timeout` set for migrations (PostgreSQL `SET lock_timeout = '5s'`; strong_migrations' `lock_timeout` setting); MySQL `SET SESSION lock_wait_timeout` (the default is 31536000 seconds); data work in its own migration or task outside the DDL transaction | A Rails or Django migration on PostgreSQL that alters a table and backfills it in the same transaction (DDL is transactional there, so the `ACCESS EXCLUSIVE` lock is held until commit); MySQL DDL with the default metadata-lock wait queued behind a long transaction | A waiting DDL queues every later query on the table behind it |
| IR1 | A column dropped only after a release stopped reading it: Rails `self.ignored_columns += ["legacy"]` shipped first, then `remove_column`; Django `SeparateDatabaseAndState` to drop the field from the model before the column; a rename done as add, copy, switch, drop | Rails `rename_column` or `remove_column` in the release that changes the code; Django `RenameField`/`RemoveField` generated with the model change; Prisma Migrate on a renamed field (it generates `DROP COLUMN` plus `ADD COLUMN`, losing the data, unless the SQL is edited to `RENAME COLUMN`) | A drop cannot be rolled back with the deploy |
| IR2 | A reversible migration that restores the data; an irreversible one that drops data already copied elsewhere, with the copy named | Rails `remove_column :users, :legacy, :string` in `change` (reverses to an empty column); Django `RunPython(forward)` without `reverse_code` (raises on rollback) or with `RunPython.noop`; Alembic `downgrade()` that is `pass`; a MySQL migration that fails halfway (each DDL statement commits implicitly, so the earlier statements stay applied) | A rollback that runs is not a rollback that restores |
| DP1 | Expand and contract over separate deploys; Rails `ignored_columns` before the drop | A column dropped or renamed while old instances run: ActiveRecord caches the column list at boot, so their writes fail until restarted; Hibernate entities and Prisma's generated client still select it | Old instances keep running while the new schema is live |
| DP2 | A database default the old code can rely on: Rails `add_column …, default:` (kept in the schema); Django 5.0+ `db_default=`; the column nullable until every writer fills it | Django `AddField(…, default=…)`: the default is set to fill existing rows and then dropped from the column, so old code inserting without the field fails on `NOT NULL` | Every insert by an old instance fails until it is gone |
| BF1 | Bounded batches outside the DDL transaction: Rails `in_batches(of: 1_000) { \|batch\| batch.update_all(…) }`; keyset loops by primary key; Laravel `chunkById()` | One `UPDATE` over a large table, or Rails `update_all` / Django `QuerySet.update()` over all rows inside a schema migration; Laravel `chunk()` while updating the column the query filters on (offset pages skip rows) | One huge update locks rows, bloats the table and cannot be stopped halfway |
| BF3 | Django `RunPython` with `apps.get_model("app", "Model")` (the historical model); a Rails migration that defines its own minimal model class or uses SQL | A Django migration that imports the app's model; a Rails migration that calls the app's model class, its validations and callbacks | The model changes later and replaying the migration breaks |
| TB1 | Rails `transaction do … end`; Django `transaction.atomic()`; Laravel `DB::transaction(fn () => …)`; Prisma `$transaction`; Spring `@Transactional` on a public method called through the proxy | Spring `@Transactional` reached by a call from the same class (self-invocation skips the proxy) or expecting rollback on a checked exception (default rollback is on unchecked exceptions only); Django in autocommit with `ATOMIC_REQUESTS` off and no `atomic()`; a `rescue` inside a Rails transaction block that swallows a non-database error raised between two writes (the block then commits the first); MySQL MyISAM tables (no transactions) | A failure between two writes leaves half of it |
| TB2 | Rails `after_commit`; Django `transaction.on_commit()`; Laravel `->afterCommit()` on dispatched jobs; an outbox table written in the same transaction | Rails `after_save`/`after_create` that enqueues a job or sends mail; a Django `post_save` handler that does the same (it runs inside the transaction) | The job can run before the commit, or the write rolls back after the announcement |
| CU1 | Atomic SQL: `UPDATE wallets SET balance = balance - :amt WHERE id = :id AND balance >= :amt`; Rails `update_counters`, `with_lock`, a `lock_version` column; Django `F("balance") - amt` in `.update()`, `select_for_update()` inside `atomic()`; JPA `@Version`, `@Lock(PESSIMISTIC_WRITE)`; Laravel `lockForUpdate()`, `increment()`. A row with a single writer by design (one worker per partition), named at `path:line` | `obj.balance -= amt; obj.save()` in any ORM; Rails `lock!` outside a transaction (in autocommit the lock ends with the statement); relying on InnoDB's default `REPEATABLE READ` to prevent lost updates (a plain `SELECT` takes no lock) | Two writers both save what they read and one change is lost |
| CU2 | A conditional update whose count is checked: Rails `Order.where(id:, status: "pending").update_all(status: "paid")` returning 1; Django `.filter(pk=…, status="pending").update(…)` returning 1 | `if order.pending?` then `order.update!(status: "paid")`; the Django or Laravel equivalent read-then-save | Two requests both see the old state |
| CU3 | An idempotency key under a unique constraint, written with an upsert: PostgreSQL 9.5+ `INSERT … ON CONFLICT DO NOTHING`; MySQL `INSERT … ON DUPLICATE KEY UPDATE`; Rails `insert_all`/`upsert_all` (`unique_by:` on PostgreSQL and SQLite only) | A "seen before?" `SELECT` without a unique key behind it; MySQL `INSERT IGNORE` as the dedupe (it also turns other errors, such as truncation, into warnings) | Every queue, webhook sender and client retries |
| DE1 | A cascade that removes rows owned only by the parent (line items of a draft) when the parent itself is never deleted in production; `ON DELETE RESTRICT` / `NO ACTION` on core references; Rails `dependent: :restrict_with_error`; Django `on_delete=models.PROTECT` | Rails `dependent: :destroy` read as a database cascade (it loads and destroys each child in Ruby, and `delete`/`delete_all` skip it), or `ON DELETE CASCADE` read as running callbacks (it runs none); JPA `CascadeType.REMOVE` / `orphanRemoval` (only through `EntityManager.remove`, not JPQL bulk deletes); a MySQL trigger expected to fire on rows removed by a cascade (cascaded foreign key actions do not fire triggers) | One delete can remove a customer's whole history, or leave half of it |
| DE2 | PostgreSQL partial unique index `… WHERE deleted_at IS NULL`; every raw query adds the same filter the scope does | A unique index on `email` alone with soft-deleted rows (blocks re-registration); a unique index on `(email, deleted_at)` (live rows all have `deleted_at` `NULL`, and `NULL`s are distinct, so live duplicates pass); Laravel `SoftDeletes` read as covering `DB::table()` queries (the query builder applies no Eloquent global scope) | A deleted row reappears, or blocks a new one |
| DE3 | One deletion path that removes the dependants, or a foreign key that does | Rails `delete`/`delete_all` on a model whose cleanup lives in callbacks; Laravel mass `Model::where(…)->delete()` (no `deleting`/`deleted` events); JPA JPQL bulk `DELETE` | Orphans turn up later, in reports and invoices |
| TP1 | Exact types: PostgreSQL `numeric(12,2)`; MySQL `DECIMAL(12,2)`; Rails `t.decimal precision: 12, scale: 2`; Django `DecimalField(max_digits=12, decimal_places=2)`; Prisma `Decimal`; JPA `BigDecimal`; integer minor units in `bigint`. A float column holding a measurement where rounding is acceptable (a ratio, a coordinate), never money or a count | `float`, `double precision`, `real`, MySQL `FLOAT`/`DOUBLE`; Rails `t.float`, Django `FloatField`, Prisma `Float` for amounts; Rails `t.decimal :price` with no precision on MySQL (MySQL's default is `DECIMAL(10,0)`: no cents); PostgreSQL `money` (its input and output follow `lc_monetary`) | A float column cannot store 0.1, and every row keeps the error it was written with |
| TP2 | PostgreSQL `timestamptz`; Django with `USE_TZ = True` (the default from 5.0; `DateTimeField` is `timestamptz` on PostgreSQL); Rails with `default_timezone` left at `:utc` and every writer in UTC | PostgreSQL `timestamp` (without time zone) filled with `now()` or `CURRENT_TIMESTAMP` in a session whose `TimeZone` is not UTC (stored as that local time); MySQL `DATETIME` filled with `NOW()` (session local time, no zone kept); MySQL `TIMESTAMP` for dates past 2038-01-19 03:14:07 UTC (out of range); Rails `default_timezone = :local`; Django `USE_TZ = False` | A zone change or DST shifts what every stored value means |
| TP3 | MySQL with `STRICT_TRANS_TABLES` in `sql_mode` (default since 5.7) on every connection that writes, e.g. Rails' MySQL adapter (`strict: true` by default) and Laravel's `'strict' => true`; MySQL `utf8mb4` (the default character set since 8.0); PostgreSQL `varchar(n)` (refuses longer values on insert, unless the excess is only spaces) | MySQL non-strict mode (truncates strings and clips out-of-range numbers with only a warning), e.g. a script or second service connecting with an empty `sql_mode`; MySQL `utf8` / `utf8mb3` (three bytes: emoji and other 4-byte characters are refused in strict mode, cut off in non-strict); PostgreSQL explicit cast `::varchar(10)` (truncates silently) | Silently changed data is found only when someone reads it |
| KI1 | A unique index on the business key, normalised as compared: PostgreSQL `citext` or a unique index on `lower(email)`; MySQL a `_ci` collation (8.0's default `utf8mb4_0900_ai_ci` is also accent-insensitive, so `é` and `e` collide); then Rails 6.0+ `create_or_find_by`, Django `get_or_create` (on an `IntegrityError` it reads again), or Rails `find_or_create_by` / Laravel `firstOrCreate` with the unique violation rescued and the row read again | Rails `find_or_create_by`, Django `get_or_create` and Laravel `firstOrCreate` on columns with no unique index (two callers both find nothing and both insert); a case-sensitive PostgreSQL unique index on `email` while lookups use `lower(email)` | Two concurrent creates both find nothing |
| KI2 | 64-bit keys: `bigint`/`bigserial`, MySQL `BIGINT AUTO_INCREMENT`; Rails 5.1+ default primary and `t.references` keys; Django `BigAutoField` (set by `DEFAULT_AUTO_FIELD` in projects from `startproject` since 3.2); Laravel `$table->id()` | PostgreSQL `serial`/`integer` keys (max 2,147,483,647) on a growing table; Rails tables created before 5.1; Django without `DEFAULT_AUTO_FIELD` (`AutoField`, a 32-bit integer); Prisma `Int @id @default(autoincrement())`; Laravel `increments()`; a 32-bit foreign key pointing at a 64-bit key | Inserts stop on the day the sequence passes the type's range |
