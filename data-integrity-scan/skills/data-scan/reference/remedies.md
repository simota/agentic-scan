# Remedies — data-layer changes, preconditions and rollout pitfalls

**Read when:** REVIEW, to name the remedy a hazard needs; VERIFY, to check its
preconditions and its rollout; PLAN, to write steps. **Reader:** the agent
running the skill. **Decision it supports:** which change to the schema, the
migrations or the write paths closes the hazard, what it needs first, and how
to break it into steps that each leave production working.

`findings[].remedy` is one name from the first column, exactly; a finding
needing several uses the first and lists the rest in `steps`, or is split
into findings linked by `depends_on` (`reference/plan.md`).

## Remedies

| Remedy | Closes | Preconditions to check | Typical steps |
|---|---|---|---|
| Add Not-Null Constraint | SC1 | Every writer fills the column today, and existing nulls are counted (a read-only query or a documented count) | 1. Fill existing nulls in batches. 2. Add a `CHECK (col IS NOT NULL) NOT VALID`, validate it, then set `NOT NULL` where the engine uses the check to skip the scan |
| Add Foreign Key | SC2, DE3 | Orphaned rows are counted and their owner decided; every writer that deletes the referenced rows is known | 1. Fix or remove the orphans. 2. Add the key without validating it (`NOT VALID`, `validate: false`). 3. Validate it in a later migration |
| Add Unique Constraint | SC3, KI1 | Existing duplicates are counted and the merge rule decided; the key is normalised as the code compares it (case, whitespace) | 1. Merge or remove duplicates. 2. Build the unique index online. 3. Attach it as a constraint where the engine allows; keep the code check for the error message |
| Add Check Constraint | SC3, AI3 | The rule is a single-row condition (a range, a non-negative amount, an allowed status) and existing rows satisfy it | 1. Make every writer stop producing violations, then fix existing violating rows in batches. 2. Add the check `NOT VALID` (it already refuses new violations, so a later update to any column of a row still violating it would fail). 3. Validate it in a later migration |
| Move Invariant into Schema | AI1, AI3 | The invariant can be stated as a partial unique index, an exclusion constraint, a generated column or a trigger the team accepts | 1. Express the invariant in the schema, unvalidated where possible. 2. Fix existing violations. 3. Validate, then keep the code check only for messages |
| Reconcile Derived Data | AI2 | The source of truth for the derived value is identified; every path that writes the source is known | 1. Write the derived value in the same transaction as its source on every path, or compute it on read. 2. Add a reconciliation query or job that reports drift. 3. Correct existing drift in batches |
| Split into Expand and Contract | DP1, DP2, DP3, IR1 | The old and new shapes can coexist; the deploy order is documented (`reference/recon.md` §3) | 1. Expand: add the new shape, write both. 2. Backfill. 3. Switch reads. 4. Contract: stop writing and remove the old shape in a later deploy, after its data is kept where it cannot be rebuilt |
| Add Column Without Rewrite | ML1, DP2 | The engine and version the repository targets add the column without rewriting the table (a constant default, nullable) | 1. Add the column nullable or with a constant default. 2. Backfill in batches. 3. Add the constraint unvalidated, then validate it |
| Build Index Concurrently | ML2 | The migration tool can run outside a transaction (`disable_ddl_transaction!`, `CONCURRENTLY`, `ALGORITHM=INPLACE, LOCK=NONE`) | 1. Build the index online in its own migration. 2. Check it is valid afterwards (an interrupted concurrent build leaves an invalid index) |
| Set Lock and Statement Timeouts | ML3, TB3 | The runner can set session settings per migration or per transaction | 1. Set a short `lock_timeout` (and a `statement_timeout` for data work) on migrations. 2. Retry the migration on timeout instead of waiting |
| Make Migration Reversible | IR2 | What the up step removes is known, and where it can be restored from | 1. Write the reverse step, or keep the removed data (an archive table) so the reverse can restore it. 2. State irreversibility explicitly where no reverse is possible, naming the backup that covers it |
| Batch the Backfill | BF1, BF2 | The rows to change can be selected by a key range or a marker, so each batch is bounded and a rerun skips what is done | 1. Move the backfill out of the schema migration. 2. Update in bounded batches by key, committing each. 3. Make each batch skip rows already done |
| Decouple Migrations from Models | BF3, BR2 | The migration's needs can be written in SQL or with a model class frozen inside the migration | 1. Replace model calls with SQL or a local model. 2. Replay all migrations from an empty database and compare the result with the committed schema |
| Widen Transaction Boundary | TB1 | Every write the operation makes is in one database, and no step waits on the network inside it | 1. Wrap the writes in one transaction, ordering them so a failure leaves nothing partial. 2. Move any external call out of it |
| Publish After Commit | TB2 | The side effect can run after commit, or the codebase has or accepts an outbox table | 1. Move the call to `after_commit`, or write an outbox row in the same transaction. 2. Deliver the outbox with retries and an idempotency key |
| Use Optimistic Locking | CU1, CU2 | Conflicts are rare and the caller can retry or report them | 1. Add a version column with a default. 2. Check it on every update and handle the conflict |
| Lock Rows for Update | CU1, CU2 | The lock is held only for the read-check-write, inside one short transaction; lock order is the same everywhere | 1. Read with `SELECT … FOR UPDATE` (`lock`, `with_for_update`). 2. Check and write in the same transaction. 3. Or write it as one conditional `UPDATE` and check the affected count |
| Use Idempotent Upsert | CU3, KI1, BF2 | The operation has a natural or client-supplied key that a unique index can hold | 1. Add the unique index on the key. 2. Write with `INSERT … ON CONFLICT` / `upsert` / `find_or_create` backed by it. 3. Return the existing result on a repeat |
| Use Exact Numeric Type | TP1 | Every reader and writer of the column is known, and the rounding rule for existing values is decided | 1. Add a `decimal` or integer-minor-units column. 2. Backfill with the decided rounding. 3. Switch reads and writes, then drop the float column (expand and contract) |
| Store Timestamps in UTC | TP2 | The zone existing values were written in is known for every writer | 1. Add a zone-aware column, or convert in place with the known source zone. 2. Set the application and connection zone explicitly |
| Widen Column Type | TP3, KI2 | The engine's cost of the change is known (rewrite or not), and every foreign key that references the column is listed | 1. Widen in place where the engine does not rewrite, or add a wider column and switch to it. 2. Widen every referencing column the same way |
| Use Surrogate Key | KI3 | Every reference to the natural key is found, in code, other tables and other services; for a table with no primary key, its duplicate rows are counted | 1. Add a surrogate id. 2. Move references to it (expand and contract). 3. Keep the natural key as a uniquely indexed attribute |
| Make Deletion Consistent | DE1, DE2, DE3 | Every path that deletes the entity is found, and whether deletion is hard or soft is decided | 1. Route deletes through one path or enforce them with foreign keys. 2. Make every query and unique index treat soft-deleted rows the same way. 3. Clean existing orphans in batches |
| Rehearse Restore | BR1 | Who can run a restore and against which environment is known; the review itself never restores anything | 1. Write the restore procedure in the repository. 2. Run it into a disposable environment and record the date and the result |

## Preservation pitfalls per engine

A remedy changes production data or schema, so each step must leave the data
intact and the application working while it rolls out. Check these in VERIFY
before calling a step `Online`:

| Engine or tool | Pitfalls |
|---|---|
| PostgreSQL | Changing a column type rewrites the table unless the cast is binary-compatible; `ADD COLUMN` with a volatile default rewrites it (a constant default does not since 11); `CREATE INDEX CONCURRENTLY` cannot run inside a transaction and leaves an invalid index when interrupted; `SET NOT NULL` scans the table unless a validated check already proves it (12 and later); `ADD CONSTRAINT … NOT VALID` still takes a strong lock (`ACCESS EXCLUSIVE` for a check, `SHARE ROW EXCLUSIVE` on both tables for a foreign key) but only for a moment, and `VALIDATE` scans under `SHARE UPDATE EXCLUSIVE`, which does not block writes: the gain is lock duration, not lock strength, so set a `lock_timeout`, since even the brief lock queues behind long transactions |
| MySQL / InnoDB | Online DDL depends on version and operation (`ALGORITHM=INSTANT/INPLACE/COPY`); changing a column type usually copies the table; metadata locks queue every query behind a waiting DDL; non-strict SQL mode truncates silently; `utf8` is three bytes and loses characters `utf8mb4` keeps |
| SQLite | `ALTER TABLE` supports little; most changes recreate the table, and foreign keys are enforced only with `PRAGMA foreign_keys = ON` per connection |
| ORMs and migration tools | Rails wraps each migration in a transaction unless `disable_ddl_transaction!`; Django runs data and schema operations together unless split, and `atomic = False` is needed for concurrent indexes; Prisma and other generated migrations may drop and recreate a column for a rename; an ORM's cached column list makes old instances fail on a dropped column until restarted |
| Any | A lock is queued behind the longest running query, so even a fast DDL can block every write; a backfill in one transaction holds every row lock it took until commit; replication applies a large change on replicas afterwards, so lag grows with it |

A pitfall that applies and cannot be ruled out statically raises `rollout` to
`Staged` or `Downtime`, and is named in `rollout_reason`.
