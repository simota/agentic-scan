# Recon — the data map

**Read when:** RECON, before any unit is reviewed. **Reader:** the agent
running the skill, cold. **Decision it supports:** which units to review
first, which hazards can carry exposure, and how a fix could reach
production.

Recon answers four questions for every unit: *what must not be corrupted*
(core tables and every path that writes them), *what the schema enforces*
(the schema source of truth and how migrations reach production), *where data
already went wrong* (fix commits that patched data, migrations changed in the
window), and *how big it is* (table size hints). Record each in scratch; the
findings cite them.

All commands here are read-only. Name each tool before running it. Never
connect to a database, never run a migration, the application or its tests,
and never install anything into the audited repository.

## 1. Stack and units

- Languages, frameworks and ORMs; the database engines and the versions the
  repository targets (`database.yml`, `docker-compose.yml`, connection
  strings in config, engine-specific SQL in migrations)
- Data access layers: models, repositories, query builders, raw SQL files,
  stored procedures and triggers kept in the repository
- Generated and vendored directories (out of scope; list them for
  `limitations`)
- Review units: one per top-level module or package that writes data, plus
  the cross-cutting unit (schema source of truth, migrations, migration and
  deploy configuration, shared database helpers)

## 2. Core tables, write paths and history window

List the core tables the requester named, and add any the code makes obvious
(money, orders, accounts, inventory, permissions, anything with an audit
log). For each table, find **every writer** by working backward from the
table: the model and its callbacks, raw SQL that names the table, bulk APIs
(`update_all`, `insert_all`, `bulk_create`, `executemany`), admin tools,
jobs, scripts and data migrations, and other services the repository shows
writing the same database. This is the writer-backward pass; an invariant
holds only on the paths that check it.

| Table | Writer (`path:line`) | Operation | Through the model's checks? | Flow |
|---|---|---|---|---|

Fix the history window once (default 12 months, or the whole history if
shorter) and record it in `meta.window` (`2025-10-15..2026-10-15`); the issue
and plan templates read it from there. The commands below take its start as
`<window start>` with a time of day, `2025-10-15T00:00`: a bare date counts
from the current time of day, so it would drop that day's earlier commits.
Check that the history is usable:

```
git rev-parse --short HEAD
git rev-parse --is-shallow-repository
git log --reverse --format='%h %cs' | head -1
git log --since=<window start> --oneline | wc -l
git log --since=<window start> --merges --oneline | wc -l
```

A shallow clone (`true`) holds less history than it shows, and its first
commit is only where the clone was cut: widening the window cannot help, so
treat it as missing history (`SKILL.md`, *Decide first*). In a full clone, a
first commit later than the window start means the repository is younger than
the window: use the whole history, from that commit, and record it in
`meta.window`. A history that is a single import commit, squashed per release,
or migrated without authorship makes every fix-commit claim
`Environment-dependent` or `Suspected`; say so in the chat's first line.

## 3. Schema source of truth, migration tool and deploy order

- **Schema source of truth**: the migrations directory, and the dump or
  declaration the repository treats as current (`db/schema.rb`,
  `structure.sql`, `schema.prisma`, `schema.sql`, Django models with their
  migrations, Alembic `versions/`). Note when the dump and the migrations
  disagree (`reference/perspectives.md`, BR2)
- **Migration tool and its settings**: whether each migration runs in a
  transaction, lock and statement timeouts, linters (`strong_migrations`,
  `squawk`), how online index builds are written
- **How migrations run in deploy**: the script, pipeline step or release hook
  that runs them, and whether it runs before, after or alongside the new
  code (`bin/deploy`, CI workflows, Helm hooks, `Procfile` release phase). A
  deploy order the repository does not show is `Environment-dependent`
- **Constraints by table**: for each core table, its keys, foreign keys,
  unique indexes, checks and nullability as the schema states them

## 4. Migrations and fixes in the window

- **Fix commits**: commits whose message or linked issue marks a fix
  (`git log --since=<window start> -i -E --grep='(^|[^[:alnum:]])((hot|bug)?fix(e[sd]|ing)?|bugs?)([^[:alnum:]]|$)' --no-merges --format='%h %s'`,
  whole words, so `prefix`, `debug` and `fixture` do not count, and no merge
  commit, whose subject names a `fix/` branch rather than a fix,
  adjusted to the repository's convention — conventional commits, issue
  labels). Append `-- <data paths>` (models, migrations, data access, jobs
  that write core tables) to keep the fixes that touched data code.
  `--grep` searches the whole message, so a commit can match on its body
  while `%s` shows only the subject: read each one (`git show -s <hash>`)
  before citing it. A fix that repaired rows (a data migration, a one-off
  script, an `UPDATE` in a migration) or changed a write path is the High
  evidence: data already went wrong there
- **Migrations changed in the window**: each migration file added, modified,
  renamed or deleted, with the commit that did it. `<migrations>` is the
  migrations directory as a pathspec, one per directory (`db/migrate`,
  `prisma/migrations`, `alembic/versions`):

  ```
  git log --since=<window start> --no-merges --format='@%h' --name-status -- <migrations> \
    | awk '/^@/ { h = substr($0, 2); next } NF { print h, $0 }'
  ```

  Each line is `<hash> <status>` and the path. `A` is a new migration to read
  for locking, rewrites and reversibility (`reference/perspectives.md`, ML,
  IR, DP, BF). `M`, `R` or `D` on a migration that was already merged means
  environments that ran the old version now hold another schema than a fresh
  one (BR2): read the diff (`git show <hash> -- <path>`) before citing it

## 5. Write-path churn

Churn per source file in the window, excluding generated, vendored and lock
files, and test files:

```
git log --since=<window start> --format= --name-only -- . \
  ':(exclude,glob)<generated>/**' ':(exclude,glob)**/*.lock' \
  ':(exclude,glob)**/package-lock.json' ':(exclude,glob)**/pnpm-lock.yaml' \
  ':(exclude,glob)**/go.sum' \
  ':(exclude,glob)**/*_test.go' ':(exclude,glob)**/*.test.*' \
  ':(exclude,glob)**/*.spec.*' ':(exclude,glob)**/*.test-d.*' \
  ':(exclude,glob)**/*.cy.*' ':(exclude,glob)**/test_*.py' \
  ':(exclude,glob)**/*_test.py' ':(exclude,glob)**/conftest.py' \
  ':(exclude,glob)**/test/**' ':(exclude,glob)**/tests/**' \
  ':(exclude,glob)**/__tests__/**' ':(exclude,glob)**/__mocks__/**' \
  | sort | uniq -c | sort -rn | head -50
```

`<generated>` is a glob for each generated or vendored directory, one
pathspec each (`**/dist`, `vendor`), and the pathspec is dropped when there is
none (an empty one makes git stop with `'/**' is outside repository`); a plain `':!dist'` misses
`packages/*/dist` in a monorepo. `*.lock` covers `yarn.lock`, `Cargo.lock`,
`poetry.lock`, `Gemfile.lock`, `composer.lock` and `uv.lock`. Adjust the test
patterns to the repository's own layout; `glob` keeps `*` inside one path
segment, so `test_utils/` is not mistaken for a test. Read the rows for the
writers in §2: a write path that changes often is where a new path that skips
the invariant appears.

Function-level churn, when a writer's file is large:
`n=$(git log --since=<window start> -s -L :<function>:<file> --format=%h) && printf '%s\n' "$n" | grep -c .`
(`-s` drops the diff, which would otherwise be counted line by line; git 2.22
or later honours it with `-L`). A `fatal: ... no match` prints no count: the
function was not measured, which is not zero commits. `:<function>` finds a
definition only where git knows the language or the line starts with a
letter, and takes the first such line naming it, so it misses indented
methods (JavaScript, TypeScript, Ruby without a diff driver) and can land on
an `import { name }` line, a Python docstring line or a longer name that
contains it (`merge` finds `_merge_records`). Anchor a top-level definition
with its own keyword instead (`-L ':^def <function>(:<file>'` in Python,
`-L ':^func <function>(:<file>'` in Go). For an indented one, give the range:
`-L <start>,<end>:<file>` (Python, which has no closing brace) or
`-L '/^<indent><function>(/,/^<indent>}/:<file>'`, where `<indent>` is the
definition's own indentation, so the range ends at its closing brace and not
at a nested block's.

## 6. Table size hints

Whether a migration blocks for a second or an hour depends on the table's
size, which a static review cannot measure. Use what the repository records:
capacity notes, runbooks, comments in migrations ("12M rows"), batch sizes in
existing backfills, partitioning, archival jobs, monitoring thresholds in
config. Record each with its source:

| Table | Size or growth | Source (`path:line`) |
|---|---|---|

A core table with no size hint is treated as large when it grows with use
(orders, events, ledger entries); say so in `limitations`, and keep the
finding's confidence `Environment-dependent` when its severity rests on size.

## 7. Recurring data rules

For each recurring concern, how most of the codebase does it, with the count:
keys and references, nullability, money and time types, how migrations build
indexes and add constraints, transaction placement, locking and idempotency,
deletion. This is the input to the data rule ledger
(`reference/conventions.md`).

## 8. Output of recon

In scratch: the core-table and writer table, the unit list in core-table
order, the schema and deploy notes, the fix commits that touched data code,
the migrations changed in the window, the churn rows for writers, the size
hints, the rule counts. End by deriving the data rule ledger.
