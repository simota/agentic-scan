# Inventory

**Read when:** RECON (first run, no units) and after UNITS (`--units`), and when
deciding inventory candidates in REVIEW.

```sh
python3 <skill-dir>/scripts/inventory.py <repo> --out <out>/inventory.json [--units <units.json>] [--today YYYY-MM-DD]
```

Paths in this file are relative to the skill's directory, not the reviewed
repository (SKILL.md *Paths*).

Standard library only, read-only. It walks the files under `<repo>` (skipping
VCS, dependency and build directories such as `node_modules`, `vendor`,
`build`, `dist`, `.git`, `venv` — `env` only when it holds a virtualenv or
conda environment (`pyvenv.cfg`, `bin/activate`, `conda-meta/`), so a source
directory such as `src/env/` is read; symlinks; lockfiles; minified bundles; binaries other
than assets; files over 2 MB; and secret-looking files such as `.env` — only
`.env.example`, `.env.sample`, `.env.template` and `.env.dist` are read, and
only their variable names are recorded) and lists **candidates** — never
findings. Every row carries a `path:line` location or a path.

Secret-looking directory names are excluded too, as are credential files such
as `.htpasswd`, `.pgpass`, `.docker/config.json` (and its backups), everything under `.kube/`, `*.tfstate`
and `*.kdbx`. Source code whose file or directory name only contains
`credentials`, `secret` or `kubeconfig` (`useCredentials.ts`,
`client_secret.py`) is read for its imports and identifiers, so what it uses
is not reported unused, but none of its literal text reaches the output: no
`text` excerpts, flag names, routes or dynamic key and class prefixes (its flag
checks and prefixes still keep what they name from being listed; an env var it
alone reads is not promoted to a flag). Like any source, the names of env vars
it reads appear in `env_read`, never their values. Data files
with such names (`credentials.json`, `secrets.yaml`) are skipped.

On POSIX, files are opened
relative to pinned directory descriptors without following symlinks; a file or
directory replaced during the scan cannot redirect a read through a link.
The 2 MB limit is enforced on the opened file and on the read itself.
A leading UTF-8 byte order mark is dropped before parsing.
Files whose names cannot be represented as UTF-8 are skipped and counted in
`files_skipped`, so an unusual filesystem name cannot break the JSON output.
`--out` must lie outside the scanned repository (an alias counts as inside;
exit status 2, nothing written) and cannot overwrite the source supplied
through `--units`. On runtimes
with descriptor-relative output operations, the selected output directory stays
pinned from the input check through temporary-file creation and replacement;
renaming it or replacing its path cannot redirect the write. Existing output
symlinks are replaced as directory entries without changing their targets.
An existing regular output file that shares the units input's identity is
rejected, including another hard link to that input.
`--units` requires this output protection and is rejected without writing when
the runtime cannot provide it. An inventory without `--units` still works on
those runtimes, using atomic pathname-based replacement, which cannot protect
against concurrent replacement of the output parent.

The optional `text` excerpts in `markers` and `skipped_tests` use the same
source-level secret-name and private-key checks as report excerpts. If a
source looks sensitive anywhere, these fields contain
`[omitted: source may contain secrets]`; the candidate, location, counts and
date remain available. This avoids guessing where a continued secret
expression ends. Ordinary source excerpts are preserved.

References are counted **by name**: an identifier anywhere in code or config,
string contents included (a name built from a string still counts as a use), and
a file counts as referenced when its file name appears in another file. That
makes the lists conservative: a candidate is something nothing names, not
something proven unused.

When the running Python version can parse a file, its syntax tree distinguishes
real top-level definitions from docstring examples and recognizes decorators
that span multiple lines. The same tree records imports in one-line suites,
after semicolons and across explicit line continuations, including imports in
tests; import examples inside strings or comments do not create module
references. Unsupported syntax and parser-complexity errors retain the
best-effort text scan.
TypeScript imports that name emitted `.js`, `.mjs` or `.cjs` files also
resolve to the corresponding source extensions, including `.mts` and `.cts`.
Extensionless imports conservatively consider all supported JavaScript/TypeScript
source extensions, including `.mts` and `.cts`, both as files and as directory
`index` files, for runtimes and bundlers that support them. When several candidate
files exist, all are recorded as references because the runtime's extension order
can differ. Dotted names such as `helper.client` can still be extensionless source
imports. Known source extensions retain their source-substitution order; an import
naming an existing file with another suffix keeps its direct match. This inventory
heuristic does not imply that the TypeScript compiler accepts those extensionless
paths.

Non-relative imports also resolve through `compilerOptions.paths` and
`baseUrl` of the nearest enclosing `tsconfig*.json` or `jsconfig.json`
(comments and trailing commas allowed, relative `extends` followed); a config
without aliases still keeps an ancestor's from applying. Without a matching
rule, `@/`, `~/` and `#/` imports (bundler aliases) resolve against each
enclosing directory and its `src/`, up to the governing config's directory. CSS `@import`, `@use` and
`@forward` of a package count as imports of that package. Absolute Python
imports resolve against the repository root, `src/` and every directory that
encloses the importing file, so `backend/app/main.py` importing `app.models`
reaches `backend/app/models.py`; `python -m server.jobs.nightly` names
`server/jobs/nightly.py` (or a package's `__main__.py`). A quoted dotted module path
(`"mysite.urls"`, `"polls.apps.PollsConfig"`, `"pkg.mod:app"`) and an unquoted
`pkg.mod:app` (gunicorn, uvicorn) name each package on that path and each module
inside a package (a lone first part such as `api` in `"api.example.com"` names
only a package), so
modules Django or a server loads by name are not orphans (a test that patches
`"pkg.mod.fn"` keeps nothing in use); a name ending in a
file extension (`"config.json"`) is a file name, not a module. Dotted imports also match namespace
distributions such as `azure-storage-blob` and `ruamel.yaml`; `// indirect`
requirements in `go.mod` are not listed.

JavaScript import signals include quoted binding names, Flow
[`import typeof`](https://flow.org/en/docs/types/modules/) declarations and inline
`typeof` specifiers, and static or dynamic
[source-phase imports](https://nodejs.org/api/esm.html#wasm-source-phase-imports).
The scan also retains literal `import.defer(...)` references from the
[deferred-import draft](https://tc39.es/proposal-defer-import-eval/), alongside
deferred namespace imports. Recognizing draft syntax does not imply runtime
support. `source` and `defer` still work as ordinary binding names; these are
conservative reference signals rather than full JavaScript syntax validation.
Literal module names are decoded before resolving files or packages, so
hexadecimal and Unicode escapes, escaped quotes and line continuations retain
their actual references. Escaped UTF-16 surrogate pairs resolve to the matching
Unicode name; malformed escapes, lone surrogate halves and NUL names do not
create invalid output. Quoted binding names remain separate from module names.

Dependency overlap groups and platform replacements are specific to the
manifest's ecosystem; an identically named package in another ecosystem does
not inherit its replacement suggestion.

| Key | What it collects | Perspective |
|---|---|---|
| `unreferenced_symbols` | Top-level functions, classes and module constants (Python), named exports, top-level functions and top-level `const`/`let` (JS/TS, with `exported`; default exports are judged by file, in `orphan_files`), top-level functions and types (Go; methods satisfy interfaces and are not listed), items (Rust) whose name appears nowhere but their definition; decorated definitions (route handlers, registered hooks) are skipped and counted in `decorated_symbols_skipped`; test files are skipped | DC1 |
| `orphan_files` | Python and JS/TS source files that no other non-test file imports and whose file name no other file mentions; `test_importers` lists tests that still import them; entry-like names (`main`, `index`, `app`, `__init__`, `setup`, `manage`, `cli`…) `*.config.*` and `*.d.ts` are skipped | DC2, TT1 |
| `dependencies_declared` | Declared dependency count per manifest (`package.json`, `requirements*.txt`, `pyproject.toml`, `go.mod`, `Cargo.toml`, including `[dependencies.NAME]` tables); Python import names compare case-insensitively (`PyQt5`) | DP1 |
| `unimported_dependencies` | Declared packages no source file imports; `status` is `script_only` when a package script or tool file names it, else `unreferenced`; `implicit_tool` marks toolchain packages used without an import (typescript, eslint, `@types/*`, ruff…) | DP1 |
| `duplicate_purpose` | Two or more packages from one purpose group in a manifest (date libraries, HTTP clients, utility belts, test runners, JSON libraries…) | DP2 |
| `platform_replaceable` | Packages the platform or standard library now covers (`node-fetch`, `uuid`, `six`, `mock`, `simplejson`, `pytz`…), with the replacement | DP3 |
| `env_read`, `env_declared_not_read`, `env_read_not_declared` | Environment variables read in code (process.env, including `const { PORT } = process.env`, os.environ/getenv, including `from os import getenv, environ`, import.meta.env, os.Getenv, env::var…) against those declared in the example env files; `env_read_not_declared` is empty when no example file exists (`env_declaration_files`) | CF1, CF2, OB1 |
| `feature_flags` | Flags defined in flag files (`flags.*`, `features.*`, `toggles.*`, `experiments.*`), as keys or as `export const NAME = true` constants, with their literal value (`true`, `false`, `mixed`), plus every name checked through `isEnabled("…")`, `useFlag("…")`, `variation("…")` and similar calls, plus `FEATURE_*`/`ENABLE_*` env vars; `checks` counts call sites | FF1, FF3 |
| `i18n_unreferenced`, `i18n_dynamic_prefixes` | Keys of JSON locale bundles that no string literal names (an i18next namespace prefix such as `common:` is ignored), except keys under a prefix built in a template literal (`` t(`status.${x}`) ``) | AS3 |
| `assets_unreferenced` | Images, fonts, media and PDFs whose file name (`logo@2x.png` included) no other file mentions; `public` marks files served by URL, which outside pages can still link | AS1 |
| `css_unreferenced`, `css_dynamic_prefixes` | Class selectors in CSS/SCSS/Less (outside attribute selectors and strings) that no non-CSS file names, except classes under a prefix built from a string (`` `btn-${variant}` ``); CSS modules are skipped | AS2 |
| `routes`, `unreferenced_routes` | Server routes (Flask/FastAPI decorators, Express-style `app.get`, Django `path`) and client routes (`<Route path>`, `path: "/…"`) with how many other files name the path (parameters match any segment or `${…}`; a trailing slash on either side is the same route, `/items/${id}` and `"/items/" + id` are not; a host before the path, and for server routes a mount prefix such as `/api` before `/items`, still count; route path literals in definitions do not); `unreferenced_routes` are those no other file names. `api.get("/…")` where `api` is assigned from axios, ky or ofetch is a client call, not a route | UF1, UF2, UF3, AP1 |
| `scripts`, `uninvoked_scripts` | Makefile targets (every target of a rule such as `clean distclean:`; `define` bodies, directive lines such as `export CC ::= gcc` and `::=` assignments are not rules) and `package.json` scripts with how often `make <target>` or `npm\|pnpm\|yarn\|bun [run] <script>` appears anywhere (CI, docs, other targets), on one command line where only options and their values (`-C dir`, `--directory dir`, `-j 4`, `--prefix web`), variables and other targets of the same Makefile or the files it includes (or that include it) may come between; a target in another rule's prerequisite list in that set of files (`all: build`) counts as invoked; `-C dir` or `-f file` naming a known Makefile (from the repository root or the mentioning file's directory) limits a command to that project; a package manager command counts only the script it runs (after `run`/`run-script` or `workspace NAME`, past options such as `--prefix web`), not option values; each `make` or package manager invocation counts a name once and is read up to 64 tokens; the first Make target and npm lifecycle scripts are marked `default` and not listed as uninvoked | TT3, TT4 |
| `unreferenced_files` | Shell scripts, SQL files and docs under `scripts/`, `bin/`, `tools/`, `docs/`, `db/`, `seeds/`, `fixtures/` whose file name no other file mentions (migrations and root docs such as README are skipped) | TT4, DA3, AS4 |
| `skipped_tests` | `@pytest.mark.skip`, `@unittest.skip`, `it.skip`, `xit`, `describe.skip`, `test.todo`, `#[ignore]`, `t.Skip`, `@Disabled` in test files | TT2 |
| `commented_code` | Runs of four or more comment lines of which at least 60 % look like code, in each language's own line-comment syntax (`#` for Python, Ruby, shell, YAML and TOML; `//` for JS/TS, Go, Rust, JVM, Swift, C# and SCSS/Less; both for PHP; `--` and MySQL's `#` for SQL), so Rust attributes, JS private fields and CSS id selectors are not comments | DC3 |
| `markers` | Lines with `deprecated`, `sunset` or `remove after/by/once/when/in`, and TODO/FIXME/HACK/`temporary`/`until`/`ended` lines that carry a date; `date` and `overdue` (the date is before `--today`, default today) | FF2, DU3, AP2 |
| `sql_tables_unreferenced`, `sql_columns_unreferenced` | Tables in `CREATE TABLE` statements that no non-SQL file names, and columns of the other tables that no non-SQL file names (SQL comments are ignored; a schema prefix such as `public.` is dropped, names compare case-insensitively, and a body ends at its balancing parenthesis, so table options such as MySQL's `ENGINE=InnoDB` and nested types or checks do not end it early; strings take `''` and backslash escapes and end at their line, a `'` inside a quoted identifier (`"it's"`) starts no string, and once a body never balances the rest of that file ends bodies at the first `)` followed by table options and `;`, so quoting the scan misreads costs at most one line or one table) | DA1 |

With `--units`, every row with a path also gets `unit` (the unit whose paths
cover it; the most specific prefix wins; env var and flag rows use their first
definition or location), and `by_unit` counts the candidates per unit. The
complete listings `routes`, `scripts`, `env_read` and `dependencies_declared`
are tagged but not counted; their candidates are counted in
`unreferenced_routes`, `uninvoked_scripts`, the `env_*` lists and
`unimported_dependencies`. Prefixes normalize `.` components and repeated separators before
matching, so `./server/` and `server/` cover the same files.

## Caps

Every list is measured in full first; then each list keeps at most 200 rows
and each row at most 5 locations. `limits` states the caps; `truncated` names
each list that was cut and how many rows were left out (empty when nothing was
cut) — when it is not empty, say so in `limitations` or search for the rest.

Locale key locations use a per-file index of decoded JSON keys. Escaped key
names retain their source lines; repeated leaf names use their first matching
key, as before. File-name tokens, CSS selectors and comments, and SQL table
blocks are scanned without repeatedly searching the same unfinished suffix.

## Limits

Name-based counting misses uses that never spell the name: reflection over
computed names, dependency-injection containers configured by type, framework
conventions (a file picked up by its location), serialization, templates in
another repository, cron and infrastructure outside it, and every consumer that
is not in the repository. It also counts a mention in a comment as a use.
Database contents, deployed configuration, flag-service values and traffic are
not seen. Languages beyond Python, JS/TS, Go and Rust get only the
language-neutral lists. A candidate count is a lead, not a measurement; VERIFY
settles each one (`reference/validation.md`).
