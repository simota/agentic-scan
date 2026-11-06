# Surfaces: screens, APIs, jobs, tables, services, settings

**Read when:** CATALOG; REVIEW, when a record cites a surface.

`surfaces.py scan` proposes candidates from conventions. Everything it writes is `inferred`:

| Kind | ID | Found through |
|---|---|---|
| `screen` | `SC-*` | File routes (`app/**/page.*`, `pages/**`, `routes/**/+page.svelte`), `<Route path=…>` |
| `api` | `API-*` | Flask and FastAPI decorators, Express-style `app.get`, Django `path()` |
| `job` | `JOB-*` | Celery tasks, `new Worker(…)`, `ActiveJob`, `cron.schedule` |
| `db` | `DB-*` | `CREATE TABLE`, `create_table`, `__tablename__`, Prisma `model`, Django `Model` |
| `ext` | `EXT-*` | Hosts in absolute URLs |
| `cfg` | `CFG-*` | `os.environ`, `os.getenv`, `process.env` |

It stores names and locations, never source text. Links are proposed when a file defining one surface
names another. **A proposal is not a trace.**

## Confirm what the records cite

Read the path a record depends on, then send a fragment:

```json
{"surfaces": [{"id": "API-09", "kind": "api", "name": "POST /refunds", "location": "api/refunds.py:20", "basis": "traced"}],
 "links": [{"from": "SC-03", "to": "API-09", "basis": "traced"}],
 "remove_links": [["SC-03", "API-02"]]}
```

```
python3 scripts/surfaces.py merge <out>/surfaces.json <fragment>
```

| `basis` | Meaning |
|---|---|
| `traced` | Read on the path |
| `inferred` | Proposed by the script, not read |
| `UNKNOWN` | Should exist but cannot be read statically (string-built routes, dynamic dispatch) |

Only `traced` links are drawn solid in D8. Say in `limitations` where dynamic routing makes the map
incomplete. Do not try to confirm every surface; confirm what the records cite.
