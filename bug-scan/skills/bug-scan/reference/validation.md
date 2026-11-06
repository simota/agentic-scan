# Validation: settling each record

**Read when:** VERIFY.

Every record gets `validation`: `{verdict, method, evidence}`.

| Verdict | Meaning |
|---|---|
| `Valid` | Traced end to end at `path:line` |
| `Likely` | Traced, but depends on a condition stated in `conditions` |
| `Unverified` | Not traced. Allowed only below Medium |
| `Unlikely` | A mitigation probably stops it |
| `FalsePositive` | Disproved; the evidence names what disproves it. The record stays |
| `NotApplicable` | Out of scope or a duplicate. The record stays |

`method` is `static` for reading, or `analysed` when a read-only tool was used and named.

## Try to break each record

- **The entry**: can a caller actually reach it? Is it behind a flag, role or validator?
- **The guard**: a middleware, schema, constraint or caller that already stops it
- **The test**: an existing test that pins the behaviour, which may mean it is intended
- **The sibling**: was this already fixed elsewhere, and does this path share that fix?

## Try to break each `Traced` origin

Read the fix and the origin again and ask whether the origin wrote the defect or only sat beside it. A fix
that only adds handling usually means an omission: change it to `Unattributable` rather than keep a
convincing story. When two origins are plausible and you cannot choose, record `Blamed`.

## Confidence

`Confirmed` follows from the code. `Environment-dependent` needs a named runtime condition. `Suspected` was
not fully traced. Confidence never raises or lowers severity; each further condition the code does not
control lowers severity one level.

## What static reading cannot show

Record these in `limitations` when they matter: delivery semantics, instance counts, real frequency, data
actually present, dynamic routes, server-side repository rules, and anything outside the repository.
