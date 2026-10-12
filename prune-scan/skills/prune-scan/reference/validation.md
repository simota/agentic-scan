# Validation

**Read when:** VERIFY — before any finding is merged with a verdict.

Removal is the risky direction: a wrong "unused" breaks production, while a
wrong "used" only leaves clutter. VERIFY therefore hunts for use before it
accepts non-use. Every finding answers four questions, each with evidence
(`path:line`, inventory key, unit or purpose item id, usage data the requester
supplied):

1. **Non-use or excess** — what shows the element earns nothing: no reference
   (which search, which inventory key), a dead branch, a flag value, a purpose
   item it contradicts, the scale it exceeds
2. **Dynamic use** — searched, not assumed. Check each pattern that applies and
   record what was checked in `validation.dynamic_checked`:
   - reflection and string-built names (`getattr`, `send`, `Class.forName`,
     `import()` / `require()` / `importlib` with computed names, `t(\`…${x}\`)`)
   - dependency-injection containers, plugin and entry-point registration
     (`entry_points`, `pyproject` scripts, service registries, decorators)
   - routes, jobs and handlers declared in config, YAML, annotations or by
     file location
   - templates, serialization and ORMs (fields read by name, `__all__`,
     JSON/GraphQL schemas)
   - cron, infrastructure and deployment files outside the code (Terraform,
     Helm, CI, Procfile, crontab)
3. **External use** — consumers the repository cannot show: public API
   clients, other services and repositories, mobile clients still running old
   versions, partners and webhooks, operators' scripts, data retention and legal
   duties (audit logs, personal data, financial records)
4. **Cost and loss** — what keeping it costs (the severity basis) and what
   removal would lose, in the subtraction (`loses`)

Then try to falsify it: search for the element's name in every form (snake,
camel, kebab, the URL path, the file name), in docs, CI and infrastructure
files, and for a "do not remove" note or an open issue that keeps it.

## Verdicts

| Verdict | When |
|---|---|
| `Valid` | All four answered with evidence; no dynamic or external use; the element does not earn its place. Only with confidence `Confirmed` |
| `Likely` | Non-use or excess shown in the repository, but external use, the purpose call or an unread part is not settled (`Externally-dependent`, `Purpose-dependent`, `Suspected`) |
| `Unverified` | A candidate not yet read in context. A working state only: `scripts/contract_check.py` rejects a record that still has one |
| `Unlikely` | Evidence points to use (a dynamic caller, a consumer, an intent note) or to a place it earns; kept, counted, never in the subtraction summary |
| `FalsePositive` | Not unneeded (the inventory missed a dynamic or framework use) — kept, excluded from counts |
| `NotApplicable` | Outside the agreed scope, or kept by a recorded decision (a documented deprecation window still open, a legal hold) — kept, excluded from counts |

## Confidence

| Confidence | When |
|---|---|
| `Confirmed` | No reference anywhere, dynamic patterns checked, and nothing outside the repository can reach it (or usage data the requester supplied shows none); for PX and OB, the purpose item is `documented` or `stated` |
| `Externally-dependent` | Unused inside the repository, but something outside could use it: a public API, another service, an old mobile version, ops tooling, data duties. Name what would settle it (logs, a consumer list, a retention policy) |
| `Purpose-dependent` | The finding rests on an `inferred` purpose item; a human decides keep or remove. The finding id goes in a `decisions` line |
| `Suspected` | It rests on something not read: generated code, a library's internals, configuration not in the repository |

`Valid` needs `Confirmed`: `Externally-dependent`, `Purpose-dependent` and
`Suspected` findings are at most `Likely` (`findings.py` refuses `Valid` with
them). A finding citing an `inferred` purpose item must be `Purpose-dependent`
(`findings.py` refuses any other confidence), so it always lands in `decisions`.
`render.py` uses the same rule: an open `Valid` finding is "remove now" or
"reduce or consolidate"; every other open, counted finding is "decide with a
human".
