# Perspectives — reviewing from more than one angle

**Read when:** CHECKLIST, to choose which perspectives apply; REVIEW, after the
commitments hunt (`reference/commitments.md`), as the coverage sweep; REPORT,
to fill the `perspectives` table in `findings.json`. **Reader:** the agent
running the skill.

The commitments ledger finds what this app's own promises forbid. The
perspectives then make sure nothing outside the ledger is skipped: apply each
one within every review unit (`SKILL.md`, *Run contract*), work through its
hunt steps below, and record every perspective in the report — including the
ones that found nothing and the ones not run. The names below are the exact
values of `perspectives[].name` and `findings[].category`.

| Perspective | The question it asks |
|---|---|
| Data inventory and minimisation | Is each personal element collected for a purpose and used for it? |
| Purpose and consent | Does processing that needs consent wait for it, and stop when it is withdrawn? |
| Retention and deletion | Is each element removed from every store when its period ends or the subject leaves? |
| Data subject rights | Do access, export, rectification and deletion reach every store and processor? |
| Third-party sharing | Does personal data reach only the parties and fields the commitments name? |
| Logs, telemetry and errors | Is personal data kept out of logs, traces, error reports and analytics events? |
| Exposure to other actors | Do other users, tenants, staff and public links see only what they need? |
| Storage protection | Are sensitive categories encrypted, tokenised or pseudonymised where required? |
| Client-side tracking | Do cookies, storage and third-party scripts in the client respect consent? |
| Identifiers and pseudonymisation | Are identifiers kept out of URLs and shared datasets, and is "anonymised" data really unlinkable? |
| Non-production and derived copies | Is real personal data kept out of seeds, fixtures, staging, training sets and warehouses without controls? |
| Location and transfers | Do storage and processing locations match what the commitments state? |

Rules:

- A perspective not applicable to this application is recorded as `N/A` with a
  reason (e.g. `Client-side tracking: N/A — backend service, no client in the repo`)
- A perspective that could not be checked statically is recorded as `not
  checked` with what would be needed
- Every finding names the perspective that surfaced it in `category`
- A hunt step covered by a commitments ledger entry cites it (`C-…`) in the
  perspective's `note` instead of being re-run
- The `note` lists the hunt step IDs applied and each one left out with its
  reason
- A step is `sound` only when its *Sound when* cell can be filled with the
  control's `path:line` on the flow. "The vendor is compliant" is not evidence

## Hunt steps per perspective

Each step says **what** to hunt, **where** to look, and what evidence makes it
**sound** — with the reason. Vendor and framework names are examples only.
Steps marked *(sound constructs)* have a table at the end of this file. The
ledger family (`reference/commitments.md` §2) that usually covers a
perspective is in brackets.

### Data inventory and minimisation (MN) [MIN]

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| MN1 | Fields collected and never used, or used only for a purpose the commitments do not state | Data map (`reference/recon.md` §2) vs readers of each field | Each field has a reader serving a stated purpose — because data never collected cannot leak |
| MN2 | Over-broad collection: full date of birth for an age check, precise location where city suffices, contact book upload, device permissions requested up front | Forms, mobile permission requests, SDK auto-collection settings | The narrowest form the purpose needs, requested when needed — because precision is risk |
| MN3 | Free-text fields and uploads that invite sensitive data without handling it as such | Free-text and upload fields | Treated as personal (retention, access, logging) — because users write anything into them |

### Purpose and consent (PC) [CONSENT]

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| PC1 | *(sound constructs)* Processing for consent-based purposes (analytics, ads, marketing email, personalisation) without checking a recorded consent first | Call sites of analytics and marketing code; consent store readers | A consent check at `path:line` gates each call — because a gate on one path does not cover its siblings |
| PC2 | Withdrawal not honoured: opt-out not propagated to processors, cached consent, jobs that re-enable | Preference update handlers, sync jobs, cached flags | Withdrawal updates every consumer and processor — because consent that cannot be withdrawn is not consent |
| PC3 | Purpose creep: data collected for one purpose read by code serving another (support data in marketing, security logs in analytics) | Readers of each element across modules | Each reader's purpose is a stated purpose for that element — because purpose limits travel with the data |
| PC4 | Children and age: no age gate where the commitments require one, or children's data processed like adults' | Signup flows, age fields | An age check and a separate handling path — because the rules differ |

### Retention and deletion (RD) [RETAIN]

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| RD1 | *(sound constructs)* No retention for an element the commitments give a period for; jobs that exist but skip stores | Retention jobs and TTLs vs the data map's stores | A job or TTL per store at `path:line` — because a period kept in one store and not another is not kept |
| RD2 | *(sound constructs)* Account deletion that leaves data: soft delete only, related tables not cascaded, files, caches, search indexes, analytics, queues, third parties not reached | Deletion handlers and cascades vs the data map | Every store holding the element is reached or anonymised, at `path:line` — because one forgotten store keeps the subject identifiable |
| RD3 | Backups and logs outliving stated periods | Backup and log retention config | Retention configured within the stated period, or the commitment names the exception — because backups are stores too |

### Data subject rights (DR) [RIGHTS]

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| DR1 | Export or access that reads only some stores | Export handlers vs the data map | Every store holding the subject's data is read — because an incomplete export misstates what is held |
| DR2 | Rectification that leaves stale copies (search index, cache, warehouse, third parties) | Profile update handlers and sync jobs | Updates propagate to every copy — because the stale copy is what others see |
| DR3 | Rights requests not forwarded to processors that hold the data | Third-party deletion and update API calls | A call per processor listed in the data map — because the processor still holds it |
| DR4 | Identity of the requester not verified before export or deletion | Rights request handlers | The same authentication as account access — because an export to the wrong person is a breach |

### Third-party sharing (TP) [SHARE]

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| TP1 | *(sound constructs)* Payloads sent to third parties carrying more fields than needed or than disclosed (whole user objects, free text, identifiers) | Outbound API clients, SDK calls, webhooks, LLM/AI API prompts | An explicit field allow-list per payload at `path:line` — because a whole object sends every field added later |
| TP2 | Third parties absent from the sub-processor list or policy | Manifests, SDK initialisation, outbound hosts vs the commitments | Every recipient is listed — because an undisclosed recipient breaks the promise regardless of payload |
| TP3 | SDK auto-collection: session replay, automatic form capture, IP and device collection left on | SDK init options | Auto-collection off or masked for personal fields at `path:line` — because SDK defaults collect broadly |
| TP4 | Customer-configured webhooks or integrations sending other subjects' data | Integration and webhook code | Payload scoped to what the receiving customer may see — because the integration widens the audience |

### Logs, telemetry and errors (LT) [CONTAIN]

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| LT1 | *(sound constructs)* Personal fields in log calls, request logging of bodies, headers or query strings | Log calls near personal fields; HTTP logging middleware | A redaction filter or field allow-list on the logger at `path:line` — because logs are copied, shipped and kept longer than data |
| LT2 | *(sound constructs)* Error trackers capturing request bodies, user objects, local variables or breadcrumbs with personal data | Error tracker init and `beforeSend`-style hooks | Scrubbing configured for the personal fields — because error context is sent to a third party |
| LT3 | Analytics events and APM attributes carrying personal data (emails, names, free text, precise location) | Event tracking calls, span attributes | Events carry pseudonymous IDs and non-personal properties — because event stores are broad and long-lived |
| LT4 | Personal data in URLs (emails, names, tokens in paths or query strings) | Route definitions, link builders, redirects | Personal values in bodies, not URLs — because URLs reach logs, referrers and browser history |

### Exposure to other actors (EX) [CONTAIN]

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| EX1 | Responses and views showing other users' personal fields beyond need (full email, phone, address in lists, member directories, comments) | Serializers and templates for multi-user views | An explicit output shape per audience, masked where full values are not needed — because every viewer is a recipient |
| EX2 | Staff and support tools: unrestricted search, unmasked sensitive fields, impersonation without audit | Admin panels, support tools | Role-scoped access, masking and an audit log at `path:line` — because insiders are recipients too |
| EX3 | Public or shareable links exposing personal data, guessable IDs on public routes | Share-link and public routes | Unguessable tokens, expiry and minimal content — because a link travels |

### Storage protection (SP) [PROTECT]

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| SP1 | Sensitive categories stored in plain text where commitments or the named regulation require encryption or tokenisation | Models for sensitive fields; encryption helpers; IaC | Encryption or tokenisation at `path:line` protects the data and access path named by the commitment; trace database reads and logical exports separately from storage encryption — because encryption layers protect different access paths |
| SP2 | Keys and access: one key for everything, keys next to data, broad database credentials | Key management config | Separate keys per purpose, managed outside the database — because the key decides who can read |

Accept storage encryption when the commitment requires protection of data at
rest. Where it also requires protection from database readers or plaintext
logical exports, trace those paths and their controls. For example,
[Azure SQL TDE](https://learn.microsoft.com/en-us/azure/azure-sql/database/transparent-data-encryption-tde-overview?view=azuresql)
decrypts pages for reads and does not encrypt the contents of a BACPAC export.

### Client-side tracking (CT) [CONSENT]

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| CT1 | *(sound constructs)* Third-party scripts, pixels and SDKs loaded or initialised before consent | HTML templates, tag manager setup, app bootstrap | Loaded only after the matching consent category is granted — because loading is already sharing |
| CT2 | Cookies and local storage set for non-essential purposes before consent; long expiries | Cookie setters, storage writes | Non-essential storage gated on consent with stated expiries — because the commitments name them |
| CT3 | Personal data kept in client storage (local storage, IndexedDB, mobile preferences) unencrypted or after logout | Client storage writes; logout handlers | Minimal client storage cleared on logout — because shared devices are common |

### Identifiers and pseudonymisation (ID)

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| ID1 | "Anonymised" data that is pseudonymous: hashed emails or phones, stable IDs, quasi-identifiers (postcode, birth date, gender) kept together | Anonymisation code, exports for analytics or partners | The claimed loss of linkability is supported for each recipient after checking identifiers, quasi-identifiers, available keys, mappings and candidate identities; otherwise `UNKNOWN` — because keyed or rotated pseudonyms can still be matched to a subject |
| ID2 | Emails or government IDs used as primary keys or join keys across systems | Schemas and integration payloads | Internal opaque IDs, personal values kept as attributes — because a key spreads to every table and system |

Treat keyed, rotated identifiers as pseudonymisation unless the claimed loss
of linkability is separately supported. A holder of a retained key and
candidate emails can recompute `HMAC(key, email)` and match exported rows
within that key's period. Generalising quasi-identifiers does not remove that
match. [HMAC-based pseudonymisation](https://docs.cloud.google.com/sensitive-data-protection/docs/pseudonymization)
preserves record relationships for the same key; assess each recipient's
available information and leave unobserved linkability controls `UNKNOWN`.

### Non-production and derived copies (NP) [CONTAIN]

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| NP1 | Real personal data in seeds, fixtures, snapshots, test data or documentation (report location and kind only) | Seed and fixture files, test snapshots, docs | Synthetic data — because the repository is copied to every developer and CI |
| NP2 | Production-to-staging refresh or debug dumps without masking | Scripts and jobs copying databases | A masking step on every personal field at `path:line` — because staging has weaker controls |
| NP3 | Personal data loaded into warehouses, ML training sets or LLM prompts without the controls of the source | Pipelines, training scripts, prompt builders | Minimised, pseudonymised and covered by retention and deletion — because a derived copy escapes deletion |

### Location and transfers (LO)

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| LO1 | Stores and processors in regions the commitments do not state | IaC regions, storage and queue config, third-party endpoints | Regions match the stated locations; others are `UNKNOWN` — because the repository shows intent, not the deployed state |
| LO2 | Data residency features per tenant configured but not applied on every store | Tenant region settings vs storage selection code | Every store honours the tenant region — because one shared store breaks residency |

## Sound constructs

A cell is `sound` only for a construct in the *Sound* column, cited at
`path:line` on the flow; an *Unsound* construct is a candidate even when it
looks like a control. Every named API is a labelled example (`e.g.`), not a
list to grep for: find this stack's equivalent and confirm its configuration.

| Step | Sound (labelled examples) | Unsound look-alike (labelled examples) | Why |
|---|---|---|---|
| PC1 | A consent check before each consent-based call, reading the stored consent for that purpose (e.g. a `hasConsent("analytics")` guard around `track()`; a consent manager that blocks SDK calls by category) | Consent checked once at signup and never again; a banner that records a choice nobody reads; a check in the UI while the server sends events regardless | Each processing call must wait for the current consent |
| RD1 | A scheduled job or store-level TTL per store, with the period from config matching the commitment (e.g. a database TTL index, an object storage lifecycle rule in IaC, a cron job deleting by `created_at`) | A retention period in the policy with no job; a job that covers the main table only; a TTL on a cache while the source table keeps everything | A period kept in one store is not kept |
| RD2 | A deletion path that walks the data map: cascades or explicit deletes per table, file deletion, cache and search index purge, warehouse deletion, processor deletion API calls; anonymisation where deletion is impossible | `user.is_active = False` only; deleting the user row while orders, messages and files keep the name and email; "deletion" that leaves the search index | The remaining store keeps the subject identifiable |
| TP1 | Payloads built from an explicit field list (e.g. a dedicated DTO for the provider; `pick(user, ["id","plan"])`); prompts built from selected fields with personal values removed | Sending the whole ORM object or request body (e.g. `json=user.__dict__`, `JSON.stringify(user)`); free text sent to an AI API without minimisation | Every field added later is sent too |
| LT1 | A logger-level filter or formatter that redacts named fields and patterns (e.g. Python `logging.Filter`, `structlog` processors, pino `redact` paths, Logback masking); request logging without bodies | Redaction at some call sites only; `logger.info(f"user {user}")` with a `__repr__` that prints email; request body logging in production config | One unredacted path writes the data to every log destination |
| LT2 | Error tracker options with request-body and PII collection off and a scrubbing hook (e.g. Sentry `send_default_pii=False` with `before_send` removing personal fields; data scrubbing rules configured in the repo) | Default options with user context set from the full user object; local variables capture on; breadcrumbs recording form inputs | Error context is shipped to a third party |
| CT1 | Scripts injected only after consent for their category (e.g. a consent manager gating tags; dynamic `import()` after `consent.granted`); server-side tagging that strips identifiers | Tags hard-coded in the HTML head; a consent banner rendered after the analytics script already ran; `defer` mistaken for gating | Loading the script already shares data |
