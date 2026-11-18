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
| Identifiers and pseudonymisation | Are identifiers kept out of shared datasets, and is "anonymised" data really unlinkable? (Identifiers in URLs are LT4.) |
| Non-production and derived copies | Is real personal data kept out of seeds, fixtures, staging, training sets and warehouses without controls? |
| Location and transfers | Do storage and processing locations match what the commitments state? |

Rules:

- A perspective not applicable to this application is recorded as `N/A` with a
  reason (e.g. `Client-side tracking: N/A — backend service, no client in the repo`)
- A perspective that could not be checked statically is recorded as `not
  checked` with what would be needed
- A perspective whose hunt steps were only partly reached (effort ran out, one
  store was unreadable) is recorded as `partly applied`; the note names the
  steps not reached
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
| MN2 | *(sound constructs)* Over-broad collection: full date of birth for an age check, precise location where city suffices, contact book upload, device permissions requested up front | Forms, mobile permission requests, SDK auto-collection settings; location precision, background-location permission and sampling interval | The narrowest form the purpose needs, requested when needed — because precision is risk |
| MN3 | Free-text fields and uploads that invite sensitive data without handling it as such | Free-text and upload fields | Treated as personal (retention, access, logging) — because users write anything into them |
| MN4 | Sensitive categories inferred from other data (health or pregnancy from purchases, orientation or religion from behaviour, age from content; scoring and profiling) | ML features, segmentation and scoring code, ad audiences | Inferred attributes are not derived, or are handled as the sensitive category they reveal — because inference creates the data |

### Purpose and consent (PC) [CONSENT, INSTRUCT]

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| PC1 | *(sound constructs)* Processing for consent-based purposes (analytics, ads, marketing email, personalisation) without checking a recorded consent first | Call sites of analytics and marketing code; consent store readers | A consent check at `path:line` gates each call — because a gate on one path does not cover its siblings |
| PC2 | *(sound constructs)* Withdrawal not honoured: opt-out not propagated to processors, cached consent, jobs that re-enable | Preference update handlers, sync jobs, cached flags | Withdrawal updates every consumer and processor — because consent that cannot be withdrawn is not consent |
| PC3 | Purpose creep: data collected for one purpose read by code serving another (support data in marketing, security logs in analytics) | Readers of each element across modules | Each reader's purpose is a stated purpose for that element — because purpose limits travel with the data |
| PC4 | *(sound constructs)* Children and age: no age gate where the commitments require one; a child's data collected or stored before verifiable parental consent completes (signup, location, profile); unconsented or declined signups never purged; SDKs in a child's session not tagged child-directed (ads, analytics, ad identifiers) | Signup and consent flows, age fields, SDK initialisation per account type | An age check, collection only after consent, purge of unconsented records, and child-directed SDK settings at `path:line` — because the rules for children differ and consent must come first |

### Retention and deletion (RD) [RETAIN]

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| RD1 | *(sound constructs)* No retention for an element the commitments give a period for; jobs that exist but skip stores (a job that purges a derived cache while the raw table, such as location points, keeps everything) | Retention jobs and TTLs vs the data map's stores | A job or TTL per store at `path:line`; deleting by day or month bucket, so data may outlive the period by at most one bucket, is sound — because a period kept in one store and not another is not kept |
| RD2 | *(sound constructs)* Account deletion that leaves data: soft delete only, related tables not cascaded, files, caches, search indexes, vector stores and embeddings, warehouse copies, analytics, queues, third parties not reached; a bulk delete that skips per-object delete hooks (e.g. a queryset delete that never removes stored files) | Deletion handlers and cascades vs the data map | Every store holding the element is reached or anonymised, at `path:line` — because one forgotten store keeps the subject identifiable |
| RD3 | Backups and logs outliving stated periods | Backup and log retention config | Retention configured within the stated period, or the commitment names the exception — because backups are stores too |

### Data subject rights (DR) [RIGHTS]

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| DR1 | Export or access that reads only some stores | Export handlers vs the data map | Every store holding the subject's data is read — because an incomplete export misstates what is held |
| DR2 | *(sound constructs)* Rectification that leaves stale copies (search index, cache, warehouse, third parties) | Profile update handlers and sync jobs | Updates propagate to every copy — because the stale copy is what others see |
| DR3 | *(sound constructs)* Rights requests not forwarded to processors that hold the data | Third-party deletion and update API calls | A call per processor listed in the data map — because the processor still holds it |
| DR4 | Identity of the requester not verified before export or deletion | Rights request handlers | The same authentication as account access — because an export to the wrong person is a breach |

### Third-party sharing (TP) [SHARE]

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| TP1 | *(sound constructs)* Payloads sent to third parties carrying more fields than needed or than disclosed (whole user objects, free text, identifiers) | Outbound API clients, SDK calls, webhooks, LLM/AI API prompts | An explicit field allow-list per payload at `path:line` — because a whole object sends every field added later |
| TP2 | Third parties absent from the sub-processor list or policy | Manifests, SDK initialisation, outbound hosts vs the commitments | Every recipient is listed — because an undisclosed recipient breaks the promise regardless of payload |
| TP3 | *(sound constructs)* SDK auto-collection: session replay, automatic form capture, IP and device collection left on | SDK init options | Auto-collection off or masked for personal fields at `path:line` — because SDK defaults collect broadly |
| TP4 | Customer-configured webhooks or integrations sending other subjects' data | Integration and webhook code | Payload scoped to what the receiving customer may see — because the integration widens the audience |
| TP5 | *(sound constructs)* AI/LLM providers keeping or training on prompts, files or embeddings, or holding personal data in their own stores (assistants, threads, files, vector stores) | AI client initialisation and request options, upload and embedding calls | Retention and training opt-out set at `path:line` (or `UNKNOWN` in `decisions`), and provider-side objects removed on deletion and listed in exports — because the provider is a store too |
| TP6 | *(sound constructs)* App-store and platform declarations contradicted by the code: Data safety answers, App Store privacy labels and iOS privacy manifests that deny collection, linking, tracking or sharing the SDKs, permissions and outbound calls actually perform (a third-party geocoder receiving coordinates, ad identifiers read by an SDK) | `PrivacyInfo.xcprivacy`, Data safety files, `Info.plist`, `AndroidManifest.xml`, build files and SDK initialisation vs outbound clients | Every declared data type and purpose matches what the code sends — because the declaration is a published commitment to every user |

### Logs, telemetry and errors (LT) [CONTAIN]

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| LT1 | *(sound constructs)* Personal fields in log calls, request logging of bodies, headers or query strings | Log calls near personal fields; HTTP logging middleware | A redaction filter or field allow-list on the logger at `path:line` — because logs are copied, shipped and kept longer than data |
| LT2 | *(sound constructs)* Error trackers capturing request bodies, user objects, local variables or breadcrumbs with personal data | Error tracker init and `beforeSend`-style hooks | Scrubbing configured for the personal fields — because error context is sent to a third party |
| LT3 | *(sound constructs)* Analytics events and APM attributes carrying personal data (emails, names, free text, precise location) | Event tracking calls, span attributes | Events carry pseudonymous IDs and non-personal properties — because event stores are broad and long-lived |
| LT4 | *(sound constructs)* Personal data in URLs (emails, names, tokens in paths or query strings) | Route definitions, link builders, redirects | Personal values in bodies, not URLs — because URLs reach logs, referrers and browser history |

### Exposure to other actors (EX) [CONTAIN]

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| EX1 | *(sound constructs)* Responses and views showing other users' personal fields beyond need (full email, phone, address in lists, member directories, comments) | Serializers and templates for multi-user views | An explicit output shape per audience, masked where full values are not needed — because every viewer is a recipient |
| EX2 | Staff and support tools: unrestricted search, unmasked sensitive fields, impersonation without audit | Admin panels, support tools | Role-scoped access, masking and an audit log at `path:line` — because insiders are recipients too |
| EX3 | Public or shareable links exposing personal data, guessable IDs on public routes | Share-link and public routes | Unguessable tokens, expiry and minimal content — because a link travels |
| EX4 | *(sound constructs)* Personal responses cacheable by shared caches or CDNs, or cached under keys without the user or tenant (missing `Cache-Control: private`/`no-store`) | Response header middleware, CDN and edge config, cache decorators | Personal responses are `private` or `no-store`, and cache keys include the subject — because a shared cache serves one user's data to the next |
| EX5 | Sensitive content in push, SMS or e-mail bodies and subjects (lock screens, shared inboxes, provider logs) | Notification and mail builders | Generic text with the detail behind sign-in — because notifications are shown and stored outside the app |
| EX6 | *(sound constructs)* Tenant or owner scoping bypassed outside the main data layer: raw SQL, a second database, search and vector-store queries (RAG retrieval), caches keyed without the tenant, background jobs using an unscoped manager, lookups by e-mail across tenants | Raw queries, retrieval and search clients, cache keys, task code using unscoped managers | Every query outside the scoped data layer filters by tenant or owner at `path:line`, and the filter is mandatory, not optional — because one unscoped path serves another customer's data |

### Storage protection (SP) [PROTECT]

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| SP1 | *(sound constructs)* Sensitive categories stored in plain text where commitments or the named regulation require encryption or tokenisation | Models for sensitive fields; encryption helpers; IaC | Encryption or tokenisation at `path:line` protects the data and access path named by the commitment; trace database reads and logical exports separately from storage encryption — because encryption layers protect different access paths |
| SP2 | Keys and access: one key for everything, keys next to data, broad database credentials | Key management config | Separate keys per purpose, managed outside the database — because the key decides who can read |

Accept storage encryption when the commitment requires protection of data at
rest. Where it also requires protection from database readers or plaintext
logical exports, trace those paths and their controls. For example,
[Azure SQL TDE](https://learn.microsoft.com/en-us/azure/azure-sql/database/transparent-data-encryption-tde-overview?view=azuresql)
decrypts pages for reads and does not encrypt the contents of a BACPAC export.

### Client-side tracking (CT) [CONSENT]

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| CT1 | *(sound constructs)* Third-party scripts, pixels and SDKs loaded or initialised before consent | HTML templates, tag manager setup, app bootstrap, mobile SDK initialisation, advertising-ID access vs the tracking-permission prompt | Loaded only after the matching consent category is granted — because loading is already sharing |
| CT2 | *(sound constructs)* Cookies and local storage set for non-essential purposes before consent; long expiries | Cookie setters, storage writes | Non-essential storage gated on consent with stated expiries — because the commitments name them |
| CT3 | *(sound constructs)* Personal data kept in client storage (local storage, IndexedDB, mobile preferences) unencrypted or after logout | Client storage writes; logout handlers | Minimal client storage cleared on logout — because shared devices are common |

### Identifiers and pseudonymisation (ID) [CONTAIN]

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| ID1 | *(sound constructs)* "Anonymised" data that is pseudonymous: hashed emails or phones, stable IDs, quasi-identifiers (postcode, birth date, gender) kept together | Anonymisation code, exports for analytics or partners | The claimed loss of linkability is supported for each recipient after checking identifiers, quasi-identifiers, available keys, mappings and candidate identities; statically sound only when all identifiers and quasi-identifiers are removed or the data is aggregated; otherwise `UNKNOWN` — because keyed or rotated pseudonyms can still be matched to a subject |
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
| NP2 | *(sound constructs)* Production-to-staging refresh or debug dumps without masking | Scripts and jobs copying databases | A masking step on every personal field at `path:line` — because staging has weaker controls |
| NP3 | *(sound constructs)* Personal data loaded into warehouses, ML training sets or LLM prompts without the controls of the source | Pipelines, training scripts, prompt builders; append-only delta loads and every model built on them (dbt and the like); a keyed pseudonym next to the same subject's plaintext in one row | Minimised, pseudonymised and covered by retention and deletion — because a derived copy escapes deletion |

### Location and transfers (LO) [SHARE]

| Step | Hunt | Where to look | Sound when — because |
|---|---|---|---|
| LO1 | *(sound constructs)* Stores and processors in regions the commitments do not state | IaC regions, storage and queue config, third-party endpoints | Regions match the stated locations; others are `UNKNOWN` — because the repository shows intent, not the deployed state |
| LO2 | Data residency features per tenant configured but not applied on every store | Tenant region settings vs storage selection code | Every store honours the tenant region — because one shared store breaks residency |

## Sound constructs

A cell is `sound` only for a construct in the *Sound* column, cited at
`path:line` on the flow; an *Unsound* construct is a candidate even when it
looks like a control. Every named API is a labelled example (`e.g.`), not a
list to grep for: find this stack's equivalent, confirm its configuration, and
check the version the repository pins before relying on a stated default.

| Step | Sound (labelled examples) | Unsound look-alike (labelled examples) | Why |
|---|---|---|---|
| MN2 | The coarsest precision the purpose needs, requested in context (e.g. iOS `kCLLocationAccuracyReduced` (iOS 14+) and `requestWhenInUseAuthorization`; Android `ACCESS_COARSE_LOCATION` only; coordinates rounded server-side before storage; a birth year or an "over 18" answer for an age check) | Permissions requested at first launch for features the user has not opened; Android `ACCESS_BACKGROUND_LOCATION` (separate since Android 10) or iOS `requestAlwaysAuthorization` for a foreground feature; browser `getCurrentPosition` with `enableHighAccuracy: true` stored at full precision; a full `<input type="date">` birth date kept after the age check | Precision collected is precision held, logged and shared |
| PC1 | A consent check before each consent-based call, reading the stored consent for that purpose (e.g. a `hasConsent("analytics")` guard around `track()`; a consent manager that blocks SDK calls by category; a server-side guard reading the consent record before a Segment, Mixpanel or marketing-email call in a Django/Rails/Spring/Express service) | Consent checked once at signup and never again; a banner that records a choice nobody reads; a check in the UI while the server sends events regardless (e.g. a browser consent manager in front of server-side `analytics.track()` calls); a marketing job that selects all users instead of opted-in ones | Each processing call must wait for the current consent |
| PC2 | Withdrawal written to the consent record and pushed to each consumer (e.g. GA `gtag('consent', 'update', {analytics_storage: 'denied'})`; Firebase `setAnalyticsCollectionEnabled(false)`, which persists across app launches; Mixpanel `opt_out_tracking()`; an unsubscribe propagated to the e-mail provider's API) | The flag updated in the database while a cached copy (session, Redis, mobile preferences) still says granted; a startup path that calls `setAnalyticsCollectionEnabled(true)` unconditionally; opt-out stored locally only, so a sync job re-subscribes the address at the provider | The stale consumer keeps processing after withdrawal |
| PC4 | Child-directed settings applied before the first request in a child's session (e.g. Google Mobile Ads `RequestConfiguration` with `setTagForChildDirectedTreatment(TAG_FOR_CHILD_DIRECTED_TREATMENT_TRUE)` or `setTagForUnderAgeOfConsent(...)`; analytics collection disabled for child accounts); records created only after parental consent completes, with a purge job for pending ones | The tag set after ads have already been requested; an age field collected but never read by SDK initialisation; the child's profile and location saved at signup "pending" consent with no expiry | Settings and consent that come after collection do not cover it |
| RD1 | A scheduled job or store-level TTL per store, with the period from config matching the commitment (e.g. a MongoDB TTL index with `expireAfterSeconds` on a `Date` field; Redis `EXPIRE`; an S3 lifecycle rule in IaC that also sets `NoncurrentVersionExpiration` on a versioned bucket; DynamoDB TTL with reads filtering expired items; a cron job, Rails Active Job, Django management command or Spring `@Scheduled` task deleting by `created_at`) | A retention period in the policy with no job; a job that covers the main table only; a TTL on a cache while the source table keeps everything; a MongoDB TTL index on a field stored as a string or number (such documents never expire); an S3 `Expiration` rule on a versioned bucket, which adds a delete marker and keeps the old versions; DynamoDB TTL read as exact (AWS deletes expired items typically within a few days) | A period kept in one store is not kept |
| RD2 | A deletion path that walks the data map: cascades or explicit deletes per table (e.g. Rails `dependent: :destroy`, Postgres `ON DELETE CASCADE`, JPA `CascadeType.REMOVE` / `orphanRemoval` on entity removal), file deletion (e.g. Active Storage `purge`), cache and search index purge, warehouse deletion, processor deletion API calls; a soft delete followed by a scheduled hard delete (e.g. `paranoia` `really_destroy!`, GORM `Unscoped().Delete`); anonymisation where deletion is impossible | `user.is_active = False` only; deleting the user row while orders, messages and files keep the name and email; "deletion" that leaves the search index; `paranoia` `acts_as_paranoid` (its `destroy` only sets `deleted_at`), `discard` (`discard` only sets `discarded_at`), Hibernate `@SQLDelete`, or a GORM model with a `gorm.DeletedAt` field treated as account deletion with no purge; Rails `delete` / `delete_all`, which skip callbacks and `dependent:`; a JPQL bulk `DELETE`, which skips cascades | The remaining store keeps the subject identifiable |
| DR2 | Every write path triggers the copy update (e.g. re-indexing from the database change stream (CDC), or from a commit hook that every writer goes through) | A search or cache sync on a model callback while other paths skip it: Rails `update_columns` / `update_all`, Django `QuerySet.update()` / `bulk_update` (no `save()`, no `post_save` signal), a JPA `@Modifying` bulk update (no entity listeners) | The stale copy is what other readers see |
| DR3 | A deletion or suppression call per processor in the data map, at `path:line` (e.g. the GA4 User Deletion API; a Segment regulation of type `SUPPRESS_WITH_DELETE`; Mixpanel or Amplitude deletion APIs; Mailchimp permanent delete of the member) | Segment `SUPPRESS` only (stops new data, keeps stored data); archiving or unsubscribing a contact at the e-mail provider; deleting locally and relying on the processor's own retention | The processor still holds the data |
| TP1 | Payloads built from an explicit field list (e.g. a dedicated DTO or Java record for the provider; `pick(user, ["id","plan"])`; Rails `as_json(only: [:id, :plan])`; a Go struct declared for the request); prompts built from selected fields with personal values removed | Sending the whole ORM object or request body (e.g. `json=user.__dict__`, `JSON.stringify(user)`, Rails `user.to_json`, Go `json.Marshal(user)` on the model struct, a Jackson-serialised JPA entity); free text sent to an AI API without minimisation | Every field added later is sent too |
| TP3 | Auto-collection options set explicitly to off or masked at `path:line` (e.g. Sentry Session Replay `replayIntegration` keeping `maskAllText` and `blockAllMedia` (both default `true`); Datadog RUM `defaultPrivacyLevel: 'mask'`; Firebase `google_analytics_adid_collection_enabled` set to `false` in `AndroidManifest.xml` where the ad ID is not needed) | `maskAllText: false` or `unmask` selectors covering personal fields; a replay or heatmap tool added through a tag manager with no masking config in the repo; Segment `page()` calls that send `url`, `search` and `referrer` from pages carrying personal values in the query string | SDK defaults decide what leaves the device |
| TP5 | Provider-side storage turned off or cleaned up at `path:line` (e.g. OpenAI Responses API `store: false` (`store` defaults to `true` there); uploaded files and vector stores deleted on account deletion via the provider's delete endpoints) | A Responses API call with no `store` setting; files and vector stores uploaded per user and never deleted; prompt logging in an LLM gateway or tracing tool that keeps full prompts | The provider becomes another store the deletion path must reach |
| TP6 | Declarations generated or reviewed against the SDKs actually linked (e.g. iOS `PrivacyInfo.xcprivacy` `NSPrivacyTracking`, `NSPrivacyTrackingDomains` and `NSPrivacyCollectedDataTypes` matching the ads and analytics SDKs; the merged `AndroidManifest.xml` checked for permissions SDKs add, removed with `tools:node="remove"` where unused) | `NSPrivacyTracking` false while an ads SDK reads the IDFA after the ATT prompt; Data safety saying "no device identifiers" while the merged manifest holds `com.google.android.gms.permission.AD_ID` (needed for the advertising ID when targeting Android 13+) from an ads or analytics dependency | The declaration covers what linked SDKs do, not only the app's own code |
| LT1 | A filter or formatter that redacts named fields and patterns on every handler and logger the record passes through (e.g. Python `logging.Filter` on each handler, `structlog` processors; Rails `config.filter_parameters` for request parameters; pino `redact` paths such as `req.headers.authorization`, `req.headers.cookie`, `*.email`; a winston custom `format` (winston has no built-in redaction); Logback with logstash-logback-encoder `MaskingJsonGeneratorDecorator`; Go `slog` with `HandlerOptions.ReplaceAttr` or a `LogValuer` on the user type); request logging without bodies | Redaction at some call sites only; a filter on one handler while a framework default handler (or a root handler reached by propagation) writes unfiltered; a parent-logger filter, which does not run for records propagated from child loggers; `logger.info(f"user {user}")` with a `__repr__` that prints email; Rails `filter_parameters` relied on for `Rails.logger.info("#{user.email}")` or custom Lograge fields (it filters parameters, not message strings); pino `redact: ['email']`, which covers only a top-level key; pino-http's default request serializer (logs headers, including cookies) with no redaction; Spring `CommonsRequestLoggingFilter` with `setIncludePayload(true)` or `spring.mvc.log-request-details=true` in a production profile; Django `sensitive_post_parameters` / `sensitive_variables` relied on for ordinary logging (they filter error reports only); Go `log.Printf("%+v", user)` | One unredacted path writes the data to every log destination |
| LT2 | Error tracker options with request-body and PII collection off and a scrubbing hook (e.g. Sentry Python `send_default_pii=False` with `before_send` removing personal fields; Sentry JS `sendDefaultPii: false` with `beforeSend` and `beforeBreadcrumb`; Spring Boot `sentry.send-default-pii=false`; `setUser({ id })` only; data scrubbing rules configured in the repo) | Default options with user context set from the full user object (e.g. `Sentry.setUser(user)`); local variables capture on (Sentry Python `include_local_variables` defaults to `True`); request bodies, which Sentry Python attaches under `max_request_body_size` (default `"medium"`) even with `send_default_pii=False`; breadcrumbs recording form inputs or console output; a Next.js app scrubbing in the client config while the server and edge configs have no hook | Error context is shipped to a third party. Read the whole hook before calling it incomplete: scrubbing of frame variables, extras and breadcrumbs often sits further down, and every process that initialises the SDK (web, workers, cron, server and edge runtimes) needs its own check |
| LT3 | Events and spans keyed by an internal opaque ID with an allow-list of properties; attributes removed or redacted before export (e.g. OpenTelemetry Collector `attributes` processor with `action: delete`, or the contrib `redaction` processor with `allowed_keys`; Datadog Agent `apm_config.replace_tags` / `DD_APM_REPLACE_TAGS`) | Segment `identify(userId, { email, name })`, whose traits go to every enabled destination; `span.setAttribute("user.email", …)`; Datadog `DD_TRACE_HEADER_TAGS` copying headers as span tags; the collector `hash` action presented as anonymisation (an unkeyed hash of an email is matchable, see ID1); full URLs with query strings as span attributes | Event and trace stores are broad, shared and long-lived |
| LT4 | Personal values in POST bodies or behind opaque, expiring tokens; query strings stripped before analytics (e.g. GA4 `page_location` overridden with the URL minus the query) | GET forms and links carrying `?email=`; GA4 collecting the full `page_location`, query included; access logs whose default format records the request line with the query (e.g. nginx `combined`, morgan `combined`); a redirect that appends the email to a third-party URL, which also reaches it through `Referer` | URLs are copied into logs, analytics, referrers and history |
| EX1 | An output shape per audience (e.g. a DRF serializer with explicit `fields`; Rails `as_json(only:)` or a serializer/view model; a Spring DTO; GraphQL field-level authorization on `email`, `phone`); masking in that shape (`j***@example.com`) | DRF `fields = "__all__"`; Rails `render json: @user`; a JPA `@Entity` returned from a `@RestController`; Next.js `getServerSideProps` returning the full user object (props are serialised into `__NEXT_DATA__` in the HTML) or a Server Component passing it to a Client Component (serialised into the payload), hidden only by the React component not rendering it | What reaches the client is disclosed, whether or not the UI shows it |
| EX4 | Personal responses sent with `Cache-Control: private` or `no-store`, and every cache key including the user or tenant (e.g. Spring Security's default `Cache-Control: no-cache, no-store, max-age=0, must-revalidate`; Rails' default `max-age=0, private, must-revalidate`; Next.js personalised routes rendered dynamically by reading `cookies()` / `headers()`) | Next.js personalised data fetched in a statically rendered route or one with `export const revalidate`; Next.js 14 `fetch` caching by default (`force-cache`; uncached by default from Next.js 15) relied on as per-user; `getServerSideProps` setting `Cache-Control: public, s-maxage=…` on a personalised page; a CDN rule caching all HTML (e.g. Cloudflare "Cache Everything"); Rails `expires_in …, public: true`; Spring Security cache headers disabled; Django `@cache_page` on a personalised view, which keys only by URL and the response's `Vary` headers | A shared cache serves one user's data to the next |
| EX6 | Tenant filtering enforced below the application code (e.g. Postgres row-level security with `FORCE ROW LEVEL SECURITY` and the tenant set per transaction with `SET LOCAL` or `set_config('app.tenant_id', …, true)`); a scoped repository or query object that every path must use; search and vector queries built with a mandatory tenant filter | RLS enabled while the app connects as the table owner without `FORCE` (owners bypass policies), or as a superuser or `BYPASSRLS` role; session-level `SET app.tenant_id` on a pooled connection (e.g. PgBouncer transaction mode), which the next request inherits; Supabase `service_role` key (bypasses RLS) in a request path; a Hibernate `@Filter` that is never enabled on the session; Django `Model.objects` used where a tenant-scoped manager exists; a vector store query with the tenant as an optional metadata filter | One unscoped path serves another customer's data |
| SP1 | Field-level encryption or tokenisation with keys held outside the database (e.g. Rails 7+ Active Record Encryption `encrypts :ssn`; a JPA `AttributeConverter` calling a KMS-backed library; a vault or token service returning references) | Base64 or reversible encoding called encryption; Rails `encrypts …, deterministic: true` assumed to hide equal values (deterministic encryption exposes equality, by design, to allow queries); `config/master.key` or the key literal committed; Postgres `pgp_sym_encrypt(data, 'literal key')` with the key in the SQL, where statement logging captures it; storage-level encryption (disk, RDS) cited for a commitment about database readers | Encryption protects only the paths where the key is absent |
| CT1 | Scripts injected only after consent for their category (e.g. a consent manager gating tags; dynamic `import()` after `consent.granted`; GTM tags with consent checks plus GA consent mode where `gtag('consent', 'default', {…: 'denied'})` runs before any `config` call and tags load only after `update` (basic consent mode); Firebase collection off in the manifest or `Info.plist` (`firebase_analytics_collection_enabled` / `FIREBASE_ANALYTICS_COLLECTION_ENABLED` false) and `setAnalyticsCollectionEnabled(true)` or `setConsent` after consent; iOS `ATTrackingManager.requestTrackingAuthorization` before any SDK reads the IDFA); server-side tagging that strips identifiers | Tags hard-coded in the HTML head; a consent banner rendered after the analytics script already ran; `defer` mistaken for gating; Next.js `<Script strategy="afterInteractive">` or `@next/third-parties` `<GoogleAnalytics>` rendered unconditionally in the root layout (strategy sets timing, not consent); GA advanced consent mode read as "nothing sent" (tags load and send cookieless pings while denied); the consent `default` set after `config`; Firebase `firebase_analytics_collection_deactivated`, which disables collection permanently and cannot be re-enabled after consent | Loading the script already shares data |
| CT2 | Non-essential cookies and storage written only after consent, with expiries matching the stated ones (e.g. GA consent mode `analytics_storage: 'denied'` until consent, which keeps `_ga` from being written; explicit `maxAge` / `expires` on Express `res.cookie` or Rails `cookies[...]`) | Rails `cookies.permanent` (a 20-year expiry) for a preference or tracking cookie; a pixel or SDK writing to `localStorage` on load; essential and non-essential values combined in one cookie | Stored identifiers persist and are read before the choice is made |
| CT3 | Minimal client storage, cleared on logout (e.g. `redux-persist` `persistor.purge()` and TanStack Query `queryClient.clear()` in the logout handler; personal secrets in the iOS Keychain or Android Keystore-backed storage, deleted on logout) | Personal data in `localStorage`, iOS `UserDefaults` or Android `SharedPreferences` in plain text; a persisted Redux store or query cache that survives logout; Keychain items left on logout (they can survive app deletion); a service-worker cache of `/api/me` responses | The next person on the device reads it |
| ID1 | Removal or aggregation where anonymity is claimed; where a join key is needed, a keyed hash (e.g. HMAC-SHA-256 with a secret key held outside the dataset and away from the recipient, per recipient), recorded as pseudonymisation, not anonymisation | An unsalted `sha256(email)` or `md5(phone)` called anonymised (anyone holding candidate emails recomputes it; normalised SHA-256 emails are also what ad-platform audience matching accepts); a salt shared with or recoverable by the recipient; a per-row salt stored next to the hash; a hash of the email kept with postcode, birth date and gender | A hash of a guessable value is a lookup, not anonymisation |
| NP2 | A masking step on every personal column, failing when a new column has no rule (e.g. PostgreSQL Anonymizer masking rules; a custom dump script with a column allow-list); synthetic seeds (e.g. Faker in Rails `db/seeds.rb`, Django factories) | `pg_dump` / `mysqldump` restored to staging as is; Django `dumpdata` from production committed as fixtures; masking of `email` and `name` while free-text, JSON and file columns keep personal values; test snapshots recorded from production API responses | Staging and developer machines have weaker controls |
| NP3 | Derived copies receive deletions and follow retention (e.g. CDC or connector delete flags such as Fivetran `_fivetran_deleted` applied in downstream models; a dbt model that removes or anonymises deleted subjects; pseudonymised identifiers in training sets) | dbt incremental or append-only models that never remove rows deleted at the source; a soft-delete flag carried into the warehouse and ignored by every model built on it; a training set exported once and kept outside every retention job | A derived copy escapes the source's deletion |
| LO1 | Regions set explicitly and matching the commitments (e.g. Terraform `region` per provider and resource; Sentry EU DSN host `ingest.de.sentry.io`; Datadog `site: 'datadoghq.eu'` / `DD_SITE`; single-region buckets and databases) | Provider defaults left in place (e.g. Datadog's default US site, a vendor's US endpoint); S3 cross-region replication, DynamoDB global tables or GCS multi-region locations adding regions not stated; read replicas or backups copied to another region | Data is held wherever any copy is |
