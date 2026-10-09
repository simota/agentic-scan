# Recon — the personal data map

**Read when:** RECON, before any finding is written. Nothing in later phases is
trustworthy until this map exists, because a flow cannot be judged without
knowing which data it carries and whose it is.

The map is a working artifact. Keep it in scratch; it is not part of the final
report unless asked. It holds field names and locations, never values.

## 1. Stack and deployable units

Language, framework, ORM, front end, mobile apps, analytics and tracking SDKs,
error trackers, log shippers, email and messaging providers, payment and
identity providers, with versions from lockfiles. Every deployable unit and
where it is configured to run (regions in IaC or config).

## 2. Personal data inventory

Search models, schemas, migrations, DTOs, forms, API payloads and mobile
permission requests for personal data: names, contact details, addresses,
identifiers (account IDs, device IDs, advertising IDs, IP addresses, cookies),
government and financial identifiers, precise location, health, biometrics,
date of birth and age, photos and voice, communications content, behavioural
data (events, history), free-text fields where users write about themselves or
others.

| Element | Category | Subjects | Collected at (`path:line`) | Stored in | Sensitive |
|---|---|---|---|---|---|

- *Category*: contact, identifier, financial, location, health, content,
  behavioural, technical…
- *Subjects*: end users, customers' customers, employees, children, visitors,
  third parties named by users
- *Stored in*: every store — primary database tables, caches, search indexes,
  vector stores and embeddings, file and object storage, analytics warehouse,
  queues, logs, backups, and stores kept by providers (AI assistants and
  threads, e-mail and messaging providers)

Free-text and file-upload fields are personal data by default.

## 3. Flows and sinks

For each element, every place it goes after collection:

- **Third parties** — outbound API calls, SDK calls (analytics, ads, error
  tracking, support chat, email, CRM, AI/LLM APIs), webhooks to customers,
  exports, data pipelines. Record the exact payload fields sent
- **Logs and telemetry** — log calls near personal fields, request logging
  middleware (bodies, headers, query strings), error tracker context and
  breadcrumbs, APM attributes, analytics event properties
- **Other actors** — API responses, UIs, emails and notifications, shared
  links, exports seen by other users, admins or support staff
- **Copies** — seeds and fixtures, test snapshots, staging refresh scripts,
  ML training sets, data warehouse loads, caches

## 4. Consent and preferences

Consent and preference records (where stored, what purposes), the code that
reads them before processing, cookie banners and consent managers, the order
in which SDKs initialise relative to consent, marketing opt-in and opt-out,
"do not sell or share" signals, age gates.

## 5. Retention, deletion and rights

- Retention jobs and TTLs per store, and soft-delete flags
- Account deletion and closure paths: what each one deletes, anonymises or
  leaves, store by store (map against §2 *Stored in*)
- Data export (access and portability) paths: which stores they read
- Rectification paths, and copies that keep the old value
- Requests forwarded to processors (deletion APIs of third parties)

## 6. Storage and protection

Field-level encryption, tokenisation and hashing of identifiers, database
encryption settings in IaC, backup configuration and retention, access paths
for staff and support tools (impersonation, admin panels, data browsers).

## 7. Location and transfers

Regions configured for databases, storage buckets, queues and functions;
third parties' endpoints when the repository names a region; CDN and logging
destinations.

## 8. Commitments in the repository — input to the ledger

Record what the later hunt needs (`reference/commitments.md`):

- Privacy policy, terms, consent texts and cookie notices (in the repository,
  in the front end, or in localisation files)
- App-store privacy declarations and permission purpose strings (privacy
  manifests, Data safety answers, `Info.plist` and `AndroidManifest.xml`)
- Retention schedules in docs, config or job definitions
- Records of processing, data maps, sub-processor lists, DPIAs if present
- Settings screens that promise behaviour ("we never share", "delete my
  account", "download my data")
- Regulations or frameworks the requester named
