# findings.json — the record

**Read when:** REPORT, before writing the first fragment; whenever the record is
re-rendered. **Reader:** the agent running the skill and anyone editing the
renderer. `scripts/render.py` (`validate`) is the executable form of this file.

`findings.json` is the single source for the dashboard, the assessment and the
chat summary. It is written only through `scripts/findings.py` (`merge` for
fragments, `remove` and `renumber` for review IDs) and `scripts/iac_scan.py
--into`. A rescan replaces the `I-*` findings, `meta.commit` and `inventory`,
keeps the triage of unchanged `I-*`, rewrites `I-*` IDs in `F-*` evidence and
every prose line (its own carry-over notes in `limitations` excepted), and
when a cited baseline finding is gone marks the `F-*` `Unverified`, sets its
attack paths to `unknown` with a `note`, and adds a line to `limitations`.

- A fragment updates a known record (and `meta`) key by key; a key set to `null` is removed
  (e.g. `"condition": null` after a finding becomes `Confirmed`)
- A `perspectives` entry replaces the recorded entry with the same `name` whole,
  so send its `status` and `note` together. Lines in `checked_ok`, `decisions`,
  `limitations` and `next_steps` are appended without duplicates and no command
  removes them (except the rescan note `remove` takes with its record): merge a
  line once it is final
- `findings.py remove <out>/findings.json F-007 AP-03` deletes review findings or
  attack paths, the ID lists that point at them and the `limitations` line a
  rescan wrote about them (`F-007: Baseline references removed by rescan: …`),
  and rewords another record's rescan note that names one ("a removed finding");
  it refuses while other prose still names one of them
- `findings.py renumber <out>/findings.json` gives `F-*` the IDs `F-001…` in
  severity order, then location, rewriting attack-path links and F-IDs in text;
  run it once every review finding is merged
- A fragment may set an `I-*` finding's `validation`, `confidence`, `condition`
  (required with `Environment-dependent`) and `severity`, nothing else
- `findings.py status <out>/findings.json` lists `Unverified` findings (untriaged
  `I-*`, and any finding a rescan reopened) and
  references to IDs that do not exist; `contract_check.py` fails on the latter (a
  standalone `F-NNN`, `AP-NN` or `I-NNN` in prose is read as a record ID; cite
  another tracker's keys in a URL, in `references`, or as `#AP-123`; an ID used as
  a path component, as in `docs/F-001/`, or after a name and a `.` in a resource
  address, as in `aws_s3_bucket.F-001` or the instance key `aws_s3_bucket.logs["F-001"]`, is not a reference (`F-001...F-003` is two); a URL ends at whitespace or the
  first non-ASCII character)
- An `I-*` named in the `validation.evidence` of its root-cause `F-*` is shown as
  covered by that finding and counted once: name in that evidence only the `I-*`
  the finding is the root cause of

## Top level

```json
{
  "schema_version": 1,
  "meta": {},
  "inventory": {},
  "attack_paths": [],
  "findings": [],
  "perspectives": [],
  "checked_ok": [],
  "decisions": [],
  "limitations": [],
  "next_steps": []
}
```

Every object accepts only the keys listed in this file; `validate` refuses any
other key (a typo such as `contrats` would otherwise vanish from every report).
Every string must be valid UTF-8 (a JSON `\ud800` escape alone is refused), the
record nests at most 32 levels, and `location` line numbers have at most nine
digits.

## meta

| Field | Required | Content |
|---|---|---|
| `project` | yes | Name of the assessed estate or repository |
| `scope` | yes | Accounts/projects/clusters and environments in scope |
| `date` | yes | `YYYY-MM-DD`, a real calendar date |
| `assessor` | yes | Host and model |
| `method` | no | e.g. `Static review of Terraform and plan JSON; no cloud API calls` |
| `providers` | no | Subset of `aws`, `gcp`, `azure`, `kubernetes` |
| `inputs` | no | List of inputs read: `{"kind": "iac|plan|snapshot|manifest", "path": "...", "note": "..."}` |
| `commit` | set by `iac_scan.py` | Git commit of the assessed repository, or `""` outside git |

`iac_scan.py --into` writes only `meta.commit`; the first fragment carries the
rest. A minimal first fragment:

```json
{
  "meta": {"project": "acme-platform", "scope": "AWS account prod; environment prod",
           "date": "2026-10-08", "assessor": "Claude Code (<model>)",
           "method": "Static review of Terraform; no cloud API calls", "providers": ["aws"],
           "inputs": [{"kind": "iac", "path": "envs/prod/"}]}
}
```

## inventory

Written by `iac_scan.py --into`: `{"resources": N, "by_provider": {...}, "files": N, "not_run": [...]}`,
with counts as non-negative integers and `not_run` as a list of strings.
Fragments may not set it.

## attack_paths

```json
{
  "id": "AP-01",
  "entry": "Internet",
  "target": "Customer database (aws_db_instance.main)",
  "status": "open",
  "edges": [
    "Internet → ALB listener :443 (modules/web/alb.tf:12)",
    "ALB → ECS task SG allows 8080 from ALB SG (modules/web/sg.tf:30)",
    "Task role can read secret db/master (modules/web/iam.tf:41)"
  ],
  "findings": ["F-001", "F-003"],
  "note": ""
}
```

`status` is `open` (every edge allowed in the inputs), `blocked` (an edge is
denied — name it in `note`), or `unknown` (an edge is `UNKNOWN`; name it).
Every finding ID listed must exist. A High or Medium finding linked to an
`unknown` path (from either side) is `Environment-dependent` or `Suspected`,
never `Confirmed`; a complete record is refused otherwise. IDs start at `AP-01`, with at least two
digits; the sequence continues through `AP-100` and beyond.

| Field | Required | Content |
|---|---|---|
| `id` | yes | `AP-01`… |
| `entry` | yes | The entry actor (`reference/attack-paths.md` §1), one line |
| `target` | yes | The crown jewel, with its resource address, one line |
| `status` | yes | `open`, `blocked`, `unknown` |
| `edges` | yes | Non-empty list of edges, each with `path:line`, or marked `UNKNOWN` with what would decide it (then the status is not `open`) |
| `findings` | no | `F-*` / `I-*` IDs on this path |
| `note` | `blocked`, `unknown` | The denying or unknown edge |

## findings

| Field | Required | Content |
|---|---|---|
| `id` | yes | `F-001`… (review) or `I-001`… (`iac_scan.py`), with at least three digits; continues through `F-1000` / `I-1000` and beyond |
| `title` | yes | One line naming the weakness |
| `severity` | yes | `High`, `Medium`, `Low`, `Info` |
| `confidence` | yes | `Confirmed`, `Environment-dependent`, `Suspected` |
| `category` | yes | A perspective name from `reference/perspectives.md` |
| `provider` | yes | `aws`, `gcp`, `azure`, `kubernetes`, `multi` |
| `resources` | yes | Resource addresses (`module.web.aws_security_group.app`) |
| `location` | yes | `path:line` or `path:line-line` in the assessed repository; lines start at 1 and a range does not run backwards |
| `actor` | F-* | The entry actor and the preconditions it needs |
| `path` | F-* | Numbered edges of the attack path, `\n`-separated |
| `contrast` | F-* | A sibling resource configured soundly, with `path:line`, or `none` and why |
| `impact` | F-* | Expected vs actual, and the bounded impact |
| `fix` | F-* | One line: the boundary restored and where it goes |
| `regression` | F-* | A policy-as-code assertion of the secure state |
| `controls` | F-*, where one applies | List of strings: benchmark and section title, e.g. `["CIS AWS Foundations — S3 Block Public Access is enabled"]`; add the section number only from the edition the requester uses |
| `cwe` | F-*, where one applies | `CWE-` and a number, e.g. `CWE-284` |
| `attack_paths` | no | `AP-*` IDs this finding is an edge of |
| `condition` | Environment-dependent | The unverified setting the grade assumes |
| `references` | no | `[{"title": "...", "url": "https://..."}]`; both required, https only, no credentials |
| `rule` | I-* | The baseline rule ID (`AWS-NET-001`…) |
| `detail` | no | What the baseline rule matched; written by `iac_scan.py` |
| `validation` | yes | `{"verdict": "...", "evidence": "..."}` |

IDs are ordered by their numeric suffix within each prefix, so `I-999` precedes
`I-1000`. IDs are unique by number: `F-001` and `F-0001` (or `AP-01` and
`AP-001`) are the same ID and cannot both appear. Review IDs run without gaps in severity order, then location; the
minimum width is padding, not a limit on the number of findings. Numbers start
at 1 (`F-000` is refused) and have at most nine digits.

### validation

| Verdict | Meaning | Evidence |
|---|---|---|
| `Valid` | Every edge read; no compensating control in the inputs | required |
| `Likely` | Strong signals, one edge `UNKNOWN` | optional |
| `Unverified` | Not yet examined (the `I-*` default) | optional |
| `Unlikely` | Signals point away, not ruled out | optional |
| `FalsePositive` | The inputs contradict the claim | required |
| `NotApplicable` | Not applicable to the assessed environment | required |

`FalsePositive` and `NotApplicable` findings stay in the record and are shown as
excluded. `Valid` + `Confirmed` requires every edge in `path` to cite `path:line`.

## Lists

- `perspectives`: `{"name": "...", "status": "Applied|N/A|Not checked", "note": "..."}`
  — one per perspective in `reference/perspectives.md`
- `checked_ok`, `decisions`, `limitations`, `next_steps`: lists of strings.
  `decisions` holds what a human decided (with who decided) and what a human
  must still decide; only the former documents intent (`reference/validation.md`)

## Prose rules

`findings.py merge` refuses known credential shapes (access keys, private keys,
tokens) in every string it saves, including metadata, reference titles and
URLs, resource addresses and nested fields. This also checks retained content
from an existing record; credential refusals do not echo a matching value.

Finding text describes the weakness, never an attack. Literal exploit strings
and instance-metadata addresses remain prohibited in finding prose, attack-path
descriptions, perspective notes and the string lists. Ordinary reference URLs
and input paths are preserved rather than interpreted as attack prose.
