# findings.json — the record

**Read when:** REPORT, before writing the first fragment; whenever the record is
re-rendered. **Reader:** the agent running the skill and anyone editing the
renderer. `scripts/render.py` (`validate`) is the executable form of this file.

`findings.json` is the single source for the dashboard, the assessment and the
chat summary. It is written only through `scripts/findings.py` (`merge` for
fragments, `remove` and `renumber` for review IDs) and `scripts/iac_scan.py
--into` (`I-*` findings and `meta.commit`).

- A fragment updates a known record key by key; a key set to `null` is removed
  (e.g. `"condition": null` after a finding becomes `Confirmed`)
- `findings.py remove <out>/findings.json F-007 AP-03` deletes review findings or
  attack paths and the ID lists that point at them
- `findings.py renumber <out>/findings.json` gives `F-*` the IDs `F-001…` in
  severity order, then location, rewriting attack-path links and F-IDs in text;
  run it once every review finding is merged
- A fragment may set an `I-*` finding's `validation`, `confidence` and `condition`
  (required with `Environment-dependent`), nothing else
- `findings.py status <out>/findings.json` lists untriaged `I-*` findings and
  references to IDs that do not exist; `contract_check.py` fails on the latter (a
  standalone `F-NNN` or `AP-NN` in prose is read as a record ID; cite another
  tracker's keys in a URL or as `#AP-123`)
- An `I-*` named in the `validation.evidence` of its root-cause `F-*` is shown as
  covered by that finding and counted once

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

## inventory

Written by `iac_scan.py --into`: `{"resources": N, "by_provider": {...}, "files": N, "not_run": [...]}`.
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
Every finding ID listed must exist. IDs start at `AP-01`, with at least two
digits; the sequence continues through `AP-100` and beyond.

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
| `controls` | no | List of strings: benchmark and section title, e.g. `["CIS AWS Foundations — S3 Block Public Access is enabled"]`; add the section number only from the edition the requester uses |
| `cwe` | no | `CWE-` and a number, e.g. `CWE-284` |
| `attack_paths` | no | `AP-*` IDs this finding is an edge of |
| `condition` | Environment-dependent | The unverified setting the grade assumes |
| `references` | no | `[{"title": "...", "url": "https://..."}]`; both required, https only, no credentials |
| `rule` | I-* | The baseline rule ID (`AWS-NET-001`…) |
| `detail` | no | What the baseline rule matched; written by `iac_scan.py` |
| `validation` | yes | `{"verdict": "...", "evidence": "..."}` |

IDs are ordered by their numeric suffix within each prefix, so `I-999` precedes
`I-1000`. IDs are unique by number: `F-001` and `F-0001` (or `AP-01` and
`AP-001`) are the same ID and cannot both appear. Review IDs run without gaps in severity order, then location; the
minimum width is padding, not a limit on the number of findings.

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
- `checked_ok`, `decisions`, `limitations`, `next_steps`: lists of strings

## Prose rules

`findings.py merge` refuses known credential shapes (access keys, private keys,
tokens) in every string it saves, including metadata, reference titles and
URLs, resource addresses and nested fields. This also checks retained content
from an existing record; credential refusals do not echo a matching value.

Finding text describes the weakness, never an attack. Literal exploit strings
and instance-metadata addresses remain prohibited in finding prose, attack-path
descriptions, perspective notes and the string lists. Ordinary reference URLs
and input paths are preserved rather than interpreted as attack prose.
