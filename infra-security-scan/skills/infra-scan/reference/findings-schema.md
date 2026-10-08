# findings.json — the record

**Read when:** REPORT, before writing the first fragment; whenever the record is
re-rendered. **Reader:** the agent running the skill and anyone editing the
renderer. `scripts/render.py` (`validate`) is the executable form of this file.

`findings.json` is the single source for the dashboard, the assessment and the
chat summary. It is written only through `scripts/findings.py merge` (fragments)
and `scripts/iac_scan.py --into` (`I-*` findings and `meta.commit`).

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

## meta

| Field | Required | Content |
|---|---|---|
| `project` | yes | Name of the assessed estate or repository |
| `scope` | yes | Accounts/projects/clusters and environments in scope |
| `date` | yes | `YYYY-MM-DD` |
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
Every finding ID listed must exist.

## findings

| Field | Required | Content |
|---|---|---|
| `id` | yes | `F-001`… (review) or `I-001`… (`iac_scan.py`) |
| `title` | yes | One line naming the weakness |
| `severity` | yes | `High`, `Medium`, `Low`, `Info` |
| `confidence` | yes | `Confirmed`, `Environment-dependent`, `Suspected` |
| `category` | yes | A perspective name from `reference/perspectives.md` |
| `provider` | yes | `aws`, `gcp`, `azure`, `kubernetes`, `multi` |
| `resources` | yes | Resource addresses (`module.web.aws_security_group.app`) |
| `location` | yes | `path:line` or `path:line-line` in the assessed repository |
| `actor` | F-* | The entry actor and the preconditions it needs |
| `path` | F-* | Numbered edges of the attack path, `\n`-separated |
| `impact` | F-* | Expected vs actual, and the bounded impact |
| `fix` | F-* | One line: the boundary restored and where it goes |
| `regression` | F-* | A policy-as-code assertion of the secure state |
| `controls` | no | Benchmark and section title, e.g. `CIS AWS Foundations — S3 Block Public Access is enabled`; add the section number only from the edition the requester uses |
| `cwe` | no | e.g. `CWE-284` |
| `attack_paths` | no | `AP-*` IDs this finding is an edge of |
| `condition` | Environment-dependent | The unverified setting the grade assumes |
| `references` | no | `[{"title": "...", "url": "https://..."}]`, https only, no credentials |
| `rule` | I-* | The baseline rule ID (`AWS-NET-001`…) |
| `validation` | yes | `{"verdict": "...", "evidence": "..."}` |

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

Finding text describes the weakness, never an attack. `findings.py merge`
refuses literal exploit strings, live credential shapes (access keys, private
keys, tokens) and instance-metadata addresses in prose fields.
