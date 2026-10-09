# Validation — is each finding real in this estate?

**Read when:** VERIFY, for every finding before it reaches the report; and when
triaging `I-*` baseline hits.

A rule hit or a reviewer's claim is a hypothesis. Record the verdict in
`validation` (`reference/findings-schema.md`). Severity, confidence and verdict
are separate axes.

Nothing is deleted: a finding judged false stays in the record with its
evidence, shown as excluded.

## Four claims for every finding

State the finding as: which entry actor, through which edges, past which
controls, reaches what. Check each claim and write what decided it into
`validation.evidence` with `path:line`:

1. **Reachability** — every edge of the attack path is allowed in the inputs
   (`reference/attack-paths.md` §2). Network edges name the listener, the rule
   and the target; identity edges name the trust policy or binding, and the
   exact permission
2. **Preconditions** — the resource is actually created in the environment in
   scope: `count` / `for_each` conditions, feature flags, module inputs per
   environment, a resource only in a non-prod `tfvars`
3. **Compensating controls** — look for what would block it and say where you
   looked: an explicit deny, a permission boundary, an SCP or org policy, a VPC
   Service Controls perimeter, a bucket-level public access block overriding a
   policy, an account-level block, a NACL, a NetworkPolicy, a WAF in front,
   a condition key on the grant. A control outside the inputs makes the finding
   `Environment-dependent`, with the control named in `condition`
4. **Impact** — what the jewel at the end is, and what the actor can do there
   (read, write, delete, administer)

## Falsification

For each High and Medium finding, write at least one check that would prove it
wrong, and run it by reading:

- "Is the resource overridden in another file or by a later module call?"
- "Does an `aws_s3_account_public_access_block` cover this bucket?"
- "Is the `0.0.0.0/0` rule attached to anything?" (a security group with no
  attachment is reachable by nothing)
- "Does the trust policy's `StringLike` on `sub` actually pin the repository?"
- "Is this service account bound anywhere a workload runs?"

## Triaging `I-*`

Each baseline hit gets a verdict; `contract_check.py` fails while any `I-*` is
still `Unverified`:

| Situation | Verdict |
|---|---|
| The hit is on an intended public edge (a CDN-fronted public asset bucket, an ALB on 443) and the intent is documented | `NotApplicable`, evidence citing the intent; record it in `checked_ok` |
| The parser read a value that is overridden or unresolved | `FalsePositive` or `Unlikely`, citing the override |
| The hit is real and is an edge of an attack path | `Valid` or `Likely`; the root-cause `F-*` finding, if one is written, names the `I-*` in its `validation.evidence` |
| The hit is real but leads nowhere | Keep its severity from the rule; verdict `Valid`; note "no path" in evidence |

Treat standalone `I-*` IDs in `F-*.validation.evidence` as baseline references;
IDs embedded in source filenames or URLs are left unchanged.
On rescan, the scanner updates them together with attack-path references when
the same rule, file and previously affected resources survive. If a reference
disappears or loses resources, its evidence names the former rule and file,
the finding becomes `Unverified` / `Suspected`, and linked attack paths become
`unknown`, whether linked through the finding's `attack_paths` or the path's
`findings`. Recheck those findings before giving them a definitive verdict again.

## Verdicts

| Verdict | Meaning |
|---|---|
| `Valid` | Every edge read; no compensating control in the inputs |
| `Likely` | Strong signals; one edge `UNKNOWN` |
| `Unverified` | Not yet examined |
| `Unlikely` | Signals point away; not ruled out |
| `FalsePositive` | The inputs contradict the claim |
| `NotApplicable` | Not applicable to the environment in scope |

`Valid`, `FalsePositive` and `NotApplicable` need nonblank evidence.

## IaC vs deployed

Static configuration says what was *declared*. Unless a snapshot of the deployed
state was supplied, every finding carries the limitation that the deployed
resource may differ (manual change, failed apply, another root module). Say so
once in `limitations`, not on each finding.
