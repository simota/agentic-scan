# Attack paths — from an entry actor to a crown jewel

**Read when:** CHECKLIST, to write the hypotheses; REVIEW, to trace them edge by
edge; REPORT, to fill `attack_paths` in `findings.json`.

A misconfiguration matters by where it leads. This file is how the skill judges
that: for each crown jewel, each entry actor, the chain of edges between them.

## 1. Entry actors

| Actor | Starts with |
|---|---|
| Internet | Network reach to any public address; no credentials |
| Any cloud principal | Credentials for *some* AWS account or Google account (`allAuthenticatedUsers`, `Principal: "*"` with no org condition) |
| Organization member | Any identity in the organization, e.g. a developer's read-only role |
| CI identity | A workflow run in a repository the trust policy accepts — including forks and other repositories if the condition is loose |
| Third party | A vendor account named in a trust or resource policy |
| Compromised workload | Code execution on one VM, container or function, and the identity and metadata it holds |
| Cluster tenant | A pod or namespace user in a shared cluster |

## 2. Edge kinds

Every edge is one of these, and is cited at `path:line` or marked `UNKNOWN`:

| Edge | Allowed when | Blocked by |
|---|---|---|
| Network | A route plus every rule on the way permits the source (listener, SG / firewall ingress, NACL, Kubernetes NetworkPolicy) | Any rule on the path denying it, a private-only endpoint, a perimeter |
| Assume / impersonate | A trust policy, `actAs` / token-creator binding, or workload-identity mapping admits the actor | A condition the actor cannot satisfy (`ExternalId`, `sub`, `aws:PrincipalOrgID`, attribute condition) |
| Permission | An identity policy or binding grants the action on the resource | An explicit deny, a permission boundary, an SCP / org policy, a session policy |
| Resource policy | The target's own policy (bucket, key, secret, queue) admits the principal | The target's policy not naming it, a deny, a VPC-endpoint or org condition |
| Credential | A secret readable at the current position (user data, env vars, state, metadata) grants a further identity | The secret not being present or not being valid (do not test it) |
| Escalation | A permission that produces more permission (IP2) | A boundary or scope that confines what it can produce |

## 3. Procedure

1. Write each hypothesis as `AP-nn: <actor> → … → <crown jewel>` in the
   checklist, with the first edge you would test
2. In REVIEW, trace each edge in order. Stop at the first edge that is
   **blocked** (cite the control; the path is `blocked`) or **UNKNOWN** (name
   what would decide it; the path is `unknown`). A path with every edge allowed
   is `open`
3. For every `open` path, the weakest edge's fix is the finding. If several
   edges are independently wrong, each is a finding naming the same `AP-*`
4. Try variants: the same actor via a sibling resource (another environment,
   another listener, another role created by the same module), and another
   actor to the same jewel
5. Paths that end `blocked` go into `checked_ok` with the control that blocked
   them — they are the report's negative evidence

## 4. Grading from the path

- Severity comes from the actor at the start and the jewel at the end
  (`SKILL.md` severity table), not from the rule an edge breaks
- Each edge the attacker does not control alone (a compromised workload, a
  specific repository, a guardrail state not in the inputs) lowers one level
- Confidence: `Confirmed` when every edge is read in the inputs;
  `Environment-dependent` when one edge depends on a stated setting outside
  them (`condition` names it); `Suspected` when an edge was inferred

## 5. Common paths worth hypothesising first

| Path | Edges to check |
|---|---|
| Internet → public bucket / snapshot | Public access block or prevention, bucket policy, ACL, object ownership |
| Internet → SSRF in a public workload → instance metadata → role → data | Public listener, IMDS v1 or no metadata concealment, role permissions, target resource policy |
| Any GitHub repository → OIDC role → apply identity → everything | Trust `sub` / `aud` conditions, role permissions, state bucket policy |
| Any Google account → `allAuthenticatedUsers` binding → data | Binding resource, role, org policy domain restriction |
| Compromised pod → node / cloud role | Pod security, IRSA / WI mapping conditions, node role permissions, IMDS hop limit |
| Developer read-only → secrets | `describe` on functions / task definitions / instances exposing env vars or user data, state bucket read |
| Vendor account → cross-account role → data | `ExternalId`, role permissions, whether the vendor still needs it (`decisions`) |
| Low-privilege role → escalation permission → admin | IP2 permissions, boundaries, SCPs |
