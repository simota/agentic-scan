# Gates: what could have stopped a defect

**Read when:** RECON, to write the gate ledger; TRIAGE, to name the gate an event should have met.

Record each gate in `findings.json` as `{id, kind, name, status, evidence}`:

| Field | Rule |
|---|---|
| `id` | `G-01`… |
| `kind` | `test`, `lint`, `type`, `ci`, `review`, `flag`, `monitoring` |
| `status` | `present`, `absent` or `unknown` |
| `evidence` | Required as `path:line` when `present` |

Look at: test suites and what they reach, lint and type configuration, CI workflows and which jobs
actually block, `CODEOWNERS` and review rules, feature flags, and alerting configuration.

- `absent` means it was looked for and not found, which is a claim. Name where you looked in `checked_ok`
- `unknown` is for what the repository cannot show, such as whether review rules are enforced on the
  server. Do not guess
- A gate that exists but does not run on the affected path is `absent` for that path. Record it as a
  separate gate with a precise name (`E2E for checkout`)

## Naming the gate in a fix event

`gate_missed` is a **judgement**: the gate that should have stopped this defect. It does not show what
the change passed through, which git cannot tell you. D1 labels the column accordingly.
