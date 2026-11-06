# Tracking: what a defect record holds

**Read when:** REVIEW, before writing a record; RECONCILE, when a ledger is named.

## Required ranges

| Record | Required |
|---|---|
| Open High or Medium | Everything in the list below |
| Open Low or Info | Identity, state, evaluation, surfaces, evidence |
| `Fixed` or `Verified` | Identity, state, origin and fix commits, detection |
| `FalsePositive` or `NotApplicable` | Title and validation with evidence |

Fields outside a range may still be recorded. A required field that cannot be determined holds
`UNKNOWN` and the reason. `contract_check.py` enforces these ranges.

## Identity

`key` is computed from the pattern, first file, surfaces and an optional `variant`, so it survives moved lines
and new titles. Two records at one place (a past defect and its regression, or two separate defects) collide,
and the contract refuses that: give one a short, stable `variant` such as `blank-only-input`. Do not change a
`variant` later, or the ledger sees a new defect.

## Status

`Open`, `Triaged`, `Reopened`, `Unverified`, `Accepted`, `Fixed`, `Verified`. `Fixed` needs `fixed_in`.
`NotSeen` exists only in the ledger.

## Risk and hazard

`risk` holds `likelihood`, `impact`, `level`, `detectability` and `basis`. `level` comes from this table,
and a record that disagrees with it is refused:

| Likelihood \ Impact | Low | Medium | High |
|---|---|---|---|
| High | Medium | High | High |
| Medium | Low | Medium | High |
| Low | Low | Low | Medium |

Likelihood is judged from code, not measured; say so in `basis` unless the requester supplied data.
`severity` says how serious the code makes this; `risk` adds how likely it is. They can differ.

`hazard` holds `classes` (money, data loss, data inconsistency, security, privacy, availability, legal,
wrong display…), `irreversible` and `silent` (`yes`, `no`, `unknown`), `reach` and `recovery`.

## Relations

| `type` | Meaning | Direction |
|---|---|---|
| `regression_of` | A past defect came back | `to` is the earlier record |
| `caused_by` | Another defect or its fix caused this | `to` is the cause |
| `same_root_cause` | One cause, separately recorded | Either |
| `blocks` | Fix this first | `to` is what waits |
| `duplicate_of` | The same defect | `to` is the one reported |

Each needs `strength` (`Traced` or `Blamed`) and `evidence`. Sharing a DB table or job is computed by the
figure and is never recorded as a relation, because it does not imply cause.

## Reproduction

`repro.state` is one of:

| State | Meaning |
|---|---|
| `static` | Derived from code, not run |
| `test` | Confirmed by an existing test; `last_run` cites it |
| `verified` | Run; `last_run` cites the result from `verify-scan` or the requester |
| `not-reproduced` | Run, and it did not happen |
| `unknown` | Steps cannot be settled; say what is missing |

Inputs are synthetic. Never record a real user's data or a production value.

## After the fix

- **`sibling_sites`**: `{location, state, evidence}` for every site with the same shape, each `affected`,
  `safe` or `unknown`. Search before writing the fix direction. Partial fixes are the commonest recurrence
- **`data_remediation`**: `needed` (`yes`, `no`, `unknown`), `locate`, `method`, `count`. Fixing code does not
  repair data already written

## Releases and detection

- **`affected_releases`**: from `history.py --releases <origin> <fix>`. `UNKNOWN` without tags or an origin.
  A `Blamed` origin makes the range provisional: say so in `basis`
- **`detection`**: `source`, `stage` (`dev`, `ci`, `release`, `unknown`), `detected_at`, `days_to_detect`,
  `days_to_fix`, `basis`. Compute days from dates. `UNKNOWN` when the source cannot be read

## The ledger

```
python3 scripts/ledger.py reconcile <ledger.json> <out>/findings.json --repo <repo> --fragment <scratch>/ledger-fragment.json
python3 scripts/findings.py merge <out>/findings.json <scratch>/ledger-fragment.json
python3 scripts/ledger.py set <ledger.json> <key> --status Accepted --owner TEAM --reason TEXT
```

It must live outside the reviewed repository. Run reconcile only after the run's verdicts are final.

| Result | When |
|---|---|
| New | The key is not in the ledger |
| Continuing | The key is found again |
| Reopened | The key is found again after `Fixed` or `Verified` |
| `NotSeen` | Not found in this run. **Not proof of a fix**: the scope may differ |

A human's `Accepted` and `owner` are never overwritten. When a key is new but its pattern and file match an
old entry, the run names both in `decisions` instead of linking them, because a person should decide.
