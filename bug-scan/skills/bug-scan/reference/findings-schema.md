# Findings file: the one source for every output

**Read when:** TRIAGE, before the first fragment; REPORT.

## Shape

Enum values stay in English in both languages. Labels and headings follow `meta.lang`.

```json
{
  "meta": {"project": "acme-shop", "scope": "api/, web/", "commit": "3f2a9c1", "date": "2026-11-06",
           "assessor": "Claude Code (<model>)", "method": "git history 12 months; static review", "lang": "ja",
           "sample": {"read": 48, "candidates": 48}},
  "summary": "…",
  "gates": [{"id": "G-01", "kind": "ci", "name": "CI", "status": "present", "evidence": ".github/workflows/ci.yml:12"}],
  "fix_events": [{"id": "E-001", "commit": "c3d4e5f", "type": "commission", "pattern": "BP11", "module": "api/orders",
                  "origin": {"commits": ["a1b2c3d"], "channel": "feature", "strength": "Traced", "reason": "…"},
                  "gate_missed": ["G-01"], "regression_test": true, "detected": "release"},
                 {"id": "E-002", "commit": "9f8e7d6", "type": "not-defect", "note": "renamed a flag"}],
  "findings": [{
    "id": "BG-001", "title": "…", "status": "Open", "pattern": "BP11", "module": "api/orders",
    "first_seen": "2026-07-02", "last_seen": "2026-11-06",
    "introduced_in": {"commit": "a1b2c3d", "strength": "Traced", "reason": "…"},
    "severity": "High", "confidence": "Confirmed",
    "validation": {"verdict": "Valid", "method": "static", "evidence": "api/orders/validate.py:42 …"},
    "risk": {"likelihood": "Medium", "impact": "High", "level": "High", "detectability": "…", "basis": "…"},
    "hazard": {"classes": ["money"], "irreversible": "no", "silent": "yes", "reach": "…", "recovery": "…"},
    "relations": [{"type": "regression_of", "to": "BG-004", "strength": "Traced", "evidence": "…"}],
    "repro": {"state": "static", "preconditions": ["…"], "steps": ["…"], "expected": "…", "actual": "…", "last_run": "not run"},
    "surfaces": [{"id": "SC-02"}, {"id": "API-01"}, {"id": "DB-01", "op": "W: discount_total"}],
    "actors": ["signed-in buyer"], "conditions": [],
    "location": ["api/orders/validate.py:42"], "events": ["E-001", "E-002", "E-003"],
    "tests": "none", "tests_missing": "…", "fix": "…", "guard": "…", "regression_test": "…",
    "sibling_sites": [{"location": "api/admin/coupons.py:27", "state": "affected", "evidence": "…"}],
    "affected_releases": {"first": "v1.5", "last": "v1.6", "basis": "tag"},
    "data_remediation": {"needed": "yes", "locate": "…", "method": "…", "count": "UNKNOWN"},
    "detection": {"source": "…", "stage": "dev", "detected_at": "2026-07-02", "days_to_detect": 11, "basis": "…"},
    "path": [{"from": "…", "to": "…", "state": "allowed", "at": "api/orders/routes.py:31", "why": "…"}]
  }],
  "issues": [{"id": "I-01", "kind": "untested", "at": "worker/refunds/", "feeds": ["BP05"]}],
  "imports": [{"key": "security-scan:F-001", "scan": "security-scan", "title": "…", "severity": "Medium", "location": ["a.py:1"]}],
  "perspectives": [{"name": "BP01", "status": "applied", "note": "…"}],
  "checked_ok": ["…"], "limitations": ["…"], "decisions": ["…"], "next_steps": ["…"]
}
```

## Merge semantics

- Unknown keys are refused, and `key` is computed and refused in a fragment. A refused batch writes nothing
- `meta` updates key by key; `gates`, `fix_events`, `findings` and `issues` match by `id`, `imports` by `key`
- `perspectives` replace by `name`. String lists append without duplicates
- `null` removes an optional key. `{"remove": {"next_steps": ["…"]}}` deletes an exact item
- A string holding a personal e-mail address or something shaped like a secret is refused

## Commands

```
python3 scripts/findings.py merge <out>/findings.json <fragment>…
python3 scripts/findings.py renumber <out>/findings.json
python3 scripts/render.py <out>/findings.json --out <out>
python3 scripts/contract_check.py <out> --repo <checkout>
python3 scripts/findings.py counts <out>/findings.json
```

## What `contract_check.py` refuses

It checks shape and consistency, not whether a finding is true. It refuses:

- Files other than the contract's; a dashboard or report that differs from a fresh render
- `Traced` without a reason or origin commits; `Blamed` without commits; `Unattributable` with commits
- A commit, event, gate, relation, surface or module that the other files do not hold
- `meta.sample` missing or disagreeing with what is recorded, so a sample cannot pass for the whole
- Two records with one tracking key; set a `variant` (`tracking.md`)
- A required field missing for the record's range (`tracking.md`)
- An unresolved record with no risk judgement, or a risk level that disagrees with the fixed table
- High with fewer than 3 `Traced` events; High or Medium with no settled verdict or no `path:line` evidence
- A `verified` reproduction with no `last_run`
- Personal e-mail addresses, author keys, or anything shaped like a secret
- Empty `checked_ok` or `limitations`, or a pattern missing from `perspectives`
- With `--repo`: a cited file that is missing or a line past its end
