# CLAUDE.md

Agent skill for static security review of cloud infrastructure configuration
(the application's own source is out of scope).

- The skill lives in `skills/infra-security-scan/`; `SKILL.md` is the contract, and every
  `reference/*.md` must be named in it and start with a `**Read when:**` line
- `scripts/` are Python 3.10+ standard library only; no PyYAML, no cloud SDKs
- `make test` runs the unit tests; `make check` runs them plus the skill
  consistency checks — run `make check` before committing
- `reference/findings-schema.md` and `scripts/render.py` (`validate`) must
  change together; the perspective names in the first table of
  `reference/perspectives.md` are read at runtime by `render.py` and
  `contract_check.py`, and every category in `iac_scan.RULES` must be one of them
- Fixtures under `tests/fixtures/` are deliberately insecure configuration.
  Never put a realistic credential in them; tests build credential-shaped
  strings at runtime
