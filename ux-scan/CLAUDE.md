# CLAUDE.md

Agent skill `ux-scan` (`skills/ux-scan/SKILL.md`): read-only design, layout and
UI/UX review, rendering through
`skills/ux-scan/scripts/report_format.py` and its `report_*.py` siblings.

- `make test` / `make check` before reporting done; `make demo` renders the sample with PDF.
- Scripts are standard library only, so the skill stays self-contained when symlinked.
- The report modules (`report_format.py`, `report_style.py`, `report_pdf.py`, `report_output.py`) and `skills/ux-scan/scripts/report_assets/` are owned here; edit them in place.
- Every `reference/*.md` must be cited from SKILL.md and open with a `**Read when:**` line (`make check` enforces it).
- `scripts/ci/check_doc_refs.py` (run by `make check`) checks backticked paths that start with `reference/` or `scripts/` (resolved against the skill directory) or with `skills/ux-scan/`, `docs/`, `examples/`, `tests/` or `scripts/ci/` (resolved against the repository), plus relative Markdown links. Other backticked paths, such as the reviewed app's files named as examples in the references (`package.json`, `app/**/page.*`), are not checked and need not exist here.
- `AGENTS.md` is this file with the heading `# AGENTS.md`; `make check` fails when the two drift.
- `examples/tasklane/` is a fictional fixture with deliberate UX defects; tests depend on its exact contents and line numbers.
