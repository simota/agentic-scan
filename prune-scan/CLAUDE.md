# CLAUDE.md

Agent skill `prune-scan` (`skills/prune-scan/SKILL.md`): read-only minus-design
review that reports what in an app's repository can be removed, reduced or
consolidated, modelled on security-scan and laid out like ux-scan, rendering through the bundled report kit.

- `make test` / `make check` before reporting done; `make demo` renders the sample with PDF.
- Scripts are standard library only, so the skill stays self-contained when symlinked.
- `skills/prune-scan/scripts/scan_report_kit/` is owned here (scan-report-kit is retired); edit it in place.
- Every `reference/*.md` must be cited from SKILL.md and open with a `**Read when:**` line (`make check` enforces it).
- `scripts/ci/check_doc_refs.py` (run by `make check`) checks backticked paths that start with `reference/` or `scripts/` (resolved against the skill directory) or with `skills/prune-scan/`, `docs/`, `examples/`, `tests/` or `scripts/ci/` (resolved against the repository), alone or as the first word of a backticked command (`scripts/render.py --lang ja`), plus relative Markdown links. Other backticked paths, such as the reviewed app's files named as examples in the references (`package.json`, `server/app.py:56`), are not checked and need not exist here.
- `AGENTS.md` is this file with the heading `# AGENTS.md`; `make check` fails when the two drift.
- `examples/larder/` is a fictional fixture with deliberate unneeded elements in every perspective family; tests depend on its exact contents and line numbers.
- `examples/access.sample.log` is a fictional month of Larder traffic (documentation IP ranges only) for `usage.py`; tests depend on its exact counts.
- `examples/findings.sample.json` and `examples/findings.sample.ja.json` must keep identical ids, severities, confidences, locations, perspectives, refs and verdicts (a test enforces it), and stay in renumber order.
