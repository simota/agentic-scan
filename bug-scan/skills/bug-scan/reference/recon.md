# Recon: the map the rest of the run stands on

**Read when:** RECON, before reading any fix.

Record the following in scratch, each with the file it came from:

- Stack and deployable units: languages, frameworks, services, clients
- Modules: top-level areas, matching `history.py --module-depth` so fix events and churn line up.
  Change the depth if the default of 2 splits or merges the areas people think in
- Core flows: the flows whose correctness matters most (payment, ordering, permissions, data
  sync). Name them before reading fixes, because severity is judged against them
- Gates: see `gates.md`
- History quality:
  - `git rev-parse --is-shallow-repository`: shallow history cannot support D1 or D3
  - Squash merges: one commit may hold several changes, which widens blame
  - Fix prefix share: `history.py` reports `prefix_share`. A low share means fix candidates come from
    words in subjects and recall is lower
  - Tags: without tags, `affected_releases` stays `UNKNOWN`
  - PRs and issues: read only what the requester supplies, or `gh` for their own repository

When only a checklist was asked for, stop after CATALOG and list the patterns, gates and flows that
apply to this codebase.
