# Report

**Read when:** CHECKLIST, when only a checklist was asked for; REPORT — rendering and writing the chat summary.

```sh
python3 <skill-dir>/scripts/render.py <out>/findings.json --out <out> --lang ja|en --repo <repo> [--no-pdf]
python3 <skill-dir>/scripts/contract_check.py <out> [--no-pdf]
```

`<skill-dir>` is the directory holding SKILL.md; never run a same-named script
from the reviewed repository (SKILL.md *Paths*).

`render.py` maps `findings.json` into scan-report-kit's common format
(`scan-report/1`) and writes `dashboard.html`, `report.html` and `report.pdf`
in the shared design. Each finding shows its element, the basis, the purpose
item (from `units.json`), the cost of keeping, the subtraction (what, what
remains, what is lost), the risk, and its unit and entry point. An open `Valid`
finding's next action is the subtraction itself; any other open finding's is
"Verify first". With `--repo`, each finding's first `path:line` is embedded as
a short excerpt (never from secret-looking files; secret-looking lines are
masked). Secret-looking directories are excluded as well. If a secret
assignment has a multiline or ambiguous value, or a private key block appears
anywhere in the source, the source's excerpt is omitted. The whole bounded
source is checked so a secret cannot lose its identifying line when the
excerpt starts partway through the value. Sources containing both a secret
name and block-comment syntax are also omitted because comment boundaries
and string continuation differ across languages.

Every page is stamped with the SHA-256 of the `findings.json` it
shows and, when present, the adjacent `units.json` used for its purpose and
unit labels. `contract_check.py` compares both stamps with the current records
and rejects pages left stale by a change to either input. Stamps must be real,
unique metadata in the document head; text in a comment or another element
does not count. Incomplete HTML documents are rejected even when their input
stamps match. A present but unreadable `units.json`, including a broken
symlink, is an input error rather than an omitted baseline.
On POSIX systems with descriptor-relative opens, the check pins the selected
output directory through every ancestor and uses that descriptor for all
artifact inspection and reads. It also rejects a directory that changes
identity during the check. Ancestors need only search permission when the
runtime exposes `O_PATH` or `O_SEARCH`; otherwise they must also be readable.

The rendered next steps open with the **subtraction summary**, computed from
the open, counted findings (`Unlikely` ones are left out):

| Line | Holds |
|---|---|
| Subtraction - remove now | `Valid`, `Confirmed`, action `remove` |
| Subtraction - reduce or consolidate | `Valid`, `Confirmed`, action `reduce` or `consolidate` |
| Subtraction - decide with a human | everything else: `Likely`, `Externally-dependent`, `Purpose-dependent`, `Suspected` |

The record's own `next_steps` follow it; do not write the summary lines into
the record.

Exit 3 means no PDF: no engine found, an engine that failed, or a timeout —
the message says which. `PRUNE_SCAN_PDF_TIMEOUT` overrides the engine's timeout
in seconds for the one retry SKILL.md allows. For a requester language other
than `ja` or `en`, the prose is in their language and the labels are `--lang en`
(SKILL.md *Outputs* row).

## Checklist deliverable

When only a checklist was asked for: the stack, the purpose baseline (with what
is `inferred`), the consumers and the units first; then one section per unit
listing its entry points and the applicable perspectives and hunt steps, each
with the concrete files to read and any inventory candidate marked
`unverified`; then the perspectives judged N/A with a reason; last, where to
start and the one decision a human must make (usually: confirm the purpose and
non-goals, or the consumers outside the repository).

## Chat summary

Satisfy SKILL.md *Done when* first. First line: status and counts, e.g.
`prune-scan complete: 5 High, 9 Medium, 21 Low, 1 Info (36 open); remove now 25, reduce 3, decide 8`.
Then:

- the High findings, one line each with `path:line` and what to subtract
- decisions that need a human (`decisions`), Purpose-dependent ones first
- what was not reviewed (`limitations`), in one line
- where the outputs and the scratch directory are
