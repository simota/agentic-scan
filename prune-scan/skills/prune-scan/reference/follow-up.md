# Follow-up review

**Read when:** the requester asks what changed since an earlier prune-scan, or
asks for a review after removals were made; REPORT of that follow-up review.

Removal is a later, separate request, so the useful question after it is
"what did the subtraction achieve, and what does it leave behind?" A follow-up
answers that in two steps: a fresh review first, then a comparison.

```sh
python3 <skill-dir>/scripts/compare.py <earlier-out> <out> --repo <repo> \
    --json <scratch>/compare.json --fragment <scratch>/carry.json [--lang ja|en]
```

`<skill-dir>` is the directory holding SKILL.md (SKILL.md *Paths*).

## 1. Review independently first

Run the whole contract (RECON to VERIFY) on the current repository into a
**new** output directory, without reading the earlier record (SKILL.md
*Independence*). Reuse the earlier `units.json` only as the starting point of
UNITS: re-read the purpose sources and entry points, because removals change
them. Only once VERIFY has settled the new findings, compare.

## 2. Compare

`compare.py` reads both output directories (a `findings.json` or
`inventory.json` path names its directory) and compares whatever both hold.
It never writes inside `--repo`, and `--json` and `--fragment` may not name an
input. Put both in scratch: they are not contracted outputs.

Findings are matched by what they name, never by id, because `renumber`
assigns ids afresh in every review. Passes, strictest first, each keeping only
one-to-one matches: perspective and element; perspective and location file;
element alone. Each earlier open, counted finding lands in one bucket:

| Bucket | Means | Do |
|---|---|---|
| `resolved` | The later record has it as `Fixed` | Nothing |
| `accepted` | The later record has it as `Accepted` | Check that `decisions` says who kept it and why |
| `ruled_out` | The later review found it `FalsePositive` or `NotApplicable` | Say why in the chat summary: the earlier verdict was wrong, or a recorded decision now keeps it |
| `persisting` | Still open; `changes` lists severity, confidence, verdict, action or status that moved | Report what moved; an unchanged `Valid` finding is still "remove now" |
| `missing` | The later review did not find it | Confirm it is gone (below), then carry it as `Fixed` |

Later open findings with no earlier match are `new`; often the next wave,
orphaned by the removals. Earlier `Fixed` or `Accepted` findings open again
are `reopened`. With `inventory.json` in both directories, each inventory
section lists the candidates that `appeared` and are `gone`; rows are matched
on their names and files, not line numbers, so code moving inside a file does
not count. An `appeared` candidate is decided in REVIEW like any other. When
either inventory was truncated (`limits`, `truncated`), counts for those
sections are partial.

## 3. Carry what is gone

A `missing` finding is not proof of removal: the review may not have reached
its unit, or the element may have moved. `--repo` records, per missing finding,
the paths that are `paths_gone` and `paths_present`. For each:

- every path gone: read the code that referred to it and confirm nothing still
  does; it was removed
- a path still present: open it and confirm the element itself is gone (a
  function deleted from a module that stays)
- the element is still there: the follow-up review missed it. Write it as a
  new open finding instead, and add the unit or perspective it slipped through
  to `limitations` if it was not reached

`--fragment` writes a `findings.py merge` fragment holding every missing
finding as `status: Fixed`, with fresh ids after the later record's last id,
its unit, entry point and purpose item mapped onto the later `units.json` (by
id when the same item still has that name or text, otherwise by name or text,
and a unit by the most specific path prefix covering the location), and earlier
id references in its prose rewritten to the later record's ids. Left out and
named under "not carried", with the reason: a finding no later unit or purpose
item fits, one the later baseline cannot hold (a `Confirmed` finding whose
purpose item is now `inferred`), and one that was `Unlikely` (evidence of use:
record its removal only after confirming it by hand).
Each carried finding's `validation.evidence` ends with a note saying when it was
carried and whether its file is gone (`--lang ja` writes the note in Japanese).

Delete from the fragment every finding that the checks above did not confirm,
then merge, renumber and render as usual:

```sh
python3 <skill-dir>/scripts/findings.py merge <out>/findings.json <scratch>/carry.json
python3 <skill-dir>/scripts/findings.py renumber <out>/findings.json
```

Carried findings render as `Fixed`: counted in the "Fixed / Accepted" totals,
with no next action and out of the subtraction summary, so the report shows the
progress beside what is still open. Add one `checked_ok` line naming the
earlier review (date and commit) the follow-up was compared with.

## 4. Chat summary

After the *Done when* checks, the usual summary (`reference/report.md`) with,
right after its first line, the line `compare.py` prints first
(`prune-scan follow-up: 36 -> 29 open; resolved …`), then the new findings and
the inventory candidates that appeared, and every `ruled_out` or `reopened`
finding with its reason.
