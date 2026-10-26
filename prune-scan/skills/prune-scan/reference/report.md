# Report

**Read when:** CHECKLIST, when only a checklist was asked for; REPORT — rendering and writing the chat summary.

```sh
python3 <skill-dir>/scripts/render.py <out>/findings.json --out <out> --lang ja|en --repo <repo> [--no-pdf]
python3 <skill-dir>/scripts/contract_check.py <out> [--no-pdf] [--allow <name>]...
```

`<skill-dir>` is the directory holding SKILL.md; never run a same-named script
from the reviewed repository (SKILL.md *Paths*).

`render.py` maps `findings.json` into scan-report-kit's common format
(`scan-report/1`) and writes `dashboard.html`, `report.html` and `report.pdf`
in the shared design. Each finding shows its element, the basis, the purpose
item (from `units.json`), the cost of keeping, the subtraction (what, what
remains, what is lost), the risk, and its unit and entry point. An open `Valid`
finding's next action is the subtraction itself; any other open, counted
finding's is "Verify first", except an `Unlikely` one, which is kept and has no
next action. With `--repo`, each finding's first `path:line` can be embedded
as a short excerpt. Secret-looking files and directories (env files such as
`.env.local`, `.envrc` and `production.env` included), and files named for a
secret (`passwords.txt`, `.vault-token`), are excluded. If a
secret-looking name (including `DB_PASS`, upper-case `*_KEY` constants and a
password inside a URL), a credential recognizable by its value whatever it is
called (Slack and Discord webhook URLs; GitHub, GitLab, Slack, AWS, Stripe,
Google, OpenAI, Anthropic, npm and SendGrid key formats; JWTs; a literal
`Bearer` or `Basic` header value) or a private key block appears anywhere in
the bounded source, its entire optional excerpt is omitted, including apparently
single-line assignments. Expression continuation and comment boundaries
differ across languages, so a quoted value does not prove that the next line
is safe to publish. This conservative check can also omit harmless source
that uses a secret-looking name; the finding's prose and location remain.

All excerpts in one report conversion use a single repository selection.
Where descriptor-relative opens are available, the repository directory stays
open until conversion finishes; changing its pathname or an intentional alias
cannot switch later excerpts to another repository. An unavailable initial
selection omits excerpts for the entire conversion. Other runtimes retain the
original canonical path and identity for the per-read fallback checks.

With `--repo`, an `--out` that is the repository or lies inside it (through
any alias) exits with status 2 before anything is written. Rendering keeps the
actual input files open and pins the selected output directory before building
the pages. HTML and PDF engines write into a private
temporary directory; publication, stale-PDF removal, and any rollback use the
pinned output directory. Replacing its pathname cannot redirect those writes
or delete an input. Existing output symlinks and non-regular files are refused,
as are output entries sharing an input file's identity. Rendering requires
descriptor-relative file operations; a runtime without that support exits with
status 2 before writing report outputs. Temporary storage must be outside
`--out` and `--repo`; set `TMPDIR` to a different directory when necessary.
Each published file is replaced atomically, but the report set as a whole is
not atomic. A failed publication restores the previous set; if restoration
also fails, recovery files are retained and their location is reported.

Every page is stamped with the SHA-256 of the `findings.json` it
shows and, when present, the adjacent `units.json` used for its purpose and
unit labels. `contract_check.py` compares both stamps with the current records
and rejects pages left stale by a change to either input. Stamps must be real,
unique metadata in the document head; text in a comment or another element
does not count. Unexpected text or elements before or directly inside the
head are rejected, including content that would implicitly move subsequent
metadata into the body. Ordinary title, style and script contents remain
valid. Ambiguous script markup that can keep a closing tag and subsequent
metadata inside script text is conservatively rejected. Character references
that the Python parser would silently discard cannot make a corrupted stamp
match the expected hash. Raw-text and RCDATA elements, including `noscript`
with scripting enabled, cannot supply apparent document-closing tags from
their text. `plaintext` is rejected because it cannot close the explicit
document envelope. Unclosed `template` elements and apparent document-closing
tags inside a template cannot complete the envelope, even when the template
is subsequently closed. Incomplete HTML documents are rejected even when
their input stamps match. A present but unreadable `units.json`, including a
broken symlink, is an input error rather than an omitted baseline.
On POSIX systems with descriptor-relative opens, the check captures the output
directory's identity before resolving the path and verifies it when opening
the directory. It pins every ancestor and uses the selected directory's
descriptor for all artifact inspection and reads. Before reporting success,
it verifies that both the resolved path and the original requested path still
identify the inspected directory. Retargeting an intentional alias, including
an ancestor alias, therefore invalidates the check. Runtimes without
descriptor-relative opens also compare both paths with the selected
directory's initial identity at the end. Ancestors need only search permission
when the runtime exposes `O_PATH` or `O_SEARCH`; otherwise they must also be
readable.

The check keeps each inspected artifact open and fingerprints the bytes it
validates. Before reporting success, it rechecks each file's identity, version
and content, then checks every artifact pathname again after all content
reads. The directory's artifact names are also rechecked. Replacements,
removals, writes during inspection, and newly appearing unapproved artifacts
require another check. Explicitly allowed extras remain outside these checks,
except that an allowed directory holding either `dashboard.html` or
`report.html` (a second language) must hold both, complete and stamped with the current `findings.json` and
`units.json`, and an allowed symbolic link to a directory is refused; `--allow` never exempts a required artifact. These checks detect observed
changes without locking writers or providing an atomic snapshot of the entire
report set.

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
in seconds for the one retry SKILL.md allows; a value that is not a positive
number of seconds exits 2 before anything is written. For a requester language other
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
