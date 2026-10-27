# Evidence

**Read when:** VERIFY — capturing each finding's screenshots, videos or logs; REPORT — citing them in `evidence`.

Every report carries its evidence. Each included finding (every verdict but
`FalsePositive` and `NotApplicable`) cites at least one file that shows the
defect as found (`stage: "before"`), and a `Fixed` finding also cites one that
shows the fix (`stage: "after"`). `scripts/contract_check.py` refuses a report
that misses either. The files sit in `<out>/evidence/`, next to `findings.json`;
`scripts/render.py` embeds screenshots and log excerpts in `report.html` (and so
in `report.pdf`), before and after side by side, and writes `evidence.html`,
which also plays the videos.

GIF recordings use an image preview in `evidence.html`; MP4/WebM recordings use
video controls. Recordings stay linked to files in `evidence/`, including from
second-language pages. The printable report names and links each recording
instead of embedding its frames; animation is not preserved in the PDF.

## What to capture

| Kind | Files | Capture it when | How |
|---|---|---|---|
| `screenshot` | `.png`, `.jpg`, `.jpeg`, `.webp`, `.gif`; at most 5 MiB | The UI was rendered: a running URL the requester gave, or the app started as they asked (SKILL.md *Decide first*). Overlap, truncation, contrast, missing states | `scripts/capture.py screenshot <url> --viewport 360x640 --out <out>/evidence/U-006-before-360.png`, one per viewport that shows the defect; or the host's browser tool, saved into `evidence/` |
| `video` | `.webm`, `.mp4`, `.gif`; at most 200 MiB | The defect is a sequence: focus lost in a dialog, an error that clears input, layout shift, motion | The host's browser recorder (Playwright `recordVideo`, a browser-extension GIF), saved into `evidence/`. The PDF names the video; `evidence.html` plays it |
| `log` | `.txt`, `.log`, `.json`; UTF-8, at most 1 MiB | Always possible, and the evidence of a static review: the source lines, the inventory row, the search that found every occurrence, a console or test run | `scripts/capture.py log --out <out>/evidence/U-003-source.log --cwd <repo> -- awk 'NR>=13 && NR<=17 {print FILENAME ":" FNR ": " $0}' src/components/TaskList.tsx` |

A rendering claim (overlap, truncation, contrast, a viewport defect) graded
`Confirmed` needs a screenshot or video. When nothing could be rendered, cite a
log and record "Nothing was rendered: evidence is source and command logs" in
`limitations`.

`capture.py log` runs the command without a shell, from `--cwd`, and saves the
command line, working directory, exit status and capture time above its output;
lines that look like secrets are masked anywhere along the line, including the
command line itself, and output past the 1 MiB log limit is cut with a note.
Run read-only commands only: it is evidence, not a change. `capture.py
screenshot` needs Chrome or Chromium (`CHROME` names the binary); like the PDF,
it may have to run outside the host's sandbox.

## Rules

- **Name** — a plain file name inside `evidence/`: letters, digits, `.`, `_` and
  `-`, an extension of its kind. Name it after the finding, stage and viewport
  (`U-006-before-360.png`, `U-006-after-360.png`); `renumber` leaves file names
  as written, so the name stays a name, not a reference
- **Before and after** — `before` (the default) shows the defect in the reviewed
  checkout; `after` shows the same view once fixed, captured the same way and at
  the same viewport, so the pair compares like with like. Capture `after` only
  from a real fixed build (a later re-review, or a fix the requester applied); a
  drawn proposal is a `mockup` (`reference/mockups.md`), never evidence
- **No secrets or personal data** — use test accounts and fixture data; crop or
  recapture a screen that shows real people's data. Log excerpts in the report
  are masked again, but the files in `evidence/` are published as they are
- **Exactly the cited files** — `evidence/` holds the files the record cites and
  nothing else; remove a stray capture or cite it. Replacing a file makes every
  page stale until it is rendered again
- **Never** write evidence inside the reviewed repository

## In the record

```json
"evidence": [
  {"kind": "log", "file": "U-006-source.log", "caption": "app.css sets .sidebar to 480px"},
  {"kind": "screenshot", "file": "U-006-before-360.png", "viewport": "360x640",
   "url": "http://localhost:5173/", "captured": "2026-10-12T09:30:00Z",
   "caption": "The task list starts off screen"},
  {"kind": "screenshot", "file": "U-006-after-360.png", "stage": "after", "viewport": "360x640",
   "caption": "The sidebar collapses; the list fits"}
]
```

`kind`, `file` and a one-line `caption` are required; `stage` (`before` or
`after`), `viewport` (`WIDTHxHEIGHT`), `url` (http or https) and `captured` are
optional. A finding cites 1 to 12 files, each once; one file may serve several
findings. `"evidence": null` in a fragment removes the list. Also name the
evidence in `validation.evidence`, so the verdict says what it rests on.
