# Figures: what each one answers

**Read when:** REPORT, and when a figure looks wrong; the fix is in the record, not the drawing.

Every figure is generated from the record, with a table of the same facts. A figure is presentation, never
evidence; do not pad the record to draw one.

| Figure | Question | Comes from |
|---|---|---|
| D7 Related defects | What connects, and what to fix first | `findings[].relations`, shared surfaces |
| D8 Surface map | Which screens, APIs and tables a defect reaches | `surfaces.json`, `findings[].surfaces`, `imports` |
| D9 Risk and hazard | What is dangerous, and what to look at first | `risk`, `hazard` of open records |
| D1 Injection path map | Which change, which gate, found where | `fix_events`, `gates` |
| D2 Pattern by module | What repeats, and where | `fix_events`; colour follows `Traced` only |
| D3 Fix chains | Do fixes breed fixes | `fix_events` origins, `history.json` |
| D4 Hotspot quadrant | Where is it dangerous | `history.json` modules, `fix_events` |
| D5 Live entry points | How the same bug happens today | `findings[].path` |
| D6 Issues to patterns | Which issues feed which patterns | `issues`, `fix_events`, findings |

Records judged `FalsePositive` or `NotApplicable` never count as open or get highlighted.

## `path` for D5

```json
[{"from": "POST /orders", "to": "validator", "state": "allowed", "at": "api/orders/routes.py:31", "why": "reachable when signed in"},
 {"from": "validator", "to": "wrong total", "state": "blocked", "at": "tests/test_total.py:44", "why": "pinned by a test"}]
```

`state` is `allowed`, `blocked` or `unknown`. Trace in order and stop at the first `blocked` or `unknown`: later
hops are drawn as not reached. A stopped path is the report's negative evidence.

## Omitted and cut figures

D1 and D3 are omitted, with the reason on the page, when fewer than 20 defects are classified or the history
is shallow. Any figure with nothing recorded says so. Labels cut to fit stay whole in the table, and a drawing
that holds only the top rows says so while the table keeps them all.

## What each figure cannot show

- D1's gate column is a judgement, not a record of what a change passed
- D3 must be read against the base rate printed under it
- D4's density swings at low commit counts, and test presence is judged from file names
- D6 links are hypotheses to test by fixing and measuring again
- D7's thin lines mean a shared DB table or job, not a cause
- The dashboard's severity sidebar counts a closed record with no severity as Info, because the shared kit
  requires a severity. The record's tracking field says none was recorded

## Dashboard and printed report

On the dashboard the figures follow the register. Tab enters a figure and the arrow keys move inside it; each part
has an accessible name, and a defect ID opens its record. The printable report has the same links and no focus stops.
