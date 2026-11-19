# console-triage Label Reference

This is the canonical label reference for the console-triage layer (band, tiles, verdicts, perspectives, triage board, and inspector) across 12 skills. security-scan is the reference. Use the same labels in the dashboard and the print version (assessment.html / report.html).

This table covers only the console-triage layer. Keep labels for existing elements such as priority lists, findings tables, and filters. If a label key is shared with an existing element, create a separate key for the console.

## 1. Shared Labels

| Location | ja | en |
|---|---|---|
| Band count labels | `open` / `closed` / `excluded` (uppercased in CSS) | Same |
| Severity tile names | `High` / `Medium` / `Low` / `Info` | Same |
| Tile annotation | `未解決 {open} · 対応済 {closed} · {ids}` | `open {open} · closed {closed} · {ids}` |
| Tile legend | `1 マス = 1 件。` ■ `未解決` □ `対応済み（{closed の status}）` | `1 cell = 1 record.` ■ `open` □ `{closed statuses, lowercase, separated by "or"}` |
| Heading: severity | `Severity` / `集計対象 {n} 件（除外 {x} 件は数えない）` | `Severity` / `{n} included records; {x} excluded are not counted` |
| Heading: verdicts | `Verdict` / `記録 {n} 件の判定。除外の判定は独立した区画` | `Verdict` / `all {n} records; excluded verdicts kept as their own block` |
| Heading: perspectives | `Perspectives` / `観点 {n}` | `Perspectives` / `{n} perspectives` |
| Heading: triage | `Triage` / `全件をいずれかのレーンに置いています。カードを選ぶと詳細を表示します` | `Triage` / `every record in one lane; pick a card to inspect it` |
| Lane heading numbers | `1.` `2.` … | Same |
| Inspector headings | `該当箇所` / `根拠` / `修正方針` | `Where` / `Evidence` / `Fix direction` |
| Band button: link to print version | `印刷用レポート` | `Printable report` |
| Band button: link to Markdown | `Markdown レポート` | `Markdown report` |
| Band button: color theme | `配色を切り替え` | `Toggle color theme` |

- In the legend's parentheses, list the statuses that the skill counts as 「対応済み」. Most skills use `Fixed / Accepted`, and bug-scan follows its existing mapping. infra-security-scan has no status and omits the entire □ entry.
- Keep any other buttons in the band as they are, including ux-scan's `エビデンス` / `Before / After`.

## 2. Lane Names

ja uses `Uppercase English / Japanese`, and en uses `Uppercase English`.

| Skill | Lanes (Display Order) |
|---|---|
| security-scan / prompt-scan | `FIX NOW / 修正計画`、`VERIFY FIRST / 先に検証` |
| architecture-scan | `PLAN THE FIX / 修正を計画`、`VERIFY FIRST / 先に検証` |
| data-integrity-scan | `READY TO SHIP / すぐ適用できる`、`STAGE THE ROLLOUT / 段階的に適用する`、`VERIFY FIRST / 先に検証` |
| logic-scan | `READY TO FIX / すぐ直せる`、`COORDINATE THE CHANGE / 影響先と合意して直す`、`VERIFY FIRST / 先に検証` |
| test-gap-scan | `READY TO WRITE / すぐ書ける`、`CHANGE PRODUCTION CODE FIRST / 先に本番コードを整える`、`VERIFY FIRST / 先に検証` |
| bug-scan | `FIX DIRECTION RECORDED / 修正方針あり`、`NO FIX DIRECTION / 修正方針なし` |
| prune-scan | `REMOVE NOW / 今すぐ削除`、`REDUCE OR CONSOLIDATE / 縮小・統合`、`DECIDE WITH A HUMAN / 人が判断`、`UNLIKELY / 可能性低` |
| ux-scan | `FIX / 修正`、`VERIFY FIRST / 先に検証` |
| infra-security-scan / performance-scan / privacy-scan | `OPEN / 未解決` |
| All skills (at the end) | `CLOSED / 対応済・受容`、`EXCLUDED / 誤検知・除外` (infra-security-scan omits CLOSED) |
