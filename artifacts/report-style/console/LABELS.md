# console-triage 表記表

12 スキルの console-triage 層(帯・タイル・判定・観点・トリアージ盤・インスペクター)で使う表記の正本です。基準は security-scan です。dashboard と印刷版(assessment.html / report.html)の両方に同じ表記を使います。

この表は console-triage 層の表記だけを対象にします。既存の優先リスト・一覧テーブル・フィルタなど、旧来の部分のラベルは変えません。同じラベルキーを旧来の部分と共有している場合は、console 用のキーを別に作ってください。

## 1. 共通の表記

| 場所 | ja | en |
|---|---|---|
| 帯の件数ラベル | `open` / `closed` / `excluded`(CSS で大文字表示) | 同左 |
| 重大度タイルの名前 | `High` / `Medium` / `Low` / `Info` | 同左 |
| タイルの補足 | `未解決 {open} · 対応済 {closed} · {ids}` | `open {open} · closed {closed} · {ids}` |
| タイルの凡例 | `1 マス = 1 件。` ■ `未解決` □ `対応済み（{closed の status}）` | `1 cell = 1 record.` ■ `open` □ `{closed の status, 小文字, or 区切り}` |
| 見出し: 重大度 | `Severity` / `集計対象 {n} 件（除外 {x} 件は数えない）` | `Severity` / `{n} included records; {x} excluded are not counted` |
| 見出し: 判定 | `Verdict` / `記録 {n} 件の判定。除外の判定は独立した区画` | `Verdict` / `all {n} records; excluded verdicts kept as their own block` |
| 見出し: 観点 | `Perspectives` / `観点 {n}` | `Perspectives` / `{n} perspectives` |
| 見出し: トリアージ | `Triage` / `全件をいずれかのレーンに置いています。カードを選ぶと詳細を表示します` | `Triage` / `every record in one lane; pick a card to inspect it` |
| レーン見出しの番号 | `1.` `2.` … | 同左 |
| インスペクターの見出し | `該当箇所` / `根拠` / `修正方針` | `Where` / `Evidence` / `Fix direction` |
| 帯のボタン: 印刷版へのリンク | `印刷用レポート` | `Printable report` |
| 帯のボタン: Markdown へのリンク | `Markdown レポート` | `Markdown report` |
| 帯のボタン: 配色 | `配色を切り替え` | `Toggle color theme` |

- 凡例の括弧内は、そのスキルで「対応済み」に数える status を書きます(多くは `Fixed / Accepted`、bug-scan は既存の変換に合わせる)。status を持たない infra-security-scan は、□ の項目ごと出しません。
- 帯にある上記以外のボタン(ux-scan の `エビデンス` / `Before / After` など)はそのままです。

## 2. レーン名

ja は `英語(大文字) / 日本語`、en は `英語(大文字)` です。

| スキル | レーン(並び順) |
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
| 全スキル共通(末尾) | `CLOSED / 対応済・受容`、`EXCLUDED / 誤検知・除外`(infra-security-scan は CLOSED なし) |
