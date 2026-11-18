<!--
パフォーマンス上の検出事項を、オーナーや管理者に報告するテンプレート。1 通に複数の finding を載せてよい。
件数と各 finding は findings.json から転記し、ダッシュボードと食い違わないようにする。
件数は findings.json のフィールドではない。n_<深刻度> は判定が FalsePositive / NotApplicable 以外の
該当深刻度の件数、n_excluded はそれ以外の件数、n_likely / n_unverified / n_unlikely は除外以外の
判定別件数。「うち Valid」は深刻度ごとの Valid 件数。
任意フィールド: meta.commit が空なら UNKNOWN と書き、値のないフィールドの行は削除する。
location が配列なら path:line を 1 つずつバッククォートで囲み、「, 」で区切る。

送る前に確認すること:
- 計測していないレイテンシ・スループット・メモリの数値を書かない
- Unverified / Likely / Unlikely の finding を確定した事実として書かない
-->

**件名:** [パフォーマンス報告] {{meta.project}} — High {{n_high}} 件 / Medium {{n_medium}} 件（{{meta.date}}）

## 1. サマリー

<!-- 結論から書く。例:「注文一覧が明細ごとにクエリを発行しており、注文の増加に伴いゲートウェイのタイムアウトに達する。」 -->


| 深刻度 | 件数 | うち Valid |
|---|---|---|
| High | {{n_high}} | |
| Medium | {{n_medium}} | |
| Low | {{n_low}} | |
| Info | {{n_info}} | |

除外（FalsePositive / NotApplicable）: {{n_excluded}} 件。可能性が高い（Likely）: {{n_likely}} 件。未検証（Unverified）: {{n_unverified}} 件。可能性が低い（Unlikely）: {{n_unlikely}} 件。

## 2. 対象と方法

| 項目 | 値 |
|---|---|
| システム | {{meta.project}} |
| 範囲 | {{meta.scope}} |
| リビジョン | {{meta.commit}} |
| 方法 | {{meta.method}} |
| 診断日 / 診断者 | {{meta.date}} / {{meta.assessor}} |

稼働中の環境には負荷を一切かけていない。

## 3. 優先して対応すべき検出事項

<!-- High と Medium の finding を深刻度順に 1 件ずつこのブロックで書き、Low と Info は ID だけ列挙する。
templates/issue.ja.md で登録した issue へリンクし、未登録なら「未登録」と書く。 -->

### {{id}}: {{title}}

- **深刻度 / 確度 / 検証判定:** {{severity}} / {{confidence}} / {{validation.verdict}}
- **場所:** `{{location}}`
- **ワークロード / 規模の要因:** {{workload}} / {{scale_driver}}
- **コストモデル:** {{cost_model}}
- **影響:** {{impact}}
- **修正方針:** {{fix}}
- **計測（修正前 → 修正後）:** {{measurement.before.result}} → {{measurement.after.result}}（{{measurement.environment}}）
- **対応 issue:** <issue の URL、または「未登録」>

## 4. 性能バジェット

<!-- budgets[]: 各バジェット、その根拠と状態。推定（inferred）のバジェットはオーナーへの確認事項。 -->
- 

## 5. 確認して問題なかった項目

<!-- checked_ok: 確認して問題がなかったもの。 -->
- 

## 6. 確認できなかったこと

<!-- limitations: 本番のデータ量、デプロイ先のインデックスや設定、実際のトラフィック構成など。 -->
- 

## 7. 判断が必要な事項

<!-- decisions: 確認すべきバジェット、受け入れるトレードオフ。 -->
- 

## 8. 推奨する対応順

<!-- next_steps -->
1. 

## 添付

- `report.md` — 診断レポート本文
- `dashboard.html` — 全検出事項（オフラインで閲覧可）
- 計測ログ — measurement のある finding ごとに、修正前と修正後のコマンドと生ログ（`report.md` の各 finding にも収録）
