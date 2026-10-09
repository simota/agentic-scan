<!--
パフォーマンス上の検出事項を、オーナーや管理者に報告するテンプレート。1 通に複数の finding を載せてよい。
件数と各 finding は findings.json から転記し、ダッシュボードと食い違わないようにする。

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

除外（FalsePositive / NotApplicable）: {{n_excluded}} 件。未検証（Unverified）: {{n_unverified}} 件。

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

<!-- 深刻度順。finding ごとにこのブロックを繰り返し、templates/issue.ja.md で登録した issue へリンクする。 -->

### {{id}}: {{title}}

- **深刻度 / 確度 / 検証判定:** {{severity}} / {{confidence}} / {{validation.verdict}}
- **場所:** `{{location}}`
- **ワークロード / 規模の要因:** {{workload}} / {{scale_driver}}
- **コストモデル:** {{cost_model}}
- **影響:** {{impact}}
- **修正方針:** {{fix}}
- **管理先:** <issue の URL>

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

- `report.md` — 診断結果の文書
- `dashboard.html` — 全検出事項（オフラインで閲覧可）
