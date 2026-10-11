<!--
プロンプト診断の結果を担当者・プロダクトオーナーへまとめて報告するテンプレート（メール、チケット、ドキュメント用）。
数値と各 finding の内容は findings.json から転記し、ダッシュボードと食い違わないようにする。

送る前に確認すること:
- 宛先がリポジトリの閲覧権限を持つ人に限られている。そうでなければプロンプト抜粋を外す
- 動作する指示上書き文字列、シークレットや個人データの値を含めていない
- 未検証（Unverified / Likely / Unlikely）や Model-dependent の finding を確定事項として書いていない
-->

**件名:** [プロンプト診断] {{meta.target}} — 不具合 {{n_defect}} 件 / 改善提案 {{n_improvement}} 件（{{meta.date}}）

## 1. 要約

<!-- 最初の 1 行で結論を書く。例: 「回答 JSON のフィールド名がパーサーと一致しない不具合を 1 件確認しました。修正までは該当機能の出力が破棄されます。」 -->


| 深刻度 | 不具合 | 改善提案 |
|---|---|---|
| High | {{n_high_defect}} | {{n_high_improvement}} |
| Medium | {{n_medium_defect}} | {{n_medium_improvement}} |
| Low | {{n_low_defect}} | {{n_low_improvement}} |
| Info | {{n_info_defect}} | {{n_info_improvement}} |

除外（FalsePositive / NotApplicable）: {{n_excluded}} 件。

## 2. 対象と方法

| 項目 | 値 |
|---|---|
| 対象 | {{meta.target}} |
| 範囲 | {{meta.scope}} |
| リビジョン | {{meta.commit}} |
| 診断日 / 診断者 | {{meta.date}} / {{meta.assessor}} |

プロンプトとコードを静的に読んだ結果です。モデルへの送信（評価の実行）は {{eval_runs があれば「記録のとおり実施」、なければ「行っていません」}}。

## 3. 優先して対応すべき項目

<!-- 深刻度順。1 件ごとに下のブロックを繰り返す。詳細は templates/issue.ja.md で起票した issue へリンクする。 -->

### {{id}}: {{title}}

- **種別 / 深刻度 / 確度 / 判定:** {{kind}} / {{severity}} / {{confidence}} / {{validation.verdict}}
- **場所:** `{{location}}`（{{prompt}}）
- **症状:** {{symptom}}
- **影響:** {{impact}}
- **修正方針:** {{fix}}

## 4. 確認して問題がなかった項目

- {{checked_ok[]}}

## 5. 判断が必要な事項

- {{decisions[]}}

## 6. 制約事項

- {{limitations[]}}

## 7. 次のステップ

- {{next_steps[]}}

詳細は添付の report.pdf とダッシュボード（dashboard.html）を参照してください。
