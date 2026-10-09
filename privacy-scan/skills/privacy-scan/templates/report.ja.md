<!--
プライバシー上の検出事項を、オーナー、DPO、管理者に報告するテンプレート。1 通に複数の finding を載せてよい。
件数と各 finding は findings.json から転記し、ダッシュボードと食い違わないようにする。

送る前に確認すること:
- 個人データの値をどこにも書かない。フィールド名とプレースホルダーだけを使う
- Unverified / Likely / Unlikely の finding を確定した事実として書かない
- 技術的なレビューであり、法的見解ではない
-->

**件名:** [プライバシー報告] {{meta.project}} — High {{n_high}} 件 / Medium {{n_medium}} 件（{{meta.date}}）

## 1. サマリー

<!-- 結論から書く。例:「決済時のエラーで顧客の住所がエラー監視サービスに送られている。まずリクエストの取得を止める。」 -->


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

ソースコードのみを読み、データストア・ログ・バックアップにはアクセスしていない。技術的なレビューであり、法的見解ではない。

## 3. 優先して対応すべき検出事項

<!-- 深刻度順。finding ごとにこのブロックを繰り返し、templates/issue.ja.md で登録した issue へリンクする。 -->

### {{id}}: {{title}}

- **深刻度 / 確度 / 検証判定:** {{severity}} / {{confidence}} / {{validation.verdict}}
- **場所:** `{{location}}`
- **個人データ / データ主体:** {{data}} / {{subjects}}
- **影響:** {{impact}}
- **修正方針:** {{fix}}
- **管理先:** <issue の URL>

## 4. プライバシー上の約束

<!-- commitments[]: 各約束、その根拠と状態。推定（inferred）の約束はオーナーへの確認事項。 -->
- 

## 5. 確認して問題なかった項目

<!-- checked_ok: 確認して問題がなかったもの。 -->
- 

## 6. 確認できなかったこと

<!-- limitations: 委託先側の設定、契約、実際に保存されているデータ、デプロイ先のリージョン。 -->
- 

## 7. 判断が必要な事項

<!-- decisions: 確認すべき約束、契約状況が不明な提供先、すでに送信・保存済みのデータの扱い。 -->
- 

## 8. 推奨する対応順

<!-- next_steps -->
1. 

## 添付

- `report.md` — 診断結果の文書
- `dashboard.html` — 全検出事項（オフラインで閲覧可）
