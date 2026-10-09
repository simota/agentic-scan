<!--
設計上の検出事項を、オーナー、テックリード、管理者に報告するテンプレート。1 通に複数の finding を載せてよい。
件数と各 finding は findings.json から転記し、ダッシュボードと食い違わないようにする。
件数は report.md の 1 行目と同じ。除外判定（FalsePositive / NotApplicable）は数えない。
「うち Valid」はその深刻度で判定が Valid の件数。n_likely と n_unverified は判定ごとの件数。

送る前に確認すること:
- 各 finding は好みではなく、根拠のある不具合または変更コストを述べている
- Unverified / Likely / Unlikely の finding を確定した事実として書かない
-->

**件名:** [アーキテクチャ報告] {{meta.project}} — High {{n_high}} 件 / Medium {{n_medium}} 件（{{meta.date}}）

## 1. サマリー

<!-- 結論から書く。例:「請求書の書き込み元が 2 つあり、返金処理が税計算ルールを通っていない。まず billing 経由に揃える。」 -->


| 深刻度 | 件数 | うち Valid |
|---|---|---|
| High | {{n_high}} | |
| Medium | {{n_medium}} | |
| Low | {{n_low}} | |
| Info | {{n_info}} | |

除外（FalsePositive / NotApplicable）: {{n_excluded}} 件。可能性が高い（Likely）: {{n_likely}} 件。未検証（Unverified）: {{n_unverified}} 件。

## 2. 対象と方法

| 項目 | 値 |
|---|---|
| システム | {{meta.project}} |
| 範囲 | {{meta.scope}} |
| リビジョン | {{meta.commit}} |
| 方法 | {{meta.method}} |
| 診断日 / 診断者 | {{meta.date}} / {{meta.assessor}} |

コードの変更やアプリケーションの実行はしていない。

## 3. 優先して対応すべき検出事項

<!-- 深刻度順。finding ごとにこのブロックを繰り返し、templates/issue.ja.md で登録した issue へリンクする。 -->

### {{id}}: {{title}}

- **深刻度 / 確度 / 検証判定:** {{severity}} / {{confidence}} / {{validation.verdict}}
- **場所:** `{{location}}`
- **シナリオ / 影響範囲:** {{scenario}} / {{blast_radius}}
- **影響:** {{impact}}
- **修正方針:** {{fix}}
- **適合性チェック:** {{guard}}
- **管理先:** <issue の URL>

## 4. 設計ルール

<!-- rules[]: 各ルール、その根拠と状態。推定（inferred）のルールはオーナーへの確認事項。 -->
- 

## 5. 確認して問題なかった項目

<!-- checked_ok: 確認して問題がなかったもの。 -->
- 

## 6. 確認できなかったこと

<!-- limitations: 実行時の構成、メッセージ配信の保証、チームの担当範囲、ロードマップなど。 -->
- 

## 7. 判断が必要な事項

<!-- decisions: 確認すべきルール、コードと食い違う設計文書、受け入れるトレードオフ。 -->
- 

## 8. 推奨する対応順

<!-- next_steps -->
1. 

## 添付

- `report.md` — 診断結果の文書
- `dashboard.html` — 全検出事項（オフラインで閲覧可）
