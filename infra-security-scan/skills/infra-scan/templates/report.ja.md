<!--
検出結果をインフラ担当者・セキュリティ窓口へまとめて報告するテンプレート（メール、非公開チケット用）。
各 finding は findings.json から転記する。件数も findings.json から数える: n_* は FalsePositive /
NotApplicable と、F-* に統合された I-* を除く（ダッシュボードの要約と同じ数え方）。

送る前に確認すること:
- 宛先が対象アカウント / プロジェクトの情報を見てよい人に限られている
- シークレットの値、侵入手順を含めていない
- 未検証（Unverified / Likely / Unlikely）の finding を確定事項として書いていない
-->

**件名:** [インフラ診断報告] {{meta.project}} — High {{n_high}} 件 / 未遮断の攻撃経路 {{n_open_paths}} 本（{{meta.date}}）

## 1. 要約

<!-- 最初の 1 行で結論。例: 「任意の GitHub リポジトリから本番デプロイ用ロールを引き受けられる経路を 1 本確認しました。」 -->


| 深刻度 | 件数 | うち検証済み（Valid） |
|---|---|---|
| High | {{n_high}} | |
| Medium | {{n_medium}} | |
| Low | {{n_low}} | |
| Info | {{n_info}} | |

除外（FalsePositive / NotApplicable）: {{n_excluded}} 件。検出事項に統合: {{n_covered}} 件。未検証: {{n_unverified}} 件。

## 2. 対象と方法

| 項目 | 値 |
|---|---|
| 対象 | {{meta.project}} |
| 範囲（アカウント / プロジェクト / 環境） | {{meta.scope}} |
| 入力 | {{meta.inputs}} |
| リビジョン | {{meta.commit}} |
| 方法 | {{meta.method}} |
| 診断日 / 診断者 | {{meta.date}} / {{meta.assessor}} |

構成ファイルの静的レビューであり、クラウド API の呼び出しや稼働中リソースへの通信は行っていません。

## 3. 未遮断の攻撃経路

<!-- attack_paths のうち status: open のもの。起点 → 到達先、関係する finding。 -->
- **{{attack_paths[].id}}:** {{attack_paths[].entry}} → {{attack_paths[].target}}（{{attack_paths[].findings}}）

## 4. 優先して対応すべき項目

<!-- High / Medium を深刻度順に。1 件 3〜5 行。 -->
### {{id}} [{{severity}}] {{title}}

- **リソース / 場所:** `{{resources}}` / `{{location}}`
- **起点:** {{actor}}
- **影響:** {{impact}}
- **修正方針:** {{fix}}

## 5. 問題がなかった項目

{{checked_ok}}

## 6. 判断をお願いしたい事項

{{decisions}}

## 7. 制約事項

{{limitations}}

## 8. 次のステップ

{{next_steps}}

添付: dashboard.html, assessment.pdf
