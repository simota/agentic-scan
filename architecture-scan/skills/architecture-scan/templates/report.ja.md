<!--
設計上の検出事項を、オーナー、テックリード、管理者に報告するテンプレート。1 通に複数の finding を載せてよい。
件数と各 finding は findings.json から転記し、ダッシュボードと食い違わないようにする。
{{n_*}} の値はすべて `python3 scripts/findings.py counts <out>/findings.json` の出力から転記する。
数え方は report.md のタイトル直下の件数行と同じで、除外判定（FalsePositive / NotApplicable）は数えない。

送る前に確認すること:
- 各 finding は好みではなく、根拠のある不具合または変更コストを述べている
- Unverified / Likely / Unlikely の finding を確定した事実として書かない
-->

**件名:** [アーキテクチャ報告] {{meta.project}} — High {{n_high}} 件 / Medium {{n_medium}} 件（{{meta.date}}）

## 1. サマリー

<!-- 結論から書く。例:「請求書の書き込み元が 2 つあり、返金処理が税計算ルールを通っていない。まず billing 経由に揃える。」 -->


| 重大度 | 件数 | うち Valid |
|---|---|---|
| High | {{n_high}} | {{n_high_valid}} |
| Medium | {{n_medium}} | {{n_medium_valid}} |
| Low | {{n_low}} | {{n_low_valid}} |
| Info | {{n_info}} | {{n_info_valid}} |

除外（FalsePositive / NotApplicable）: {{n_excluded}} 件。可能性が高い（Likely）: {{n_likely}} 件。未検証（Unverified）: {{n_unverified}} 件。可能性が低い（Unlikely）: {{n_unlikely}} 件。
診断後の対応: 修正済み（Fixed）{{n_fixed}} 件、受容（Accepted）{{n_accepted}} 件（上の件数は診断時点のリビジョンのもので、これらを含む）。

## 2. 対象と方法

| 項目 | 値 |
|---|---|
| システム | {{meta.project}} |
| 範囲 | {{meta.scope}} |
| リビジョン | {{meta.commit}} | <!-- meta.commit がないときは report.md と同じく UNKNOWN -->
| 方法 | {{meta.method}} | <!-- meta.method がないときは report.md のタイトル直下の方法の行を転記する -->
| 診断日 / 診断者 | {{meta.date}} / {{meta.assessor}} |

コードの変更やアプリケーションの実行はしていない。
<!-- GUARD を実施した場合は上の文を差し替え、追加した適合性チェック、その置き場所、修正を適用したかを書く。 -->

## 3. 優先して対応すべき検出事項

<!-- 判定が FalsePositive / NotApplicable でない High と Medium の finding を重大度順に載せる。finding ごとに
このブロックを繰り返し、templates/issue.ja.md で登録した issue へリンクする。Low と Info は添付の report.md に任せる。 -->

### {{id}}: {{title}}

- **重大度 / 確度 / 検証判定:** {{severity}} / {{confidence}} / {{validation.verdict}}
- **場所:** {{location}} <!-- location ごとにコードスパンにし、読点で区切る -->
- **シナリオ / 影響範囲:** {{scenario}} / {{blast_radius}}
- **何が起きるか:** {{impact}}
- **修正方針:** {{fix}}
- **適合性チェック:** {{guard}}
- **管理先:** <issue の URL>

## 4. 設計ルール

<!-- rules[]: 各ルール、その出典と状態。推定（inferred）のルールはオーナーへの確認事項。ベースライン（source が
baseline で始まる）は一般的なファミリーのルールで、確認事項ではない。 -->
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
