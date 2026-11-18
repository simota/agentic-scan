<!--
1 件の finding を 1 件の issue として登録するテンプレート（1 対処 = 1 issue）。
各欄の {{field}} は findings.json の同名フィールドから転記する。空の任意欄は行ごと削除し、
すべての行を削除した節は見出しごと削除する（Low の finding には現在の強制・露出の根拠・守るべき不変条件・手順がないことがある）。
削除した節を指す「対応完了の条件」の項目も削除する。
- {{location}}: location ごとにコードスパンにし、読点で区切る
- {{invariants}}: 1 行に 1 つずつ箇条書きにする
- {{steps}}: 番号付きの手順と verify: 行を 1 行に 1 つずつ書く
- {{enforcement.sites}}: 強制箇所ごとにコードスパンにする
- {{depends_on}}: その finding の ID（`F-…`）。起票する人が issue へのリンクに置き換える。なければ「なし」
- （{{step}}）: 任意。なければ括弧ごと削除し、観点は残す

登録前に確認すること:
- FalsePositive / NotApplicable の finding は登録しない
- リポジトリから写した文には、登録すると通知が飛ぶ @メンションや owner/repo#N のリンクが含まれることがある。
  そうした文はコードスパンに入れる
- Likely / Unverified / Unlikely の finding を確定した事実として書かない。未確定の点を書く
- 足りない制約の一覧ではなく、データが壊れる・失われる・ロックされる経路と露出の根拠を書く
- ソース抜粋・テーブル名・行数はリポジトリと同じ機密区分になる
-->

**タイトル:** [data][{{severity}}/{{rollout}}] {{title}} ({{id}})

## 概要

| 項目 | 値 |
|---|---|
| ID | {{id}} |
| 重大度（露出）/ 適用方法 / 規模 | {{severity}} / {{rollout}} / {{effort}} |
| 適用方法の理由 | {{rollout_reason}} |
| 確度 / 検証判定 | {{confidence}} / {{validation.verdict}}（検証方法: {{validation.method}}） |
| 危険 → 対処 | {{hazard}} → {{remedy}} |
| 観点 | {{category}}（{{step}}） |
| 場所 | {{location}} |
| 対象リビジョン / 履歴の期間 | {{meta.commit}} / {{meta.window}} |

## データに起こりうること

{{impact}}

- **露出の根拠:** {{exposure}}
- **シナリオ:** {{scenario}}
- **影響範囲:** {{blast_radius}}

## 追跡

{{trace}}

## 現在の強制

- **強制の状況:** {{enforcement.net}}
- **強制箇所:** {{enforcement.sites}}
- **不足:** {{enforcement.gaps}}

## 守るべき不変条件

{{invariants}}

## 修正方針

{{fix}}

## 手順（各手順は 1 回のデプロイ以内。各手順の後も本番は動き続ける）

{{steps}}

- **先行する検出事項:** {{depends_on}}

## 根拠

{{validation.evidence}}

## 対応完了の条件

- [ ] 「守るべき不変条件」がすべて、スキーマかすべての書き込み経路で強制され、ビルドとテストが green のままマージされた
- [ ] 追加した制約やロックが、対象の不正な書き込みを拒否することをステージングのコピーか使い捨てのデータベースで確認した
- [ ] 各手順が、適用方法で許した以上に書き込みを止めずに適用された。誤りに見えた既存の行は別途起票した
- [ ] findings.json の `status` を `findings.py merge` で取り込む fragment で `Fixed` に更新し、render と check を通した
