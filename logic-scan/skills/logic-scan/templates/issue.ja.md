<!--
1 件の finding を 1 件の issue として登録するテンプレート（1 対処 = 1 issue）。
各欄の {{field}} は findings.json の同名フィールドから転記する。空の任意欄は行ごと削除し、
すべての行を削除した節は見出しごと削除する（Low の finding には反例・現在の担保・露出の根拠・守るべきルール・手順がないことがある）。
削除した節を指す「対応完了の条件」の項目も削除する。
- {{location}}: location ごとにコードスパンにし、読点で区切る
- {{invariants}}: 1 行に 1 つずつ箇条書きにする
- {{steps}}: 番号付きの手順と verify: 行を 1 行に 1 つずつ書く
- {{enforcement.sites}}: 担保箇所ごとにコードスパンにする
- {{depends_on}}: その finding の ID（`F-…`）。起票する人が issue へのリンクに置き換える。なければ「なし」
- （{{step}}）: 任意。なければ括弧ごと削除し、観点は残す

登録前に確認すること:
- FalsePositive / NotApplicable の finding は登録しない
- リポジトリから写した文には、登録すると通知が飛ぶ @メンションや owner/repo#N のリンクが含まれることがある。
  そうした文はコードスパンに入れる
- Likely / Unverified / Unlikely の finding を確定した事実として書かない。未確定の点を書く
- 書き方の好みではなく、誤った結果を反例と露出の根拠とともに書く
- ソース抜粋・金額・顧客らしき値はリポジトリと同じ機密区分になる
-->

**タイトル:** [logic][{{severity}}/{{change}}] {{title}} ({{id}})

## 概要

| 項目 | 値 |
|---|---|
| ID | {{id}} |
| 重大度（露出）/ 修正の波及 / 規模 | {{severity}} / {{change}} / {{effort}} |
| 波及の理由 | {{change_reason}} |
| 確度 / 検証判定 | {{confidence}} / {{validation.verdict}}（検証方法: {{validation.method}}） |
| 欠陥 → 対処 | {{hazard}} → {{remedy}} |
| 観点 | {{category}}（{{step}}） |
| 場所 | {{location}} |
| 対象リビジョン / 履歴の期間 | {{meta.commit}} / {{meta.window}} |

## 反例

- **入力:** {{counterexample.input}}
- **正しい結果:** {{counterexample.expected}}
- **実際の結果:** {{counterexample.actual}}
- **正解の根拠:** {{counterexample.oracle}}

## 起こる誤り

{{impact}}

- **露出の根拠:** {{exposure}}
- **シナリオ:** {{scenario}}
- **影響範囲:** {{blast_radius}}

## 追跡

{{trace}}

## 現在の担保

- **担保の状況:** {{enforcement.net}}
- **担保箇所:** {{enforcement.sites}}
- **不足:** {{enforcement.gaps}}

## 守るべきルール

{{invariants}}

## 修正方針

{{fix}}

## 手順（各手順はビルドを green で終える。修正は反例のテストと同じ変更で入れる）

{{steps}}

- **先行する検出事項:** {{depends_on}}

## 根拠

{{validation.evidence}}

## 対応完了の条件

- [ ] 反例が、修正を戻すと失敗し修正があると通るテストになり、ビルドとテストが green のままマージされた
- [ ] 「守るべきルール」がすべて、反例が乗っている境界値も含めてテストで検証されている
- [ ] 結果が変わる呼び出し元をすべて確認した。すでに出た誤った結果はついでに書き換えず、判断事項として起票した
- [ ] findings.json の `status` を `findings.py merge` で取り込む fragment で `Fixed` に更新し、render と check を通した
