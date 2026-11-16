<!--
1 件の finding を 1 件の issue として登録するテンプレート（1 対処 = 1 issue）。
各欄の {{field}} は findings.json の同名フィールドから転記する。空の任意欄は行ごと削除し、
すべての行を削除した節は見出しごと削除する（Low の finding には現在のテスト・露出の根拠・検証すべき結果・手順がないことがある）。
削除した節を指す「対応完了の条件」の項目も削除する。
- {{location}}: location ごとにコードスパンにし、読点で区切る
- {{asserts}}: 1 行に 1 つずつ箇条書きにする
- {{steps}}: 番号付きの手順と verify: 行を 1 行に 1 つずつ書く
- {{coverage.tests}}: テストごとにコードスパンにする
- {{depends_on}}: その finding の ID（`F-…`）。起票する人が issue へのリンクに置き換える。なければ「なし」
- （{{step}}）: 任意。なければ括弧ごと削除し、観点は残す

登録前に確認すること:
- FalsePositive / NotApplicable の finding は登録しない
- リポジトリから写した文には、登録すると通知が飛ぶ @メンションや owner/repo#N のリンクが含まれることがある。
  そうした文はコードスパンに入れる
- Likely / Unverified / Unlikely の finding を確定した事実として書かない。未確定の点を書く
- カバレッジの割合ではなく、不具合が漏れる経路と露出の根拠を書く
- ソース抜粋はリポジトリと同じ機密区分になる
-->

**タイトル:** [test][{{severity}}/{{testability}}] {{title}} ({{id}})

## 概要

| 項目 | 値 |
|---|---|
| ID | {{id}} |
| 重大度（露出）/ テスト容易性 / 規模 | {{severity}} / {{testability}} / {{effort}} |
| 確度 / 検証判定 | {{confidence}} / {{validation.verdict}}（検証方法: {{validation.method}}） |
| テストの不足 → 対処 | {{gap}} → {{remedy}} |
| 観点 | {{category}}（{{step}}） |
| 場所 | {{location}} |
| 対象リビジョン / 履歴の期間 | {{meta.commit}} / {{meta.window}} |

## 見逃される不具合

{{impact}}

- **露出の根拠:** {{exposure}}
- **シナリオ:** {{scenario}}
- **影響範囲:** {{blast_radius}}

## 追跡

{{trace}}

## 現在のテスト

- **カバー状況:** {{coverage.net}}
- **テスト:** {{coverage.tests}}
- **不足:** {{coverage.gaps}}

## 検証すべき結果

{{asserts}}

## 修正方針

{{fix}}

## 手順（各手順の後は green、本番の振る舞いは変えない）

{{steps}}

- **先行する検出事項:** {{depends_on}}

## 根拠

{{validation.evidence}}

## 対応完了の条件

- [ ] 「検証すべき結果」をすべて確かめるテストが、ビルドとテストが green のままマージされた
- [ ] 追加したテストが、対象の振る舞いを壊したときに失敗することを確認した
- [ ] 本番の振る舞いが変わっていない。誤りに見えた挙動は別途起票した
- [ ] findings.json の `status` を `findings.py merge` で取り込む fragment で `Fixed` に更新し、render と check を通した
