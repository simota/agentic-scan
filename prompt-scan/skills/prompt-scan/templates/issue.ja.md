<!--
1 件の finding を 1 件の issue として登録する（1 根本原因 = 1 修正箇所 = 1 issue）。
各欄の {{field}} は findings.json の同名フィールドから転記する。手で埋める場合、欄がすべて空の表の行と節は削除し、それ以外の空欄には — を書く。
scripts/export.py issues はすべての finding についてこのテンプレートを埋め、コメント・空の行・空の節を除く。

登録前に確認すること:
- 動作する指示上書き（ジェイルブレイク・インジェクション）の文字列を書かない。弱点と変数名で示す
- シークレットや個人データの値を書かない。場所と種類だけを書く
- プロンプト本文はリポジトリと同じ機密区分になる。issue の閲覧範囲がリポジトリより広いなら抜粋を貼らない
-->

**タイトル:** [{{severity}}][{{kind}}] {{title}} ({{id}})

## 概要

| 項目 | 値 |
|---|---|
| ID | {{id}} |
| 種別 | {{kind}}（defect = 不具合 / improvement = 改善提案） |
| 深刻度 | {{severity}} |
| 確度 | {{confidence}}（Model-dependent なら「確認方法」の評価ケースで決着させる） |
| 検証判定 | {{validation.verdict}}（方法: {{validation.method}}） |
| 観点 | {{category}} |
| 対象プロンプト | {{prompt}} |
| 場所 | `{{location}}` |
| 対象リビジョン | {{meta.commit}} |
| 診断日 / 診断者 | {{meta.date}} / {{meta.assessor}} |

## 症状

{{symptom}}

## 原因

{{cause}}

## 影響

{{impact}}

## 修正方針

{{fix}}

## 改善案

<!-- improvement の場合は必須。defect でも書き換え案があれば書く。 -->

現在:

```
{{proposal.before}}
```

提案:

```
{{proposal.after}}
```

## 確認方法

<!-- 評価ケース（入力・期待する出力の性質・判定方法）またはテストのアサーション。 -->
{{test}}

## 根拠

{{validation.evidence}}

## 対応完了の条件

- [ ] 修正がマージされた
- [ ] 確認方法の評価ケースまたはテストが追加され、修正後に成功する
- [ ] 同じプロンプトの既存の評価ケースが引き続き成功する
- [ ] findings.json の `status` を `Fixed` に更新した（評価の実行は `eval_runs` に別途記録する）
