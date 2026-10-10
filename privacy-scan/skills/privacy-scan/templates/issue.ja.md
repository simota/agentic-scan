<!--
1 件の finding を 1 件の issue として登録するテンプレート（1 根本原因 = 1 修正箇所 = 1 issue）。
各欄の {{field}} は findings.json の同名フィールドから転記する。空の任意欄は行ごと削除する。

登録前に確認すること:
- 個人データの値を書かない。フィールド名とプレースホルダー（<顧客のメールアドレス> など）で示す
- 未修正（status: Open）の High は公開 issue ではなく非公開のトラッカーに登録する
- 技術的な検出事項であり、法的見解ではない。法令適合の判断は法務・DPO に回す
-->

**タイトル:** [{{severity}}] {{title}} ({{id}})

## 概要

| 項目 | 値 |
|---|---|
| ID | {{id}} |
| 深刻度 | {{severity}} |
| 確度 | {{confidence}}（Environment-dependent の場合は前提条件 — {{conditions}}） |
| 検証判定 | {{validation.verdict}}（方法: {{validation.method}}） |
| 観点 | {{category}} — {{step}}（step がなければ省く） |
| 場所 | `{{location}}` |
| 対象リビジョン | {{meta.commit}} |
| 診断日 / 診断者 | {{meta.date}} / {{meta.assessor}} |

## 何が起きるか

{{impact}}

- **個人データ:** {{data}}
- **データ主体:** {{subjects}}
- **破られている約束:** {{commitment}} — {{commitments[id].statement}}（根拠: {{commitments[id].source}}。`inferred` が true なら推定と明記）

## データの流れ

{{flow}}

**対照（約束が守られている流れ）:** {{contrast}}

<!-- 該当する呼び出し箇所が複数ある場合はすべて列挙する（同じ根本原因なら同じ issue）。 -->

## 根拠

{{validation.evidence}}

## 修正方針

{{fix}}

- **再発防止チェック（合成データのみ）:** {{guard}}

## 参考

- [{{references[].title}}]({{references[].url}})

## 未確定事項

<!-- 静的解析では確認できない条件: 委託先側の設定、契約や DPA、実際に保存されているデータ、デプロイ先のリージョン。 -->
- 

## 対応完了の条件

- [ ] 修正がマージされた
- [ ] 合成データを使ったチェックが、修正前に失敗し修正後に成功する
- [ ] 対象機能が引き続き動作する（positive control）
- [ ] 修正前に送信・保存済みのデータについて、担当者と方針（削除・通知・受容）が決まった
- [ ] findings.json の `status` を `Fixed` に更新した

---

_ソースコードの静的レビューによる技術的な指摘であり、法的見解ではない。_
